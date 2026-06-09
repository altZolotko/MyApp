"""
Модуль централизованного управления конфигурацией.

Назначение: загрузка конфигурации клиента с сервера управления (pull-модель)
по HTTP REST API. Первоначальный bootstrap выполняется из локального JSON-файла.
После успешной аутентификации клиент получает актуальные параметры и сохраняет
их в локальный кеш (config_cache.json).

Реализуемые требования:
  ФТ-6  — централизованное управление конфигурацией (pull-модель)
  Г     — pull с сервера управления, кеширование
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

from utils.logger import get_logger

_log = get_logger("config")

_DEFAULT_CACHE_PATH = "config_cache.json"

_REQUIRED_FIELDS: dict[str, type] = {
    "server_ip": str, "server_port": int, "ca_cert_path": str,
    "initial_cert_path": str, "initial_key_path": str,
    "rekey_interval": int, "rekey_bytes": int, "reconnect_timeout": int,
    "max_reconnect_attempts": int, "session_lifetime": int,
}

_OPTIONAL_FIELDS: dict[str, Any] = {
    "log_level": "INFO", "log_file": None, "mgmt_server_url": None,
    "protected_subnets": [], "tun_interface": "tun0",
    "tun_address": "10.8.0.2", "tun_netmask": "255.255.255.0",
    "keepalive_interval": 30,
}


class ConfigError(Exception):
    """Ошибка конфигурации."""


class Config:
    """Объект конфигурации VPN-клиента."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._data:
            return self._data[name]
        if name in _OPTIONAL_FIELDS:
            return _OPTIONAL_FIELDS[name]
        raise AttributeError(f"Параметр конфигурации не найден: {name}")

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def update(self, new_data: dict) -> None:
        _log.info("Обновление конфигурации: %d параметров", len(new_data))
        self._data.update(new_data)

    def to_dict(self) -> dict:
        return dict(self._data)


def validate_config(data: dict) -> None:
    """Проверяет конфигурацию на наличие обязательных полей и корректность типов."""
    for field_name, expected_type in _REQUIRED_FIELDS.items():
        if field_name not in data:
            raise ConfigError(f"Отсутствует обязательный параметр: {field_name}")
        if not isinstance(data[field_name], expected_type):
            raise ConfigError(f"Параметр '{field_name}': ожидается {expected_type.__name__}")
    port = data.get("server_port", 0)
    if not (1 <= port <= 65535):
        raise ConfigError(f"Некорректный server_port: {port}")
    if data.get("rekey_interval", 0) < 60:
        raise ConfigError("рекеинтервал rekey_interval слишком мал (минимум 60 с)")
    _log.info("Конфигурация прошла валидацию")


def load_bootstrap_config(path: str) -> Config:
    """Загружает начальную конфигурацию из JSON-файла."""
    _log.info("Загрузка bootstrap-конфигурации из %s", path)
    if not os.path.exists(path):
        raise ConfigError(f"Файл конфигурации не найден: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Ошибка парсинга JSON: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Ошибка чтения файла: {exc}") from exc
    validate_config(data)
    return Config(data)


def load_cached_config(cache_path: str = _DEFAULT_CACHE_PATH) -> Optional[Config]:
    """Загружает кешированную конфигурацию."""
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        validate_config(data)
        return Config(data)
    except (json.JSONDecodeError, ConfigError, OSError):
        return None


def save_config_cache(config: Config, cache_path: str = _DEFAULT_CACHE_PATH) -> None:
    """Сохраняет конфигурацию в локальный кеш."""
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        os.chmod(cache_path, 0o600)
    except OSError as exc:
        _log.warning("Не удалось сохранить кеш: %s", exc)


def pull_remote_config(mgmt_url: str, session_token: str) -> Optional[dict]:
    """Получает конфигурацию с сервера управления (HTTP GET /vpn/config)."""
    url = f"{mgmt_url}/vpn/config"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {session_token}"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError):
        return None


class ConfigManager:
    """Менеджер конфигурации: объединяет bootstrap, кеш и pull с сервера."""

    def __init__(self, bootstrap_path: str) -> None:
        self._bootstrap_path = bootstrap_path
        self._config: Optional[Config] = None

    def initialize(self) -> Config:
        cached = load_cached_config()
        if cached is not None:
            self._config = cached
            return cached
        self._config = load_bootstrap_config(self._bootstrap_path)
        return self._config

    def update_from_server(self, session_token: str) -> bool:
        if self._config is None:
            return False
        mgmt_url = self._config.get("mgmt_server_url")
        if not mgmt_url:
            return False
        remote_data = pull_remote_config(mgmt_url, session_token)
        if remote_data is None:
            return False
        try:
            validate_config({**self._config.to_dict(), **remote_data})
            self._config.update(remote_data)
            save_config_cache(self._config)
            return True
        except ConfigError:
            return False

    @property
    def config(self) -> Optional[Config]:
        return self._config
