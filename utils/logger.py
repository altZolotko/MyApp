"""
Модуль централизованного логирования VPN-клиента.

Назначение: настройка единого логгера для всех компонентов системы.
Ведётся журнал всех операций с криптоматериалами (без раскрытия значений ключей),
событий безопасности, ошибок протокола.

Реализуемые требования: НФТ-4, требование 7 (документирование операций).
"""

import logging
import logging.handlers
import os
import sys
from typing import Optional


_LOGGER_INITIALIZED: bool = False
_ROOT_LOGGER_NAME: str = "vpn_gov"


def setup_logger(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Инициализирует корневой логгер приложения.

    Настраивает вывод в stdout и (опционально) в файл с ротацией.
    Формат записей включает метку времени, имя компонента, уровень и сообщение.

    :param log_level: строковый уровень логирования (DEBUG/INFO/WARNING/ERROR)
    :param log_file: путь к файлу журнала (None — только stdout)
    :return: настроенный логгер
    """
    global _LOGGER_INITIALIZED

    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    if _LOGGER_INITIALIZED:
        return logger

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, mode=0o750, exist_ok=True)
            except OSError as exc:
                logger.warning("Не удалось создать каталог журнала %s: %s", log_dir, exc)

        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 МБ
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("Не удалось открыть файл журнала %s: %s", log_file, exc)

    _LOGGER_INITIALIZED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Возвращает дочерний логгер по имени компонента.

    :param name: имя компонента (crypto, tunnel, session и т.д.)
    :return: дочерний логгер
    """
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")


def log_crypto_event(logger: logging.Logger, event: str, details: str = "") -> None:
    """
    Специализированная запись о криптографической операции.

    Обязательна для аудита по ПКЗ-2005. Не раскрывает значения ключей.

    :param logger: логгер компонента
    :param event: краткое описание события (KEYGEN, SIGN, VERIFY и т.д.)
    :param details: дополнительный контекст (без ключевого материала)
    """
    logger.info("[КРИПТО-АУДИТ] %s %s", event, details)
