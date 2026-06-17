"""
Разрешение путей для упакованного (PyInstaller) и режима разработки.

Обеспечивает корректное расположение пользовательских данных:
  - Windows: %APPDATA%\\VPNGov\\
  - Linux:   ~/.config/vpngov/
"""

import os
import sys


def is_packaged() -> bool:
    """True когда приложение запущено как PyInstaller-бандл."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def get_resource_root() -> str:
    """Директория, где находятся встроенные ресурсы (config, иконки и т.п.)."""
    if is_packaged():
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_install_root() -> str:
    """Директория установки / запуска исполняемого файла."""
    if is_packaged():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_user_data_dir() -> str:
    """Директория пользовательских данных (конфиги, сертификаты, кеш)."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        path = os.path.join(base, "VPNGov")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config"))
        path = os.path.join(base, "vpngov")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def get_default_certs_dir() -> str:
    """Директория сертификатов по умолчанию (внутри пользовательских данных)."""
    return os.path.join(get_user_data_dir(), "certs")


def get_default_config_path() -> str:
    """
    Путь к конфигурационному файлу.
    Приоритет: пользовательские данные → встроенный bootstrap.
    При первом запуске копирует bundled-конфиг в AppData.
    """
    user_config = os.path.join(get_user_data_dir(), "config_bootstrap.json")
    if os.path.exists(user_config):
        return user_config
    bundled = os.path.join(get_resource_root(), "config_bootstrap.json")
    if os.path.exists(bundled) and not os.path.exists(user_config):
        try:
            import shutil
            shutil.copy2(bundled, user_config)
            return user_config
        except OSError:
            pass
    return bundled


def get_wintun_dll_path() -> str:
    """
    Путь к wintun.dll.
    Поиск: рядом с .exe (установка) → встроенные ресурсы → CWD.
    """
    candidates = [
        os.path.join(get_install_root(), "wintun.dll"),
        os.path.join(get_resource_root(), "wintun.dll"),
        "wintun.dll",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return "wintun.dll"


def get_log_dir() -> str:
    """Директория для файлов логов."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", get_user_data_dir())
        path = os.path.join(base, "VPNGov", "Logs")
    else:
        path = os.path.join(get_user_data_dir(), "logs")
    os.makedirs(path, mode=0o750, exist_ok=True)
    return path
