"""
Точка входа VPN-клиента Роскомнадзора.

Назначение: инициализация всех подсистем, выполнение рукопожатия с VPN-сервером,
запуск TUN-туннеля. Реализует полный цикл работы клиента с автоматическим
восстановлением соединения.

Платформы: Linux (Astra Linux SE 1.7+) и Windows 10/11 (с wintun.dll).

Порядок запуска:
  1. Проверка прав администратора
  2. Загрузка конфигурации (bootstrap → кеш)
  3. Настройка логирования
  4. Загрузка сертификатов
  5. Выполнение рукопожатия (аутентификация + выработка ключей)
  6. Pull конфигурации с сервера управления
  7. Создание TUN-интерфейса и установка маршрутов
  8. Запуск asyncio-циклов туннеля
  9. Автоматическое восстановление при обрыве

Реализуемые требования:
  ФТ-1..6 — все функциональные требования
  НФТ-1   — Astra Linux SE 1.7 / Windows 10+
  НФТ-3   — asyncio для ввода-вывода
"""

import asyncio
import os
import struct
import sys
from typing import Optional

from vpn_core.auth import Authenticator
from vpn_core.config_manager import ConfigManager
from vpn_core.protocol import FrameCodec
from vpn_core.pygost_provider import PygostProvider
from vpn_core.session import Session, SessionConfig
from vpn_core.tunnel import create_tun_interface, VpnTunnel, connect_with_retry, is_admin
from utils.logger import get_logger, setup_logger
from utils.zeroize import secure_context

_log = get_logger("main")


def check_admin() -> None:
    """
    Проверяет наличие прав администратора/root.
    Linux: os.geteuid() == 0
    Windows: IsUserAnAdmin() через ctypes
    """
    if is_admin():
        return
    if sys.platform == "win32":
        print(
            "ОШИБКА: VPN-клиент должен быть запущен от имени Администратора "
            "(требуется для управления WinTun-адаптером).",
            file=sys.stderr,
        )
    else:
        print(
            "ОШИБКА: VPN-клиент должен быть запущен от имени root (CAP_NET_ADMIN).",
            file=sys.stderr,
        )
    sys.exit(1)


def load_cert_and_key(cert_path: str, key_path: str) -> tuple[bytes, bytes]:
    """
    Загружает DER-сертификат и бинарный закрытый ключ с диска.

    :param cert_path: путь к DER-файлу сертификата
    :param key_path:  путь к файлу закрытого ключа (32 байта)
    :return: (cert_der_bytes, private_key_bytes)
    """
    with open(cert_path, "rb") as f:
        cert_der = f.read()
    with open(key_path, "rb") as f:
        private_key = f.read()
    if len(private_key) != 32:
        raise ValueError(f"Закрытый ключ должен быть 32 байта, получено {len(private_key)}")
    return cert_der, private_key


async def perform_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    auth: Authenticator,
) -> Optional[tuple]:
    """
    Выполняет протокол рукопожатия с сервером.

    :param reader: asyncio StreamReader
    :param writer: asyncio StreamWriter
    :param auth:   объект аутентификатора
    :return: (session_id, enc_key, mac_key, peer_pub) или None при ошибке
    """
    # Шаг 1: ClientHello
    hello_bytes, eph_kp, ukm = auth.build_client_hello()
    length_prefix = struct.pack("!H", len(hello_bytes))
    writer.write(length_prefix + hello_bytes)
    await writer.drain()
    _log.info("ClientHello отправлен")

    # Шаг 2: Получение ServerHello
    try:
        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
        server_hello_len = struct.unpack("!H", len_bytes)[0]
        server_hello = await asyncio.wait_for(
            reader.readexactly(server_hello_len), timeout=30.0
        )
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        _log.error("Таймаут или обрыв при получении ServerHello: %s", exc)
        return None

    # Шаг 3: Обработка ServerHello, проверка сертификата и выработка ключей
    auth_result = auth.process_server_hello(server_hello, eph_kp, ukm)
    if auth_result is None:
        _log.error("Рукопожатие не выполнено: ошибка аутентификации сервера")
        return None

    # Шаг 4: ClientFinished (наша подпись)
    finished = auth.build_client_finished(
        auth_result.session_id, auth_result.peer_public_key
    )
    length_prefix = struct.pack("!H", len(finished))
    writer.write(length_prefix + finished)
    await writer.drain()
    _log.info("ClientFinished отправлен, рукопожатие завершено")

    return (
        auth_result.session_id,
        auth_result.enc_key,
        auth_result.mac_key,
        auth_result.peer_public_key,
    )


async def run_vpn_client(config_path: str = "config_bootstrap.json") -> None:
    """
    Основная async-функция VPN-клиента.

    :param config_path: путь к bootstrap-конфигурации
    """
    # Инициализация конфигурации
    cfg_mgr = ConfigManager(config_path)
    config = cfg_mgr.initialize()

    setup_logger(
        log_level=config.log_level,
        log_file=config.log_file,
    )
    _log.info("=== VPN-клиент Роскомнадзора v1.0 запущен ===")

    # Загрузка сертификатов и ключа
    try:
        with open(config.ca_cert_path, "rb") as f:
            ca_cert_der = f.read()
        client_cert_der, client_prv_key = load_cert_and_key(
            config.initial_cert_path, config.initial_key_path
        )
    except (FileNotFoundError, ValueError) as exc:
        _log.error("Ошибка загрузки сертификатов: %s", exc)
        _log.error(
            "Запустите 'python -m utils.cert_gen' для генерации тестовых сертификатов"
        )
        sys.exit(2)

    # Инициализация криптопровайдера
    crypto = PygostProvider()

    # Аутентификатор
    with secure_context(client_prv_key) as prv_buf:
        auth = Authenticator(
            crypto=crypto,
            our_cert_der=client_cert_der,
            our_private_key=bytes(prv_buf),
            ca_cert_der=ca_cert_der,
        )

        # Кодек кадров
        codec = FrameCodec(crypto)

        # TUN-интерфейс (Linux: LinuxTunInterface, Windows: WindowsTunInterface)
        tun = create_tun_interface(config.tun_interface)

        try:
            tun.open()
            tun.configure(
                ip_address=config.tun_address,
                netmask=config.tun_netmask,
            )
            tun.add_routes(config.protected_subnets)
        except OSError as exc:
            _log.error("Ошибка создания TUN-интерфейса: %s", exc)
            sys.exit(3)

        # Главный цикл с поддержкой переаутентификации
        session_obj: Optional[Session] = None

        try:
            while True:
                _log.info(
                    "Подключение к VPN-серверу %s:%d",
                    config.server_ip,
                    config.server_port,
                )

                try:
                    reader, writer = await asyncio.open_connection(
                        config.server_ip, config.server_port
                    )
                except (ConnectionRefusedError, OSError) as exc:
                    _log.error("Не удалось подключиться: %s", exc)
                    await asyncio.sleep(config.reconnect_timeout)
                    continue

                # Рукопожатие
                result = await perform_handshake(reader, writer, auth)
                if result is None:
                    writer.close()
                    await asyncio.sleep(5)
                    continue

                session_id, enc_key, mac_key, peer_pub = result

                # Pull конфигурации с сервера управления
                session_token = f"{session_id:08x}"
                cfg_mgr.update_from_server(session_token)

                # Создание сессии
                sess_config = SessionConfig(
                    session_lifetime=config.session_lifetime,
                    rekey_interval=config.rekey_interval,
                    rekey_bytes=config.rekey_bytes,
                    max_reconnect_attempts=config.max_reconnect_attempts,
                    reconnect_timeout=config.reconnect_timeout,
                )
                session_obj = Session(
                    session_id=session_id,
                    enc_key=enc_key,
                    mac_key=mac_key,
                    config=sess_config,
                    crypto=crypto,
                )

                # Запуск туннеля
                tunnel = VpnTunnel(
                    session=session_obj,
                    codec=codec,
                    tun=tun,
                    reader=reader,
                    writer=writer,
                    keepalive_interval=config.keepalive_interval,
                )
                await tunnel.run()

                # Если сессия истекла — полная переаутентификация (новый итерация)
                if session_obj.is_expired():
                    _log.info("Сессия истекла. Полная переаутентификация.")
                    session_obj.close()
                    session_obj = None
                    writer.close()
                    continue

                # Иначе — выход из цикла (штатное завершение или неустранимая ошибка)
                session_obj.close()
                writer.close()
                break

        finally:
            tun.remove_routes(config.protected_subnets)
            tun.close()
            if session_obj is not None:
                session_obj.close()
            _log.info("VPN-клиент завершил работу")


def main() -> None:
    """Точка входа: проверка прав, парсинг аргументов, запуск asyncio."""
    check_admin()

    config_path = "config_bootstrap.json"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    # Предварительная настройка логгера до чтения конфига
    setup_logger("INFO")

    # Windows требует ProactorEventLoop для asyncio (поддержка subprocess и pipes)
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        asyncio.run(run_vpn_client(config_path))
    except KeyboardInterrupt:
        _log.info("Прерывание по Ctrl+C")
    except Exception as exc:
        _log.exception("Критическая ошибка: %s", exc)
        sys.exit(99)


if __name__ == "__main__":
    main()
