"""
TunnelWorker — QThread that runs a real full-tunnel VPN session (TUN-интерфейс)
in a background thread.

Responsibilities:
  - Проверка прав администратора/root
  - Загрузка конфигурации (bootstrap/кеш) и подстановка параметров из GUI
  - Загрузка сертификатов
  - Создание и настройка TUN-интерфейса
  - Подключение к host:port (до 15 попыток), рукопожатие ГОСТ
  - Запуск VpnTunnel (реальная пересылка IP-пакетов через TUN)
  - Периодическая эмиссия статистики трафика
  - Корректная остановка по запросу (stop())
"""

import asyncio
import os
import threading
import time

from PyQt5.QtCore import QThread, pyqtSignal

from main import load_cert_and_key, perform_handshake
from utils.zeroize import secure_context
from vpn_core.auth import Authenticator
from vpn_core.config_manager import Config, ConfigError, ConfigManager
from vpn_core.protocol import FrameCodec
from vpn_core.pygost_provider import PygostProvider
from vpn_core.session import Session, SessionConfig
from vpn_core.tunnel import VpnTunnel, create_tun_interface, is_admin

_DEFAULT_TUN_CONFIG = {
    "rekey_interval": 3600,
    "rekey_bytes": 104857600,
    "reconnect_timeout": 30,
    "max_reconnect_attempts": 5,
    "session_lifetime": 86400,
    "log_level": "INFO",
    "log_file": None,
    "mgmt_server_url": None,
    "protected_subnets": ["10.0.0.0/8", "172.16.0.0/12"],
    "tun_interface": "tun0",
    "tun_address": "10.8.0.2",
    "tun_netmask": "255.255.255.0",
    "keepalive_interval": 30,
}


class TunnelWorker(QThread):
    """
    Background QThread for the real full-tunnel VPN session.

    Signals
    -------
    status_changed(state: str, message: str)
        States: "connecting", "connected", "disconnected", "error"
    log_line(level: str, text: str)
    stats_updated(data: dict)
        Keys: "bytes_out", "bytes_in", "packets_out", "packets_in", "elapsed"
    session_ready(data: dict)
        Keys: "session_id", "enc_key_preview", "mac_key_preview", "algorithm"
    """

    status_changed = pyqtSignal(str, str)
    log_line = pyqtSignal(str, str)
    stats_updated = pyqtSignal(dict)
    session_ready = pyqtSignal(dict)

    def __init__(
        self,
        host: str,
        port: int,
        certs_dir: str,
        config_path: str = "config_bootstrap.json",
        parent=None,
    ):
        super().__init__(parent)
        self._host = host
        self._port = port
        self._certs_dir = certs_dir
        self._config_path = config_path
        self._stop_flag = threading.Event()
        self._start_time: float = 0.0

    def run(self) -> None:
        self._stop_flag.clear()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._async_main())
        except Exception as exc:
            self.log_line.emit("ERROR", f"Критическая ошибка: {exc}")
            self.status_changed.emit("error", f"Ошибка: {exc}")
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:
                pass
            loop.close()

    def stop(self) -> None:
        self._stop_flag.set()

    # ------------------------------------------------------------------ private

    async def _async_main(self) -> None:
        # -- Проверка прав --
        if not is_admin():
            self.log_line.emit(
                "ERROR", "Требуются права root/Administrator для полного туннеля"
            )
            self.status_changed.emit("error", "Недостаточно прав")
            return

        # -- Загрузка конфигурации --
        self.log_line.emit("INFO", "Загрузка конфигурации...")
        try:
            cfg_mgr = ConfigManager(self._config_path)
            config = cfg_mgr.initialize()
        except ConfigError as exc:
            self.log_line.emit(
                "WARNING",
                f"Конфигурация не найдена ({exc}), используются значения по умолчанию",
            )
            cfg_mgr = None
            config = Config(dict(_DEFAULT_TUN_CONFIG))

        config.update(
            {
                "server_ip": self._host,
                "server_port": self._port,
                "ca_cert_path": os.path.join(self._certs_dir, "ca.der"),
                "initial_cert_path": os.path.join(self._certs_dir, "client.der"),
                "initial_key_path": os.path.join(self._certs_dir, "client_key.bin"),
            }
        )

        # -- Загрузка сертификатов --
        self.log_line.emit("INFO", "Загрузка сертификатов...")
        try:
            with open(config.ca_cert_path, "rb") as f:
                ca_cert_der = f.read()
            client_cert_der, client_prv_key = load_cert_and_key(
                config.initial_cert_path, config.initial_key_path
            )
        except (OSError, ValueError) as exc:
            self.log_line.emit("ERROR", f"Ошибка загрузки сертификатов: {exc}")
            self.status_changed.emit("error", f"Сертификаты не найдены: {exc}")
            return

        self.log_line.emit("SUCCESS", "Сертификаты загружены")

        crypto = PygostProvider()
        codec = FrameCodec(crypto)

        # -- TUN-интерфейс --
        self.log_line.emit(
            "INFO", f"Создание TUN-интерфейса {config.tun_interface}..."
        )
        tun = create_tun_interface(config.tun_interface)
        try:
            tun.open()
            tun.configure(ip_address=config.tun_address, netmask=config.tun_netmask)
            tun.add_routes(config.protected_subnets)
        except OSError as exc:
            self.log_line.emit("ERROR", f"Ошибка создания TUN-интерфейса: {exc}")
            self.status_changed.emit("error", f"TUN недоступен: {exc}")
            try:
                tun.close()
            except Exception:
                pass
            return

        self.log_line.emit(
            "SUCCESS",
            f"TUN-интерфейс {config.tun_interface} настроен ({config.tun_address})",
        )

        session_obj = None

        try:
            with secure_context(client_prv_key) as prv_buf:
                auth = Authenticator(
                    crypto=crypto,
                    our_cert_der=client_cert_der,
                    our_private_key=bytes(prv_buf),
                    ca_cert_der=ca_cert_der,
                )

                while not self._stop_flag.is_set():
                    reader = None
                    writer = None

                    # -- Подключение (до 15 попыток) --
                    self.status_changed.emit("connecting", "Подключение...")
                    self.log_line.emit(
                        "INFO", f"Подключение к {self._host}:{self._port}..."
                    )

                    for attempt in range(1, 16):
                        if self._stop_flag.is_set():
                            self.status_changed.emit("disconnected", "Отменено")
                            return
                        try:
                            reader, writer = await asyncio.open_connection(
                                self._host, self._port
                            )
                            break
                        except (ConnectionRefusedError, OSError) as exc:
                            self.log_line.emit(
                                "WARNING", f"Попытка {attempt}/15 неудачна: {exc}"
                            )
                            if attempt < 15:
                                if self._stop_flag.is_set():
                                    self.status_changed.emit(
                                        "disconnected", "Отменено"
                                    )
                                    return
                                await asyncio.sleep(2)

                    if reader is None:
                        self.log_line.emit(
                            "ERROR",
                            "Не удалось подключиться к серверу после 15 попыток",
                        )
                        self.status_changed.emit("error", "Нет соединения с сервером")
                        return

                    self.log_line.emit("SUCCESS", "TCP-соединение установлено")

                    # -- Рукопожатие ГОСТ --
                    self.log_line.emit(
                        "INFO", "Рукопожатие ГОСТ (взаимная аутентификация)..."
                    )
                    try:
                        result = await perform_handshake(reader, writer, auth)
                    except Exception as exc:
                        self.log_line.emit("ERROR", f"Ошибка рукопожатия: {exc}")
                        self.status_changed.emit(
                            "error", f"Ошибка рукопожатия: {exc}"
                        )
                        writer.close()
                        return

                    if result is None:
                        self.log_line.emit("ERROR", "Верификация сервера не прошла!")
                        self.status_changed.emit(
                            "error", "Ошибка аутентификации сервера"
                        )
                        writer.close()
                        return

                    session_id, enc_key, mac_key, _ = result

                    if cfg_mgr is not None:
                        cfg_mgr.update_from_server(f"{session_id:08x}")

                    session_hex = f"0x{session_id:08x}"
                    enc_preview = enc_key[:8].hex() + "..."
                    mac_preview = mac_key[:8].hex() + "..."

                    self.log_line.emit("SUCCESS", f"Сессия установлена: {session_hex}")
                    self.log_line.emit(
                        "INFO",
                        f"Ключ шифрования: {enc_preview} ({len(enc_key) * 8} бит, Кузнечик)",
                    )
                    self.log_line.emit(
                        "INFO",
                        f"Ключ имитозащиты: {mac_preview} ({len(mac_key) * 8} бит, Стрибог)",
                    )

                    self.session_ready.emit(
                        {
                            "session_id": session_hex,
                            "enc_key_preview": enc_preview,
                            "mac_key_preview": mac_preview,
                            "algorithm": "Кузнечик CTR + HMAC-Стрибог-256 (полный туннель)",
                        }
                    )

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

                    self.status_changed.emit(
                        "connected", "Подключено (полный туннель)"
                    )
                    self.log_line.emit(
                        "SUCCESS",
                        f"Весь трафик маршрутизируется через {config.tun_interface}",
                    )
                    self._start_time = time.monotonic()

                    tunnel = VpnTunnel(
                        session=session_obj,
                        codec=codec,
                        tun=tun,
                        reader=reader,
                        writer=writer,
                        keepalive_interval=config.keepalive_interval,
                    )

                    stats_task = asyncio.ensure_future(self._stats_loop(tunnel))
                    watch_task = asyncio.ensure_future(self._watch_stop(tunnel))
                    try:
                        await tunnel.run()
                    finally:
                        stats_task.cancel()
                        watch_task.cancel()
                        await asyncio.gather(
                            stats_task, watch_task, return_exceptions=True
                        )

                    # Если сессия истекла — переподключиться с новой аутентификацией
                    if session_obj.is_expired() and not self._stop_flag.is_set():
                        self.log_line.emit("INFO", "Сессия истекла. Переподключение...")
                        session_obj.close()
                        session_obj = None
                        writer.close()
                        continue

                    session_obj.close()
                    session_obj = None
                    writer.close()
                    break

            # Нормальное завершение (stop_flag или цикл завершён)
            self.status_changed.emit("disconnected", "Отключено")
            self.log_line.emit("INFO", "Туннель закрыт")

        finally:
            try:
                tun.remove_routes(config.protected_subnets)
                tun.close()
            except Exception:
                pass
            if session_obj is not None:
                session_obj.close()

    async def _stats_loop(self, tunnel: VpnTunnel) -> None:
        try:
            while True:
                await asyncio.sleep(1)
                self.stats_updated.emit(
                    {
                        "bytes_out": tunnel.bytes_out,
                        "bytes_in": tunnel.bytes_in,
                        "packets_out": tunnel.packets_out,
                        "packets_in": tunnel.packets_in,
                        "elapsed": int(time.monotonic() - self._start_time),
                    }
                )
        except asyncio.CancelledError:
            pass

    async def _watch_stop(self, tunnel: VpnTunnel) -> None:
        try:
            while not self._stop_flag.is_set():
                await asyncio.sleep(0.2)
            tunnel.stop()
        except asyncio.CancelledError:
            pass
