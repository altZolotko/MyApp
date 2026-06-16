"""
VpnWorker — QThread that runs asyncio VPN session in a background thread.

Responsibilities:
  - Load certificates from certs_dir
  - Connect to host:port (up to 15 attempts)
  - Perform GOST handshake (ClientHello → ServerHello → ClientFinished)
  - Emit session_ready with session info
  - Loop: encrypt demo message, send, receive echo, emit stats
  - Gracefully stop when stop() is called
"""

import asyncio
import os
import struct
import threading
import time

from PyQt5.QtCore import QThread, pyqtSignal

from vpn_core.auth import Authenticator
from vpn_core.protocol import FrameCodec, ReplayGuard
from vpn_core.pygost_provider import PygostProvider


class VpnWorker(QThread):
    """
    Background QThread that manages the asyncio VPN event loop.

    Signals
    -------
    status_changed(state: str, message: str)
        States: "connecting", "connected", "disconnected", "error"
    log_line(level: str, text: str)
        Levels: "INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG"
    stats_updated(data: dict)
        Keys: "bytes_out", "bytes_in", "packets_out", "packets_in", "elapsed"
    session_ready(data: dict)
        Keys: "session_id", "enc_key_preview", "mac_key_preview", "algorithm"
    frame_exchanged(direction: str, seq: int, text_preview: str)
        direction: "OUT" or "IN"
    """

    status_changed = pyqtSignal(str, str)
    log_line = pyqtSignal(str, str)
    stats_updated = pyqtSignal(dict)
    session_ready = pyqtSignal(dict)
    frame_exchanged = pyqtSignal(str, int, str)

    def __init__(self, host: str, port: int, certs_dir: str, parent=None):
        super().__init__(parent)
        self._host = host
        self._port = port
        self._certs_dir = certs_dir
        self._stop_flag = threading.Event()

        # Stats
        self._bytes_out = 0
        self._bytes_in = 0
        self._packets_out = 0
        self._packets_in = 0
        self._start_time: float = 0.0

    def run(self) -> None:
        """Entry point for the QThread. Creates a fresh asyncio loop and runs it."""
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
                # Cancel pending tasks
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
        """Signal the worker to stop gracefully."""
        self._stop_flag.set()

    # ------------------------------------------------------------------ private

    async def _async_main(self) -> None:
        """Main coroutine: load certs, connect, handshake, data loop."""

        # -- Load certificates --
        self.log_line.emit("INFO", "Загрузка сертификатов...")
        try:
            ca_path = os.path.join(self._certs_dir, "ca.der")
            client_cert_path = os.path.join(self._certs_dir, "client.der")
            client_key_path = os.path.join(self._certs_dir, "client_key.bin")

            with open(ca_path, "rb") as f:
                ca_cert_der = f.read()
            with open(client_cert_path, "rb") as f:
                client_cert_der = f.read()
            with open(client_key_path, "rb") as f:
                client_prv_key = f.read()
        except OSError as exc:
            self.log_line.emit("ERROR", f"Ошибка чтения сертификатов: {exc}")
            self.status_changed.emit("error", f"Сертификаты не найдены: {exc}")
            return

        self.log_line.emit("SUCCESS", "Сертификаты загружены")

        # -- Create crypto objects --
        crypto = PygostProvider()
        auth = Authenticator(
            crypto=crypto,
            our_cert_der=client_cert_der,
            our_private_key=client_prv_key,
            ca_cert_der=ca_cert_der,
        )
        codec = FrameCodec(crypto)

        # -- Connect to server (up to 15 attempts) --
        self.status_changed.emit("connecting", "Подключение...")
        self.log_line.emit("INFO", f"Подключение к {self._host}:{self._port}...")

        reader = None
        writer = None
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
                    "WARNING",
                    f"Попытка {attempt}/15 неудачна: {exc}",
                )
                if attempt < 15:
                    if self._stop_flag.is_set():
                        self.status_changed.emit("disconnected", "Отменено")
                        return
                    await asyncio.sleep(2)

        if writer is None:
            self.log_line.emit("ERROR", "Не удалось подключиться к серверу после 15 попыток")
            self.status_changed.emit("error", "Нет соединения с сервером")
            return

        self.log_line.emit("SUCCESS", "TCP-соединение установлено")

        # -- Handshake --
        self.log_line.emit("INFO", "Рукопожатие ГОСТ (взаимная аутентификация)...")
        try:
            hello_bytes, eph_kp, ukm = auth.build_client_hello()
            writer.write(struct.pack("!H", len(hello_bytes)) + hello_bytes)
            await writer.drain()
            self.log_line.emit(
                "DEBUG",
                f"--> ClientHello ({len(hello_bytes)} байт, ECDH + UKM)",
            )

            len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=20.0)
            srv_len = struct.unpack("!H", len_bytes)[0]
            server_hello = await asyncio.wait_for(
                reader.readexactly(srv_len), timeout=20.0
            )
            self.log_line.emit("DEBUG", f"<-- ServerHello ({srv_len} байт)")

            auth_result = auth.process_server_hello(server_hello, eph_kp, ukm)
            if auth_result is None:
                self.log_line.emit("ERROR", "Верификация сервера не прошла!")
                self.status_changed.emit("error", "Ошибка аутентификации сервера")
                writer.close()
                return

            finished = auth.build_client_finished(
                auth_result.session_id, auth_result.peer_public_key
            )
            writer.write(struct.pack("!H", len(finished)) + finished)
            await writer.drain()
            self.log_line.emit(
                "DEBUG",
                f"--> ClientFinished ({len(finished)} байт, подпись ГОСТ Р 34.10)",
            )

        except asyncio.TimeoutError:
            self.log_line.emit("ERROR", "Таймаут рукопожатия")
            self.status_changed.emit("error", "Таймаут рукопожатия")
            writer.close()
            return
        except Exception as exc:
            self.log_line.emit("ERROR", f"Ошибка рукопожатия: {exc}")
            self.status_changed.emit("error", f"Ошибка рукопожатия: {exc}")
            writer.close()
            return

        # -- Emit session ready --
        enc_key = auth_result.enc_key
        mac_key = auth_result.mac_key
        session_hex = f"0x{auth_result.session_id:08x}"
        enc_preview = enc_key[:8].hex() + "..."
        mac_preview = mac_key[:8].hex() + "..."

        self.log_line.emit(
            "SUCCESS",
            f"Сессия установлена: {session_hex}",
        )
        self.log_line.emit(
            "INFO",
            f"Ключ шифрования: {enc_preview} ({len(enc_key) * 8} бит, Кузнечик)",
        )
        self.log_line.emit(
            "INFO",
            f"Ключ имитозащиты: {mac_preview} ({len(mac_key) * 8} бит, Стрибог)",
        )

        self.session_ready.emit({
            "session_id": session_hex,
            "enc_key_preview": enc_preview,
            "mac_key_preview": mac_preview,
            "algorithm": "Кузнечик CTR + HMAC-Стрибог-256",
        })
        self.status_changed.emit("connected", "Подключено")
        self._start_time = time.monotonic()

        # -- Data loop --
        client_guard = ReplayGuard()
        seq_num = 1
        demo_messages = [
            b"Privet ot VPN-klienta! Paket nomer 1.",
            b"Shifrovanie: Kuznyechik-256 CTR (GOST R 34.12-2015)",
            b"Imiozashita: HMAC-Stribog-256 (GOST R 34.11-2012)",
            b"Zashita ot replay: seq_num 64 bita, monotonnyi.",
        ]
        msg_index = 0

        while not self._stop_flag.is_set():
            msg = demo_messages[msg_index % len(demo_messages)]
            msg_index += 1

            try:
                frame = codec.pack(
                    session_id=auth_result.session_id,
                    seq_num=seq_num,
                    plaintext=msg,
                    enc_key=enc_key,
                    mac_key=mac_key,
                )
                writer.write(struct.pack("!H", len(frame)) + frame)
                await writer.drain()

                frame_size = len(frame)
                self._bytes_out += frame_size
                self._packets_out += 1
                text_out = msg.decode("ascii", errors="replace")
                self.frame_exchanged.emit("OUT", seq_num, text_out)

                # Receive echo
                try:
                    len_bytes = await asyncio.wait_for(
                        reader.readexactly(2), timeout=8.0
                    )
                    fr_len = struct.unpack("!H", len_bytes)[0]
                    raw = await asyncio.wait_for(
                        reader.readexactly(fr_len), timeout=8.0
                    )
                    result = codec.unpack(raw, enc_key, mac_key, client_guard)
                    if result and not result.is_keepalive:
                        self._bytes_in += len(raw)
                        self._packets_in += 1
                        echo_text = result.payload.decode("ascii", errors="replace")
                        self.frame_exchanged.emit("IN", result.seq_num, echo_text)
                except asyncio.TimeoutError:
                    self.log_line.emit("WARNING", f"[seq={seq_num}] Таймаут ответа")

                seq_num += 1

            except Exception as exc:
                if not self._stop_flag.is_set():
                    self.log_line.emit("ERROR", f"Ошибка передачи данных: {exc}")
                    self.status_changed.emit("error", f"Ошибка: {exc}")
                break

            # Emit stats
            elapsed = time.monotonic() - self._start_time
            self.stats_updated.emit({
                "bytes_out": self._bytes_out,
                "bytes_in": self._bytes_in,
                "packets_out": self._packets_out,
                "packets_in": self._packets_in,
                "elapsed": int(elapsed),
            })

            # Sleep with stop-flag check
            if self._stop_flag.is_set():
                break
            for _ in range(40):
                if self._stop_flag.is_set():
                    break
                await asyncio.sleep(0.1)

        # -- Cleanup --
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass

        self.status_changed.emit("disconnected", "Отключено")
        self.log_line.emit("INFO", "Соединение закрыто")
