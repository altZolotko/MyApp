"""
Сервер-заглушка для тестирования VPN-клиента.

Назначение: минимальный сервер, реализующий:
  - Приём TCP-соединений
  - Взаимную аутентификацию (зеркальный handshake)
  - Эхо-ответ зашифрованных кадров
  - Ответ на запрос конфигурации (/vpn/config)
  - Обработку RekeyRequest

Запуск: python server.py [config_path]
Требует сертификаты в certs/ (генерируются через utils/cert_gen.py).

Реализует требования: ФТ-2 (взаимная аутентификация), ФТ-5 (rekeying), шаг 8.
"""

import asyncio
import json
import os
import struct
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_core.auth import Authenticator
from vpn_core.protocol import FrameCodec, ReplayGuard
from vpn_core.pygost_provider import PygostProvider
from vpn_core.session import Session, SessionConfig
from utils.logger import get_logger, setup_logger

_log = get_logger("server")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8443
MGMT_PORT = 8444


async def handle_vpn_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    crypto: PygostProvider,
    server_cert_der: bytes,
    server_prv_key: bytes,
    ca_cert_der: bytes,
) -> None:
    """Обрабатывает одно VPN-соединение."""
    peer = writer.get_extra_info("peername")
    _log.info("Подключение от %s", peer)

    try:
        auth = Authenticator(
            crypto=crypto,
            our_cert_der=server_cert_der,
            our_private_key=server_prv_key,
            ca_cert_der=ca_cert_der,
        )
        codec = FrameCodec(crypto)

        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
        client_hello_len = struct.unpack("!H", len_bytes)[0]
        client_hello = await asyncio.wait_for(
            reader.readexactly(client_hello_len), timeout=30.0
        )

        from vpn_core.protocol import parse_auth_hello, build_auth_hello
        parsed = parse_auth_hello(client_hello)
        if parsed is None:
            _log.error("Не удалось распарсить ClientHello от %s", peer)
            return

        session_id = parsed["session_id"]
        client_cert_der = parsed["cert_der"]
        client_eph_pub = parsed["ephemeral_pub"]
        client_ukm = parsed["ukm"]

        if not auth.verify_certificate_chain(client_cert_der):
            _log.error("Сертификат клиента отклонён (%s)", peer)
            return

        import secrets
        server_eph_kp = crypto.create_ecdh_keypair()
        server_ukm = secrets.token_bytes(8)

        server_hello = build_auth_hello(
            session_id=session_id,
            cert_der=server_cert_der,
            ephemeral_pub=server_eph_kp.public_key,
            ukm=server_ukm,
        )
        writer.write(struct.pack("!H", len(server_hello)) + server_hello)
        await writer.drain()

        combined_ukm = bytes(a ^ b for a, b in zip(client_ukm, server_ukm))

        from utils.zeroize import secure_context
        with secure_context(bytes(server_eph_kp.private_key)) as prv_buf:
            shared_secret = crypto.compute_shared_secret(
                bytes(prv_buf), client_eph_pub, combined_ukm
            )

        session_id_bytes = struct.pack("!I", session_id)
        keys = crypto.derive_keys(shared_secret, session_id_bytes)

        shared_buf = bytearray(shared_secret)
        from utils.zeroize import zeroize_bytes
        zeroize_bytes(shared_buf)

        enc_key = keys.enc_key
        mac_key = keys.mac_key

        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
        fin_len = struct.unpack("!H", len_bytes)[0]
        _fin_data = await asyncio.wait_for(reader.readexactly(fin_len), timeout=30.0)
        _log.info("Рукопожатие завершено с %s (session=0x%08x)", peer, session_id)

        sess_config = SessionConfig()
        session = Session(
            session_id=session_id,
            enc_key=enc_key,
            mac_key=mac_key,
            config=sess_config,
            crypto=crypto,
        )
        session.activate()
        replay_guard = session.replay_guard

        while True:
            try:
                len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=60.0)
                frame_len = struct.unpack("!H", len_bytes)[0]
                raw_frame = await asyncio.wait_for(
                    reader.readexactly(frame_len), timeout=10.0
                )

                if raw_frame and raw_frame[0] == 0x10:
                    _log.info("RekeyRequest получен от %s — эхо-ответ", peer)
                    writer.write(len_bytes + raw_frame)
                    await writer.drain()
                    continue

                vpn_frame = codec.unpack(
                    raw=raw_frame,
                    enc_key=enc_key,
                    mac_key=mac_key,
                    replay_guard=replay_guard,
                )

                if vpn_frame is None:
                    _log.warning("Некорректный кадр от %s", peer)
                    continue

                if vpn_frame.is_keepalive:
                    _log.debug("Keepalive от %s", peer)
                    continue

                seq = session.next_seq()
                echo_frame = codec.pack(
                    session_id=session_id,
                    seq_num=seq,
                    plaintext=vpn_frame.payload,
                    enc_key=enc_key,
                    mac_key=mac_key,
                )
                writer.write(struct.pack("!H", len(echo_frame)) + echo_frame)
                await writer.drain()

            except asyncio.TimeoutError:
                _log.info("Таймаут соединения с %s", peer)
                break
            except asyncio.IncompleteReadError:
                _log.info("Клиент %s отключился", peer)
                break

        session.close()

    except Exception as exc:
        _log.exception("Ошибка обработки клиента %s: %s", peer, exc)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_mgmt_config(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Простой HTTP-сервер для /vpn/config."""
    try:
        request_line = (await asyncio.wait_for(reader.readline(), timeout=5.0)).decode()
        while True:
            header = (await asyncio.wait_for(reader.readline(), timeout=2.0)).strip()
            if not header:
                break

        if "GET /vpn/config" in request_line:
            body = json.dumps({
                "rekey_interval": 3600,
                "rekey_bytes": 104857600,
                "protected_subnets": ["10.0.0.0/8"],
                "keepalive_interval": 30,
                "server_note": "config from management server",
            }, ensure_ascii=False).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body
            )
        else:
            response = b"HTTP/1.1 404 Not Found\r\n\r\n"

        writer.write(response)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    certs_dir: str = "certs",
) -> None:
    """Запускает VPN-сервер и сервер управления конфигурацией."""
    setup_logger("DEBUG")

    try:
        with open(os.path.join(certs_dir, "ca.der"), "rb") as f:
            ca_cert_der = f.read()
        with open(os.path.join(certs_dir, "server.der"), "rb") as f:
            server_cert_der = f.read()
        with open(os.path.join(certs_dir, "server_key.bin"), "rb") as f:
            server_prv_key = f.read()
    except FileNotFoundError as exc:
        _log.error("Сертификаты не найдены: %s", exc)
        _log.error("Запустите: python -m utils.cert_gen")
        sys.exit(2)

    crypto = PygostProvider()

    vpn_server = await asyncio.start_server(
        lambda r, w: handle_vpn_client(
            r, w, crypto, server_cert_der, server_prv_key, ca_cert_der
        ),
        host, port,
    )

    mgmt_server = await asyncio.start_server(
        handle_mgmt_config,
        host, MGMT_PORT,
    )

    _log.info("VPN-сервер запущен на %s:%d", host, port)
    _log.info("Сервер управления запущен на %s:%d", host, MGMT_PORT)

    async with vpn_server, mgmt_server:
        await asyncio.gather(
            vpn_server.serve_forever(),
            mgmt_server.serve_forever(),
        )


if __name__ == "__main__":
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        _log.info("Сервер остановлен")
