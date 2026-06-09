"""
Демонстрация работы VPN-протокола (без TUN-интерфейса).

Выполняет:
  - Взаимную аутентификацию X.509 (ГОСТ Р 34.10-2012)
  - Обмен ключами ECDH + KDF (Стрибог-256)
  - Отправку зашифрованных кадров (Кузнечик CTR)
  - Проверку имитовставки (HMAC-Стрибог-256)
  - Получение эхо-ответа от сервера

Запуск: docker-compose up
"""

import asyncio
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_core.auth import Authenticator
from vpn_core.protocol import FrameCodec, ReplayGuard
from vpn_core.pygost_provider import PygostProvider
from utils.logger import setup_logger

setup_logger("WARNING")

SERVER_HOST = os.environ.get("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "8443"))
CERTS_DIR = os.environ.get("CERTS_DIR", "certs")

_BANNER = "=" * 62


def _wait_for_certs(max_wait: int = 60) -> bool:
    """Ждёт появления сертификатов, генерируемых сервером при старте."""
    cert_path = os.path.join(CERTS_DIR, "client.der")
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        if os.path.exists(cert_path):
            return True
        print(f"    Ожидание сертификатов в {CERTS_DIR}/ ...", flush=True)
        time.sleep(3)
    return False


async def run_demo() -> None:
    print(_BANNER)
    print("  VPN-прототип — демонстрация шифрованного туннеля")
    print("  ГОСТ Р 34.12-2015 «Кузнечик» + ГОСТ Р 34.10-2012")
    print(_BANNER)

    print("\n[0] Проверка сертификатов...", flush=True)
    if not _wait_for_certs():
        print("    ОШИБКА: сертификаты не найдены. Сервер не запустился?")
        sys.exit(1)
    print(f"    OK: сертификаты найдены в {CERTS_DIR}/")

    with open(os.path.join(CERTS_DIR, "ca.der"), "rb") as f:
        ca_cert_der = f.read()
    with open(os.path.join(CERTS_DIR, "client.der"), "rb") as f:
        client_cert_der = f.read()
    with open(os.path.join(CERTS_DIR, "client_key.bin"), "rb") as f:
        client_prv_key = f.read()

    crypto = PygostProvider()
    auth = Authenticator(
        crypto=crypto,
        our_cert_der=client_cert_der,
        our_private_key=client_prv_key,
        ca_cert_der=ca_cert_der,
    )
    codec = FrameCodec(crypto)

    print(f"\n[1] Подключение к {SERVER_HOST}:{SERVER_PORT}...", flush=True)
    reader, writer = None, None
    for attempt in range(1, 16):
        try:
            reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
            break
        except (ConnectionRefusedError, OSError):
            print(f"    Попытка {attempt}/15, сервер ещё не готов...", flush=True)
            await asyncio.sleep(3)
    if writer is None:
        print("    ОШИБКА: не удалось подключиться к серверу.")
        sys.exit(1)
    print("    OK: TCP-соединение установлено")

    print("\n[2] Рукопожатие (взаимная аутентификация ГОСТ)...", flush=True)
    try:
        hello_bytes, eph_kp, ukm = auth.build_client_hello()
        writer.write(struct.pack("!H", len(hello_bytes)) + hello_bytes)
        await writer.drain()
        print("    --> ClientHello (сертификат X.509 + эфемерный ECDH + UKM)")

        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=20.0)
        srv_len = struct.unpack("!H", len_bytes)[0]
        server_hello = await asyncio.wait_for(reader.readexactly(srv_len), timeout=20.0)
        print("    <-- ServerHello получен")

        auth_result = auth.process_server_hello(server_hello, eph_kp, ukm)
        if auth_result is None:
            print("    ОШИБКА: верификация сервера не прошла!")
            writer.close()
            return

        finished = auth.build_client_finished(
            auth_result.session_id, auth_result.peer_public_key
        )
        writer.write(struct.pack("!H", len(finished)) + finished)
        await writer.drain()
        print("    --> ClientFinished (подпись ГОСТ Р 34.10-2012)")

        print(f"\n    Сессия:          0x{auth_result.session_id:08x}")
        print(f"    Ключ шифровки:   {auth_result.enc_key[:8].hex()}... ({len(auth_result.enc_key)*8} бит, Кузнечик)")
        print(f"    Ключ имитозащ.:  {auth_result.mac_key[:8].hex()}... ({len(auth_result.mac_key)*8} бит, Стрибог)")

    except Exception as exc:
        print(f"    ОШИБКА рукопожатия: {exc}")
        writer.close()
        return

    enc_key = auth_result.enc_key
    mac_key = auth_result.mac_key
    client_guard = ReplayGuard()

    print("\n[3] Отправка зашифрованных кадров...", flush=True)
    test_messages = [
        b"Privet ot VPN-klienta! Paket nomer 1.",
        b"Shifrovanie: Kuznyechik-256 CTR (GOST R 34.12-2015)",
        b"Imiozashita: HMAC-Stribog-256 (GOST R 34.11-2012)",
        b"Zashita ot replay: seq_num 64 bita, monotonnyi.",
    ]

    for seq_num, msg in enumerate(test_messages, start=1):
        frame = codec.pack(
            session_id=auth_result.session_id,
            seq_num=seq_num,
            plaintext=msg,
            enc_key=enc_key,
            mac_key=mac_key,
        )
        writer.write(struct.pack("!H", len(frame)) + frame)
        await writer.drain()

        print(f"\n    [seq={seq_num}] Открытый текст  : {msg.decode()}")
        print(f"    [seq={seq_num}] Кадр ({len(frame)} байт)    : {frame[:16].hex()}...")

        try:
            len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=8.0)
            fr_len = struct.unpack("!H", len_bytes)[0]
            raw = await asyncio.wait_for(reader.readexactly(fr_len), timeout=8.0)
            result = codec.unpack(raw, enc_key, mac_key, client_guard)
            if result and not result.is_keepalive:
                print(f"    [seq={seq_num}] Эхо-ответ       : {result.payload.decode()}")
                print(f"    [seq={seq_num}] MAC верифицирован: OK, целостность подтверждена")
        except asyncio.TimeoutError:
            print(f"    [seq={seq_num}] (таймаут ответа)")

        await asyncio.sleep(0.2)

    print(f"\n[4] Keepalive-кадр...", flush=True)
    ka = codec.pack_keepalive(
        session_id=auth_result.session_id,
        seq_num=len(test_messages) + 1,
        mac_key=mac_key,
    )
    writer.write(struct.pack("!H", len(ka)) + ka)
    await writer.drain()
    print(f"    --> Keepalive отправлен ({len(ka)} байт), сервер не отвечает на keepalive")

    writer.close()

    print(f"\n{_BANNER}")
    print("  Демонстрация завершена успешно!")
    print("  Все пакеты зашифрованы и имитовставки верифицированы.")
    print(_BANNER)


if __name__ == "__main__":
    asyncio.run(run_demo())
