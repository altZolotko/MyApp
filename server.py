"""
VPN-сервер: взаимная аутентификация ГОСТ, шифрование Кузнечик CTR,
имитозащита HMAC-Стрибог-256, опциональный NAT/forwarding gateway.

Gateway-режим (активируется при наличии прав root на Linux):
  - Создаёт серверный TUN-интерфейс tun_srv0 (10.8.0.1/24)
  - Включает ip_forward
  - Добавляет правила iptables (MASQUERADE + FORWARD)
  - Пересылает входящие IP-пакеты от клиентов в реальную сеть и обратно

Echo-режим (fallback, совместим с demo_client.py и GUI demo-режимом):
  - Payload-пакеты возвращаются клиенту без изменений

Запуск: python server.py
Требует сертификаты в certs/ (генерируются через utils/cert_gen.py).
"""

import asyncio
import json
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_core.auth import Authenticator
from vpn_core.protocol import FrameCodec, build_auth_hello, parse_auth_hello
from vpn_core.pygost_provider import PygostProvider
from vpn_core.session import Session, SessionConfig
from vpn_core.tunnel import TunInterface, create_tun_interface, is_admin
from utils.logger import get_logger, setup_logger
from utils.zeroize import secure_context, zeroize_bytes

_log = get_logger("server")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8443
MGMT_PORT = 8444

GATEWAY_TUN_NAME = "tun_srv0"
GATEWAY_TUN_ADDRESS = "10.8.0.1"
GATEWAY_TUN_NETMASK = "255.255.255.0"


@dataclass
class GatewayState:
    tun: TunInterface
    subnet_cidr: str
    egress_iface: Optional[str]
    ip_forward_prev: Optional[str]


# ── Gateway helpers ───────────────────────────────────────────────────────────

def _prefix_len(netmask: str) -> int:
    return sum(bin(int(b)).count("1") for b in netmask.split("."))


def _network_cidr(ip_address: str, netmask: str) -> str:
    parts_ip = [int(b) for b in ip_address.split(".")]
    parts_nm = [int(b) for b in netmask.split(".")]
    network = ".".join(str(a & b) for a, b in zip(parts_ip, parts_nm))
    return f"{network}/{_prefix_len(netmask)}"


def _detect_egress_iface() -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            tokens = line.split()
            if "dev" in tokens:
                return tokens[tokens.index("dev") + 1]
    except Exception:
        pass
    return None


def _run_iptables(args: list) -> bool:
    try:
        subprocess.run(
            ["iptables"] + args,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as exc:
        _log.warning("iptables %s: %s", " ".join(str(a) for a in args), exc)
        return False


def _enable_ip_forward() -> Optional[str]:
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path) as f:
            prev = f.read().strip()
        with open(path, "w") as f:
            f.write("1\n")
        _log.info("ip_forward включён (было: %s)", prev)
        return prev
    except OSError as exc:
        _log.warning("Не удалось включить ip_forward: %s", exc)
        return None


def _restore_ip_forward(prev: Optional[str]) -> None:
    if prev is None:
        return
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(prev + "\n")
    except OSError:
        pass


def _is_ipv4_packet(payload: bytes) -> bool:
    if len(payload) < 20 or (payload[0] >> 4) != 4:
        return False
    ihl = (payload[0] & 0xf) * 4
    if ihl < 20 or ihl > len(payload):
        return False
    total_len = struct.unpack("!H", payload[2:4])[0]
    return total_len == len(payload)


def _setup_gateway() -> Optional[GatewayState]:
    if sys.platform == "win32":
        _log.info("Gateway-режим недоступен на Windows — эхо-режим")
        return None
    if not is_admin():
        _log.info("Нет прав root — сервер работает в эхо-режиме")
        return None

    _log.info("Инициализация gateway (TUN + NAT)...")
    try:
        tun = create_tun_interface(GATEWAY_TUN_NAME)
        tun.open()
        tun.configure(ip_address=GATEWAY_TUN_ADDRESS, netmask=GATEWAY_TUN_NETMASK)
    except OSError as exc:
        _log.warning("Не удалось создать серверный TUN: %s — эхо-режим", exc)
        return None

    subnet_cidr = _network_cidr(GATEWAY_TUN_ADDRESS, GATEWAY_TUN_NETMASK)
    ip_forward_prev = _enable_ip_forward()

    egress = _detect_egress_iface()
    if egress:
        _run_iptables(["-t", "nat", "-A", "POSTROUTING", "-s", subnet_cidr,
                       "-o", egress, "-j", "MASQUERADE"])
        _run_iptables(["-A", "FORWARD", "-i", GATEWAY_TUN_NAME, "-o", egress,
                       "-j", "ACCEPT"])
        _run_iptables(["-A", "FORWARD", "-i", egress, "-o", GATEWAY_TUN_NAME,
                       "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        _log.info("NAT: %s → %s (MASQUERADE)", subnet_cidr, egress)
    else:
        _log.warning("Egress-интерфейс не найден — NAT не настроен, "
                     "работает только внутренняя маршрутизация VPN-подсети")

    _log.info("Gateway запущен: %s @ %s/24", GATEWAY_TUN_NAME, GATEWAY_TUN_ADDRESS)
    return GatewayState(
        tun=tun,
        subnet_cidr=subnet_cidr,
        egress_iface=egress,
        ip_forward_prev=ip_forward_prev,
    )


def _teardown_gateway(gw: Optional[GatewayState]) -> None:
    if gw is None:
        return
    _log.info("Остановка gateway...")
    if gw.egress_iface:
        _run_iptables(["-t", "nat", "-D", "POSTROUTING", "-s", gw.subnet_cidr,
                       "-o", gw.egress_iface, "-j", "MASQUERADE"])
        _run_iptables(["-D", "FORWARD", "-i", GATEWAY_TUN_NAME, "-o", gw.egress_iface,
                       "-j", "ACCEPT"])
        _run_iptables(["-D", "FORWARD", "-i", gw.egress_iface, "-o", GATEWAY_TUN_NAME,
                       "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    _restore_ip_forward(gw.ip_forward_prev)
    try:
        gw.tun.close()
    except Exception:
        pass


def _unregister_routes(
    client_routes: Dict[str, Tuple],
    writer: asyncio.StreamWriter,
) -> None:
    stale = [ip for ip, (_, w) in client_routes.items() if w is writer]
    for ip in stale:
        del client_routes[ip]


async def _gateway_reader_loop(
    gw: GatewayState,
    codec: FrameCodec,
    client_routes: Dict[str, Tuple],
) -> None:
    """Читает IP-пакеты с серверного TUN и пересылает нужному клиенту."""
    _log.info("Gateway reader запущен (%s)", GATEWAY_TUN_NAME)
    while True:
        try:
            packet = await gw.tun.async_read()
            if not packet or not _is_ipv4_packet(packet):
                continue

            dst_ip = ".".join(str(b) for b in packet[16:20])
            entry = client_routes.get(dst_ip)
            if entry is None:
                continue

            session, writer = entry
            seq = session.next_seq()
            try:
                frame = codec.pack(
                    session_id=session.session_id,
                    seq_num=seq,
                    plaintext=packet,
                    enc_key=session.enc_key,
                    mac_key=session.mac_key,
                )
                writer.write(struct.pack("!H", len(frame)) + frame)
                await writer.drain()
            except Exception as exc:
                _log.warning("Ошибка пересылки пакета клиенту %s: %s", dst_ip, exc)
                _unregister_routes(client_routes, writer)

        except asyncio.CancelledError:
            _log.info("Gateway reader остановлен")
            break
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            _log.warning("Ошибка в gateway reader: %s", exc)


# ── Client handler ────────────────────────────────────────────────────────────

async def handle_vpn_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    crypto: PygostProvider,
    server_cert_der: bytes,
    server_prv_key: bytes,
    ca_cert_der: bytes,
    codec: FrameCodec,
    gw: Optional[GatewayState],
    client_routes: Dict[str, Tuple],
) -> None:
    """Обрабатывает одно VPN-соединение клиента."""
    peer = writer.get_extra_info("peername")
    _log.info("Подключение от %s", peer)

    try:
        auth = Authenticator(
            crypto=crypto,
            our_cert_der=server_cert_der,
            our_private_key=server_prv_key,
            ca_cert_der=ca_cert_der,
        )

        # Шаг 1: ClientHello
        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
        client_hello_len = struct.unpack("!H", len_bytes)[0]
        client_hello = await asyncio.wait_for(
            reader.readexactly(client_hello_len), timeout=30.0
        )

        parsed = parse_auth_hello(client_hello)
        if parsed is None:
            _log.error("Не удалось разобрать ClientHello от %s", peer)
            return

        session_id = parsed["session_id"]
        client_cert_der = parsed["cert_der"]
        client_eph_pub = parsed["ephemeral_pub"]
        client_ukm = parsed["ukm"]

        if not auth.verify_certificate_chain(client_cert_der):
            _log.error("Сертификат клиента отклонён (%s)", peer)
            return

        # Шаг 2: ServerHello
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

        # Выработка ключей
        combined_ukm = bytes(a ^ b for a, b in zip(client_ukm, server_ukm))
        with secure_context(bytes(server_eph_kp.private_key)) as prv_buf:
            shared_secret = crypto.compute_shared_secret(
                bytes(prv_buf), client_eph_pub, combined_ukm
            )

        session_id_bytes = struct.pack("!I", session_id)
        keys = crypto.derive_keys(shared_secret, session_id_bytes)
        shared_buf = bytearray(shared_secret)
        zeroize_bytes(shared_buf)

        # Шаг 3: ClientFinished
        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
        fin_len = struct.unpack("!H", len_bytes)[0]
        await asyncio.wait_for(reader.readexactly(fin_len), timeout=30.0)
        _log.info("Рукопожатие завершено с %s (session=0x%08x)", peer, session_id)

        sess_config = SessionConfig()
        session = Session(
            session_id=session_id,
            enc_key=keys.enc_key,
            mac_key=keys.mac_key,
            config=sess_config,
            crypto=crypto,
        )
        session.activate()
        replay_guard = session.replay_guard

        # Цикл обработки данных
        while True:
            try:
                len_bytes = await asyncio.wait_for(
                    reader.readexactly(2), timeout=60.0
                )
                frame_len = struct.unpack("!H", len_bytes)[0]
                raw_frame = await asyncio.wait_for(
                    reader.readexactly(frame_len), timeout=10.0
                )

                if raw_frame and raw_frame[0] == 0x10:
                    _log.info("RekeyRequest от %s — эхо-ответ", peer)
                    writer.write(struct.pack("!H", len(raw_frame)) + raw_frame)
                    await writer.drain()
                    continue

                vpn_frame = codec.unpack(
                    raw=raw_frame,
                    enc_key=session.enc_key,
                    mac_key=session.mac_key,
                    replay_guard=replay_guard,
                )

                if vpn_frame is None:
                    _log.warning("Некорректный кадр от %s", peer)
                    continue

                if vpn_frame.is_keepalive:
                    _log.debug("Keepalive от %s", peer)
                    continue

                if gw is not None and _is_ipv4_packet(vpn_frame.payload):
                    # Gateway-режим: пересылаем IP-пакет в реальную сеть
                    src_ip = ".".join(str(b) for b in vpn_frame.payload[12:16])
                    client_routes[src_ip] = (session, writer)
                    gw.tun.write(vpn_frame.payload)
                else:
                    # Echo-режим: возвращаем payload обратно клиенту
                    seq = session.next_seq()
                    echo_frame = codec.pack(
                        session_id=session_id,
                        seq_num=seq,
                        plaintext=vpn_frame.payload,
                        enc_key=session.enc_key,
                        mac_key=session.mac_key,
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
        _unregister_routes(client_routes, writer)
        try:
            writer.close()
        except Exception:
            pass


# ── Management server ─────────────────────────────────────────────────────────

async def handle_mgmt_config(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Простой HTTP-сервер для /vpn/config."""
    try:
        request_line = (
            await asyncio.wait_for(reader.readline(), timeout=5.0)
        ).decode()
        while True:
            header = (await asyncio.wait_for(reader.readline(), timeout=2.0)).strip()
            if not header:
                break

        if "GET /vpn/config" in request_line:
            body = json.dumps(
                {
                    "rekey_interval": 3600,
                    "rekey_bytes": 104857600,
                    "protected_subnets": ["10.0.0.0/8"],
                    "keepalive_interval": 30,
                    "server_note": "config from management server",
                },
                ensure_ascii=False,
            ).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                + b"\r\n" + body
            )
        else:
            response = b"HTTP/1.1 404 Not Found\r\n\r\n"

        writer.write(response)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


# ── Entry point ───────────────────────────────────────────────────────────────

async def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    certs_dir: str = "certs",
) -> None:
    """Запускает VPN-сервер и сервер управления конфигурацией."""
    try:
        with open(os.path.join(certs_dir, "ca.der"), "rb") as f:
            ca_cert_der = f.read()
        with open(os.path.join(certs_dir, "server.der"), "rb") as f:
            server_cert_der = f.read()
        with open(os.path.join(certs_dir, "server_key.bin"), "rb") as f:
            server_prv_key = f.read()
    except FileNotFoundError as exc:
        _log.error("Сертификаты не найдены: %s", exc)
        raise

    crypto = PygostProvider()
    codec = FrameCodec(crypto)
    client_routes: Dict[str, Tuple] = {}
    gw = _setup_gateway()

    vpn_server = await asyncio.start_server(
        lambda r, w: handle_vpn_client(
            r, w, crypto, server_cert_der, server_prv_key, ca_cert_der,
            codec, gw, client_routes,
        ),
        host,
        port,
    )
    mgmt_server = await asyncio.start_server(
        handle_mgmt_config, host, MGMT_PORT
    )

    _log.info("VPN-сервер запущен на %s:%d", host, port)
    _log.info("Сервер управления запущен на %s:%d", host, MGMT_PORT)
    if gw is not None:
        _log.info(
            "Gateway-режим активен: %s @ %s/24",
            GATEWAY_TUN_NAME,
            GATEWAY_TUN_ADDRESS,
        )
    else:
        _log.info("Эхо-режим: gateway недоступен (нет root или Windows)")

    try:
        coros = [
            vpn_server.serve_forever(),
            mgmt_server.serve_forever(),
        ]
        if gw is not None:
            coros.append(_gateway_reader_loop(gw, codec, client_routes))
        async with vpn_server, mgmt_server:
            await asyncio.gather(*coros)
    finally:
        _teardown_gateway(gw)


if __name__ == "__main__":
    setup_logger("DEBUG")
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        _log.info("Сервер остановлен")
    except FileNotFoundError:
        sys.exit(2)
