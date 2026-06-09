"""
Модуль TUN-туннеля и маршрутизации (full-tunnel режим).

Назначение: создаёт и управляет виртуальным TUN-интерфейсом, реализует два
асинхронных цикла обработки трафика:
  - Исходящий: чтение IP-пакета из TUN → шифрование → отправка по TCP
  - Входящий:  чтение из TCP → расшифровка → запись в TUN

Keepalive: периодически отправляет пустые кадры для поддержания соединения.
Маршрутизация: устанавливает маршруты для защищённых подсетей через TUN.

TUN-интерфейс создаётся через /dev/net/tun (Linux, Astra Linux SE 1.7).
Требует прав root (CAP_NET_ADMIN).

Реализуемые требования:
  ФТ-1  — шифрование транзитного трафика (Кузнечик CTR)
  ФТ-4  — full-tunnel режим через TUN-интерфейс
  НФТ-3 — асинхронная обработка ввода-вывода (asyncio)
"""

import asyncio
import fcntl
import os
import struct
import subprocess
import sys
from typing import Optional

from vpn_core.protocol import FrameCodec, ReplayGuard
from vpn_core.session import Session, SessionState
from utils.logger import get_logger

_log = get_logger("tunnel")

# Константы ioctl для создания TUN-интерфейса (Linux)
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # Без заголовка пакетной информации

# Размер буфера чтения из TUN (MTU + запас)
_TUN_MTU = 1500
_READ_BUF = 65536

# Таймаут чтения из сокета (секунды)
_READ_TIMEOUT = 5.0

# Максимальный размер кадра (2 байта длина + кадр)
_MAX_FRAME_SIZE = 65535 + 2


class TunInterface:
    """
    Виртуальный TUN-интерфейс.

    Создаёт TUN-устройство через /dev/net/tun, настраивает IP-адрес и MTU.
    """

    def __init__(self, iface_name: str = "tun0") -> None:
        self._name = iface_name
        self._fd: Optional[int] = None

    def open(self) -> int:
        """
        Создаёт и открывает TUN-интерфейс.

        :return: файловый дескриптор TUN
        :raises PermissionError: если нет прав root
        :raises OSError: при ошибке ioctl
        """
        _log.info("Открытие TUN-интерфейса %s", self._name)

        tun_fd = os.open("/dev/net/tun", os.O_RDWR)

        ifreq = struct.pack("16sH14s", self._name.encode(), IFF_TUN | IFF_NO_PI, b"")
        try:
            fcntl.ioctl(tun_fd, TUNSETIFF, ifreq)
        except OSError as exc:
            os.close(tun_fd)
            raise OSError(f"Ошибка создания TUN-интерфейса: {exc}") from exc

        flags = fcntl.fcntl(tun_fd, fcntl.F_GETFL)
        fcntl.fcntl(tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self._fd = tun_fd
        _log.info("TUN-интерфейс %s открыт (fd=%d)", self._name, tun_fd)
        return tun_fd

    def configure(
        self,
        ip_address: str,
        netmask: str = "255.255.255.0",
        mtu: int = _TUN_MTU,
    ) -> None:
        """
        Настраивает IP-адрес, маску и MTU TUN-интерфейса через ip/ifconfig.

        :param ip_address: IP-адрес TUN-интерфейса
        :param netmask:    маска подсети
        :param mtu:        MTU (по умолчанию 1500)
        """
        _log.info(
            "Настройка TUN %s: IP=%s mask=%s MTU=%d",
            self._name, ip_address, netmask, mtu
        )
        self._run_cmd(["ip", "addr", "add", f"{ip_address}/{_mask_to_prefix(netmask)}",
                       "dev", self._name])
        self._run_cmd(["ip", "link", "set", self._name, "up", "mtu", str(mtu)])

    def add_routes(self, subnets: list) -> None:
        """
        Добавляет маршруты к защищённым подсетям через TUN.

        :param subnets: список CIDR-сетей, например ["10.0.0.0/8"]
        """
        for subnet in subnets:
            _log.info("Маршрут %s → %s", subnet, self._name)
            self._run_cmd(["ip", "route", "add", subnet, "dev", self._name])

    def remove_routes(self, subnets: list) -> None:
        """Удаляет маршруты при завершении работы."""
        for subnet in subnets:
            try:
                self._run_cmd(["ip", "route", "del", subnet, "dev", self._name])
            except Exception:
                pass

    def close(self) -> None:
        """Закрывает TUN fd и гасит интерфейс."""
        if self._fd is not None:
            try:
                self._run_cmd(["ip", "link", "set", self._name, "down"])
            except Exception:
                pass
            os.close(self._fd)
            self._fd = None
            _log.info("TUN-интерфейс %s закрыт", self._name)

    @staticmethod
    def _run_cmd(args: list) -> None:
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise OSError(f"Команда {args[0]} завершилась с кодом {result.returncode}: {result.stderr}")


def _mask_to_prefix(mask: str) -> int:
    """Конвертирует маску подсети в длину префикса."""
    return sum(bin(int(x)).count("1") for x in mask.split("."))


class VpnTunnel:
    """
    Основной класс VPN-туннеля.

    Управляет двумя asyncio-задачами:
      - _task_tun_to_server: TUN → шифрование → TCP
      - _task_server_to_tun: TCP → расшифровка → TUN
    Периодически отправляет keepalive-кадры.
    """

    def __init__(
        self,
        session: Session,
        codec: FrameCodec,
        tun_fd: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        keepalive_interval: int = 30,
    ) -> None:
        self._session = session
        self._codec = codec
        self._tun_fd = tun_fd
        self._reader = reader
        self._writer = writer
        self._keepalive_interval = keepalive_interval

        self._running = False
        self._tasks: list = []

    async def run(self) -> None:
        """
        Запускает все asyncio-задачи туннеля и ожидает их завершения.
        """
        self._running = True
        self._session.activate()

        loop = asyncio.get_event_loop()

        self._tasks = [
            asyncio.ensure_future(self._tun_to_server(loop)),
            asyncio.ensure_future(self._server_to_tun()),
            asyncio.ensure_future(self._keepalive_loop()),
            asyncio.ensure_future(self._rekey_monitor()),
        ]

        _log.info("VPN-туннель запущен (сессия 0x%08x)", self._session.session_id)

        try:
            done, pending = await asyncio.wait(
                self._tasks, return_when=asyncio.FIRST_EXCEPTION
            )
            for task in done:
                if task.exception():
                    _log.error("Задача туннеля завершилась с ошибкой: %s", task.exception())
        finally:
            self._stop()

    def _stop(self) -> None:
        """Останавливает все задачи туннеля."""
        self._running = False
        for task in self._tasks:
            if not task.done():
                task.cancel()

    async def _tun_to_server(self, loop: asyncio.AbstractEventLoop) -> None:
        """Читает IP-пакеты из TUN, шифрует и отправляет на сервер."""
        _log.debug("Запущена задача TUN→Server")

        while self._running:
            if self._session.state not in (SessionState.ACTIVE, SessionState.REKEYING):
                await asyncio.sleep(0.01)
                continue

            try:
                packet = await self._async_read_tun(loop)
                if not packet:
                    continue

                seq = self._session.next_seq()
                frame = self._codec.pack(
                    session_id=self._session.session_id,
                    seq_num=seq,
                    plaintext=packet,
                    enc_key=self._session.enc_key,
                    mac_key=self._session.mac_key,
                )

                self._writer.write(struct.pack("!H", len(frame)) + frame)
                await self._writer.drain()

                self._session.account_bytes(len(packet))

            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.error("Ошибка в TUN→Server: %s", exc)
                self._session.mark_broken()
                break

    async def _async_read_tun(self, loop: asyncio.AbstractEventLoop) -> bytes:
        """Асинхронно читает IP-пакет из TUN fd."""
        future: asyncio.Future = loop.create_future()

        def _on_readable():
            try:
                data = os.read(self._tun_fd, _READ_BUF)
                if not future.done():
                    future.set_result(data)
            except BlockingIOError:
                pass
            except OSError as exc:
                if not future.done():
                    future.set_exception(exc)
            finally:
                loop.remove_reader(self._tun_fd)

        loop.add_reader(self._tun_fd, _on_readable)
        return await asyncio.wait_for(future, timeout=_READ_TIMEOUT)

    async def _server_to_tun(self) -> None:
        """Читает кадры из TCP-соединения, расшифровывает и записывает в TUN."""
        _log.debug("Запущена задача Server→TUN")

        while self._running:
            if self._session.state not in (SessionState.ACTIVE, SessionState.REKEYING):
                await asyncio.sleep(0.01)
                continue

            try:
                len_bytes = await asyncio.wait_for(
                    self._reader.readexactly(2), timeout=_READ_TIMEOUT
                )
                frame_len = struct.unpack("!H", len_bytes)[0]

                if frame_len == 0 or frame_len > _MAX_FRAME_SIZE:
                    _log.warning("Некорректная длина кадра: %d", frame_len)
                    continue

                raw_frame = await asyncio.wait_for(
                    self._reader.readexactly(frame_len), timeout=_READ_TIMEOUT
                )

                vpn_frame = self._codec.unpack(
                    raw=raw_frame,
                    enc_key=self._session.enc_key,
                    mac_key=self._session.mac_key,
                    replay_guard=self._session.replay_guard,
                )

                if vpn_frame is None:
                    _log.error(
                        "БЕЗОПАСНОСТЬ: нарушение целостности кадра, разрыв сессии 0x%08x",
                        self._session.session_id,
                    )
                    self._session.mark_broken()
                    break

                if vpn_frame.is_keepalive:
                    _log.debug("Keepalive получен")
                    continue

                os.write(self._tun_fd, vpn_frame.payload)

            except asyncio.TimeoutError:
                continue
            except asyncio.IncompleteReadError:
                _log.warning("TCP-соединение закрыто сервером")
                self._session.mark_broken()
                break
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.error("Ошибка в Server→TUN: %s", exc)
                self._session.mark_broken()
                break

    async def _keepalive_loop(self) -> None:
        """Периодически отправляет keepalive-кадры для поддержания TCP-соединения."""
        while self._running:
            try:
                await asyncio.sleep(self._keepalive_interval)

                if self._session.state != SessionState.ACTIVE:
                    continue

                frame = self._codec.pack_keepalive(
                    session_id=self._session.session_id,
                    seq_num=self._session.next_seq(),
                    mac_key=self._session.mac_key,
                )
                self._writer.write(struct.pack("!H", len(frame)) + frame)
                await self._writer.drain()
                _log.debug("Keepalive отправлен")

            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.warning("Ошибка отправки keepalive: %s", exc)

    async def _rekey_monitor(self) -> None:
        """Периодически проверяет необходимость обновления ключей."""
        while self._running:
            try:
                await asyncio.sleep(60)

                if self._session.needs_rekey():
                    _log.info("Инициирование rekeying для сессии 0x%08x",
                              self._session.session_id)
                    await self._session.perform_rekey(b"", self._writer)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.warning("Ошибка мониторинга rekeying: %s", exc)


async def connect_with_retry(
    session: Session,
    host: str,
    port: int,
    tun: TunInterface,
    subnets: list,
    codec: FrameCodec,
    keepalive_interval: int,
) -> None:
    """
    Управляет жизненным циклом VPN-соединения с автоматическим восстановлением.

    При разрыве — повторяет подключение с экспоненциальной задержкой.
    При истечении сессии — инициирует полную переаутентификацию (возвращает).
    """
    while True:
        try:
            _log.info("Подключение к VPN-серверу %s:%d", host, port)
            reader, writer = await asyncio.open_connection(host, port)

            tunnel = VpnTunnel(
                session=session,
                codec=codec,
                tun_fd=tun._fd,
                reader=reader,
                writer=writer,
                keepalive_interval=keepalive_interval,
            )
            await tunnel.run()

        except (ConnectionRefusedError, OSError) as exc:
            _log.warning("Не удалось подключиться к %s:%d: %s", host, port, exc)

        if session.is_expired():
            _log.info("Сессия истекла — требуется переаутентификация")
            break

        if not session.can_reconnect():
            _log.error("Исчерпан лимит попыток переподключения")
            break

        attempts = session.increment_reconnect()
        delay = session.reconnect_delay()
        _log.info(
            "Попытка переподключения %d через %.0f с",
            attempts, delay
        )
        session.mark_broken()
        await asyncio.sleep(delay)
