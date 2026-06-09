"""
Модуль TUN-туннеля и маршрутизации (Linux + Windows).

Linux:   /dev/net/tun + fcntl.ioctl, asyncio add_reader
Windows: WinTun (wintun.dll) + run_in_executor + WaitForMultipleObjects

Требования Windows:
  - wintun.dll рядом с программой (https://www.wintun.net/)
  - Запуск от имени Администратора
  - Python 3.10+

Реализуемые требования:
  ФТ-1  — шифрование транзитного трафика
  ФТ-4  — full-tunnel через TUN-интерфейс
  НФТ-3 — asyncio I/O
"""

import asyncio
import os
import struct
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Optional

if sys.platform != "win32":
    import fcntl
else:
    import ctypes
    import ctypes.wintypes

from vpn_core.protocol import FrameCodec, ReplayGuard
from vpn_core.session import Session, SessionState
from utils.logger import get_logger

_log = get_logger("tunnel")

_TUN_MTU          = 1500
_READ_BUF         = 65536
_READ_TIMEOUT_MS  = 5000
_READ_TIMEOUT_S   = _READ_TIMEOUT_MS / 1000.0
_MAX_FRAME_SIZE   = 65535 + 2


# ─── Вспомогательные функции ─────────────────────────────────────────────────

def _run_cmd(args: list) -> None:
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise OSError(
            f"Команда '{args[0]}' завершилась с кодом {result.returncode}: "
            f"{result.stderr.strip()}"
        )


def _mask_to_prefix(mask: str) -> int:
    return sum(bin(int(x)).count("1") for x in mask.split("."))


def _prefix_to_mask(prefix: int) -> str:
    n = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ".".join(str((n >> (24 - i * 8)) & 0xFF) for i in range(4))


# ─── Абстрактный TUN-интерфейс ───────────────────────────────────────────────

class TunInterface(ABC):
    """Кросс-платформенная абстракция TUN-интерфейса."""

    @abstractmethod
    def open(self) -> None:
        """Открывает/создаёт TUN-адаптер."""

    @abstractmethod
    def configure(
        self, ip_address: str, netmask: str = "255.255.255.0", mtu: int = _TUN_MTU
    ) -> None:
        """Назначает IP-адрес, маску и MTU."""

    @abstractmethod
    def add_routes(self, subnets: list) -> None:
        """Добавляет маршруты к защищённым подсетям через TUN."""

    @abstractmethod
    def remove_routes(self, subnets: list) -> None:
        """Удаляет маршруты при завершении работы."""

    @abstractmethod
    async def async_read(self) -> bytes:
        """Асинхронно читает один IP-пакет.
        Возбуждает asyncio.TimeoutError если пакет не пришёл за _READ_TIMEOUT_S."""

    @abstractmethod
    def write(self, data: bytes) -> None:
        """Записывает IP-пакет в TUN."""

    @abstractmethod
    def close(self) -> None:
        """Закрывает TUN-адаптер и освобождает ресурсы."""


# ─── Linux-реализация (/dev/net/tun + fcntl) ─────────────────────────────────

if sys.platform != "win32":
    _TUNSETIFF = 0x400454CA
    _IFF_TUN   = 0x0001
    _IFF_NO_PI = 0x1000

    class LinuxTunInterface(TunInterface):
        """TUN-интерфейс для Linux через /dev/net/tun. Требует root (CAP_NET_ADMIN)."""

        def __init__(self, iface_name: str = "tun0") -> None:
            self._name = iface_name
            self._fd: Optional[int] = None

        def open(self) -> None:
            fd = os.open("/dev/net/tun", os.O_RDWR)
            ifreq = struct.pack("16sH14s", self._name.encode(), _IFF_TUN | _IFF_NO_PI, b"")
            try:
                fcntl.ioctl(fd, _TUNSETIFF, ifreq)
            except OSError as exc:
                os.close(fd)
                raise OSError(f"Ошибка создания TUN-интерфейса: {exc}") from exc
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            self._fd = fd
            _log.info("TUN-интерфейс %s открыт (fd=%d)", self._name, fd)

        def configure(
            self, ip_address: str, netmask: str = "255.255.255.0", mtu: int = _TUN_MTU
        ) -> None:
            prefix = _mask_to_prefix(netmask)
            _run_cmd(["ip", "addr", "add", f"{ip_address}/{prefix}", "dev", self._name])
            _run_cmd(["ip", "link", "set", self._name, "up", "mtu", str(mtu)])

        def add_routes(self, subnets: list) -> None:
            for subnet in subnets:
                _log.info("Маршрут %s → %s", subnet, self._name)
                _run_cmd(["ip", "route", "add", subnet, "dev", self._name])

        def remove_routes(self, subnets: list) -> None:
            for subnet in subnets:
                try:
                    _run_cmd(["ip", "route", "del", subnet, "dev", self._name])
                except Exception:
                    pass

        async def async_read(self) -> bytes:
            loop = asyncio.get_event_loop()
            future: asyncio.Future = loop.create_future()

            def _on_readable() -> None:
                try:
                    data = os.read(self._fd, _READ_BUF)
                    if not future.done():
                        future.set_result(data)
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if not future.done():
                        future.set_exception(exc)
                finally:
                    loop.remove_reader(self._fd)

            loop.add_reader(self._fd, _on_readable)
            return await asyncio.wait_for(future, timeout=_READ_TIMEOUT_S)

        def write(self, data: bytes) -> None:
            os.write(self._fd, data)

        def close(self) -> None:
            if self._fd is not None:
                try:
                    _run_cmd(["ip", "link", "set", self._name, "down"])
                except Exception:
                    pass
                os.close(self._fd)
                self._fd = None
                _log.info("TUN-интерфейс %s закрыт", self._name)


# ─── Windows-реализация (WinTun) ─────────────────────────────────────────────

if sys.platform == "win32":

    class WindowsTunInterface(TunInterface):
        """
        TUN-интерфейс для Windows через WinTun (wintun.dll).

        Требования:
          - wintun.dll рядом с программой: https://www.wintun.net/
          - Права Администратора
        """

        _WINTUN_CAPACITY = 0x400000   # 4 MiB — размер кольцевого буфера
        _WAIT_OBJECT_0   = 0x00000000

        def __init__(self, iface_name: str = "VPN0") -> None:
            self._name = iface_name
            self._ip_address: str = ""
            self._dll = None
            self._adapter = None
            self._session = None
            self._read_event = None    # Win32 HANDLE — «пакет готов»
            self._stop_event = None    # Win32 HANDLE — «остановить»

        # — Загрузка DLL ———————————————————————————————————————————————————

        def _load_dll(self):
            try:
                dll = ctypes.WinDLL("wintun.dll")
            except OSError:
                raise OSError(
                    "wintun.dll не найден.\n"
                    "Скачайте архив с https://www.wintun.net/ , распакуйте wintun.dll "
                    "(amd64/wintun.dll) рядом с программой."
                )
            # Привязываем типы всех используемых функций
            dll.WintunCreateAdapter.restype  = ctypes.c_void_p
            dll.WintunCreateAdapter.argtypes = [
                ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
            ]
            dll.WintunCloseAdapter.restype  = None
            dll.WintunCloseAdapter.argtypes = [ctypes.c_void_p]

            dll.WintunStartSession.restype  = ctypes.c_void_p
            dll.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

            dll.WintunEndSession.restype  = None
            dll.WintunEndSession.argtypes = [ctypes.c_void_p]

            dll.WintunGetReadWaitEvent.restype  = ctypes.c_void_p
            dll.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]

            dll.WintunReceivePacket.restype  = ctypes.c_void_p
            dll.WintunReceivePacket.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
            ]
            dll.WintunReleaseReceivePacket.restype  = None
            dll.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

            dll.WintunAllocateSendPacket.restype  = ctypes.c_void_p
            dll.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

            dll.WintunSendPacket.restype  = None
            dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            return dll

        # — Жизненный цикл —————————————————————————————————————————————————

        def open(self) -> None:
            self._dll = self._load_dll()
            _log.info("Создание WinTun-адаптера '%s'", self._name)

            self._adapter = self._dll.WintunCreateAdapter(self._name, "VPN", None)
            if not self._adapter:
                raise OSError(f"WintunCreateAdapter: ошибка {ctypes.GetLastError()}")

            self._session = self._dll.WintunStartSession(
                self._adapter, self._WINTUN_CAPACITY
            )
            if not self._session:
                self._dll.WintunCloseAdapter(self._adapter)
                raise OSError(f"WintunStartSession: ошибка {ctypes.GetLastError()}")

            self._read_event = self._dll.WintunGetReadWaitEvent(self._session)
            # Ручное событие для прерывания ожидания при остановке
            self._stop_event = ctypes.windll.kernel32.CreateEventW(
                None, True, False, None
            )
            _log.info("WinTun-адаптер '%s' запущен", self._name)

        def configure(
            self, ip_address: str, netmask: str = "255.255.255.0", mtu: int = _TUN_MTU
        ) -> None:
            self._ip_address = ip_address
            prefix = _mask_to_prefix(netmask)
            _log.info(
                "Настройка WinTun '%s': IP=%s/%d MTU=%d",
                self._name, ip_address, prefix, mtu,
            )
            # PowerShell: удаляем старый адрес (если есть), назначаем новый
            _run_cmd([
                "powershell", "-Command",
                f"Remove-NetIPAddress -InterfaceAlias '{self._name}' "
                f"-Confirm:$false -ErrorAction SilentlyContinue; "
                f"New-NetIPAddress -InterfaceAlias '{self._name}' "
                f"-IPAddress {ip_address} -PrefixLength {prefix} -Confirm:$false",
            ])
            _run_cmd([
                "netsh", "interface", "ipv4", "set", "subinterface",
                self._name, f"mtu={mtu}", "store=persistent",
            ])

        def add_routes(self, subnets: list) -> None:
            for subnet in subnets:
                _log.info("Маршрут %s → '%s'", subnet, self._name)
                try:
                    _run_cmd([
                        "powershell", "-Command",
                        f"New-NetRoute -InterfaceAlias '{self._name}' "
                        f"-DestinationPrefix '{subnet}' "
                        f"-NextHop '{self._ip_address}' -Confirm:$false",
                    ])
                except Exception as exc:
                    _log.warning("Не удалось добавить маршрут %s: %s", subnet, exc)

        def remove_routes(self, subnets: list) -> None:
            for subnet in subnets:
                try:
                    _run_cmd([
                        "powershell", "-Command",
                        f"Remove-NetRoute -InterfaceAlias '{self._name}' "
                        f"-DestinationPrefix '{subnet}' "
                        f"-Confirm:$false -ErrorAction SilentlyContinue",
                    ])
                except Exception:
                    pass

        # — Чтение/запись пакетов ——————————————————————————————————————————

        def _blocking_read(self) -> Optional[bytes]:
            """
            Блокирует поток не дольше _READ_TIMEOUT_MS мс.
            Возвращает IP-пакет или None (таймаут / сигнал остановки).
            """
            size = ctypes.c_uint32(0)
            # Пробуем без ожидания
            ptr = self._dll.WintunReceivePacket(self._session, ctypes.byref(size))
            if ptr:
                data = bytes((ctypes.c_ubyte * size.value).from_address(ptr))
                self._dll.WintunReleaseReceivePacket(self._session, ptr)
                return data

            # Ждём: событие «пакет» ИЛИ событие «стоп»
            handles = (ctypes.c_void_p * 2)(self._read_event, self._stop_event)
            ret = ctypes.windll.kernel32.WaitForMultipleObjects(
                2, handles, False, _READ_TIMEOUT_MS
            )
            # ret == 0 → read_event; ret == 1 → stop_event; 0x102 → timeout
            if ret != self._WAIT_OBJECT_0:
                return None

            ptr = self._dll.WintunReceivePacket(self._session, ctypes.byref(size))
            if ptr:
                data = bytes((ctypes.c_ubyte * size.value).from_address(ptr))
                self._dll.WintunReleaseReceivePacket(self._session, ptr)
                return data
            return None

        async def async_read(self) -> bytes:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, self._blocking_read)
            if data is None:
                raise asyncio.TimeoutError()
            return data

        def write(self, data: bytes) -> None:
            ptr = self._dll.WintunAllocateSendPacket(self._session, len(data))
            if not ptr:
                raise OSError(
                    f"WintunAllocateSendPacket: ошибка {ctypes.GetLastError()}"
                )
            ctypes.memmove(ptr, data, len(data))
            self._dll.WintunSendPacket(self._session, ptr)

        def close(self) -> None:
            if self._stop_event:
                ctypes.windll.kernel32.SetEvent(self._stop_event)
            if self._session:
                self._dll.WintunEndSession(self._session)
                self._session = None
            if self._adapter:
                self._dll.WintunCloseAdapter(self._adapter)
                self._adapter = None
            if self._stop_event:
                ctypes.windll.kernel32.CloseHandle(self._stop_event)
                self._stop_event = None
            _log.info("WinTun-адаптер '%s' закрыт", self._name)


# ─── Фабрика ─────────────────────────────────────────────────────────────────

def create_tun_interface(iface_name: str = "tun0") -> TunInterface:
    """Создаёт TunInterface для текущей платформы (Linux или Windows)."""
    if sys.platform == "win32":
        return WindowsTunInterface(iface_name)
    return LinuxTunInterface(iface_name)


# ─── VpnTunnel ───────────────────────────────────────────────────────────────

class VpnTunnel:
    """
    Основной класс VPN-туннеля.

    Управляет четырьмя asyncio-задачами:
      - _tun_to_server:  TUN → шифрование → TCP
      - _server_to_tun:  TCP → расшифровка → TUN
      - _keepalive_loop: keepalive-кадры
      - _rekey_monitor:  мониторинг rekeying

    Реализуемые требования: ФТ-1, ФТ-4, НФТ-3
    """

    def __init__(
        self,
        session: Session,
        codec: FrameCodec,
        tun: TunInterface,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        keepalive_interval: int = 30,
    ) -> None:
        self._session = session
        self._codec = codec
        self._tun = tun
        self._reader = reader
        self._writer = writer
        self._keepalive_interval = keepalive_interval
        self._running = False
        self._tasks: list = []

    async def run(self) -> None:
        """Запускает все задачи туннеля и ожидает их завершения."""
        self._running = True
        self._session.activate()

        self._tasks = [
            asyncio.ensure_future(self._tun_to_server()),
            asyncio.ensure_future(self._server_to_tun()),
            asyncio.ensure_future(self._keepalive_loop()),
            asyncio.ensure_future(self._rekey_monitor()),
        ]
        _log.info("VPN-туннель запущен (сессия 0x%08x)", self._session.session_id)

        try:
            done, _ = await asyncio.wait(
                self._tasks, return_when=asyncio.FIRST_EXCEPTION
            )
            for task in done:
                if task.exception():
                    _log.error(
                        "Задача туннеля завершилась с ошибкой: %s", task.exception()
                    )
        finally:
            self._stop()

    def _stop(self) -> None:
        self._running = False
        for task in self._tasks:
            if not task.done():
                task.cancel()

    # ── TUN → Server ──────────────────────────────────────────────────────────

    async def _tun_to_server(self) -> None:
        _log.debug("Запущена задача TUN→Server")
        while self._running:
            if self._session.state not in (SessionState.ACTIVE, SessionState.REKEYING):
                await asyncio.sleep(0.01)
                continue
            try:
                packet = await self._tun.async_read()
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

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.error("Ошибка в TUN→Server: %s", exc)
                self._session.mark_broken()
                break

    # ── Server → TUN ──────────────────────────────────────────────────────────

    async def _server_to_tun(self) -> None:
        _log.debug("Запущена задача Server→TUN")
        while self._running:
            if self._session.state not in (SessionState.ACTIVE, SessionState.REKEYING):
                await asyncio.sleep(0.01)
                continue
            try:
                len_bytes = await asyncio.wait_for(
                    self._reader.readexactly(2), timeout=_READ_TIMEOUT_S
                )
                frame_len = struct.unpack("!H", len_bytes)[0]

                if frame_len == 0 or frame_len > _MAX_FRAME_SIZE:
                    _log.warning("Некорректная длина кадра: %d", frame_len)
                    continue

                raw_frame = await asyncio.wait_for(
                    self._reader.readexactly(frame_len), timeout=_READ_TIMEOUT_S
                )
                vpn_frame = self._codec.unpack(
                    raw=raw_frame,
                    enc_key=self._session.enc_key,
                    mac_key=self._session.mac_key,
                    replay_guard=self._session.replay_guard,
                )

                if vpn_frame is None:
                    _log.error(
                        "БЕЗОПАСНОСТЬ: нарушение целостности кадра, разрыв 0x%08x",
                        self._session.session_id,
                    )
                    self._session.mark_broken()
                    break

                if vpn_frame.is_keepalive:
                    _log.debug("Keepalive получен")
                    continue

                self._tun.write(vpn_frame.payload)

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

    # ── Keepalive ─────────────────────────────────────────────────────────────

    async def _keepalive_loop(self) -> None:
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
                _log.warning("Ошибка keepalive: %s", exc)

    # ── Rekey monitor ─────────────────────────────────────────────────────────

    async def _rekey_monitor(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(60)
                if self._session.needs_rekey():
                    _log.info(
                        "Инициирование rekeying 0x%08x", self._session.session_id
                    )
                    await self._session.perform_rekey(b"", self._writer)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _log.warning("Ошибка rekeying: %s", exc)


# ─── Автоматическое переподключение ──────────────────────────────────────────

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

    При разрыве повторяет с экспоненциальной задержкой.
    При истечении сессии возвращает управление для переаутентификации.
    """
    while True:
        try:
            _log.info("Подключение к VPN-серверу %s:%d", host, port)
            reader, writer = await asyncio.open_connection(host, port)
            tunnel = VpnTunnel(
                session=session,
                codec=codec,
                tun=tun,
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
        _log.info("Попытка переподключения %d через %.0f с", attempts, delay)
        session.mark_broken()
        await asyncio.sleep(delay)
