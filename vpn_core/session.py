"""
Модуль управления VPN-сессией.

Назначение: реализует конечный автомат состояний сессии, управление
сессионными ключами, периодическое обновление ключей (rekeying) и
автоматическое восстановление соединения при обрыве.

Состояния сессии:
  NEW      — сессия создана, рукопожатие не выполнено
  ACTIVE   — сессия активна, трафик зашифрован
  REKEYING — выполняется процедура обновления ключей
  BROKEN   — соединение разорвано, ожидается восстановление
  CLOSED   — сессия закрыта окончательно

Реализуемые требования:
  ФТ-5  — автоматическое восстановление соединения
  НФТ-4 — безопасная работа с ключами (затирание при закрытии)
  А     — сохранение контекста счётчиков seq при переподключении
  Б     — периодическое обновление ключей (rekeying)
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from vpn_core.crypto_interface import CryptoProvider, SessionKeys
from vpn_core.protocol import ReplayGuard
from utils.logger import get_logger, log_crypto_event
from utils.zeroize import SecureBuffer, zeroize_bytes

_log = get_logger("session")


class SessionState(Enum):
    """Состояния сессии VPN."""
    NEW = auto()
    ACTIVE = auto()
    REKEYING = auto()
    BROKEN = auto()
    CLOSED = auto()


@dataclass
class SessionConfig:
    """
    Конфигурационные параметры сессии.

    Атрибуты:
        session_lifetime:       максимальное время жизни сессии (секунды)
        rekey_interval:         интервал обновления ключей (секунды)
        rekey_bytes:            порог объёма данных для обновления ключей (байты)
        max_reconnect_attempts: максимальное число попыток переподключения
        reconnect_timeout:      начальный таймаут переподключения (секунды)
    """
    session_lifetime: int = 86400
    rekey_interval: int = 3600
    rekey_bytes: int = 104857600
    max_reconnect_attempts: int = 5
    reconnect_timeout: int = 30


class SessionKeyStore:
    """
    Безопасное хранилище сессионных ключей.

    Хранит ключи в bytearray и затирает их при закрытии.
    Реализуемые требования: Д (безопасное обращение с ключами).
    """

    def __init__(self, enc_key: bytes, mac_key: bytes) -> None:
        self._enc_buf = bytearray(enc_key)
        self._mac_buf = bytearray(mac_key)
        self._active = True

    @property
    def enc_key(self) -> bytes:
        if not self._active:
            raise RuntimeError("Попытка использовать затёртые ключи")
        return bytes(self._enc_buf)

    @property
    def mac_key(self) -> bytes:
        if not self._active:
            raise RuntimeError("Попытка использовать затёртые ключи")
        return bytes(self._mac_buf)

    def rotate(self, new_enc: bytes, new_mac: bytes) -> None:
        """Атомарно заменяет ключи (при rekeying)."""
        log_crypto_event(_log, "KEY_ROTATE", "ротация сессионных ключей")
        zeroize_bytes(self._enc_buf)
        zeroize_bytes(self._mac_buf)
        self._enc_buf = bytearray(new_enc)
        self._mac_buf = bytearray(new_mac)
        log_crypto_event(_log, "KEY_ROTATE_OK", "")

    def wipe(self) -> None:
        """Затирает все ключи."""
        log_crypto_event(_log, "KEY_WIPE", "затирание сессионных ключей")
        if self._active:
            zeroize_bytes(self._enc_buf)
            zeroize_bytes(self._mac_buf)
            self._active = False

    def __del__(self) -> None:
        self.wipe()


class Session:
    """
    Объект VPN-сессии. Управляет состоянием, ключами, счётчиками.

    Автоматически инициирует rekeying при достижении порогов времени/объёма.
    Поддерживает восстановление после обрыва с сохранением seq-контекста.
    """

    def __init__(
        self,
        session_id: int,
        enc_key: bytes,
        mac_key: bytes,
        config: SessionConfig,
        crypto: CryptoProvider,
    ) -> None:
        self.session_id = session_id
        self._key_store = SessionKeyStore(enc_key, mac_key)
        self._config = config
        self._crypto = crypto

        self._state = SessionState.NEW
        self._replay_guard = ReplayGuard()
        self._seq_counter: int = 0

        self._created_at: float = time.monotonic()
        self._last_rekey_at: float = time.monotonic()
        self._bytes_since_rekey: int = 0
        self._reconnect_attempts: int = 0

        self._rekey_task: Optional[asyncio.Task] = None

        log_crypto_event(_log, "SESSION_CREATE", f"id=0x{session_id:08x}")

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def enc_key(self) -> bytes:
        return self._key_store.enc_key

    @property
    def mac_key(self) -> bytes:
        return self._key_store.mac_key

    @property
    def replay_guard(self) -> ReplayGuard:
        return self._replay_guard

    def next_seq(self) -> int:
        """Возвращает следующий порядковый номер и инкрементирует счётчик."""
        self._seq_counter += 1
        return self._seq_counter

    def activate(self) -> None:
        """Переводит сессию в состояние ACTIVE после успешного рукопожатия."""
        self._state = SessionState.ACTIVE
        log_crypto_event(_log, "SESSION_ACTIVE", f"id=0x{self.session_id:08x}")

    def mark_broken(self) -> None:
        """Помечает сессию как разорванную (ожидание восстановления)."""
        self._state = SessionState.BROKEN
        _log.warning("Сессия 0x%08x: соединение разорвано", self.session_id)

    def close(self) -> None:
        """Окончательно закрывает сессию с затиранием ключей."""
        self._state = SessionState.CLOSED
        self._key_store.wipe()
        log_crypto_event(_log, "SESSION_CLOSE", f"id=0x{self.session_id:08x}")

    def account_bytes(self, num_bytes: int) -> None:
        """
        Учитывает переданный объём данных. Проверяет необходимость rekeying.

        :param num_bytes: количество байт, переданных в последнем пакете
        """
        self._bytes_since_rekey += num_bytes

    def needs_rekey(self) -> bool:
        """
        Проверяет, нужно ли обновление ключей.

        Условия:
          - Прошло rekey_interval секунд с последнего rekeying
          - Передано rekey_bytes байт с последнего rekeying

        :return: True если необходимо обновление
        """
        if self._state != SessionState.ACTIVE:
            return False

        elapsed = time.monotonic() - self._last_rekey_at
        if elapsed >= self._config.rekey_interval:
            _log.info("Rekeying: превышен временной интервал (%.0f с)", elapsed)
            return True

        if self._bytes_since_rekey >= self._config.rekey_bytes:
            _log.info(
                "Rekeying: превышен объём данных (%d байт)", self._bytes_since_rekey
            )
            return True

        return False

    async def perform_rekey(
        self,
        peer_pub_key: bytes,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """
        Выполняет процедуру обновления ключей (rekeying) без разрыва туннеля.

        :param peer_pub_key: текущий открытый ключ партнёра
        :param writer:       asyncio StreamWriter для отправки данных серверу
        :return: True при успехе
        """
        if self._state == SessionState.REKEYING:
            _log.warning("Rekeying уже выполняется, пропускаем")
            return False

        self._state = SessionState.REKEYING
        log_crypto_event(_log, "REKEY_START", f"id=0x{self.session_id:08x}")

        try:
            import secrets as _secrets
            import struct as _struct

            new_kp = self._crypto.create_ecdh_keypair()
            ukm = _secrets.token_bytes(8)

            rekey_req = (
                b"\x10"
                + _struct.pack("!I", self.session_id)
                + new_kp.public_key
                + ukm
            )

            length_prefix = _struct.pack("!H", len(rekey_req))
            writer.write(length_prefix + rekey_req)
            await writer.drain()

            server_eph_pub = new_kp.public_key
            combined_ukm = ukm

            from utils.zeroize import secure_context as _sc
            with _sc(bytes(new_kp.private_key)) as prv_buf:
                new_secret = self._crypto.compute_shared_secret(
                    bytes(prv_buf), server_eph_pub, combined_ukm
                )

            session_id_bytes = _struct.pack("!I", self.session_id)
            new_keys = self._crypto.derive_keys(new_secret, session_id_bytes)

            new_secret_buf = bytearray(new_secret)
            zeroize_bytes(new_secret_buf)

            self._key_store.rotate(new_keys.enc_key, new_keys.mac_key)
            self._last_rekey_at = time.monotonic()
            self._bytes_since_rekey = 0

            log_crypto_event(_log, "REKEY_OK", f"id=0x{self.session_id:08x}")
            return True

        except Exception as exc:
            _log.error("Ошибка rekeying: %s", exc)
            return False
        finally:
            if self._state == SessionState.REKEYING:
                self._state = SessionState.ACTIVE

    def is_expired(self) -> bool:
        """
        Проверяет, не истёк ли срок жизни сессии.

        :return: True если сессия истекла
        """
        elapsed = time.monotonic() - self._created_at
        return elapsed >= self._config.session_lifetime

    def can_reconnect(self) -> bool:
        """
        Проверяет возможность восстановления соединения.

        :return: True если можно попытаться переподключиться
        """
        if self.is_expired():
            _log.info("Сессия истекла — требуется полная переаутентификация")
            return False
        if self._reconnect_attempts >= self._config.max_reconnect_attempts:
            _log.warning(
                "Исчерпан лимит попыток переподключения (%d)",
                self._config.max_reconnect_attempts,
            )
            return False
        return True

    def increment_reconnect(self) -> int:
        """
        Инкрементирует счётчик попыток переподключения.

        :return: текущее число попыток
        """
        self._reconnect_attempts += 1
        return self._reconnect_attempts

    def reset_reconnect_counter(self) -> None:
        """Сбрасывает счётчик попыток после успешного восстановления."""
        self._reconnect_attempts = 0

    def reconnect_delay(self) -> float:
        """
        Вычисляет задержку перед следующей попыткой переподключения.

        Использует экспоненциальный backoff: base * 2^(attempt-1).

        :return: задержка в секундах
        """
        delay = self._config.reconnect_timeout * (2 ** (self._reconnect_attempts - 1))
        return min(delay, 300.0)  # Максимум 5 минут

    def save_context(self) -> dict:
        """
        Сохраняет контекст сессии для восстановления после разрыва.

        :return: словарь с параметрами контекста (без ключевого материала)
        """
        return {
            "session_id": self.session_id,
            "last_seq": self._replay_guard.last_seq,
            "seq_counter": self._seq_counter,
            "created_at_epoch": self._created_at,
            "reconnect_attempts": self._reconnect_attempts,
        }
