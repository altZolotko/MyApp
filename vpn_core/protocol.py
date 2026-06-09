"""
Протокол упаковки/распаковки кадров VPN.

Назначение: определяет формат кадра, сериализацию/десериализацию, проверку
порядкового номера (защита от replay-атак) и верификацию имитовставки.

Формат кадра (всего: 4 + 8 + 2 + N + 32 байта):
  ┌──────────────┬────────────────┬─────────────┬───────────────┬────────────────────┐
  │ session_id   │  seq_num       │ payload_len │ enc_payload   │ mac                │
  │  (4 байта)   │  (8 байт, BE)  │ (2 байта BE)│ (N байт)      │ (32 байта)         │
  └──────────────┴────────────────┴─────────────┴───────────────┴────────────────────┘

Поля:
  session_id   — идентификатор сессии (4 байта big-endian)
  seq_num      — монотонно возрастающий 64-битный порядковый номер (big-endian)
  payload_len  — длина зашифрованного payload (big-endian)
  enc_payload  — зашифрованный полезный груз («Кузнечик» CTR)
  mac          — HMAC-Стрибог-256 от (session_id || seq_num || payload_len || enc_payload)

Синхропосылка для шифрования: младшие 8 байт seq_num (big-endian) — уникальна
для каждого пакета сессии.

Реализуемые требования:
  ФТ-1 — IV из счётчика пакетов (уникальна для каждого пакета)
  ФТ-3 — имитовставка по зашифрованному payload + метаданные
  А    — защита от replay-атак (проверка seq_num)
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from vpn_core.crypto_interface import CryptoProvider
from utils.logger import get_logger

_log = get_logger("protocol")

# Структура заголовка: session_id (4) + seq_num (8) + payload_len (2)
_HEADER_FMT = "!IQH"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)   # = 14 байт
_MAC_SIZE = 32                                  # 256 бит, HMAC-Стрибог-256
_MIN_FRAME_SIZE = _HEADER_SIZE + _MAC_SIZE      # минимальный кадр без payload

# Специальный признак keepalive-кадра: seq_num = 0 и payload_len = 0
_KEEPALIVE_SEQ = 0

# Максимальный допустимый payload
_MAX_PAYLOAD = 65535


@dataclass
class VpnFrame:
    """
    Распакованный VPN-кадр.

    Атрибуты:
        session_id:  идентификатор сессии
        seq_num:     порядковый номер пакета
        payload:     расшифрованный полезный груз (IP-пакет или пустой для keepalive)
        is_keepalive: признак keepalive-кадра
    """
    session_id: int
    seq_num: int
    payload: bytes
    is_keepalive: bool = field(default=False)


class ReplayGuard:
    """
    Защита от повторного воспроизведения (replay-атак).

    Хранит последний принятый seq_num и отбрасывает пакеты с меньшим или равным
    номером. При восстановлении соединения счётчик сохраняется.

    Реализуемые требования: А (защита от replay).
    """

    def __init__(self) -> None:
        self._last_seq: int = 0

    def check_and_advance(self, seq_num: int) -> bool:
        """
        Проверяет порядковый номер пакета.

        :param seq_num: порядковый номер входящего пакета
        :return: True если пакет новый, False если повтор (нужно отбросить)
        """
        if seq_num == _KEEPALIVE_SEQ:
            return True

        if seq_num <= self._last_seq:
            _log.warning(
                "Replay-защита: отброшен пакет seq=%d <= last=%d",
                seq_num,
                self._last_seq,
            )
            return False

        self._last_seq = seq_num
        return True

    @property
    def last_seq(self) -> int:
        return self._last_seq

    def restore(self, last_seq: int) -> None:
        """Восстанавливает состояние счётчика после переподключения."""
        self._last_seq = last_seq


class FrameCodec:
    """
    Кодек VPN-кадров: упаковка и распаковка.

    Все криптографические операции выполняются через CryptoProvider,
    что обеспечивает полную изоляцию криптоядра от транспортного уровня.
    """

    def __init__(self, crypto: CryptoProvider) -> None:
        """
        :param crypto: провайдер криптографических операций
        """
        self._crypto = crypto

    def pack(
        self,
        session_id: int,
        seq_num: int,
        plaintext: bytes,
        enc_key: bytes,
        mac_key: bytes,
    ) -> bytes:
        """
        Упаковывает IP-пакет в зашифрованный VPN-кадр.

        1. Шифрует payload «Кузнечик» CTR (IV = seq_num as 8 bytes big-endian)
        2. Формирует заголовок
        3. Вычисляет HMAC-Стрибог-256 по (заголовок || enc_payload)
        4. Собирает итоговый кадр

        :param session_id: идентификатор сессии (4 байта)
        :param seq_num:    порядковый номер пакета (64 бит)
        :param plaintext:  исходный IP-пакет
        :param enc_key:    ключ шифрования, 32 байта
        :param mac_key:    ключ имитозащиты, 32 байта
        :return: сериализованный кадр
        """
        if len(plaintext) > _MAX_PAYLOAD:
            raise ValueError(f"Payload слишком большой: {len(plaintext)} > {_MAX_PAYLOAD}")

        # IV = первые 8 байт порядкового номера (big-endian)
        iv = struct.pack("!Q", seq_num)[:8]

        # Шифрование
        enc_payload = self._crypto.encrypt(enc_key, iv, plaintext)

        # Заголовок
        header = struct.pack(_HEADER_FMT, session_id, seq_num, len(enc_payload))

        # Имитовставка: защищает заголовок + шифртекст
        mac_input = header + enc_payload
        mac = self._crypto.compute_mac(mac_key, mac_input)

        return header + enc_payload + mac

    def pack_keepalive(
        self,
        session_id: int,
        seq_num: int,
        mac_key: bytes,
    ) -> bytes:
        """
        Создаёт keepalive-кадр (пустой payload, seq_num без изменения счётчика).

        :param session_id: идентификатор сессии
        :param seq_num:    текущий seq_num
        :param mac_key:    ключ имитозащиты
        :return: keepalive-кадр
        """
        header = struct.pack(_HEADER_FMT, session_id, _KEEPALIVE_SEQ, 0)
        mac = self._crypto.compute_mac(mac_key, header)
        return header + mac

    def unpack(
        self,
        raw: bytes,
        enc_key: bytes,
        mac_key: bytes,
        replay_guard: ReplayGuard,
    ) -> Optional[VpnFrame]:
        """
        Распаковывает и верифицирует входящий кадр.

        1. Разбирает заголовок
        2. Проверяет имитовставку (целостность)
        3. Проверяет seq_num (replay-защита)
        4. Расшифровывает payload

        При любой ошибке возвращает None и логирует предупреждение.

        :param raw:          сырые байты кадра
        :param enc_key:      ключ шифрования
        :param mac_key:      ключ имитозащиты
        :param replay_guard: объект защиты от replay
        :return: VpnFrame или None при ошибке
        """
        if len(raw) < _MIN_FRAME_SIZE:
            _log.warning("Кадр слишком короткий: %d байт", len(raw))
            return None

        # Парсинг заголовка
        session_id, seq_num, payload_len = struct.unpack_from(_HEADER_FMT, raw, 0)

        expected_total = _HEADER_SIZE + payload_len + _MAC_SIZE
        if len(raw) != expected_total:
            _log.warning(
                "Неверная длина кадра: ожидается %d, получено %d",
                expected_total,
                len(raw),
            )
            return None

        enc_payload = raw[_HEADER_SIZE : _HEADER_SIZE + payload_len]
        received_mac = raw[_HEADER_SIZE + payload_len :]

        # Проверка имитовставки (FAIL-FIRST: до расшифровки)
        mac_input = raw[:_HEADER_SIZE + payload_len]
        if not self._crypto.verify_mac(mac_key, mac_input, received_mac):
            _log.error(
                "НАРУШЕНИЕ ЦЕЛОСТНОСТИ: имитовставка не совпадает, сессия %08x seq %d",
                session_id,
                seq_num,
            )
            return None

        # Проверка replay
        if not replay_guard.check_and_advance(seq_num):
            return None

        # Расшифровка
        if payload_len == 0:
            return VpnFrame(
                session_id=session_id,
                seq_num=seq_num,
                payload=b"",
                is_keepalive=True,
            )

        iv = struct.pack("!Q", seq_num)[:8]
        plaintext = self._crypto.decrypt(enc_key, iv, enc_payload)

        return VpnFrame(
            session_id=session_id,
            seq_num=seq_num,
            payload=plaintext,
        )


def build_auth_hello(
    session_id: int,
    cert_der: bytes,
    ephemeral_pub: bytes,
    ukm: bytes,
) -> bytes:
    """
    Формирует приветственное сообщение рукопожатия.

    Структура: version(1) | session_id(4) | cert_len(2) | cert_der | pub_len(2) | pub | ukm(8)

    :param session_id:    предложенный идентификатор сессии
    :param cert_der:      DER-сертификат клиента
    :param ephemeral_pub: эфемерный открытый ключ ECDH, 64 байта
    :param ukm:           случайный User Key Material, 8 байт
    :return: байты сообщения
    """
    return (
        b"\x01"  # version
        + struct.pack("!I", session_id)
        + struct.pack("!H", len(cert_der))
        + cert_der
        + struct.pack("!H", len(ephemeral_pub))
        + ephemeral_pub
        + ukm
    )


def parse_auth_hello(data: bytes) -> Optional[dict]:
    """
    Разбирает приветственное сообщение рукопожатия.

    :param data: сырые байты сообщения
    :return: словарь с полями или None при ошибке парсинга
    """
    try:
        offset = 0
        version = data[offset]
        offset += 1

        if version != 1:
            _log.error("Неизвестная версия протокола: %d", version)
            return None

        session_id = struct.unpack_from("!I", data, offset)[0]
        offset += 4

        cert_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        cert_der = data[offset : offset + cert_len]
        offset += cert_len

        pub_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        ephemeral_pub = data[offset : offset + pub_len]
        offset += pub_len

        ukm = data[offset : offset + 8]

        return {
            "version": version,
            "session_id": session_id,
            "cert_der": cert_der,
            "ephemeral_pub": ephemeral_pub,
            "ukm": ukm,
        }
    except (struct.error, IndexError) as exc:
        _log.error("Ошибка парсинга auth_hello: %s", exc)
        return None
