"""
Абстрактный интерфейс криптографического провайдера.

Назначение: определяет контракт (API) между криптоядром и остальными компонентами
VPN-клиента. Позволяет заменить реализацию на базе pygost на аппаратный
криптоускоритель (КриптоПро CSP, СКЗИ «Кузнечик», Token CSP) без изменения
транспортного уровня или модуля управления сессиями.

Реализуемые требования:
  НФТ-5 — модульность, абстракция криптопровайдера
  НФТ-2 — полная импортонезависимость (этот файл не импортирует ни одной
           криптобиблиотеки, только стандартную библиотеку Python)
  НФТ-4 — чёткое разделение слоёв: криптоядро / транспорт / сессия
"""

from abc import ABC, abstractmethod
from typing import NamedTuple


class KeyPair(NamedTuple):
    """
    Пара ключей: закрытый (в байтах, LE) и открытый (64 байта, x||y, LE).

    Атрибуты:
        private_key: закрытый ключ ГОСТ Р 34.10-2012, 32 байта (little-endian)
        public_key:  открытый ключ (точка кривой), 64 байта (x||y, little-endian)
    """
    private_key: bytes
    public_key: bytes


class SessionKeys(NamedTuple):
    """
    Производные ключи сессии.

    Атрибуты:
        enc_key: ключ шифрования «Кузнечик», 32 байта
        mac_key: ключ имитозащиты HMAC-Стрибог-256, 32 байта
    """
    enc_key: bytes
    mac_key: bytes


class CryptoProvider(ABC):
    """
    Абстрактный криптографический провайдер.

    Все операции с криптоматериалами выполняются исключительно через этот интерфейс.
    Смешивание вызовов провайдера с прямыми вызовами библиотек запрещено.

    Алгоритмы (в реализации pygost):
      - Шифрование:  ГОСТ Р 34.12-2015 «Кузнечик», режим CTR (ГОСТ Р 34.13-2015)
      - Хэширование: ГОСТ Р 34.11-2012 «Стрибог-256»
      - Имитовставка: HMAC-Стрибог-256
      - Подпись/верификация: ГОСТ Р 34.10-2012, кривая id-tc26-gost-3410-2012-256-paramSetA
      - Выработка ключей: VKO ГОСТ Р 34.10-2012 + KDF
    """

    @abstractmethod
    def create_ecdh_keypair(self) -> KeyPair:
        """Генерирует эфемерную пару ключей ГОСТ Р 34.10-2012-256 для ECDH."""

    @abstractmethod
    def compute_shared_secret(self, our_private_key: bytes, peer_public_key: bytes, ukm: bytes) -> bytes:
        """Вычисляет общий секрет VKO ГОСТ Р 34.10-2012."""

    @abstractmethod
    def derive_keys(self, shared_secret: bytes, session_id: bytes) -> SessionKeys:
        """Выводит ключи сессии из общего секрета по KDF."""

    @abstractmethod
    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """Шифрует данные «Кузнечик» CTR."""

    @abstractmethod
    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Расшифровывает «Кузнечик» CTR."""

    @abstractmethod
    def compute_mac(self, key: bytes, data: bytes) -> bytes:
        """Вычисляет HMAC-Стрибог-256."""

    @abstractmethod
    def verify_mac(self, key: bytes, data: bytes, mac: bytes) -> bool:
        """Проверяет HMAC-Стрибог-256 за постоянное время."""

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Подписывает ГОСТ Р 34.10-2012."""

    @abstractmethod
    def verify_signature(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Проверяет подпись ГОСТ Р 34.10-2012."""

    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """Стрибог-256 (ГОСТ Р 34.11-2012)."""
