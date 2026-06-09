"""
Реализация CryptoProvider на базе библиотеки pygost 5.0.0.

Назначение: полная реализация криптографического интерфейса с использованием
исключительно отечественных алгоритмов из pygost. Запрещено использование
зарубежных криптобиблиотек (OpenSSL, hashlib, hmac из stdlib для ГОСТ-хэшей).

Реализованные алгоритмы:
  - ГОСТ Р 34.12-2015 «Кузнечик» (128-бит блок, 256-бит ключ)
  - ГОСТ Р 34.13-2015, режим CTR (гаммирование)
  - ГОСТ Р 34.11-2012 «Стрибог-256»
  - HMAC-Стрибог-256 (реализован вручную по RFC 2104)
  - ГОСТ Р 34.10-2012, кривая id-tc26-gost-3410-2012-256-paramSetA
  - VKO ГОСТ Р 34.10-2012 (выработка общего ключа)
  - KDF: HMAC_Стрибог256(secret, label || 0x01 || context)

Реализуемые требования:
  ФТ-1  — шифрование «Кузнечик» CTR
  ФТ-2  — подпись/верификация ГОСТ Р 34.10-2012
  ФТ-3  — имитовставка HMAC-Стрибог-256
  НФТ-2 — импортонезависимость криптографии
  НФТ-4 — изолированное криптоядро
  НФТ-5 — реализация интерфейса CryptoProvider
  В     — выработка ключей и параметры ГОСТ
  Д     — безопасное обращение с ключами
"""

import os
import secrets
from typing import Optional

from pygost.gost3410 import (
    CURVES,
    public_key as gost3410_public_key,
    sign as gost3410_sign,
    verify as gost3410_verify,
    prv_unmarshal,
    pub_marshal,
    pub_unmarshal,
)
from pygost.gost3412 import GOST3412Kuznyechik
from pygost.gost3413 import ctr as gost_ctr
from pygost.gost34112012 import GOST34112012

from vpn_core.crypto_interface import CryptoProvider, KeyPair, SessionKeys
from utils.logger import get_logger, log_crypto_event
from utils.zeroize import zeroize_bytes, secure_context

_log = get_logger("crypto")

# Кривая ГОСТ Р 34.10-2012-256, набор параметров A (RFC 7836, TC26)
_CURVE_NAME = "id-tc26-gost-3410-2012-256-paramSetA"
_CURVE = CURVES[_CURVE_NAME]

# Размеры ключей в байтах
_KEY_SIZE = 32          # 256 бит
_BLOCK_SIZE = 16        # 128 бит (Кузнечик)
_IV_SIZE = 8            # 64 бит (половина блока, согласно ГОСТ Р 34.13-2015 CTR)
_MAC_SIZE = 32          # 256 бит (HMAC-Стрибог-256)
_SIG_SIZE = 64          # 512 бит (r||s, ГОСТ Р 34.10-2012-256)
_PUB_SIZE = 64          # 512 бит (x||y, ГОСТ Р 34.10-2012-256)
_STRIBOG_BLOCK = 64     # 512 бит — размер блока Стрибог (для HMAC)

# Метки для KDF
_KDF_LABEL_ENC = b"VPN enc key"
_KDF_LABEL_MAC = b"VPN mac key"
_KDF_LABEL_EXPAND = b"VPN key expansion"


def _stribog256(data: bytes) -> bytes:
    """
    Вычисляет ГОСТ Р 34.11-2012 «Стрибог-256».

    :param data: входные данные
    :return: дайджест, 32 байта
    """
    h = GOST34112012(digest_size=32)
    h.update(data)
    return h.digest()


def _hmac_stribog256(key: bytes, data: bytes) -> bytes:
    """
    Вычисляет HMAC-Стрибог-256 по RFC 2104.

    Реализовано вручную: стандартная библиотека Python (hmac, hashlib)
    не поддерживает ГОСТ-алгоритмы.

    :param key:  ключ HMAC произвольной длины
    :param data: входные данные
    :return: имитовставка, 32 байта
    """
    if len(key) > _STRIBOG_BLOCK:
        key = _stribog256(key)

    padded_key = bytearray(key) + bytearray(_STRIBOG_BLOCK - len(key))

    try:
        ipad = bytes(b ^ 0x36 for b in padded_key)
        opad = bytes(b ^ 0x5C for b in padded_key)

        h_inner = GOST34112012(digest_size=32)
        h_inner.update(ipad)
        h_inner.update(data)
        inner_digest = h_inner.digest()

        h_outer = GOST34112012(digest_size=32)
        h_outer.update(opad)
        h_outer.update(inner_digest)
        return h_outer.digest()
    finally:
        zeroize_bytes(padded_key)


def _kdf(secret: bytes, label: bytes, context: bytes) -> bytes:
    """
    Функция диверсификации ключей (KDF).

    KDF(secret, label, context) = HMAC_Стрибог256(secret, label || 0x01 || context)

    :param secret:  исходный секрет (общий секрет ECDH)
    :param label:   метка назначения ключа
    :param context: контекст (например, session_id)
    :return: производный ключ, 32 байта
    """
    return _hmac_stribog256(secret, label + b"\x01" + context)


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Сравнение двух байтовых строк за постоянное время.

    Предотвращает атаки по сторонним каналам (timing attack) при проверке
    имитовставки. Использует побитовое XOR с аккумуляцией результата.

    :param a: первая строка
    :param b: вторая строка
    :return: True если строки равны
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


class PygostProvider(CryptoProvider):
    """
    Криптографический провайдер на основе pygost 5.0.0.

    Реализует все методы CryptoProvider с использованием исключительно
    отечественных алгоритмов ГОСТ. Зарубежные криптопровайдеры не используются.
    """

    # ------------------------------------------------------------------ ECDH / KDF

    def create_ecdh_keypair(self) -> KeyPair:
        """
        Генерирует эфемерную пару ключей ГОСТ Р 34.10-2012-256.

        Закрытый ключ — криптографически случайное число от 1 до q-1.
        Открытый ключ — точка на кривой id-tc26-gost-3410-2012-256-paramSetA.

        :return: KeyPair(private_key_bytes, public_key_bytes)
        """
        log_crypto_event(_log, "KEYGEN", f"кривая={_CURVE_NAME}")

        prv_bytes = bytearray(32)
        try:
            while True:
                raw = bytearray(secrets.token_bytes(32))
                try:
                    prv_int = prv_unmarshal(bytes(raw))
                    if 1 <= prv_int < _CURVE.q:
                        prv_bytes[:] = raw
                        break
                finally:
                    zeroize_bytes(raw)

            prv_int = prv_unmarshal(bytes(prv_bytes))
            pub_point = gost3410_public_key(_CURVE, prv_int)
            pub_bytes = pub_marshal(pub_point)

            log_crypto_event(_log, "KEYGEN_OK", "пара ключей сгенерирована")
            return KeyPair(
                private_key=bytes(prv_bytes),
                public_key=pub_bytes,
            )
        finally:
            zeroize_bytes(prv_bytes)

    def compute_shared_secret(
        self,
        our_private_key: bytes,
        peer_public_key: bytes,
        ukm: bytes,
    ) -> bytes:
        """
        Вычисляет общий секрет VKO ГОСТ Р 34.10-2012.

        Алгоритм: shared_point = prv * peer_pub_point; secret = x(shared_point)
        UKM влияет на выработку ключа через KDF-контекст.

        :param our_private_key: 32 байта (little-endian)
        :param peer_public_key: 64 байта (x||y, little-endian)
        :param ukm:             8 байт (User Key Material, случайный nonce)
        :return: общий секрет, 32 байта
        """
        log_crypto_event(_log, "VKO_COMPUTE", "выработка общего секрета VKO ГОСТ Р 34.10")

        prv_buf = bytearray(our_private_key)
        try:
            prv_int = prv_unmarshal(bytes(prv_buf))
            peer_pub = pub_unmarshal(peer_public_key)

            shared_x, _shared_y = _CURVE.exp(prv_int, peer_pub[0], peer_pub[1])

            raw_secret = bytearray(shared_x.to_bytes(_KEY_SIZE, "little"))
            try:
                combined = bytes(raw_secret) + ukm
                secret = _stribog256(combined)
                log_crypto_event(_log, "VKO_OK", "общий секрет выработан")
                return secret
            finally:
                zeroize_bytes(raw_secret)
        finally:
            zeroize_bytes(prv_buf)

    def derive_keys(self, shared_secret: bytes, session_id: bytes) -> SessionKeys:
        """
        Выводит ключи сессии из общего секрета по KDF.

        :param shared_secret: результат VKO, 32 байта
        :param session_id:    идентификатор сессии, 4 байта
        :return: SessionKeys(enc_key, mac_key)
        """
        log_crypto_event(_log, "KDF", f"session_id=0x{session_id.hex()}")

        with secure_context(shared_secret) as sec_buf:
            enc_key = _kdf(bytes(sec_buf), _KDF_LABEL_ENC, session_id)
            mac_key = _kdf(bytes(sec_buf), _KDF_LABEL_MAC, session_id)

        log_crypto_event(_log, "KDF_OK", "ключи enc+mac выведены")
        return SessionKeys(enc_key=enc_key, mac_key=mac_key)

    # ------------------------------------------------------------------ Шифрование

    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """
        Шифрует «Кузнечик» CTR (ГОСТ Р 34.13-2015).

        IV должен быть уникальным для каждого пакета. Рекомендуется использовать
        порядковый номер пакета (64-бит) как IV.

        :param key:       ключ, 32 байта
        :param iv:        синхропосылка, 8 байт
        :param plaintext: открытый текст
        :return: шифртекст
        """
        if len(key) != _KEY_SIZE:
            raise ValueError(f"Ключ должен быть {_KEY_SIZE} байт, получено {len(key)}")
        if len(iv) != _IV_SIZE:
            raise ValueError(f"IV должен быть {_IV_SIZE} байт, получено {len(iv)}")

        key_buf = bytearray(key)
        try:
            cipher = GOST3412Kuznyechik(bytes(key_buf))
            return gost_ctr(cipher.encrypt, _BLOCK_SIZE, plaintext, iv)
        finally:
            zeroize_bytes(key_buf)

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Расшифровывает «Кузнечик» CTR. Операция симметрична encrypt().

        :param key:        ключ, 32 байта
        :param iv:         синхропосылка, 8 байт
        :param ciphertext: шифртекст
        :return: открытый текст
        """
        return self.encrypt(key, iv, ciphertext)

    # ------------------------------------------------------------------ Имитовставка

    def compute_mac(self, key: bytes, data: bytes) -> bytes:
        """
        Вычисляет HMAC-Стрибог-256.

        :param key:  ключ имитозащиты, 32 байта
        :param data: защищаемые данные
        :return: имитовставка, 32 байта
        """
        return _hmac_stribog256(key, data)

    def verify_mac(self, key: bytes, data: bytes, mac: bytes) -> bool:
        """
        Проверяет HMAC-Стрибог-256 за постоянное время.

        :param key:  ключ имитозащиты, 32 байта
        :param data: защищаемые данные
        :param mac:  полученная имитовставка
        :return: True если имитовставка верна
        """
        expected = _hmac_stribog256(key, data)
        return _constant_time_compare(expected, mac)

    # ------------------------------------------------------------------ Подпись

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Подписывает сообщение ГОСТ Р 34.10-2012-256.

        Дайджест вычисляется алгоритмом Стрибог-256.

        :param private_key: закрытый ключ, 32 байта
        :param message:     подписываемое сообщение
        :return: подпись, 64 байта (r||s)
        """
        log_crypto_event(_log, "SIGN", "ГОСТ Р 34.10-2012")

        digest = _stribog256(message)
        prv_buf = bytearray(private_key)
        try:
            prv_int = prv_unmarshal(bytes(prv_buf))
            signature = gost3410_sign(_CURVE, prv_int, digest)
            log_crypto_event(_log, "SIGN_OK", "подпись сформирована")
            return signature
        finally:
            zeroize_bytes(prv_buf)

    def verify_signature(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """
        Проверяет подпись ГОСТ Р 34.10-2012-256.

        :param public_key: открытый ключ, 64 байта
        :param message:    проверяемое сообщение
        :param signature:  подпись, 64 байта
        :return: True если подпись верна
        """
        log_crypto_event(_log, "VERIFY", "ГОСТ Р 34.10-2012")
        try:
            digest = _stribog256(message)
            pub_point = pub_unmarshal(public_key)
            result = gost3410_verify(_CURVE, pub_point, digest, signature)
            log_crypto_event(_log, "VERIFY_OK" if result else "VERIFY_FAIL", "")
            return result
        except Exception as exc:
            _log.warning("[КРИПТО-АУДИТ] VERIFY_ERROR: %s", exc)
            return False

    # ------------------------------------------------------------------ Хэш

    def hash(self, data: bytes) -> bytes:
        """
        Стрибог-256 (ГОСТ Р 34.11-2012).

        :param data: входные данные
        :return: дайджест, 32 байта
        """
        return _stribog256(data)
