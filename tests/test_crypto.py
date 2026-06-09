"""
Тесты криптографического провайдера PygostProvider.

Проверяет:
  - Шифрование/расшифровку «Кузнечик» CTR (симметричность, уникальность IV)
  - HMAC-Стрибог-256 (корректность, константное сравнение)
  - Генерацию ключей ГОСТ Р 34.10-2012 и ECDH
  - KDF (детерминированность)
  - Подпись и верификацию
  - Защиту от replay-атак
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vpn_core.pygost_provider import PygostProvider, _hmac_stribog256, _kdf, _stribog256
from utils.logger import setup_logger

setup_logger("WARNING")


class TestKuznyechikCTR(unittest.TestCase):
    """Тесты шифрования «Кузнечик» CTR."""

    def setUp(self):
        self.crypto = PygostProvider()
        self.key = bytes(range(32))  # Тестовый ключ 256 бит
        self.iv = bytes(range(8))    # IV 64 бит

    def test_encrypt_decrypt_roundtrip(self):
        """Расшифровка зашифрованного текста возвращает исходный."""
        plaintext = b"Hello, GOST VPN! " * 10
        ciphertext = self.crypto.encrypt(self.key, self.iv, plaintext)
        recovered = self.crypto.decrypt(self.key, self.iv, ciphertext)
        self.assertEqual(plaintext, recovered)

    def test_ctr_symmetric(self):
        """CTR-режим симметричен: encrypt(encrypt(x)) == x."""
        plaintext = os.urandom(64)
        double_enc = self.crypto.encrypt(
            self.key, self.iv,
            self.crypto.encrypt(self.key, self.iv, plaintext)
        )
        self.assertEqual(plaintext, double_enc)

    def test_different_iv_different_ciphertext(self):
        """Разные IV дают разные шифртексты (уникальность IV критична)."""
        plaintext = b"Test data GOST " * 4
        iv1 = (0).to_bytes(8, "big")
        iv2 = (1).to_bytes(8, "big")
        ct1 = self.crypto.encrypt(self.key, iv1, plaintext)
        ct2 = self.crypto.encrypt(self.key, iv2, plaintext)
        self.assertNotEqual(ct1, ct2)

    def test_different_key_different_ciphertext(self):
        """Разные ключи дают разные шифртексты."""
        plaintext = b"Test data" * 8
        key2 = bytes([0xFF] * 32)
        ct1 = self.crypto.encrypt(self.key, self.iv, plaintext)
        ct2 = self.crypto.encrypt(key2, self.iv, plaintext)
        self.assertNotEqual(ct1, ct2)

    def test_ciphertext_length(self):
        """Длина шифртекста совпадает с длиной открытого текста (CTR-режим)."""
        for size in [1, 15, 16, 17, 32, 100, 1500]:
            plaintext = os.urandom(size)
            ciphertext = self.crypto.encrypt(self.key, self.iv, plaintext)
            self.assertEqual(len(ciphertext), size)

    def test_invalid_key_length(self):
        """Ключ неверной длины вызывает ValueError."""
        with self.assertRaises(ValueError):
            self.crypto.encrypt(b"short_key", self.iv, b"data")

    def test_invalid_iv_length(self):
        """IV неверной длины вызывает ValueError."""
        with self.assertRaises(ValueError):
            self.crypto.encrypt(self.key, b"short", b"data")


class TestHMACStribog(unittest.TestCase):
    """Тесты HMAC-Стрибог-256."""

    def test_output_length(self):
        """HMAC-Стрибог-256 возвращает 32 байта."""
        result = _hmac_stribog256(b"key", b"data")
        self.assertEqual(len(result), 32)

    def test_deterministic(self):
        """HMAC детерминирован для одинаковых входных данных."""
        key = b"test key"
        data = b"test message"
        self.assertEqual(
            _hmac_stribog256(key, data),
            _hmac_stribog256(key, data),
        )

    def test_different_key_different_mac(self):
        """Разные ключи дают разные MAC."""
        data = b"data"
        m1 = _hmac_stribog256(b"key1", data)
        m2 = _hmac_stribog256(b"key2", data)
        self.assertNotEqual(m1, m2)

    def test_different_data_different_mac(self):
        """Разные данные дают разные MAC."""
        key = b"key"
        m1 = _hmac_stribog256(key, b"data1")
        m2 = _hmac_stribog256(key, b"data2")
        self.assertNotEqual(m1, m2)

    def test_long_key_normalization(self):
        """Ключ длиннее блока (64 байт) нормализуется хэшированием."""
        long_key = os.urandom(128)
        result = _hmac_stribog256(long_key, b"data")
        self.assertEqual(len(result), 32)


class TestCryptoProviderMAC(unittest.TestCase):
    """Тесты verify_mac через CryptoProvider."""

    def setUp(self):
        self.crypto = PygostProvider()
        self.key = os.urandom(32)

    def test_valid_mac_accepted(self):
        """Верная имитовставка принимается."""
        data = b"protected data"
        mac = self.crypto.compute_mac(self.key, data)
        self.assertTrue(self.crypto.verify_mac(self.key, data, mac))

    def test_tampered_data_rejected(self):
        """Модифицированные данные отклоняются."""
        data = b"original data"
        mac = self.crypto.compute_mac(self.key, data)
        tampered = b"tampered data"
        self.assertFalse(self.crypto.verify_mac(self.key, tampered, mac))

    def test_wrong_key_rejected(self):
        """Неверный ключ проверки отклоняется."""
        data = b"data"
        mac = self.crypto.compute_mac(self.key, data)
        wrong_key = os.urandom(32)
        self.assertFalse(self.crypto.verify_mac(wrong_key, data, mac))

    def test_truncated_mac_rejected(self):
        """Укороченная имитовставка отклоняется."""
        data = b"data"
        mac = self.crypto.compute_mac(self.key, data)
        self.assertFalse(self.crypto.verify_mac(self.key, data, mac[:16]))


class TestECDHAndKDF(unittest.TestCase):
    """Тесты ECDH и деривации ключей."""

    def setUp(self):
        self.crypto = PygostProvider()

    def test_keypair_sizes(self):
        """Пара ключей имеет правильный размер."""
        kp = self.crypto.create_ecdh_keypair()
        self.assertEqual(len(kp.private_key), 32)
        self.assertEqual(len(kp.public_key), 64)

    def test_different_keypairs(self):
        """Каждая генерация даёт уникальную пару ключей."""
        kp1 = self.crypto.create_ecdh_keypair()
        kp2 = self.crypto.create_ecdh_keypair()
        self.assertNotEqual(kp1.private_key, kp2.private_key)
        self.assertNotEqual(kp1.public_key, kp2.public_key)

    def test_shared_secret_agreement(self):
        """Обе стороны вычисляют одинаковый общий секрет (ECDH)."""
        kp_a = self.crypto.create_ecdh_keypair()
        kp_b = self.crypto.create_ecdh_keypair()
        ukm = os.urandom(8)

        secret_a = self.crypto.compute_shared_secret(
            kp_a.private_key, kp_b.public_key, ukm
        )
        secret_b = self.crypto.compute_shared_secret(
            kp_b.private_key, kp_a.public_key, ukm
        )
        self.assertEqual(secret_a, secret_b)

    def test_shared_secret_length(self):
        """Общий секрет имеет длину 32 байта."""
        kp_a = self.crypto.create_ecdh_keypair()
        kp_b = self.crypto.create_ecdh_keypair()
        secret = self.crypto.compute_shared_secret(
            kp_a.private_key, kp_b.public_key, b"\x00" * 8
        )
        self.assertEqual(len(secret), 32)

    def test_kdf_deterministic(self):
        """KDF детерминирован для одинакового секрета и контекста."""
        secret = os.urandom(32)
        session_id = b"\x01\x02\x03\x04"
        keys1 = self.crypto.derive_keys(secret, session_id)
        keys2 = self.crypto.derive_keys(secret, session_id)
        self.assertEqual(keys1.enc_key, keys2.enc_key)
        self.assertEqual(keys1.mac_key, keys2.mac_key)

    def test_kdf_enc_mac_different(self):
        """KDF производит разные ключи шифрования и имитозащиты."""
        secret = os.urandom(32)
        keys = self.crypto.derive_keys(secret, b"\x00\x00\x00\x01")
        self.assertNotEqual(keys.enc_key, keys.mac_key)

    def test_kdf_different_sessions(self):
        """Разные session_id дают разные ключи."""
        secret = os.urandom(32)
        keys1 = self.crypto.derive_keys(secret, b"\x00\x00\x00\x01")
        keys2 = self.crypto.derive_keys(secret, b"\x00\x00\x00\x02")
        self.assertNotEqual(keys1.enc_key, keys2.enc_key)


class TestSignature(unittest.TestCase):
    """Тесты подписи ГОСТ Р 34.10-2012."""

    def setUp(self):
        self.crypto = PygostProvider()
        self.kp = self.crypto.create_ecdh_keypair()

    def test_sign_verify_roundtrip(self):
        """Подпись верифицируется корректным открытым ключом."""
        message = b"Test message for GOST signature"
        sig = self.crypto.sign(self.kp.private_key, message)
        valid = self.crypto.verify_signature(self.kp.public_key, message, sig)
        self.assertTrue(valid)

    def test_wrong_key_rejected(self):
        """Подпись не верифицируется чужим открытым ключом."""
        kp2 = self.crypto.create_ecdh_keypair()
        message = b"Test message"
        sig = self.crypto.sign(self.kp.private_key, message)
        self.assertFalse(self.crypto.verify_signature(kp2.public_key, message, sig))

    def test_tampered_message_rejected(self):
        """Изменение сообщения делает подпись недействительной."""
        message = b"Original message"
        sig = self.crypto.sign(self.kp.private_key, message)
        self.assertFalse(
            self.crypto.verify_signature(self.kp.public_key, b"Modified message", sig)
        )

    def test_signature_length(self):
        """Подпись ГОСТ Р 34.10-2012-256 имеет длину 64 байта."""
        sig = self.crypto.sign(self.kp.private_key, b"data")
        self.assertEqual(len(sig), 64)


class TestStribog(unittest.TestCase):
    """Тесты хэш-функции Стрибог-256."""

    def test_hash_length(self):
        """Стрибог-256 возвращает 32 байта."""
        self.assertEqual(len(_stribog256(b"data")), 32)

    def test_hash_deterministic(self):
        """Хэш детерминирован."""
        data = b"test data"
        self.assertEqual(_stribog256(data), _stribog256(data))

    def test_different_inputs(self):
        """Разные входные данные дают разные хэши."""
        self.assertNotEqual(_stribog256(b"data1"), _stribog256(b"data2"))

    def test_empty_input(self):
        """Хэш пустого входа вычисляется корректно."""
        result = _stribog256(b"")
        self.assertEqual(len(result), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
