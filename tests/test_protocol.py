"""
Тесты протокола фреймирования VPN-кадров.

Проверяет:
  - Корректную упаковку/распаковку кадров (pack/unpack)
  - Защиту от replay-атак (ReplayGuard)
  - Обнаружение нарушения целостности (tampered frames)
  - Keepalive-кадры
  - Граничные случаи длины payload
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vpn_core.protocol import FrameCodec, ReplayGuard, build_auth_hello, parse_auth_hello
from vpn_core.pygost_provider import PygostProvider
from utils.logger import setup_logger

setup_logger("WARNING")


class TestReplayGuard(unittest.TestCase):
    """Тесты защиты от replay-атак."""

    def setUp(self):
        self.guard = ReplayGuard()

    def test_first_packet_accepted(self):
        """Первый пакет принимается."""
        self.assertTrue(self.guard.check_and_advance(1))

    def test_sequential_packets_accepted(self):
        """Последовательные пакеты принимаются."""
        for seq in range(1, 100):
            self.assertTrue(self.guard.check_and_advance(seq))

    def test_duplicate_packet_rejected(self):
        """Дублирующийся пакет отклоняется."""
        self.guard.check_and_advance(5)
        self.assertFalse(self.guard.check_and_advance(5))

    def test_old_packet_rejected(self):
        """Пакет с меньшим seq_num отклоняется."""
        self.guard.check_and_advance(10)
        self.assertFalse(self.guard.check_and_advance(9))
        self.assertFalse(self.guard.check_and_advance(1))

    def test_keepalive_seq_always_accepted(self):
        """Keepalive (seq=0) всегда принимается."""
        self.guard.check_and_advance(100)
        self.assertTrue(self.guard.check_and_advance(0))

    def test_restore_context(self):
        """Состояние восстанавливается корректно."""
        self.guard.check_and_advance(50)
        self.guard.restore(50)
        self.assertFalse(self.guard.check_and_advance(50))
        self.assertTrue(self.guard.check_and_advance(51))

    def test_last_seq_property(self):
        """last_seq обновляется после принятия пакета."""
        self.guard.check_and_advance(42)
        self.assertEqual(self.guard.last_seq, 42)


class TestFrameCodec(unittest.TestCase):
    """Тесты кодека VPN-кадров."""

    def setUp(self):
        self.crypto = PygostProvider()
        self.codec = FrameCodec(self.crypto)
        self.enc_key = os.urandom(32)
        self.mac_key = os.urandom(32)
        self.session_id = 0xDEADBEEF
        self.guard = ReplayGuard()

    def test_pack_unpack_roundtrip(self):
        """Распаковка packed кадра возвращает исходный payload."""
        payload = b"IP packet data " * 10
        frame = self.codec.pack(
            session_id=self.session_id,
            seq_num=1,
            plaintext=payload,
            enc_key=self.enc_key,
            mac_key=self.mac_key,
        )
        result = self.codec.unpack(frame, self.enc_key, self.mac_key, self.guard)
        self.assertIsNotNone(result)
        self.assertEqual(result.payload, payload)
        self.assertEqual(result.session_id, self.session_id)
        self.assertEqual(result.seq_num, 1)

    def test_empty_payload(self):
        """Пустой payload обрабатывается корректно."""
        frame = self.codec.pack(
            session_id=self.session_id,
            seq_num=1,
            plaintext=b"",
            enc_key=self.enc_key,
            mac_key=self.mac_key,
        )
        result = self.codec.unpack(frame, self.enc_key, self.mac_key, self.guard)
        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"")

    def test_tampered_payload_rejected(self):
        """Изменение зашифрованного payload вызывает отказ верификации."""
        payload = b"Sensitive data"
        frame = self.codec.pack(
            session_id=self.session_id,
            seq_num=1,
            plaintext=payload,
            enc_key=self.enc_key,
            mac_key=self.mac_key,
        )
        tampered = bytearray(frame)
        tampered[15] ^= 0xFF
        result = self.codec.unpack(bytes(tampered), self.enc_key, self.mac_key, self.guard)
        self.assertIsNone(result)

    def test_tampered_mac_rejected(self):
        """Изменение MAC вызывает отказ верификации."""
        payload = b"Test payload"
        frame = self.codec.pack(
            session_id=self.session_id,
            seq_num=1,
            plaintext=payload,
            enc_key=self.enc_key,
            mac_key=self.mac_key,
        )
        tampered = bytearray(frame)
        tampered[-1] ^= 0xFF
        result = self.codec.unpack(bytes(tampered), self.enc_key, self.mac_key, self.guard)
        self.assertIsNone(result)

    def test_wrong_key_rejected(self):
        """Неверный ключ расшифровки/верификации — отказ."""
        payload = b"Test data"
        frame = self.codec.pack(
            session_id=self.session_id,
            seq_num=1,
            plaintext=payload,
            enc_key=self.enc_key,
            mac_key=self.mac_key,
        )
        wrong_mac_key = os.urandom(32)
        result = self.codec.unpack(frame, self.enc_key, wrong_mac_key, self.guard)
        self.assertIsNone(result)

    def test_replay_attack_rejected(self):
        """Повторная отправка кадра с тем же seq_num отклоняется."""
        payload = b"Test"
        frame = self.codec.pack(
            session_id=self.session_id,
            seq_num=5,
            plaintext=payload,
            enc_key=self.enc_key,
            mac_key=self.mac_key,
        )
        self.guard.check_and_advance(4)
        result1 = self.codec.unpack(frame, self.enc_key, self.mac_key, self.guard)
        self.assertIsNotNone(result1)

        result2 = self.codec.unpack(frame, self.enc_key, self.mac_key, self.guard)
        self.assertIsNone(result2)

    def test_keepalive_frame(self):
        """Keepalive-кадр корректно формируется и распознаётся."""
        frame = self.codec.pack_keepalive(
            session_id=self.session_id,
            seq_num=1,
            mac_key=self.mac_key,
        )
        result = self.codec.unpack(frame, self.enc_key, self.mac_key, self.guard)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_keepalive)

    def test_different_iv_per_packet(self):
        """Разные seq_num дают разные шифртексты для одного payload."""
        payload = b"Same payload data for all packets"
        frame1 = self.codec.pack(
            session_id=self.session_id, seq_num=1,
            plaintext=payload, enc_key=self.enc_key, mac_key=self.mac_key,
        )
        frame2 = self.codec.pack(
            session_id=self.session_id, seq_num=2,
            plaintext=payload, enc_key=self.enc_key, mac_key=self.mac_key,
        )
        self.assertNotEqual(frame1, frame2)

    def test_large_payload(self):
        """Большой payload (MTU) обрабатывается корректно."""
        payload = os.urandom(1472)
        frame = self.codec.pack(
            session_id=self.session_id, seq_num=1,
            plaintext=payload, enc_key=self.enc_key, mac_key=self.mac_key,
        )
        result = self.codec.unpack(frame, self.enc_key, self.mac_key, self.guard)
        self.assertIsNotNone(result)
        self.assertEqual(result.payload, payload)

    def test_truncated_frame_rejected(self):
        """Усечённый кадр отклоняется."""
        payload = b"Test"
        frame = self.codec.pack(
            session_id=self.session_id, seq_num=1,
            plaintext=payload, enc_key=self.enc_key, mac_key=self.mac_key,
        )
        result = self.codec.unpack(frame[:10], self.enc_key, self.mac_key, self.guard)
        self.assertIsNone(result)


class TestAuthHelloProtocol(unittest.TestCase):
    """Тесты сообщений рукопожатия."""

    def test_build_parse_roundtrip(self):
        """Парсинг закодированного auth_hello возвращает исходные данные."""
        session_id = 0x12345678
        cert_der = os.urandom(256)
        eph_pub = os.urandom(64)
        ukm = os.urandom(8)

        hello = build_auth_hello(session_id, cert_der, eph_pub, ukm)
        parsed = parse_auth_hello(hello)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["session_id"], session_id)
        self.assertEqual(parsed["cert_der"], cert_der)
        self.assertEqual(parsed["ephemeral_pub"], eph_pub)
        self.assertEqual(parsed["ukm"], ukm)

    def test_truncated_hello_returns_none(self):
        """Усечённое сообщение возвращает None."""
        result = parse_auth_hello(b"\x01\x00\x00\x00\x01")
        self.assertIsNone(result)

    def test_wrong_version_returns_none(self):
        """Неизвестная версия протокола возвращает None."""
        result = parse_auth_hello(b"\xFF" + b"\x00" * 20)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
