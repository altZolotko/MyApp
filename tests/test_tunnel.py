"""
Тесты модулей управления сессией и конфигурацией.

Проверяет:
  - Конечный автомат состояний Session
  - Определение необходимости rekeying
  - Восстановление контекста после переподключения
  - Загрузку и валидацию конфигурации
  - Генерацию тестовых сертификатов
"""

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vpn_core.session import Session, SessionConfig, SessionState
from vpn_core.config_manager import (
    Config,
    ConfigError,
    load_bootstrap_config,
    validate_config,
)
from vpn_core.pygost_provider import PygostProvider
from utils.logger import setup_logger

setup_logger("WARNING")

# Минимальная тестовая конфигурация
_VALID_CONFIG = {
    "server_ip": "10.0.0.1",
    "server_port": 8443,
    "ca_cert_path": "certs/ca.der",
    "initial_cert_path": "certs/client.der",
    "initial_key_path": "certs/client_key.bin",
    "rekey_interval": 3600,
    "rekey_bytes": 104857600,
    "reconnect_timeout": 30,
    "max_reconnect_attempts": 5,
    "session_lifetime": 86400,
}


class TestSessionStateMachine(unittest.TestCase):
    """Тесты конечного автомата состояний сессии."""

    def _make_session(self, **kwargs) -> Session:
        crypto = PygostProvider()
        enc_key = os.urandom(32)
        mac_key = os.urandom(32)
        defaults = dict(
            session_lifetime=86400,
            rekey_interval=3600,
            rekey_bytes=104857600,
            max_reconnect_attempts=5,
            reconnect_timeout=30,
        )
        defaults.update(kwargs)
        cfg = SessionConfig(**defaults)
        return Session(
            session_id=0xDEADBEEF,
            enc_key=enc_key,
            mac_key=mac_key,
            config=cfg,
            crypto=crypto,
        )

    def test_initial_state_new(self):
        """Начальное состояние сессии — NEW."""
        sess = self._make_session()
        self.assertEqual(sess.state, SessionState.NEW)

    def test_activate_transitions_to_active(self):
        """activate() переводит в ACTIVE."""
        sess = self._make_session()
        sess.activate()
        self.assertEqual(sess.state, SessionState.ACTIVE)

    def test_mark_broken(self):
        """mark_broken() переводит в BROKEN."""
        sess = self._make_session()
        sess.activate()
        sess.mark_broken()
        self.assertEqual(sess.state, SessionState.BROKEN)

    def test_close(self):
        """close() переводит в CLOSED."""
        sess = self._make_session()
        sess.close()
        self.assertEqual(sess.state, SessionState.CLOSED)

    def test_next_seq_monotonic(self):
        """next_seq() возвращает монотонно возрастающие номера."""
        sess = self._make_session()
        seqs = [sess.next_seq() for _ in range(100)]
        for i in range(1, len(seqs)):
            self.assertGreater(seqs[i], seqs[i - 1])

    def test_rekey_needed_by_bytes(self):
        """needs_rekey() True после превышения rekey_bytes."""
        sess = self._make_session(rekey_bytes=1000, rekey_interval=99999)
        sess.activate()
        sess.account_bytes(500)
        self.assertFalse(sess.needs_rekey())
        sess.account_bytes(600)
        self.assertTrue(sess.needs_rekey())

    def test_rekey_not_needed_when_inactive(self):
        """needs_rekey() False когда сессия неактивна."""
        sess = self._make_session(rekey_bytes=10)
        sess.account_bytes(100)
        self.assertFalse(sess.needs_rekey())

    def test_can_reconnect_within_limits(self):
        """can_reconnect() True при наличии попыток."""
        sess = self._make_session(max_reconnect_attempts=3)
        self.assertTrue(sess.can_reconnect())

    def test_can_reconnect_exhausted(self):
        """can_reconnect() False после исчерпания попыток."""
        sess = self._make_session(max_reconnect_attempts=3)
        for _ in range(3):
            sess.increment_reconnect()
        self.assertFalse(sess.can_reconnect())

    def test_reconnect_delay_exponential(self):
        """Задержка переподключения растёт экспоненциально."""
        sess = self._make_session(reconnect_timeout=10)
        sess.increment_reconnect()
        delay1 = sess.reconnect_delay()
        sess.increment_reconnect()
        delay2 = sess.reconnect_delay()
        self.assertGreater(delay2, delay1)

    def test_reconnect_delay_capped(self):
        """Задержка переподключения ограничена 300 секундами."""
        sess = self._make_session(reconnect_timeout=10)
        for _ in range(20):
            sess.increment_reconnect()
        self.assertLessEqual(sess.reconnect_delay(), 300.0)

    def test_session_not_expired_initially(self):
        """Новая сессия не истекает сразу."""
        sess = self._make_session(session_lifetime=86400)
        self.assertFalse(sess.is_expired())

    def test_save_restore_context(self):
        """save_context() возвращает корректные данные."""
        sess = self._make_session()
        sess.next_seq()
        ctx = sess.save_context()
        self.assertEqual(ctx["session_id"], 0xDEADBEEF)
        self.assertIn("last_seq", ctx)
        self.assertIn("seq_counter", ctx)

    def test_keys_wiped_after_close(self):
        """После close() ключи затёрты и недоступны."""
        sess = self._make_session()
        sess.close()
        with self.assertRaises(RuntimeError):
            _ = sess.enc_key


class TestConfigValidation(unittest.TestCase):
    """Тесты валидации конфигурации."""

    def test_valid_config_passes(self):
        """Корректная конфигурация проходит валидацию."""
        validate_config(_VALID_CONFIG)

    def test_missing_required_field(self):
        """Отсутствие обязательного поля вызывает ConfigError."""
        bad = dict(_VALID_CONFIG)
        del bad["server_ip"]
        with self.assertRaises(ConfigError):
            validate_config(bad)

    def test_wrong_type_raises(self):
        """Неверный тип поля вызывает ConfigError."""
        bad = dict(_VALID_CONFIG)
        bad["server_port"] = "not_an_int"
        with self.assertRaises(ConfigError):
            validate_config(bad)

    def test_invalid_port(self):
        """Порт вне диапазона 1-65535 вызывает ConfigError."""
        bad = dict(_VALID_CONFIG)
        bad["server_port"] = 0
        with self.assertRaises(ConfigError):
            validate_config(bad)

    def test_rekey_interval_too_small(self):
        """Слишком маленький rekey_interval вызывает ConfigError."""
        bad = dict(_VALID_CONFIG)
        bad["rekey_interval"] = 10
        with self.assertRaises(ConfigError):
            validate_config(bad)

    def test_load_from_file(self):
        """Загрузка конфигурации из JSON-файла."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(_VALID_CONFIG, f)
            tmp_path = f.name

        try:
            cfg = load_bootstrap_config(tmp_path)
            self.assertEqual(cfg.server_ip, "10.0.0.1")
            self.assertEqual(cfg.server_port, 8443)
        finally:
            os.unlink(tmp_path)

    def test_config_attribute_access(self):
        """Config поддерживает доступ через атрибуты."""
        cfg = Config(_VALID_CONFIG)
        self.assertEqual(cfg.server_ip, "10.0.0.1")
        self.assertEqual(cfg.server_port, 8443)

    def test_config_optional_defaults(self):
        """Необязательные поля возвращают значения по умолчанию."""
        cfg = Config(_VALID_CONFIG)
        self.assertEqual(cfg.log_level, "INFO")
        self.assertEqual(cfg.tun_interface, "tun0")

    def test_config_missing_file(self):
        """Загрузка несуществующего файла вызывает ConfigError."""
        with self.assertRaises(ConfigError):
            load_bootstrap_config("/nonexistent/path/config.json")


class TestCertGeneration(unittest.TestCase):
    """Тесты генерации сертификатов."""

    def test_keypair_generation(self):
        """generate_gost_keypair() возвращает ключи правильного размера."""
        from utils.cert_gen import generate_gost_keypair
        prv, pub = generate_gost_keypair()
        self.assertEqual(len(prv), 32)
        self.assertEqual(len(pub), 64)

    def test_certificate_structure(self):
        """Сгенерированный сертификат — корректная DER-структура."""
        from utils.cert_gen import generate_gost_keypair, build_certificate
        import time as _time
        prv, pub = generate_gost_keypair()
        now = int(_time.time())
        cert = build_certificate(
            subject_cn="Test",
            subject_pub_key=pub,
            issuer_cn="Test CA",
            issuer_prv_key=prv,
            serial=1,
            not_before=now,
            not_after=now + 3600,
        )
        self.assertEqual(cert[0], 0x30)
        self.assertGreater(len(cert), 100)

    def test_full_infrastructure_generation(self):
        """Генерация полной PKI-инфраструктуры (CA + client + server)."""
        from utils.cert_gen import generate_test_infrastructure
        with tempfile.TemporaryDirectory() as tmp_dir:
            generate_test_infrastructure(tmp_dir)
            expected_files = [
                "ca.der", "ca_key.bin",
                "client.der", "client_key.bin",
                "server.der", "server_key.bin",
            ]
            for fname in expected_files:
                path = os.path.join(tmp_dir, fname)
                self.assertTrue(os.path.exists(path), f"Файл не создан: {fname}")
                self.assertGreater(os.path.getsize(path), 0, f"Файл пуст: {fname}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
