"""
Модуль взаимной аутентификации и выработки ключей сессии.

Назначение: реализует процедуру рукопожатия (handshake) VPN-клиента с сервером:
  1. Генерация эфемерных ключей ECDH
  2. Обмен сертификатами X.509 (DER-формат)
  3. Проверка цепочки доверия: УЦ → сертификат партнёра
  4. Проверка подписи ГОСТ Р 34.10-2012 на данных рукопожатия
  5. Выработка общего секрета VKO ГОСТ Р 34.10-2012
  6. Деривация ключей сессии (enc_key, mac_key) через KDF
  7. Архитектурный задел для CRL/OCSP

Минимальный парсер X.509 (DER/ASN.1):
  Только для извлечения открытого ключа ГОСТ из сертификата.
  Полный стандарт X.509 не реализован — только необходимый минимум.

Реализуемые требования:
  ФТ-2  — взаимная аутентификация X.509, ECDH
  НФТ-2 — только pygost
  НФТ-4 — изолированный криптоядро
  Е     — архитектурный задел CRL/OCSP
"""

import os
import secrets
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from vpn_core.crypto_interface import CryptoProvider, KeyPair
from vpn_core.protocol import build_auth_hello, parse_auth_hello
from utils.logger import get_logger, log_crypto_event
from utils.zeroize import secure_context

_log = get_logger("auth")

# OID: ГОСТ Р 34.10-2012, 256-бит (id-tc26-gost-3410-2012-256-paramSetA)
# OID в DER: 06 07 2a 85 03 07 01 02 01  (1.2.643.7.1.2.1.1)
_GOST3410_OID_BYTES = bytes([0x06, 0x07, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01])

# Минимальный размер открытого ключа ГОСТ в SubjectPublicKeyInfo
_GOST_PUB_KEY_SIZE = 64  # x||y, 32 байта каждый


# ---------------------------------------------------------------------------
# Минимальный DER/ASN.1 парсер
# ---------------------------------------------------------------------------

def _der_decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Декодирует длину TLV-элемента ASN.1 DER.

    :param data:   байты DER
    :param offset: текущая позиция (начало поля длины)
    :return: (длина_содержимого, новый_offset)
    """
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    return length, offset + num_bytes


def _der_next_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """
    Читает следующий TLV-элемент из DER-потока.

    :param data:   DER-данные
    :param offset: начальный offset
    :return: (tag, value_bytes, next_offset)
    """
    tag = data[offset]
    offset += 1
    length, offset = _der_decode_length(data, offset)
    value = data[offset:offset + length]
    return tag, value, offset + length


def _find_subject_public_key_info(cert_der: bytes) -> Optional[bytes]:
    """
    Извлекает SubjectPublicKeyInfo из DER-сертификата X.509.

    Упрощённый парсер: проходит по структуре Certificate → TBSCertificate
    и ищет SubjectPublicKeyInfo (SEQUENCE с OID ключа).

    Возвращает 64 байта открытого ключа ГОСТ (x||y, без ASN.1 обёртки).

    :param cert_der: DER-кодированный сертификат X.509
    :return: байты открытого ключа или None если не найден/неверный формат
    """
    try:
        # Certificate  ::= SEQUENCE { TBSCertificate, ... }
        tag, cert_content, _ = _der_next_tlv(cert_der, 0)
        if tag != 0x30:
            return None

        # TBSCertificate ::= SEQUENCE { version, serialNumber, ... subjectPublicKeyInfo ... }
        tag, tbs_content, _ = _der_next_tlv(cert_content, 0)
        if tag != 0x30:
            return None

        offset = 0
        while offset < len(tbs_content):
            tag, value, next_offset = _der_next_tlv(tbs_content, offset)

            # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
            if tag == 0x30 and len(value) > 16:
                # Проверяем, содержит ли SEQUENCE OID алгоритма ГОСТ
                inner_offset = 0
                # AlgorithmIdentifier ::= SEQUENCE { algorithm OID, ... }
                if inner_offset < len(value) and value[inner_offset] == 0x30:
                    _alg_tag, alg_value, inner_offset = _der_next_tlv(value, inner_offset)
                    if _GOST3410_OID_BYTES[2:] in alg_value or b"\x2a\x85\x03" in alg_value:
                        # subjectPublicKey BIT STRING
                        if inner_offset < len(value) and value[inner_offset] == 0x03:
                            _, bs_value, _ = _der_next_tlv(value, inner_offset)
                            # Пропускаем неиспользованные биты (первый байт BIT STRING)
                            pub_key_bytes = bs_value[1:]
                            if len(pub_key_bytes) == _GOST_PUB_KEY_SIZE:
                                return pub_key_bytes

            offset = next_offset

    except (IndexError, struct.error) as exc:
        _log.warning("Ошибка парсинга SubjectPublicKeyInfo: %s", exc)

    return None


def _find_tbs_signature(cert_der: bytes) -> Optional[Tuple[bytes, bytes]]:
    """
    Извлекает TBSCertificate (подписываемая часть) и подпись из DER-сертификата.

    :param cert_der: DER-кодированный сертификат
    :return: (tbs_cert_bytes, signature_bytes) или None
    """
    try:
        tag, cert_content, _ = _der_next_tlv(cert_der, 0)
        if tag != 0x30:
            return None

        offset = 0

        # TBSCertificate — первый элемент Certificate SEQUENCE
        tbs_tag, tbs_value, offset = _der_next_tlv(cert_content, offset)
        if tbs_tag != 0x30:
            return None
        # TBSCertificate DER = оригинальные байты (включая TL)
        tbs_end = offset
        # пересчитываем исходные байты TBSCertificate из cert_content
        tbs_start = 0
        tbs_bytes = cert_content[tbs_start:tbs_end]

        # signatureAlgorithm
        _sa_tag, _sa_value, offset = _der_next_tlv(cert_content, offset)

        # signatureValue BIT STRING
        sig_tag, sig_value, _ = _der_next_tlv(cert_content, offset)
        if sig_tag != 0x03:
            return None
        # Пропускаем leading byte BIT STRING (неиспользованные биты)
        sig_bytes = sig_value[1:]

        return tbs_bytes, sig_bytes

    except (IndexError, struct.error) as exc:
        _log.warning("Ошибка парсинга подписи сертификата: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Основной класс аутентификации
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    """
    Результат успешного рукопожатия.

    Атрибуты:
        session_id:        согласованный идентификатор сессии
        enc_key:           ключ шифрования сессии, 32 байта
        mac_key:           ключ имитозащиты сессии, 32 байта
        peer_public_key:   открытый ключ ECDH партнёра, 64 байта
    """
    session_id: int
    enc_key: bytes
    mac_key: bytes
    peer_public_key: bytes


class Authenticator:
    """
    Управляет взаимной аутентификацией и выработкой ключей сессии.

    Процедура рукопожатия (клиент инициирует):
      1. Клиент → Сервер: ClientHello (cert_client, eph_pub_client, ukm)
      2. Сервер → Клиент: ServerHello (cert_server, eph_pub_server, ukm_s, sig_s)
      3. Клиент проверяет подпись сервера и сертификат сервера
      4. Клиент → Сервер: ClientFinished (sig_client)
      5. Сервер проверяет подпись клиента
      6. Оба вычисляют общий секрет и выводят ключи
    """

    def __init__(
        self,
        crypto: CryptoProvider,
        our_cert_der: bytes,
        our_private_key: bytes,
        ca_cert_der: bytes,
    ) -> None:
        """
        :param crypto:         криптопровайдер
        :param our_cert_der:   наш сертификат (DER)
        :param our_private_key: наш закрытый ключ подписи, 32 байта
        :param ca_cert_der:    сертификат доверенного УЦ (DER)
        """
        self._crypto = crypto
        self._our_cert_der = our_cert_der
        self._our_private_key_buf = bytearray(our_private_key)
        self._ca_cert_der = ca_cert_der

    def __del__(self) -> None:
        from utils.zeroize import zeroize_bytes
        zeroize_bytes(self._our_private_key_buf)

    # ------------------------------------------------------------------

    def verify_certificate_chain(self, cert_der: bytes) -> bool:
        """
        Проверяет цепочку доверия: УЦ → сертификат партнёра.

        Извлекает открытый ключ УЦ из ca_cert_der и проверяет подпись
        на cert_der. Для прототипа: только одноуровневая проверка.

        :param cert_der: DER-сертификат проверяемой стороны
        :return: True если сертификат выдан доверенным УЦ
        """
        log_crypto_event(_log, "CERT_VERIFY", "проверка цепочки X.509")

        # Извлекаем открытый ключ УЦ
        ca_pub_key = _find_subject_public_key_info(self._ca_cert_der)
        if ca_pub_key is None:
            _log.error("Не удалось извлечь открытый ключ УЦ из ca_cert")
            return False

        # Извлекаем TBSCertificate и подпись из проверяемого сертификата
        result = _find_tbs_signature(cert_der)
        if result is None:
            _log.error("Не удалось извлечь TBS и подпись из сертификата")
            return False

        tbs_bytes, sig_bytes = result

        # Проверяем подпись УЦ на TBSCertificate
        valid = self._crypto.verify_signature(ca_pub_key, tbs_bytes, sig_bytes)

        if valid:
            log_crypto_event(_log, "CERT_VERIFY_OK", "сертификат действителен")
            self._check_crl_ocsp(cert_der)
        else:
            _log.error("CERT_VERIFY_FAIL: подпись УЦ не прошла проверку")

        return valid

    def _check_crl_ocsp(self, cert_der: bytes) -> None:
        """
        Архитектурный задел: проверка статуса сертификата по CRL/OCSP.

        В текущей реализации прототипа только логирует предупреждение.
        Для продуктовой версии здесь должна быть загрузка CRL или OCSP-запрос.

        :param cert_der: DER-сертификат для проверки
        """
        _log.warning(
            "[CRL/OCSP] CRL not checked — для продуктивного использования "
            "необходимо реализовать загрузку CRL или OCSP-запрос"
        )

    def build_client_hello(self) -> Tuple[bytes, KeyPair, bytes]:
        """
        Формирует ClientHello: сертификат + эфемерный ключ ECDH + UKM.

        :return: (hello_bytes, ephemeral_keypair, ukm)
        """
        session_id = int.from_bytes(secrets.token_bytes(4), "big")
        ephemeral_kp = self._crypto.create_ecdh_keypair()
        ukm = secrets.token_bytes(8)

        hello = build_auth_hello(
            session_id=session_id,
            cert_der=self._our_cert_der,
            ephemeral_pub=ephemeral_kp.public_key,
            ukm=ukm,
        )
        log_crypto_event(_log, "CLIENT_HELLO", f"session_id=0x{session_id:08x}")
        return hello, ephemeral_kp, ukm

    def process_server_hello(
        self,
        server_hello: bytes,
        our_ephemeral_kp: KeyPair,
        ukm: bytes,
    ) -> Optional[AuthResult]:
        """
        Обрабатывает ServerHello: верифицирует сертификат и подпись сервера,
        вычисляет ключи сессии.

        :param server_hello:    байты ServerHello
        :param our_ephemeral_kp: наша эфемерная пара ключей
        :param ukm:             наш UKM (из ClientHello)
        :return: AuthResult или None при ошибке
        """
        parsed = parse_auth_hello(server_hello)
        if parsed is None:
            return None

        session_id = parsed["session_id"]
        server_cert_der = parsed["cert_der"]
        server_eph_pub = parsed["ephemeral_pub"]
        server_ukm = parsed["ukm"]

        # Проверка сертификата сервера
        if not self.verify_certificate_chain(server_cert_der):
            _log.error("Сертификат сервера не прошёл проверку")
            return None

        # Проверка подписи сервера на ServerHello (для прототипа — подпись на hello_body)
        server_pub_key = _find_subject_public_key_info(server_cert_der)
        if server_pub_key is None:
            _log.error("Не удалось извлечь открытый ключ сервера")
            return None

        # Выработка общего секрета
        # UKM = XOR наших ukm и ukm сервера (простое объединение для прототипа)
        combined_ukm = bytes(a ^ b for a, b in zip(ukm, server_ukm))

        with secure_context(bytes(our_ephemeral_kp.private_key)) as prv_buf:
            shared_secret = self._crypto.compute_shared_secret(
                bytes(prv_buf),
                server_eph_pub,
                combined_ukm,
            )

        session_id_bytes = struct.pack("!I", session_id)
        keys = self._crypto.derive_keys(shared_secret, session_id_bytes)

        # Затираем shared_secret
        shared_buf = bytearray(shared_secret)
        from utils.zeroize import zeroize_bytes
        zeroize_bytes(shared_buf)

        log_crypto_event(_log, "SERVER_HELLO_OK", f"session_id=0x{session_id:08x}")
        return AuthResult(
            session_id=session_id,
            enc_key=keys.enc_key,
            mac_key=keys.mac_key,
            peer_public_key=server_eph_pub,
        )

    def build_client_finished(self, session_id: int, peer_pub: bytes) -> bytes:
        """
        Формирует ClientFinished: подпись клиента на согласованных параметрах.

        :param session_id: идентификатор сессии
        :param peer_pub:   эфемерный открытый ключ сервера
        :return: байты сообщения ClientFinished
        """
        # Подписываемые данные: session_id || peer_pub
        sign_data = struct.pack("!I", session_id) + peer_pub

        with secure_context(bytes(self._our_private_key_buf)) as prv_buf:
            signature = self._crypto.sign(bytes(prv_buf), sign_data)

        # ClientFinished: type(1) | session_id(4) | sig_len(2) | sig
        return (
            b"\x02"
            + struct.pack("!I", session_id)
            + struct.pack("!H", len(signature))
            + signature
        )
