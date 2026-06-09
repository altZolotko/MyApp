"""
Генератор тестовых сертификатов X.509 с ключами ГОСТ Р 34.10-2012.

Назначение: создание тестового корневого УЦ и клиент/сервер сертификатов
для использования в среде разработки и тестирования. НЕ для продуктивного
использования.

Реализация: минимальная DER/ASN.1 кодировка, только необходимые поля X.509 v1.
Использует pygost для генерации ключей и подписи.

Реализуемые требования:
  ФТ-2  — X.509-сертификаты с ключами ГОСТ Р 34.10-2012 (тестовая инфраструктура)
  НФТ-2 — только pygost
"""

import os
import secrets
import struct
import time
from typing import Tuple

from pygost.gost3410 import (
    CURVES,
    public_key as gost3410_public_key,
    sign as gost3410_sign,
    prv_unmarshal,
    pub_marshal,
)
from pygost.gost34112012 import GOST34112012

from utils.logger import get_logger

_log = get_logger("cert_gen")

_CURVE_NAME = "id-tc26-gost-3410-2012-256-paramSetA"
_CURVE = CURVES[_CURVE_NAME]

# OID для ГОСТ Р 34.10-2012-256 (1.2.643.7.1.2.1.1)
_OID_GOST3410_2012_256 = bytes([0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01])
# OID для ГОСТ Р 34.11-2012-256 (1.2.643.7.1.1.2.2) — параметры алгоритма
_OID_GOST3411_2012_256 = bytes([0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02])
# OID для параметров кривой (1.2.643.7.1.2.1.1.1)
_OID_CURVE_PARAMS = bytes([0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01])


# ---------------------------------------------------------------------------
# DER-кодирование
# ---------------------------------------------------------------------------

def _encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_len(len(value)) + value


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _int_der(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _oid_der(oid_bytes: bytes) -> bytes:
    return _tlv(0x06, oid_bytes)


def _utf8str(s: str) -> bytes:
    return _tlv(0x0C, s.encode("utf-8"))


def _printstr(s: str) -> bytes:
    return _tlv(0x13, s.encode("ascii"))


def _bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return _tlv(0x03, bytes([unused_bits]) + data)


def _octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _utctime(ts: int) -> bytes:
    """Кодирует время в формате UTCTime: YYMMDDHHMMSSZ"""
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts)
    s = dt.strftime("%y%m%d%H%M%SZ")
    return _tlv(0x17, s.encode("ascii"))


def _context_tag(tag_num: int, value: bytes) -> bytes:
    return bytes([0xA0 + tag_num]) + _encode_len(len(value)) + value


def _stribog256(data: bytes) -> bytes:
    h = GOST34112012(digest_size=32)
    h.update(data)
    return h.digest()


# ---------------------------------------------------------------------------
# Генерация ключей ГОСТ
# ---------------------------------------------------------------------------

def generate_gost_keypair() -> Tuple[bytes, bytes]:
    """
    Генерирует пару ключей ГОСТ Р 34.10-2012-256.

    :return: (private_key_bytes_32, public_key_bytes_64)
    """
    while True:
        prv_bytes = secrets.token_bytes(32)
        prv_int = prv_unmarshal(prv_bytes)
        if 1 <= prv_int < _CURVE.q:
            break

    pub_point = gost3410_public_key(_CURVE, prv_int)
    pub_bytes = pub_marshal(pub_point)
    return prv_bytes, pub_bytes


# ---------------------------------------------------------------------------
# X.509 сертификат (минимальная структура)
# ---------------------------------------------------------------------------

def _build_algorithm_identifier() -> bytes:
    """AlgorithmIdentifier для ГОСТ Р 34.10-2012-256 с параметрами кривой."""
    alg_oid = _oid_der(_OID_GOST3410_2012_256)
    # Параметры: OID кривой + OID алгоритма хэширования
    params = _seq(
        _oid_der(_OID_CURVE_PARAMS),
        _oid_der(_OID_GOST3411_2012_256),
    )
    return _seq(alg_oid, params)


def _build_subject_public_key_info(pub_key: bytes) -> bytes:
    """SubjectPublicKeyInfo для открытого ключа ГОСТ."""
    alg_id = _build_algorithm_identifier()
    pub_bit_string = _bit_string(pub_key, 0)
    return _seq(alg_id, pub_bit_string)


def _build_rdn(attr_oid_bytes: bytes, value: str) -> bytes:
    """RelativeDistinguishedName с одним атрибутом."""
    return _set(_seq(_oid_der(attr_oid_bytes) + _printstr(value)))


# OID атрибутов X.509 Name
_OID_CN = bytes([0x55, 0x04, 0x03])          # commonName
_OID_O  = bytes([0x55, 0x04, 0x0A])          # organizationName
_OID_C  = bytes([0x55, 0x04, 0x06])          # countryName


def _build_name(cn: str, o: str = "RKN", c: str = "RU") -> bytes:
    """Кодирует структуру Name (Issuer/Subject)."""
    return _seq(
        _build_rdn(_OID_C, c),
        _build_rdn(_OID_O, o),
        _build_rdn(_OID_CN, cn),
    )


def build_certificate(
    subject_cn: str,
    subject_pub_key: bytes,
    issuer_cn: str,
    issuer_prv_key: bytes,
    serial: int,
    not_before: int,
    not_after: int,
    is_ca: bool = False,
) -> bytes:
    """
    Строит минимальный DER-сертификат X.509 v1.

    Структура:
      TBSCertificate {
        version         [0] EXPLICIT INTEGER v1
        serialNumber    INTEGER
        signature       AlgorithmIdentifier
        issuer          Name
        validity        Validity (UTCTime, UTCTime)
        subject         Name
        subjectPKInfo   SubjectPublicKeyInfo
      }
      signatureAlgorithm AlgorithmIdentifier
      signature          BIT STRING

    :param subject_cn:      Common Name субъекта
    :param subject_pub_key: открытый ключ субъекта (64 байта)
    :param issuer_cn:       Common Name издателя
    :param issuer_prv_key:  закрытый ключ издателя (32 байта)
    :param serial:          серийный номер сертификата
    :param not_before:      время начала действия (Unix timestamp)
    :param not_after:       время окончания действия (Unix timestamp)
    :param is_ca:           True для сертификата УЦ (self-signed)
    :return: DER-кодированный сертификат
    """
    alg_id = _build_algorithm_identifier()
    spki = _build_subject_public_key_info(subject_pub_key)
    issuer_name = _build_name(issuer_cn)
    subject_name = _build_name(subject_cn)

    validity = _seq(
        _utctime(not_before),
        _utctime(not_after),
    )

    tbs = _seq(
        _context_tag(0, _int_der(0)),    # version v1
        _int_der(serial),
        alg_id,
        issuer_name,
        validity,
        subject_name,
        spki,
    )

    # Подпись на TBSCertificate
    tbs_digest = _stribog256(tbs)
    issuer_prv_int = prv_unmarshal(issuer_prv_key)
    signature_bytes = gost3410_sign(_CURVE, issuer_prv_int, tbs_digest)

    cert = _seq(
        tbs,
        alg_id,
        _bit_string(signature_bytes, 0),
    )

    return cert


def generate_test_infrastructure(output_dir: str = "certs") -> None:
    """
    Генерирует тестовую PKI-инфраструктуру:
      - Корневой УЦ (ca.der, ca_key.bin)
      - Клиентский сертификат (client.der, client_key.bin)
      - Серверный сертификат (server.der, server_key.bin)

    :param output_dir: директория для сохранения файлов
    """
    os.makedirs(output_dir, mode=0o700, exist_ok=True)

    now = int(time.time())
    year = 365 * 24 * 3600

    # --- УЦ (самоподписанный) ---
    _log.info("Генерация ключей УЦ...")
    ca_prv, ca_pub = generate_gost_keypair()

    ca_cert = build_certificate(
        subject_cn="RKN Test CA",
        subject_pub_key=ca_pub,
        issuer_cn="RKN Test CA",
        issuer_prv_key=ca_prv,
        serial=1,
        not_before=now,
        not_after=now + 10 * year,
        is_ca=True,
    )

    _save(output_dir, "ca.der", ca_cert)
    _save(output_dir, "ca_key.bin", ca_prv)
    _log.info("УЦ: certs/ca.der")

    # --- Клиентский сертификат ---
    _log.info("Генерация ключей клиента...")
    client_prv, client_pub = generate_gost_keypair()
    client_cert = build_certificate(
        subject_cn="VPN Client",
        subject_pub_key=client_pub,
        issuer_cn="RKN Test CA",
        issuer_prv_key=ca_prv,
        serial=2,
        not_before=now,
        not_after=now + year,
    )
    _save(output_dir, "client.der", client_cert)
    _save(output_dir, "client_key.bin", client_prv)
    _log.info("Клиент: certs/client.der")

    # --- Серверный сертификат ---
    _log.info("Генерация ключей сервера...")
    server_prv, server_pub = generate_gost_keypair()
    server_cert = build_certificate(
        subject_cn="VPN Server",
        subject_pub_key=server_pub,
        issuer_cn="RKN Test CA",
        issuer_prv_key=ca_prv,
        serial=3,
        not_before=now,
        not_after=now + year,
    )
    _save(output_dir, "server.der", server_cert)
    _save(output_dir, "server_key.bin", server_prv)
    _log.info("Сервер: certs/server.der")

    # Затираем закрытый ключ УЦ из памяти
    ca_prv_buf = bytearray(ca_prv)
    from utils.zeroize import zeroize_bytes
    zeroize_bytes(ca_prv_buf)

    _log.info("PKI-инфраструктура сгенерирована в %s/", output_dir)


def _save(directory: str, filename: str, data: bytes) -> None:
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


if __name__ == "__main__":
    from utils.logger import setup_logger
    setup_logger("DEBUG")
    generate_test_infrastructure()
