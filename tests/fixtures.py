"""Общие фикстуры для тестов."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_cert_pem(domain: str, days_valid: int, days_before: int = 1) -> tuple[bytes, bytes]:
    """Возвращает (сертификат PEM, ключ PEM).

    not_valid_before = now - days_before, not_valid_after = now + days_valid.
    Для истёкшего сертификата передайте days_valid < 0 (и при необходимости days_before).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days_before))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_cert_files(base: str, domain: str, days_valid: int, days_before: int = 1) -> tuple[str, str]:
    """Записывает fullchain.pem и privkey.pem для домена, возвращает пути."""
    import pathlib

    d = pathlib.Path(base) / domain
    d.mkdir(parents=True, exist_ok=True)
    cert_pem, key_pem = make_cert_pem(domain, days_valid, days_before)
    full = d / "fullchain.pem"
    key = d / "privkey.pem"
    full.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    return str(full), str(key)
