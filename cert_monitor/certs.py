"""Чтение информации о сертификатах из локальных PEM-файлов."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class CertReadError(Exception):
    """Ошибка чтения сертификата."""


@dataclass
class CertInfo:
    path: Path
    common_name: str | None
    not_before: datetime | None
    not_after: datetime | None
    sans: list[str]

    @property
    def days_left(self) -> int:
        """Целых дней до истечения (вверх: 29.5 -> 30; отрицательное = истёк)."""
        import math

        if self.not_after is None:
            return -1
        delta = self.not_after - datetime.now(self.not_after.tzinfo)
        days = delta.total_seconds() / 86400.0
        if days >= 0:
            return math.ceil(days)
        return math.floor(days)

    @property
    def expired(self) -> bool:
        return self.not_after is None or self.not_after <= datetime.now(
            self.not_after.tzinfo
        )


def load_certificate(path: str | Path) -> CertInfo:
    """Читает PEM-сертификат (первый сертификат из fullchain)."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise CertReadError(f"не удалось прочитать {p}: {exc}") from exc

    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise CertReadError(f"{p}: невалидный PEM: {exc}") from exc

    sans: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    return CertInfo(
        path=p,
        common_name=cert.subject.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=sans,
    )


def has_cert_files(certs_dir: str | Path, domain: str) -> bool:
    """Проверяет наличие локальных fullchain/privkey для домена."""
    base = Path(certs_dir) / domain
    return (base / "fullchain.pem").exists() and (base / "privkey.pem").exists()


def cert_paths(certs_dir: str | Path, domain: str) -> tuple[Path, Path]:
    """Возвращает (fullchain.pem, privkey.pem) для домена."""
    base = Path(certs_dir) / domain
    return base / "fullchain.pem", base / "privkey.pem"


def load_private_key(path: str | Path) -> bool:
    """Проверяет, что privkey читается как валидный приватный ключ."""
    try:
        data = Path(path).read_bytes()
        serialization.load_pem_private_key(data, password=None)
        return True
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("невалидный privkey %s: %s", path, exc)
        return False
