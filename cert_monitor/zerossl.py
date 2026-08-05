"""Работа с ZeroSSL REST API: статусы сертификатов, EAB-креды."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests

from .config import ZeroSSLConfig

logger = logging.getLogger(__name__)

BASE_URL = "https://api.zerossl.com"


class ZeroSSLError(Exception):
    """Ошибка ZeroSSL API."""


def _get(
    path: str,
    config: ZeroSSLConfig,
    params: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    url = f"{BASE_URL}{path}"
    p = dict(params or {})
    p["access_key"] = config.api_key
    try:
        resp = requests.get(url, params=p, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ZeroSSLError(f"ZeroSSL GET {path} провалился: {exc}") from exc
    data = resp.json()
    if isinstance(data, dict) and data.get("success") is False:
        err = data.get("error", {})
        raise ZeroSSLError(f"ZeroSSL вернул ошибку: {err}")
    return data


def list_certificates(config: ZeroSSLConfig) -> list[dict[str, Any]]:
    """Возвращает список сертификатов аккаунта (до 100)."""
    data = _get("/v1/certificates", config, {"limit": 100})
    return data.get("results", []) if isinstance(data, dict) else []


def certificates_for_domains(
    config: ZeroSSLConfig, domains: list[str]
) -> dict[str, dict[str, Any]]:
    """Сопоставляет домен -> последний известный сертификат (по полю common_name)."""
    out: dict[str, dict[str, Any]] = {}
    try:
        certs = list_certificates(config)
    except ZeroSSLError:
        logger.warning("не удалось получить список сертификатов ZeroSSL", exc_info=True)
        return out
    for cert in certs:
        common_name = cert.get("common_name") or ""
        if common_name in domains and common_name not in out:
            out[common_name] = cert
    return out


def status_for_domain(cert: dict[str, Any]) -> str:
    """Человеко-понятный статус сертификата ZeroSSL."""
    return str(cert.get("status") or "unknown")


def expiry_for_domain(cert: dict[str, Any]) -> datetime | None:
    """Дата истечения сертификата из данных ZeroSSL (ISO 8601)."""
    raw = cert.get("valid_to") or cert.get("expires_at")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        logger.warning("не удалось распарсить дату ZeroSSL: %r", raw)
        return None


def parse_status_ts(raw: str | None) -> datetime | None:
    """Парсит ISO-дату из API (UTC)."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
