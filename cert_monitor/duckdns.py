"""Работа с DuckDNS API: определение публичного IP, обновление записей, резолв."""

from __future__ import annotations

import logging
import socket
from typing import Iterable

import requests

from .config import Domain, DuckDNSConfig

logger = logging.getLogger(__name__)

DUCKDNS_UPDATE_URL = "https://www.duckdns.org/update"


class DuckDNSError(Exception):
    """Ошибка DuckDNS API."""


def get_public_ip(ip_api: str, timeout: int = 15) -> str:
    """Возвращает текущий публичный IPv4 (текстовый ответ API)."""
    resp = requests.get(ip_api, timeout=timeout)
    resp.raise_for_status()
    ip = resp.text.strip()
    if not ip:
        raise DuckDNSError(f"IP-сервис {ip_api} вернул пустой ответ")
    return ip


def resolve_domain(name: str, timeout: float = 10.0) -> list[str]:
    """Резолвит домен, возвращает список IP (A-записи)."""
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DuckDNSError(f"не удалось разрешить {name}: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def update_duckdns(
    config: DuckDNSConfig,
    subdomains: Iterable[str],
    ip: str,
    timeout: int = 20,
) -> dict[str, str]:
    """Обновляет IP для списка поддоменов DuckDNS.

    Возвращает словарь {поддомен: ответ_duckdns}. Ответ "OK" означает успех.
    """
    subdomains = [s for s in subdomains if s]
    if not subdomains:
        return {}
    params = {
        "domains": ",".join(subdomains),
        "token": config.token,
        "ip": ip,
        "verbose": "true",
    }
    try:
        resp = requests.get(DUCKDNS_UPDATE_URL, params=params, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise DuckDNSError(f"не удалось обновить DuckDNS: {exc}") from exc

    text = resp.text.strip()
    results: dict[str, str] = {}
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise DuckDNSError(f"DuckDNS вернул пустой ответ (HTTP {resp.status_code})")
    if len(lines) == 1 and lines[0] == "OK":
        for sub in subdomains:
            results[sub] = "OK"
        return results
    # verbose: первая строка — общий статус, далее "subdomain=OK"/"subdomain=KO"
    for sub in subdomains:
        results[sub] = "KO"
    for line in lines:
        if "=" in line:
            key, _, value = line.partition("=")
            if key in results:
                results[key] = value
    return results


def domain_ips_match(name: str, expected_ip: str) -> bool:
    """True, если домен резолвится на ожидаемый IP (полезно для HTTP-01)."""
    try:
        ips = resolve_domain(name)
    except DuckDNSError:
        return False
    return expected_ip in ips
