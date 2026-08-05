"""Трекинг состояния сертификатов: локальные PEM + статус ZeroSSL.

Данные сохраняются в state.json и используются для еженедельного отчёта
и информационных писем (дата выпуска, срок действия, «до замены X дн.»).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from .certs import CertInfo, cert_paths, has_cert_files, load_certificate
from .state import State
from .zerossl import certificates_for_domains, expiry_for_domain, status_for_domain

logger = logging.getLogger(__name__)

STATUS_ISSUED = "issued"
STATUS_PENDING = "pending"
STATUS_EXPIRED = "expired"
STATUS_NO_CERT = "no-cert"
STATUS_ERROR = "error"


@dataclass
class CertStatus:
    domain: str
    issued_at: date | None = None
    not_after: date | None = None
    days_left: int | None = None
    status: str = STATUS_NO_CERT
    zero_ssl_status: str | None = None


def collect_cert_status(config, state: State, domains: list[str] | None = None) -> dict[str, CertStatus]:
    """Собирает состояние по всем (или заданным) доменам и сохраняет в state."""
    domains = domains or [d.name for d in config.domains]
    out: dict[str, CertStatus] = {}

    try:
        zs = certificates_for_domains(config.zerossl, domains)
    except Exception as exc:  # ZeroSSL не должен валить весь прогон
        logger.warning("не удалось получить статусы ZeroSSL: %s", exc)
        zs = {}

    for domain in domains:
        status = _build_for_domain(config, state, domain, zs.get(domain))
        state.set_cert_state(domain, {
            "issued_at": status.issued_at.isoformat() if status.issued_at else None,
            "not_after": status.not_after.isoformat() if status.not_after else None,
            "days_left": status.days_left,
            "status": status.status,
            "zero_ssl_status": status.zero_ssl_status,
        })
        out[domain] = status
    state.save()
    return out


def _build_for_domain(config, state: State, domain: str, zs: dict[str, Any] | None) -> CertStatus:
    st = CertStatus(domain=domain)
    if zs:
        st.zero_ssl_status = status_for_domain(zs)
        exp = expiry_for_domain(zs)
        if exp:
            st.not_after = exp.date()
            st.days_left = (exp.date() - date.today()).days

    if has_cert_files(config.paths.certs_dir, domain):
        try:
            fullchain, _ = cert_paths(config.paths.certs_dir, domain)
            info: CertInfo = load_certificate(fullchain)
        except Exception as exc:
            logger.warning("не удалось прочитать локальный сертификат %s: %s", domain, exc)
            st.status = STATUS_ERROR
            return st
        if info.not_before:
            st.issued_at = info.not_before.date()
        if info.not_after:
            st.not_after = info.not_after.date()
            st.days_left = info.days_left
        st.status = _local_status(info)
    else:
        st.status = STATUS_PENDING if st.zero_ssl_status else STATUS_NO_CERT
    return st


def _local_status(info: CertInfo) -> str:
    if info.expired:
        return STATUS_EXPIRED
    return STATUS_ISSUED


def certs_to_text(statuses: dict[str, CertStatus]) -> str:
    """Форматирует таблицу статусов сертификатов для письма."""
    if not statuses:
        return "Нет доменов в конфигурации."
    lines = ["Домен | Выпущен | Действует до | До замены | Статус"]
    lines.append("-" * len(lines[0]))
    status_ru = {
        STATUS_ISSUED: "выпущен",
        STATUS_PENDING: "ожидает выпуска",
        STATUS_EXPIRED: "истёк",
        STATUS_NO_CERT: "нет сертификата",
        STATUS_ERROR: "ошибка чтения",
    }
    for domain in sorted(statuses):
        st = statuses[domain]
        issued = st.issued_at.isoformat() if st.issued_at else "-"
        not_after = st.not_after.isoformat() if st.not_after else "-"
        days = f"{st.days_left} дн." if st.days_left is not None else "-"
        label = status_ru.get(st.status, st.status)
        extra = f" (ZeroSSL: {st.zero_ssl_status})" if st.zero_ssl_status and st.zero_ssl_status != "issued" else ""
        lines.append(f"{domain} | {issued} | {not_after} | {days} | {label}{extra}")
    return "\n".join(lines)


def days_to_text(days_left: int | None) -> str:
    if days_left is None:
        return "неизвестно"
    if days_left < 0:
        return "истёк"
    return f"{days_left} дн."


def last_renewal_hint(state: State, domain: str) -> str:
    """Подсказка о следующей дате замены из сохранённого состояния."""
    data = state.get_cert_state(domain)
    if not data or not data.get("not_after"):
        return "нет данных"
    try:
        not_after = datetime.fromisoformat(data["not_after"]).date()
    except (TypeError, ValueError):
        return "нет данных"
    days = (not_after - date.today()).days
    return days_to_text(days)
