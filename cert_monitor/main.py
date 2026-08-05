"""Оркестратор cert_monitor.

Режимы:
  - Ежедневный прогон (main / scheduler daily): трекинг IP, проверка сроков,
    двухступенчатые уведомления (7 и 1 день), продление, установка в nginx, сводка.
  - --weekly-report: еженедельное письмо со статусом сертификатов + cloud.ru.
  - --serve: постоянно работающий встроенный планировщик (Docker-режим).
  - --duckdns-only: обновить только IP DuckDNS и выйти.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from . import __version__
from .certbot import CertbotRunner, RenewResult
from .cloudru import CloudruClient, build_report, CloudruReport
from .config import Config, ConfigError
from .duckdns import (
    DuckDNSError,
    domain_ips_match,
    get_public_ip,
    update_duckdns,
)
from .install import InstallError, install
from .logging_util import setup_logging
from .notify import Notifier
from .state import State
from .tracker import (
    CertStatus,
    STATUS_EXPIRED,
    collect_cert_status,
    certs_to_text,
    days_to_text,
    last_renewal_hint,
)

logger = logging.getLogger("cert_monitor")


@dataclass
class DomainReport:
    domain: str
    days_left: int | None = None
    status: str = "unknown"
    renewed: bool = False
    error: str | None = None
    messages: list[str] = field(default_factory=list)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="cert_monitor", description=__doc__)
    parser.add_argument(
        "-c", "--config", default=None, help="путь к config.yaml (по умолчанию: ./config.yaml или /etc/cert-monitor/config.yaml)"
    )
    parser.add_argument(
        "--duckdns-only",
        action="store_true",
        help="только обновить IP DuckDNS (для cron) и выйти",
    )
    parser.add_argument(
        "--renew-dry-run",
        action="store_true",
        help="выполнить certbot renew --dry-run и выйти",
    )
    parser.add_argument(
        "--weekly-report",
        action="store_true",
        help="сформировать и отправить еженедельный отчёт, затем выйти",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="запустить встроенный планировщик (Docker-режим) и не выходить",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="DEBUG-логирование")
    return parser.parse_args(argv)


def track_duckdns(config: Config, state: State) -> str | None:
    """Обновляет IP DuckDNS, если он изменился. Возвращает новый IP или None."""
    if not config.duckdns.update_ip:
        logger.info("обновление DuckDNS IP отключено в конфиге")
        return state.last_ip

    try:
        ip = get_public_ip(config.duckdns.ip_api)
    except (DuckDNSError, Exception) as exc:
        logger.error("не удалось получить публичный IP: %s", exc)
        return state.last_ip

    if ip == state.last_ip:
        logger.info("IP не изменился: %s", ip)
        return ip

    subdomains = [d.duckdns_subdomain for d in config.domains if d.duckdns_subdomain]
    try:
        results = update_duckdns(config.duckdns, subdomains, ip)
    except DuckDNSError as exc:
        logger.error("не удалось обновить DuckDNS: %s", exc)
        return state.last_ip

    failed = [s for s, r in results.items() if r != "OK"]
    if failed:
        logger.error("DuckDNS не обновил поддомены: %s", failed)
    else:
        logger.info("DuckDNS обновлён: %s -> %s", subdomains, ip)
        state.set_last_ip(ip)
        state.save()
    return ip


def _check_domains_resolve(config: Config, ip: str | None) -> list[str]:
    """Проверяет, что домены резолвятся на текущий IP VM."""
    if not ip:
        return []
    bad: list[str] = []
    for d in config.domains:
        if not domain_ips_match(d.name, ip):
            bad.append(d.name)
    return bad


def _days_left_from_cert(config: Config, domain: str) -> int | None:
    from .certs import cert_paths, has_cert_files, load_certificate

    if not has_cert_files(config.paths.certs_dir, domain):
        return None
    fullchain, _ = cert_paths(config.paths.certs_dir, domain)
    try:
        info = load_certificate(fullchain)
        return info.days_left
    except Exception as exc:
        logger.warning("не удалось прочитать сертификат %s: %s", domain, exc)
        return None


def _publish_cert(config: Config, cb: CertbotRunner, domain: str, report: DomainReport) -> None:
    """Копирует выпущенный certbot сертификат в локальное хранилище и в nginx."""
    from .certs import cert_paths

    paths = cb.cert_paths(domain)
    if paths is None:
        report.messages.append("сертификат продлён, но пути certbot live не найдены")
        return
    fullchain, privkey = paths
    local_dir = Path(config.paths.certs_dir) / domain
    try:
        local_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fullchain, local_dir / "fullchain.pem")
        shutil.copy2(privkey, local_dir / "privkey.pem")
        report.messages.append("сертификат скопирован в локальное хранилище")
    except OSError as exc:
        report.messages.append(f"не удалось скопировать сертификат: {exc}")
        return

    if domain in config.nginx_sites:
        try:
            install(config, domain)
            report.messages.append("установлен в nginx")
        except InstallError as exc:
            report.messages.append(f"ошибка установки в nginx: {exc}")


def _attempt_renew(
    config: Config,
    cb: CertbotRunner,
    notifier: Notifier,
    domain: str,
    report: DomainReport,
    cert_state: CertStatus | None,
    state: State,
) -> None:
    """Пытается продлить сертификат и шлёт письмо-результат (или тревожное письмо)."""
    from .certbot import CertbotError

    threshold = config.certbot.renew_threshold_days
    try:
        result: tuple[RenewResult, ...] = cb.renew()
    except CertbotError as exc:
        report.status = "renew-failed"
        report.error = str(exc)
        report.messages.append("исключение при продлении")
        notifier.send(
            f"[cert-monitor] ⚠️ ОШИБКА продления: {domain}",
            f"Домен {domain}\nОшибка: {exc}\nПорог автопродления: {threshold} дн.",
        )
        return

    res = result[0] if result else None
    all_ok = bool(res and res.ok and res.changed)

    if all_ok:
        _publish_cert(config, cb, domain, report)
        report.renewed = True
        report.status = "renewed"
        report.messages.append("сертификат продлён (certbot renew)")
        state.reset_domain(domain)
        state.save()
        new_after = cert_state.not_after.isoformat() if cert_state and cert_state.not_after else "см. логи"
        notifier.send(
            f"[cert-monitor] Продлён: {domain}",
            f"Сертификат {domain} успешно продлён.\nНовый срок действия: до {new_after}.",
        )
        return

    if res is not None and res.ok and not res.changed:
        report.status = "ok"
        hint = last_renewal_hint(_state_for(config), domain)
        report.messages.append(f"продление не требуется (ещё не пора), следующая замена ~ {hint}")
        notifier.send(
            f"[cert-monitor] Продление не требуется: {domain}",
            f"Сертификат {domain} ещё не подлежит продлению.\nСледующая замена: ~ {hint}.\n"
            f"Порог автопродления: {threshold} дн.",
        )
        return

    stderr = (res.stderr if res else "") or "неизвестная ошибка"
    report.status = "renew-failed"
    report.error = stderr.strip()[:500]
    report.messages.append("сбой продления, детали в логе")
    notifier.send(
        f"[cert-monitor] ⚠️ ОШИБКА продления: {domain}",
        f"Домен {domain}\nОшибка:\n{stderr}\nПорог автопродления: {threshold} дн.",
    )


def _state_for(config: Config) -> State:
    return State(config.paths.state_file)


def run_monitor(
    config: Config,
    state: State,
    notifier: Notifier,
) -> list[DomainReport]:
    reports: list[DomainReport] = []
    cb = CertbotRunner(config.certbot, config.zerossl)
    threshold = config.certbot.renew_threshold_days
    trigger_days = max(config.notify.days or [0])

    for domain in config.domains:
        report = DomainReport(domain=domain.name)
        days = _days_left_from_cert(config, domain.name)
        report.days_left = days

        if days is None:
            report.status = "no-local-cert"
            reports.append(report)
            continue

        if days < 0:
            report.status = "expired"
            report.messages.append("сертификат истёк")

        # Двухступенчатые уведомления.
        for n in config.notify.days:
            if days <= n and not state.was_notified(domain.name, n):
                subject = f"[cert-monitor] Сертификат {domain.name} истекает через {n} дн."
                body = (
                    f"Сертификат для {domain.name} истекает через {n} дн. "
                    f"(осталось ~{days} дн., дата: см. детали).\n"
                    f"Порог автопродления: {threshold} дн.\n"
                    f"Следующая замена: ~ {days_to_text(days)}"
                )
                if notifier.send(subject, body):
                    state.mark_notified(domain.name, n)
                    report.messages.append(f"отправлено уведомление за {n} дн.")

        # Продление на пороге, а также при первом уведомительном событии (7 дн.)
        should_renew = days <= threshold or (trigger_days and days <= trigger_days)
        if should_renew:
            logger.info("продлеваю %s (осталось %s дн., порог %s)", domain.name, days, threshold)
            _attempt_renew(config, cb, notifier, domain.name, report, None, state)

        if report.status == "unknown":
            report.status = "ok"
        reports.append(report)
    return reports


def _compose_summary(reports: list[DomainReport]) -> tuple[str, str]:
    lines = ["Сводка cert_monitor:"]
    for r in reports:
        state_ru = {
            "ok": "ок",
            "renewed": "продлён",
            "renew-failed": "ОШИБКА продления",
            "expired": "истёк",
            "no-local-cert": "сертификат не выпущен",
            "unknown": "неизвестно",
        }.get(r.status, r.status)
        days = f" (осталось ~{r.days_left} дн.)" if r.days_left is not None else ""
        lines.append(f"- {r.domain}: {state_ru}{days}")
        for m in r.messages:
            lines.append(f"    * {m}")
        if r.error:
            lines.append(f"    ! {r.error}")
    body = "\n".join(lines)
    errors = [r for r in reports if r.status in ("renew-failed", "expired")]
    subject = "[cert-monitor] Есть проблемы" if errors else "[cert-monitor] Сводка"
    return subject, body


def compose_weekly_report(config: Config, state: State, cloudru: CloudruReport | None) -> str:
    """Собирает текст еженедельного отчёта."""
    statuses = collect_cert_status(config, state)
    lines = ["=== Еженедельный отчёт cert_monitor ===", ""]
    lines.append("=== Статус сертификатов ===")
    lines.append(certs_to_text(statuses))
    lines.append("")
    lines.append("=== Cloud.ru ===")
    if cloudru is None:
        lines.append("Cloud.ru отключён или не собрана сводка.")
    else:
        if cloudru.error:
            lines.append(f"Ошибка: {cloudru.error}")
        if cloudru.balance is not None:
            lines.append(f"Баланс: {cloudru.balance:,.2f} {cloudru.currency} (источник: {cloudru.balance_source})")
        else:
            lines.append("Баланс: недоступен")
        if cloudru.weekly_total is not None:
            lines.append(f"Расход за {cloudru.days} дн.: {cloudru.weekly_total:,.2f} {cloudru.currency}")
        else:
            lines.append("Расход: недоступен")
    return "\n".join(lines)


def run_weekly_report(config: Config, state: State, notifier: Notifier) -> int:
    """Еженедельный отчёт: статус сертификатов + баланс и расходы Cloud.ru."""
    today = date.today().isoformat()
    if state.get_weekly_report_sent() == today:
        logger.info("еженедельный отчёт уже отправлен сегодня, пропускаю")
        return 0

    cloudru: CloudruReport | None = None
    if config.cloudru.enabled:
        try:
            client = CloudruClient(config.cloudru)
            cloudru = build_report(client)
        except Exception as exc:
            logger.error("cloud.ru отчёт провалился: %s", exc)
            cloudru = CloudruReport(error=str(exc))

    body = compose_weekly_report(config, state, cloudru)
    subject = "[cert-monitor] Еженедельный отчёт"
    if notifier.send(subject, body):
        state.set_weekly_report_sent(today)
        state.save()
        logger.info("еженедельный отчёт отправлен")
        return 0
    logger.info("еженедельный отчёт не отправлен (SMTP выключен)")
    return 0


def serve(config: Config) -> int:
    """Запускает встроенный планировщик (Docker-режим). Блокирует поток."""
    from .scheduler import CertScheduler

    state = State(config.paths.state_file)
    notifier = Notifier(config.notify.smtp)

    def run_daily_cb() -> None:
        _run_daily(config, state, notifier)

    def run_weekly_cb() -> None:
        run_weekly_report(config, state, notifier)

    def run_duckdns_cb() -> None:
        track_duckdns(config, state)

    if not config.scheduler.enabled:
        logger.info("планировщик отключён в конфиге")
        return 0

    sched = CertScheduler(config.scheduler, run_daily_cb, run_weekly_cb, run_duckdns_cb).build()
    sched.run()
    return 0


def _run_daily(config: Config, state: State, notifier: Notifier) -> int:
    ip = track_duckdns(config, state)
    bad = _check_domains_resolve(config, ip)
    if bad:
        logger.warning("домены не резолвятся на VM IP %s: %s", ip, bad)

    reports = run_monitor(config, state, notifier)
    state.save()

    if config.notify.smtp and notifier.enabled:
        subject, body = _compose_summary(reports)
        notifier.send(subject, body)

    errors = [r for r in reports if r.status in ("renew-failed", "expired")]
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.INFO

    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
        logger.error("конфигурация не загружена: %s", exc)
        return 2

    setup_logging(config.paths.log_file, level)
    logger.info("cert_monitor %s запущен", __version__)
    logger.debug("конфиг: %s", config.redacted())

    state = State(config.paths.state_file)
    notifier = Notifier(config.notify.smtp)

    if args.serve:
        return serve(config)

    if args.duckdns_only:
        track_duckdns(config, state)
        state.save()
        logger.info("режим duckdns-only завершён")
        return 0

    if args.renew_dry_run:
        cb = CertbotRunner(config.certbot, config.zerossl)
        result = cb.renew_dry_run()
        logger.info("dry-run: rc=%s changed=%s", result.returncode, result.changed)
        if not result.ok:
            logger.error("dry-run stderr:\n%s", result.stderr)
            return 1
        return 0

    if args.weekly_report:
        return run_weekly_report(config, state, notifier)

    return _run_daily(config, state, notifier)


if __name__ == "__main__":
    sys.exit(main())