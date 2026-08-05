"""Загрузка и валидация конфигурации."""

from __future__ import annotations

import copy
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

ENV_PATTERN = re.compile(r"\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """Ошибка конфигурации."""


def _substitute_env(value: Any) -> Any:
    """Рекурсивно заменяет {env:VAR} на значение переменной окружения."""
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            var = match.group(1)
            val = os.environ.get(var)
            if val is None:
                raise ConfigError(f"переменная окружения не задана: {var}")
            return val

        try:
            return ENV_PATTERN.sub(repl, value)
        except ConfigError:
            raise
    if isinstance(value, list):
        return [_substitute_env(item) for item in value]
    if isinstance(value, dict):
        return {k: _substitute_env(v) for k, v in value.items()}
    return value


@dataclass
class Domain:
    name: str
    webroot: str
    duckdns_subdomain: str | None = None

    def __post_init__(self) -> None:
        if self.duckdns_subdomain is None:
            if self.name.endswith(".duckdns.org"):
                self.duckdns_subdomain = self.name[: -len(".duckdns.org")]


@dataclass
class DuckDNSConfig:
    token: str
    update_ip: bool = True
    ip_api: str = "https://api.ipify.org"


@dataclass
class ZeroSSLConfig:
    api_key: str
    eab_kid: str
    eab_hmac_key: str
    acme_server: str = "https://acme.zerossl.com/v2/DV90"
    certificate_validity_days: int = 90


@dataclass
class CertbotConfig:
    email: str
    renew_threshold_days: int = 14
    executable: str = "certbot"
    config_dir: str = "/etc/letsencrypt"
    post_hook: str = ""


@dataclass
class SMTPConfig:
    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to: list[str] = field(default_factory=list)
    use_tls: bool = True
    use_ssl: bool = False


@dataclass
class NotifyConfig:
    days: list[int] = field(default_factory=lambda: [7, 1])
    smtp: SMTPConfig | None = None


@dataclass
class PathsConfig:
    certs_dir: str = "/etc/cert-monitor/certs"
    state_file: str = "/var/lib/cert-monitor/state.json"
    log_file: str = "/var/log/cert-monitor/cert-monitor.log"


@dataclass
class CloudruConfig:
    enabled: bool = False
    key_id: str = ""
    secret: str = ""
    agreement_id: str = ""
    manual_balance: float | None = None
    balance_start_date: str = ""


@dataclass
class SchedulerConfig:
    """Расписание встроенного APScheduler (Docker-режим)."""
    daily_time: str = "03:15"
    weekly_time: str = "09:00"
    weekly_day: int = 6  # 0=пн .. 6=вс
    duckdns_interval_minutes: int = 5
    enabled: bool = True


@dataclass
class NginxSite:
    cert: str = ""
    key: str = ""
    reload: bool = True


@dataclass
class Config:
    domains: list[Domain]
    duckdns: DuckDNSConfig
    zerossl: ZeroSSLConfig
    certbot: CertbotConfig
    notify: NotifyConfig
    paths: PathsConfig
    nginx_sites: dict[str, NginxSite]
    cloudru: CloudruConfig = field(default_factory=CloudruConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Config":
        if path is None:
            path = _default_path()
        logger.info("загрузка конфигурации: %s", path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        except OSError as exc:
            raise ConfigError(f"не удалось открыть конфиг: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"невалидный YAML: {exc}") from exc

        raw = _substitute_env(raw)
        return cls._build(raw)

    @classmethod
    def _build(cls, raw: dict[str, Any]) -> "Config":
        domains_raw = raw.get("domains", [])
        if not isinstance(domains_raw, list) or not domains_raw:
            raise ConfigError("список domains не должен быть пустым")
        domains: list[Domain] = []
        for item in domains_raw:
            if isinstance(item, str):
                domains.append(Domain(name=item, webroot="/var/www/certbot"))
            elif isinstance(item, dict):
                name = item.get("name")
                if not name:
                    raise ConfigError("каждый домен должен иметь поле name")
                webroot = item.get("webroot", "/var/www/certbot")
                domains.append(Domain(name=name, webroot=webroot, duckdns_subdomain=item.get("duckdns_subdomain")))
            else:
                raise ConfigError(f"некорректное описание домена: {item!r}")

        duck = raw.get("duckdns", {})
        duckdns = DuckDNSConfig(
            token=duck.get("token", "") or "",
            update_ip=bool(duck.get("update_ip", True)),
            ip_api=duck.get("ip_api", "https://api.ipify.org"),
        )

        zs = raw.get("zerossl", {})
        zerossl = ZeroSSLConfig(
            api_key=zs.get("api_key", "") or "",
            eab_kid=zs.get("eab_kid", "") or "",
            eab_hmac_key=zs.get("eab_hmac_key", "") or "",
            acme_server=zs.get("acme_server", "https://acme.zerossl.com/v2/DV90"),
            certificate_validity_days=int(zs.get("certificate_validity_days", 90)),
        )

        cb = raw.get("certbot", {})
        certbot = CertbotConfig(
            email=cb.get("email", "") or "",
            renew_threshold_days=int(cb.get("renew_threshold_days", 14)),
            executable=cb.get("executable", "certbot"),
            config_dir=cb.get("config_dir", "/etc/letsencrypt"),
            post_hook=cb.get("post_hook", "") or "",
        )

        ntf = raw.get("notify", {})
        smtp_raw = ntf.get("smtp", {})
        smtp = SMTPConfig(
            host=smtp_raw.get("host", ""),
            port=int(smtp_raw.get("port", 587)),
            username=smtp_raw.get("username", "") or "",
            password=smtp_raw.get("password", "") or "",
            from_addr=smtp_raw.get("from", smtp_raw.get("username", "") or ""),
            to=list(smtp_raw.get("to", [])),
            use_tls=bool(smtp_raw.get("use_tls", True)),
            use_ssl=bool(smtp_raw.get("use_ssl", False)),
        )
        notify = NotifyConfig(
            days=sorted({int(d) for d in ntf.get("days", [7, 1])}, reverse=True),
            smtp=smtp,
        )

        paths_raw = raw.get("paths", {})
        paths = PathsConfig(
            certs_dir=paths_raw.get("certs_dir", "/etc/cert-monitor/certs"),
            state_file=paths_raw.get("state_file", "/var/lib/cert-monitor/state.json"),
            log_file=paths_raw.get("log_file", "/var/log/cert-monitor/cert-monitor.log"),
        )

        nginx_sites: dict[str, NginxSite] = {}
        for name, site in (raw.get("nginx", {}).get("sites", {}) or {}).items():
            nginx_sites[name] = NginxSite(
                cert=site.get("cert", ""),
                key=site.get("key", ""),
                reload=bool(site.get("reload", True)),
            )

        cloudru = CloudruConfig(
            enabled=bool(raw.get("cloudru", {}).get("enabled", False)),
            key_id=raw.get("cloudru", {}).get("key_id", "") or "",
            secret=raw.get("cloudru", {}).get("secret", "") or "",
            agreement_id=raw.get("cloudru", {}).get("agreement_id", "") or "",
            manual_balance=_as_float(raw.get("cloudru", {}).get("manual_balance")),
            balance_start_date=raw.get("cloudru", {}).get("balance_start_date", "") or "",
        )

        sched = raw.get("scheduler", {})
        scheduler = SchedulerConfig(
            daily_time=sched.get("daily_time", "03:15") or "03:15",
            weekly_time=sched.get("weekly_time", "09:00") or "09:00",
            weekly_day=int(sched.get("weekly_day", 6)),
            duckdns_interval_minutes=int(sched.get("duckdns_interval_minutes", 5)),
            enabled=bool(sched.get("enabled", True)),
        )

        return cls(
            domains=domains,
            duckdns=duckdns,
            zerossl=zerossl,
            certbot=certbot,
            notify=notify,
            paths=paths,
            nginx_sites=nginx_sites,
            cloudru=cloudru,
            scheduler=scheduler,
        )

    def redacted(self) -> dict[str, Any]:
        """Копия конфига без секретов (для логов)."""
        out = copy.deepcopy(self.__dict__)
        out["zerossl"] = {
            "api_key": "***",
            "eab_kid": "***",
            "eab_hmac_key": "***",
            "acme_server": self.zerossl.acme_server,
        }
        out["duckdns"] = {"token": "***", "update_ip": self.duckdns.update_ip}
        out["notify"] = {"days": self.notify.days, "smtp": "***"}
        out["cloudru"] = {
            "enabled": self.cloudru.enabled,
            "key_id": "***",
            "secret": "***",
            "agreement_id": self.cloudru.agreement_id,
            "manual_balance": self.cloudru.manual_balance,
        }
        return out


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _default_path() -> str:
    local = "config.yaml"
    if os.path.exists(local):
        return local
    return "/etc/cert-monitor/config.yaml"
