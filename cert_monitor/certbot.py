"""Обёртка над certbot для выпуска/продления через ZeroSSL ACME (EAB)."""

from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import CertbotConfig, Domain, ZeroSSLConfig

logger = logging.getLogger(__name__)


class CertbotError(Exception):
    """Ошибка certbot."""


@dataclass
class RenewResult:
    domain: str
    changed: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    logger.debug("выполняю: %s", " ".join(shlex.quote(c) for c in cmd))
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CertbotError(f"certbot превысил таймаут {timeout}s: {cmd}") from exc
    except OSError as exc:
        raise CertbotError(f"не удалось запустить certbot ({cmd[0]}): {exc}") from exc


class CertbotRunner:
    def __init__(self, cb: CertbotConfig, zs: ZeroSSLConfig) -> None:
        self.cb = cb
        self.zs = zs

    def _base(self) -> list[str]:
        return [
            self.cb.executable,
            "--non-interactive",
            "--agree-tos",
            "--email", self.cb.email,
            "--server", self.zs.acme_server,
            "--eab-kid", self.zs.eab_kid,
            "--eab-hmac-key", self.zs.eab_hmac_key,
            "--config-dir", self.cb.config_dir,
            "--logs-dir", f"{self.cb.config_dir}/logs",
            "--work-dir", f"{self.cb.config_dir}/work",
        ]

    def obtain(self, domain: Domain) -> RenewResult:
        """Первый выпуск сертификата для домена через webroot."""
        cmd = self._base() + [
            "certonly",
            "--webroot",
            "-w", domain.webroot,
            "-d", domain.name,
            "--cert-name", domain.name,
        ]
        if self.cb.post_hook:
            cmd += ["--deploy-hook", self.cb.post_hook]
        proc = _run(cmd)
        changed = proc.returncode == 0
        if not changed:
            logger.error(
                "certbot certonly для %s завершился с кодом %s\n%s",
                domain.name, proc.returncode, proc.stdout + proc.stderr,
            )
        return RenewResult(
            domain=domain.name,
            changed=changed,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def renew(self) -> tuple[RenewResult, ...]:
        """Продлевает все истекшие/подлежащие продлению сертификаты."""
        cmd = self._base() + ["renew", "--quiet"]
        if self.cb.post_hook:
            cmd += ["--deploy-hook", self.cb.post_hook]
        proc = _run(cmd)
        changed = "no renewals were attempted" not in proc.stdout
        return (
            RenewResult(
                domain="<all>",
                changed=changed,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            ),
        )

    def renew_dry_run(self) -> RenewResult:
        """Проверочный dry-run продления (не меняет сертификаты)."""
        cmd = self._base() + ["renew", "--dry-run"]
        proc = _run(cmd)
        return RenewResult(
            domain="<dry-run>",
            changed=False,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def cert_paths(self, domain: str) -> tuple[Path, Path] | None:
        base = Path(self.cb.config_dir) / "live" / domain
        fullchain = base / "fullchain.pem"
        privkey = base / "privkey.pem"
        if fullchain.exists() and privkey.exists():
            return fullchain, privkey
        return None
