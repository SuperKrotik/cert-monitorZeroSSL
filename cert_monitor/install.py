"""Установка выпущенных сертификатов в веб-сервер (nginx)."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from .config import Config, NginxSite

logger = logging.getLogger(__name__)


class InstallError(Exception):
    """Ошибка установки сертификата."""


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except OSError as exc:
        raise InstallError(f"не удалось выполнить {cmd[0]}: {exc}") from exc


def install_to_site(
    site: NginxSite, fullchain: Path, privkey: Path
) -> None:
    """Копирует fullchain/privkey в целевые пути nginx-локации."""
    for src, dst in ((fullchain, site.cert), (privkey, site.key)):
        dst_path = Path(dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst_path.with_suffix(dst_path.suffix + ".tmp")
        try:
            shutil.copy2(src, tmp)
            os.replace(tmp, dst_path)
        except OSError as exc:
            raise InstallError(f"не удалось скопировать {src} -> {dst}: {exc}") from exc
        logger.info("установлен сертификат: %s -> %s", src, dst)
        os.chmod(dst_path, 0o644)


def test_and_reload() -> None:
    """nginx -t и, при успехе, reload.

    В Docker (без systemd) перезагружаем через `nginx -s reload`.
    """
    test = _run(["nginx", "-t"])
    if test.returncode != 0:
        raise InstallError(f"nginx -t провалился:\n{test.stdout}\n{test.stderr}")

    reloaded = _try_reload_systemctl()
    if not reloaded:
        reloaded = _try_reload_nginx_s()
    if not reloaded:
        raise InstallError("не удалось перезагрузить nginx: ни systemctl, ни nginx -s")
    logger.info("nginx перезагружен")


def _try_reload_systemctl() -> bool:
    try:
        proc = _run(["systemctl", "reload", "nginx"])
    except InstallError:
        return False
    if proc.returncode == 0:
        return True
    logger.warning("systemctl reload nginx недоступен (%s), пробую nginx -s", proc.returncode)
    return False


def _try_reload_nginx_s() -> bool:
    try:
        proc = _run(["nginx", "-s", "reload"])
    except InstallError:
        return False
    return proc.returncode == 0


def install(config: Config, domain: str) -> None:
    """Устанавливает сертификаты домена в настроенные nginx-локации."""
    site = config.nginx_sites.get(domain)
    if site is None:
        return
    fullchain, privkey = _sources(config, domain)
    install_to_site(site, fullchain, privkey)
    if site.reload:
        test_and_reload()


def _sources(config: Config, domain: str) -> tuple[Path, Path]:
    """Ищет fullchain/privkey: сначала локальная копия, затем certbot live."""
    local = Path(config.paths.certs_dir) / domain
    local_full, local_key = local / "fullchain.pem", local / "privkey.pem"
    if local_full.exists() and local_key.exists():
        return local_full, local_key
    certbot = Path(config.certbot.config_dir) / "live" / domain
    cb_full, cb_key = certbot / "fullchain.pem", certbot / "privkey.pem"
    if cb_full.exists() and cb_key.exists():
        return cb_full, cb_key
    raise InstallError(f"не найдены сертификаты для домена {domain}")
