"""Тесты tracker: сбор состояния сертификатов и форматирование отчёта."""

from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from cert_monitor.config import (
    CertbotConfig,
    Config,
    Domain,
    DuckDNSConfig,
    NotifyConfig,
    PathsConfig,
    SMTPConfig,
    ZeroSSLConfig,
)
from cert_monitor.state import State
from cert_monitor.tracker import (
    STATUS_ISSUED,
    STATUS_NO_CERT,
    STATUS_PENDING,
    collect_cert_status,
    days_to_text,
)

from fixtures import write_cert_files


def build_config(certs_dir: str) -> Config:
    return Config(
        domains=[Domain(name="home.duckdns.org", webroot="/var/www/certbot")],
        duckdns=DuckDNSConfig(token="t"),
        zerossl=ZeroSSLConfig(api_key="k", eab_kid="kid", eab_hmac_key="hmac"),
        certbot=CertbotConfig(email="e@example.com"),
        notify=NotifyConfig(days=[7, 1], smtp=SMTPConfig(host="h")),
        paths=PathsConfig(certs_dir=certs_dir, state_file=str(Path(certs_dir) / "state.json")),
        nginx_sites={},
    )


class TrackerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self.state = State(str(Path(self.dir) / "state.json"))

    def test_collect_issued_cert(self) -> None:
        write_cert_files(self.dir, "home.duckdns.org", days_valid=30)
        cfg = build_config(self.dir)
        with patch("cert_monitor.tracker.certificates_for_domains", return_value={}):
            statuses = collect_cert_status(cfg, self.state)
        st = statuses["home.duckdns.org"]
        self.assertEqual(st.status, STATUS_ISSUED)
        self.assertIsNotNone(st.not_after)
        self.assertEqual(st.days_left, 30)
        saved = self.state.get_cert_state("home.duckdns.org")
        self.assertEqual(saved["days_left"], 30)

    def test_collect_no_cert(self) -> None:
        cfg = build_config(self.dir)
        with patch("cert_monitor.tracker.certificates_for_domains", return_value={}):
            statuses = collect_cert_status(cfg, self.state)
        st = statuses["home.duckdns.org"]
        self.assertEqual(st.status, STATUS_NO_CERT)

    def test_collect_pending_via_zerossl(self) -> None:
        cfg = build_config(self.dir)
        zs = {"home.duckdns.org": {"status": "pending"}}
        with patch("cert_monitor.tracker.certificates_for_domains", return_value=zs):
            statuses = collect_cert_status(cfg, self.state)
        self.assertEqual(statuses["home.duckdns.org"].status, STATUS_PENDING)
        self.assertEqual(statuses["home.duckdns.org"].zero_ssl_status, "pending")

    def test_days_to_text(self) -> None:
        self.assertEqual(days_to_text(5), "5 дн.")
        self.assertEqual(days_to_text(-1), "истёк")
        self.assertEqual(days_to_text(None), "неизвестно")


if __name__ == "__main__":
    unittest.main()