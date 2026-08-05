"""Тесты оркестратора: run_monitor, уведомления за 7/1 дней, продление."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cert_monitor.certbot import RenewResult
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
from cert_monitor.main import _compose_summary, run_monitor
from cert_monitor.notify import Notifier
from cert_monitor.state import State

from fixtures import write_cert_files


def build_config(certs_dir: str, threshold: int = 1, days: list[int] | None = None) -> Config:
    return Config(
        domains=[],
        duckdns=DuckDNSConfig(token="t"),
        zerossl=ZeroSSLConfig(api_key="k", eab_kid="kid", eab_hmac_key="hmac"),
        certbot=CertbotConfig(email="e@example.com", renew_threshold_days=threshold),
        notify=NotifyConfig(days=days or [7, 1]),
        paths=PathsConfig(
            certs_dir=certs_dir,
            state_file=str(Path(certs_dir) / "state.json"),
            log_file="",
        ),
        nginx_sites={},
    )


def add_domain(cfg: Config, name: str) -> Config:
    cfg.domains.append(Domain(name=name, webroot="/var/www/certbot"))
    return cfg


class RunMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self.state = State(str(Path(self.dir) / "state.json"))

    def _notifier(self, ok: bool = True) -> Notifier:
        n = Notifier(
            SMTPConfig(
                host="smtp.smtp.bz", port=2525, username="u@duckdns.org",
                password="p", from_addr="u@service-account.example", to=["t@gmail.com"],
            )
        )
        n.send = MagicMock(return_value=ok)
        return n

    def test_cert_with_many_days_ok_no_renew(self) -> None:
        write_cert_files(self.dir, "home.duckdns.org", days_valid=50)
        cfg = build_config(self.dir, threshold=1)
        add_domain(cfg, "home.duckdns.org")
        reports = run_monitor(cfg, self.state, self._notifier())
        self.assertEqual(reports[0].status, "ok")
        self.assertFalse(reports[0].renewed)

    def test_no_notify_when_far_from_expiry(self) -> None:
        write_cert_files(self.dir, "home.duckdns.org", days_valid=20)
        cfg = build_config(self.dir, threshold=1, days=[7, 1])
        add_domain(cfg, "home.duckdns.org")
        notifier = self._notifier()
        run_monitor(cfg, self.state, notifier)
        self.assertFalse(self.state.was_notified("home.duckdns.org", 7))
        self.assertFalse(self.state.was_notified("home.duckdns.org", 1))
        notifier.send.assert_not_called()

    def test_renew_when_below_threshold_and_notify_1_day(self) -> None:
        write_cert_files(self.dir, "home.duckdns.org", days_valid=1)
        cfg = build_config(self.dir, threshold=1, days=[7, 1])
        add_domain(cfg, "home.duckdns.org")
        notifier = self._notifier()
        with patch(
            "cert_monitor.certbot.CertbotRunner.renew",
            return_value=(RenewResult(domain="<all>", changed=True, returncode=0),),
        ):
            reports = run_monitor(cfg, self.state, notifier)
        self.assertEqual(reports[0].status, "renewed")
        self.assertTrue(reports[0].renewed)
        # Уведомление за 1 день отправлено до продления; после успешного продления флаги сброшены.
        subjects = [c.args[0] for c in notifier.send.call_args_list]
        self.assertTrue(any("истекает через 1 дн." in s for s in subjects))
        self.assertFalse(self.state.was_notified("home.duckdns.org", 1))

    def test_renew_failure(self) -> None:
        write_cert_files(self.dir, "home.duckdns.org", days_valid=1)
        cfg = build_config(self.dir, threshold=1)
        add_domain(cfg, "home.duckdns.org")
        with patch(
            "cert_monitor.certbot.CertbotRunner.renew",
            return_value=(RenewResult(domain="<all>", changed=False, returncode=1, stderr="err"),),
        ):
            reports = run_monitor(cfg, self.state, self._notifier())
        self.assertEqual(reports[0].status, "renew-failed")
        self.assertIn("err", reports[0].error or "")

    def test_summary_subject_problems(self) -> None:
        from cert_monitor.main import DomainReport

        reports = [
            DomainReport(domain="a", status="ok", days_left=20),
            DomainReport(domain="b", status="renew-failed", days_left=1, error="boom"),
        ]
        subject, body = _compose_summary(reports)
        self.assertIn("проблем", subject.lower())
        self.assertIn("a", body)
        self.assertIn("b", body)


if __name__ == "__main__":
    unittest.main()