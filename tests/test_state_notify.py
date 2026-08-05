"""Тесты State и Notifier."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cert_monitor.config import SMTPConfig
from cert_monitor.notify import Notifier
from cert_monitor.state import State


class StateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "state.json"

    def test_roundtrip(self) -> None:
        s = State(str(self.path))
        s.set_last_ip("8.8.8.8")
        s.mark_notified("home.duckdns.org", 7)
        s.save()

        s2 = State(str(self.path))
        self.assertEqual(s2.last_ip, "8.8.8.8")
        self.assertTrue(s2.was_notified("home.duckdns.org", 7))
        self.assertFalse(s2.was_notified("home.duckdns.org", 1))

        s2.mark_notified("home.duckdns.org", 1)
        s2.save()
        s3 = State(str(self.path))
        self.assertTrue(s3.was_notified("home.duckdns.org", 1))

    def test_reset_domain(self) -> None:
        s = State(str(self.path))
        s.mark_notified("home.duckdns.org", 7)
        s.mark_notified("home.duckdns.org", 1)
        s.reset_domain("home.duckdns.org")
        self.assertFalse(s.was_notified("home.duckdns.org", 7))
        self.assertFalse(s.was_notified("home.duckdns.org", 1))


class NotifierTests(unittest.TestCase):
    def test_disabled(self) -> None:
        n = Notifier(None)
        self.assertFalse(n.enabled)
        self.assertFalse(n.send("s", "b"))  # не падает без SMTP

    def test_enabled(self) -> None:
        cfg = SMTPConfig(
            host="smtp.gmail.com", port=587, username="u@gmail.com",
            password="p", from_addr="u@gmail.com", to=["t@gmail.com"],
        )
        n = Notifier(cfg)
        self.assertTrue(n.enabled)
        with patch("cert_monitor.notify.smtplib.SMTP") as SMTP:
            ok = n.send("test subject", "test body")
        self.assertTrue(ok)
        SMTP.assert_called_once()

    def test_send_failure_returns_false(self) -> None:
        cfg = SMTPConfig(
            host="smtp.gmail.com", port=587, username="u@gmail.com",
            password="p", from_addr="u@gmail.com", to=["t@gmail.com"],
        )
        n = Notifier(cfg)
        with patch("cert_monitor.notify.smtplib.SMTP", side_effect=OSError("conn")):
            self.assertFalse(n.send("s", "b"))


if __name__ == "__main__":
    unittest.main()