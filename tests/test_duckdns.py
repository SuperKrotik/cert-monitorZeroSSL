"""Тесты DuckDNS: определение IP, резолв, обновление записей (моки)."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from cert_monitor.config import DuckDNSConfig
from cert_monitor.duckdns import (
    DUCKDNS_UPDATE_URL,
    DuckDNSError,
    domain_ips_match,
    get_public_ip,
    update_duckdns,
)


def make_cfg(token: str = "tok") -> DuckDNSConfig:
    return DuckDNSConfig(token=token)


class DuckDNSTests(unittest.TestCase):
    def test_get_public_ip(self) -> None:
        mock = MagicMock()
        mock.text = " 8.8.8.8 \n"
        with patch("cert_monitor.duckdns.requests.get", return_value=mock) as get:
            ip = get_public_ip("https://api.ipify.org")
        self.assertEqual(ip, "8.8.8.8")
        get.assert_called_once()

    def test_get_public_ip_empty_raises(self) -> None:
        mock = MagicMock()
        mock.text = "   "
        with patch("cert_monitor.duckdns.requests.get", return_value=mock):
            with self.assertRaises(DuckDNSError):
                get_public_ip("https://api.ipify.org")

    def test_update_simple_ok(self) -> None:
        mock = MagicMock()
        mock.text = "OK"
        with patch("cert_monitor.duckdns.requests.get", return_value=mock) as get:
            results = update_duckdns(make_cfg(), ["home"], "1.2.3.4")
        self.assertEqual(results, {"home": "OK"})
        _, kwargs = get.call_args
        self.assertEqual(kwargs["params"]["domains"], "home")
        self.assertEqual(kwargs["params"]["ip"], "1.2.3.4")
        self.assertEqual(kwargs["params"]["token"], "tok")

    def test_update_verbose_ko(self) -> None:
        mock = MagicMock()
        mock.text = "KO\nhome=KO\n"
        with patch("cert_monitor.duckdns.requests.get", return_value=mock):
            results = update_duckdns(make_cfg(), ["home"], "1.2.3.4")
        self.assertEqual(results["home"], "KO")

    def test_update_verbose_mixed(self) -> None:
        mock = MagicMock()
        mock.text = "OK\nhome=OK\nother=KO\n"
        with patch("cert_monitor.duckdns.requests.get", return_value=mock):
            results = update_duckdns(make_cfg(), ["home", "other"], "1.2.3.4")
        self.assertEqual(results["home"], "OK")
        self.assertEqual(results["other"], "KO")

    def test_update_http_error_raises(self) -> None:
        from requests import HTTPError

        mock = MagicMock()
        mock.raise_for_status.side_effect = HTTPError("boom")
        with patch("cert_monitor.duckdns.requests.get", return_value=mock):
            with self.assertRaises(DuckDNSError):
                update_duckdns(make_cfg(), ["home"], "1.2.3.4")

    def test_domain_ips_match(self) -> None:
        with patch("cert_monitor.duckdns.resolve_domain", return_value=["1.2.3.4"]):
            self.assertTrue(domain_ips_match("home.duckdns.org", "1.2.3.4"))
            self.assertFalse(domain_ips_match("home.duckdns.org", "9.9.9.9"))


if __name__ == "__main__":
    unittest.main()
