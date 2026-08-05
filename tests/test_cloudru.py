"""Тесты модуля cloudru: IAM-токен, consumption, баланс (моки запросов)."""

from __future__ import annotations

import unittest
from datetime import date, timedelta
from unittest.mock import MagicMock, patch

from cert_monitor.cloudru import (
    CloudruClient,
    CloudruError,
    build_report,
    _extract_amount,
)
from cert_monitor.config import CloudruConfig


def make_cfg(enabled=True, agreement="agr-1", manual=100.0) -> CloudruConfig:
    return CloudruConfig(
        enabled=enabled,
        key_id="kid",
        secret="sk",
        agreement_id=agreement,
        manual_balance=manual,
    )


def mock_response(payload, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.json.return_value = payload
    return resp


class CloudruTests(unittest.TestCase):
    def test_disabled(self) -> None:
        client = CloudruClient(make_cfg(enabled=False))
        self.assertFalse(client.enabled)

    def test_get_token_caches(self) -> None:
        client = CloudruClient(make_cfg())
        with patch("cert_monitor.cloudru.requests.Session.post", return_value=mock_response({"access_token": "tok-1"})) as post:
            self.assertEqual(client.get_token(), "tok-1")
            self.assertEqual(client.get_token(), "tok-1")  # из кэша
        post.assert_called_once()

    def test_get_token_missing_field_raises(self) -> None:
        client = CloudruClient(make_cfg())
        with patch("cert_monitor.cloudru.requests.Session.post", return_value=mock_response({})):
            with self.assertRaises(CloudruError):
                client.get_token()

    def test_get_consumption_requires_agreement(self) -> None:
        client = CloudruClient(make_cfg(agreement=""))
        with self.assertRaises(CloudruError):
            client.get_consumption(date.today(), date.today())

    def test_get_consumption_records(self) -> None:
        client = CloudruClient(make_cfg())
        with patch("cert_monitor.cloudru.requests.Session.get", return_value=mock_response({"records": [{"amount": 10}]})) as get:
            with patch.object(client, "get_token", return_value="tok") as _:
                records = client.get_consumption(date(2026, 8, 1), date(2026, 8, 7))
        self.assertEqual(len(records), 1)
        _, kwargs = get.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(kwargs["params"]["agreement_id"], "agr-1")

    def test_get_consumption_bad_format(self) -> None:
        client = CloudruClient(make_cfg())
        with patch("cert_monitor.cloudru.requests.Session.get", return_value=mock_response({"foo": 1})):
            with patch.object(client, "get_token", return_value="tok"):
                with self.assertRaises(CloudruError):
                    client.get_consumption(date.today(), date.today())

    def test_weekly_consumption_error_returns_none(self) -> None:
        client = CloudruClient(make_cfg())
        with patch.object(client, "get_consumption", side_effect=CloudruError("boom")):
            total, cur, days = client.get_weekly_consumption()
        self.assertIsNone(total)

    def test_weekly_consumption_sum(self) -> None:
        client = CloudruClient(make_cfg())
        with patch.object(client, "get_consumption", return_value=[
            {"amount": 10, "currency": "RUB"},
            {"cost": {"value": "2.5", "currency": "RUB"}},
        ]):
            total, cur, days = client.get_weekly_consumption(days=7)
        self.assertAlmostEqual(total, 12.5)
        self.assertEqual(cur, "RUB")
        self.assertEqual(days, 7)

    def test_balance_api_found(self) -> None:
        client = CloudruClient(make_cfg())
        with patch("cert_monitor.cloudru.requests.Session.get", return_value=mock_response({"balance": 250.0})):
            with patch.object(client, "get_token", return_value="tok"):
                balance, source = client.get_balance()
        self.assertEqual(balance, 250.0)
        self.assertEqual(source, "api")

    def test_balance_api_unavailable_falls_back_manual(self) -> None:
        client = CloudruClient(make_cfg())
        with patch("cert_monitor.cloudru.requests.Session.get", side_effect=Exception("net")):
            balance, source = client.get_balance()
        self.assertEqual(balance, 100.0)
        self.assertEqual(source, "manual")

    def test_balance_none_when_no_manual(self) -> None:
        client = CloudruClient(make_cfg(manual=None))
        with patch.object(client, "_fetch_balance_api", return_value=None):
            balance, source = client.get_balance()
        self.assertIsNone(balance)
        self.assertEqual(source, "none")

    def test_build_report_disabled(self) -> None:
        client = CloudruClient(make_cfg(enabled=False))
        report = build_report(client)
        self.assertTrue(report.error)

    def test_extract_amount(self) -> None:
        self.assertEqual(_extract_amount({"amount": "5.0"}), 5.0)
        self.assertEqual(_extract_amount({"cost": {"value": "1.25"}}), 1.25)
        self.assertEqual(_extract_amount({"x": 1}), 0.0)


if __name__ == "__main__":
    unittest.main()