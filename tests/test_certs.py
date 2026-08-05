"""Тесты модуля certs: чтение сроков, дни до истечения."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cert_monitor.certs import (
    CertReadError,
    cert_paths,
    has_cert_files,
    load_certificate,
)

from fixtures import write_cert_files


class CertsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_load_and_days_left(self) -> None:
        full, key = write_cert_files(str(self.dir), "home.duckdns.org", days_valid=30)
        info = load_certificate(full)
        self.assertEqual(info.days_left, 30)
        self.assertFalse(info.expired)
        self.assertIn("home.duckdns.org", info.sans)

    def test_expired(self) -> None:
        full, _ = write_cert_files(str(self.dir), "old.duckdns.org", days_valid=-5, days_before=30)
        info = load_certificate(full)
        self.assertTrue(info.expired)
        self.assertLess(info.days_left, 0)

    def test_has_cert_files_and_paths(self) -> None:
        write_cert_files(str(self.dir), "home.duckdns.org", days_valid=30)
        self.assertTrue(has_cert_files(self.dir, "home.duckdns.org"))
        self.assertFalse(has_cert_files(self.dir, "missing.duckdns.org"))
        full, key = cert_paths(self.dir, "home.duckdns.org")
        self.assertTrue(full.name == "fullchain.pem")
        self.assertTrue(key.name == "privkey.pem")

    def test_invalid_pem_raises(self) -> None:
        p = self.dir / "bad.pem"
        p.write_text("not a cert")
        with self.assertRaises(CertReadError):
            load_certificate(p)


if __name__ == "__main__":
    unittest.main()
