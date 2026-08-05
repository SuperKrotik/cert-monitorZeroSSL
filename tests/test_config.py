"""Тесты конфигурации: загрузка, подстановка {env:VAR}, валидация."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from cert_monitor.config import Config, ConfigError


def write_config(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_minimal_load(self) -> None:
        cfg_path = self.dir / "config.yaml"
        write_config(cfg_path, """
domains:
  - name: "home.duckdns.org"
    webroot: "/var/www/certbot"
duckdns:
  token: "tok"
zerossl:
  api_key: "k"
  eab_kid: "kid"
  eab_hmac_key: "hmac"
certbot:
  email: "me@example.com"
notify:
  days: [7, 1]
  smtp:
    host: "smtp.gmail.com"
    username: "u@gmail.com"
    password: "p"
""")
        cfg = Config.load(str(cfg_path))
        self.assertEqual(cfg.domains[0].name, "home.duckdns.org")
        self.assertEqual(cfg.domains[0].duckdns_subdomain, "home")
        self.assertEqual(cfg.notify.days, [7, 1])
        self.assertTrue(cfg.notify.smtp is not None)

    def test_env_substitution(self) -> None:
        cfg_path = self.dir / "config.yaml"
        write_config(cfg_path, """
domains: ["x.duckdns.org"]
duckdns:
  token: "{env:TEST_DUCK_TOKEN}"
zerossl:
  api_key: "{env:TEST_ZS_KEY}"
  eab_kid: "{env:TEST_ZS_KID}"
  eab_hmac_key: "{env:TEST_ZS_HMAC}"
certbot:
  email: "e@example.com"
""")
        os.environ["TEST_DUCK_TOKEN"] = "duck"
        os.environ["TEST_ZS_KEY"] = "key"
        os.environ["TEST_ZS_KID"] = "kid"
        os.environ["TEST_ZS_HMAC"] = "hmac"
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in (
            "TEST_DUCK_TOKEN", "TEST_ZS_KEY", "TEST_ZS_KID", "TEST_ZS_HMAC")])
        cfg = Config.load(str(cfg_path))
        self.assertEqual(cfg.duckdns.token, "duck")
        self.assertEqual(cfg.zerossl.api_key, "key")

    def test_missing_env_fails(self) -> None:
        cfg_path = self.dir / "config.yaml"
        write_config(cfg_path, """
domains: ["x.duckdns.org"]
duckdns:
  token: "{env:TEST_NEVER_SET_VAR}"
zerossl:
  api_key: "k"
  eab_kid: "kid"
  eab_hmac_key: "hmac"
certbot:
  email: "e@example.com"
""")
        with self.assertRaises(ConfigError):
            Config.load(str(cfg_path))

    def test_empty_domains_fails(self) -> None:
        cfg_path = self.dir / "config.yaml"
        write_config(cfg_path, "domains: []\n")
        with self.assertRaises(ConfigError):
            Config.load(str(cfg_path))

    def test_notify_days_sorted_unique(self) -> None:
        cfg_path = self.dir / "config.yaml"
        write_config(cfg_path, """
domains: ["x.duckdns.org"]
duckdns:
  token: "t"
zerossl:
  api_key: "k"
  eab_kid: "kid"
  eab_hmac_key: "hmac"
certbot:
  email: "e@example.com"
notify:
  days: [1, 7, 7, 3]
""")
        cfg = Config.load(str(cfg_path))
        self.assertEqual(cfg.notify.days, [7, 3, 1])


if __name__ == "__main__":
    unittest.main()
