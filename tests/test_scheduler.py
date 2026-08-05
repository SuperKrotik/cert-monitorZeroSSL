"""Тесты планировщика: разбор времени, регистрация задач APScheduler."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from cert_monitor.config import SchedulerConfig
from cert_monitor.scheduler import CertScheduler, _parse_time


class ParseTimeTests(unittest.TestCase):
    def test_parse_time(self) -> None:
        self.assertEqual(_parse_time("03:15"), (3, 15))
        self.assertEqual(_parse_time("09:00"), (9, 0))
        self.assertEqual(_parse_time(":30"), (0, 30))
        with self.assertRaises(ValueError):
            _parse_time("ab:cd")


class SchedulerTests(unittest.TestCase):
    def test_build_registers_jobs(self) -> None:
        cfg = SchedulerConfig(daily_time="03:15", weekly_time="09:00", weekly_day=6, duckdns_interval_minutes=5)
        sched = CertScheduler(cfg, daily=lambda: None, weekly=lambda: None, duckdns=lambda: None)
        with patch.object(sched.scheduler, "add_job") as add_job:
            sched.build()
        self.assertEqual(add_job.call_count, 3)

    def test_apscheduler_missing_raises(self) -> None:
        cfg = SchedulerConfig()
        with patch("cert_monitor.scheduler.BlockingScheduler", None):
            with self.assertRaises(RuntimeError):
                CertScheduler(cfg, daily=lambda: None, weekly=lambda: None, duckdns=lambda: None)


if __name__ == "__main__":
    unittest.main()