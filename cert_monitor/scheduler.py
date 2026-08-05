"""Встроенный планировщик APScheduler для Docker-режима.

Задачи:
  - Ежедневно в daily_time (по умолчанию 03:15): полный прогон монитора.
  - Еженедельно в weekly_time (по умолчанию вс 09:00): еженедельный отчёт.
  - Каждые duckdns_interval_minutes (по умолчанию 5 мин): обновление IP DuckDNS.
"""

from __future__ import annotations

import logging
from typing import Callable

from .config import SchedulerConfig

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.blocking import BlockingScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
except ImportError:  # pragma: no cover
    BlockingScheduler = None
    CronTrigger = None
    IntervalTrigger = None


def _parse_time(value: str) -> tuple[int, int]:
    """Разбирает "HH:MM" -> (час, минута)."""
    hour, _, minute = value.partition(":")
    return int(hour or 0), int(minute or 0)


class CertScheduler:
    def __init__(
        self,
        config: SchedulerConfig,
        daily: Callable[[], None],
        weekly: Callable[[], None],
        duckdns: Callable[[], None],
    ) -> None:
        self.config = config
        self.daily = daily
        self.weekly = weekly
        self.duckdns = duckdns
        if BlockingScheduler is None:
            raise RuntimeError("APScheduler не установлен (requirements.txt)")
        self.scheduler = BlockingScheduler(timezone="UTC")

    def build(self) -> "CertScheduler":
        """Регистрирует все задачи согласно конфигу. Возвращает self."""
        sched_cfg = self.config
        daily_hour, daily_minute = _parse_time(sched_cfg.daily_time)
        weekly_hour, weekly_minute = _parse_time(sched_cfg.weekly_time)

        self.scheduler.add_job(
            self.daily,
            CronTrigger(hour=daily_hour, minute=daily_minute),
            id="daily",
            misfire_grace_time=3600,
            coalesce=True,
            max_instances=1,
        )
        self.scheduler.add_job(
            self.weekly,
            CronTrigger(
                hour=weekly_hour,
                minute=weekly_minute,
                day_of_week=sched_cfg.weekly_day,
            ),
            id="weekly",
            misfire_grace_time=3600,
            coalesce=True,
            max_instances=1,
        )
        self.scheduler.add_job(
            self.duckdns,
            IntervalTrigger(minutes=sched_cfg.duckdns_interval_minutes),
            id="duckdns",
            max_instances=1,
        )
        logger.info(
            "расписание: daily %s, weekly (%s %s), duckdns каждые %s мин",
            sched_cfg.daily_time,
            ["пн", "вт", "ср", "чт", "пт", "сб", "вс"][sched_cfg.weekly_day],
            sched_cfg.weekly_time,
            sched_cfg.duckdns_interval_minutes,
        )
        return self

    def run(self) -> None:
        self.scheduler.start()
