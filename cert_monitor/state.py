"""Хранение состояния: последний IP, отправленные уведомления по доменам."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class State:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = {
            "notified": {},
            "last_ip": None,
            "certs": {},
            "weekly": {"last_report": None},
        }
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._data = raw
                    self._data.setdefault("notified", {})
                    self._data.setdefault("last_ip", None)
                    self._data.setdefault("certs", {})
                    self._data.setdefault("weekly", {})
        except (OSError, ValueError) as exc:
            logger.warning("не удалось прочитать state %s: %s", self.path, exc)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(self._data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
        except OSError as exc:
            logger.error("не удалось сохранить state %s: %s", self.path, exc)

    @property
    def last_ip(self) -> str | None:
        return self._data.get("last_ip")

    def set_last_ip(self, ip: str) -> None:
        self._data["last_ip"] = ip

    def was_notified(self, domain: str, days: int) -> bool:
        return bool(self._data.get("notified", {}).get(domain, {}).get(str(days)))

    def mark_notified(self, domain: str, days: int) -> None:
        self._data.setdefault("notified", {}).setdefault(domain, {})[str(days)] = True

    def clear_notification(self, domain: str, days: int) -> None:
        self._data.setdefault("notified", {}).setdefault(domain, {}).pop(str(days), None)

    def reset_domain(self, domain: str) -> None:
        self._data.setdefault("notified", {}).pop(domain, None)

    # --- Состояние сертификатов (для еженедельного отчёта и писем) ---

    def set_cert_state(self, domain: str, info: dict[str, Any]) -> None:
        self._data.setdefault("certs", {})[domain] = info

    def get_cert_state(self, domain: str) -> dict[str, Any] | None:
        return self._data.get("certs", {}).get(domain)

    def get_all_certs(self) -> dict[str, Any]:
        return self._data.get("certs", {})

    # --- Еженедельный отчёт ---

    def set_weekly_report_sent(self, iso_date: str) -> None:
        self._data.setdefault("weekly", {})["last_report"] = iso_date

    def get_weekly_report_sent(self) -> str | None:
        return self._data.get("weekly", {}).get("last_report")
