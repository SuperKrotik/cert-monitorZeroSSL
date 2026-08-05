"""Работа с API Cloud.ru: IAM-токен, потребление (consumption), баланс.

Документация:
  - Аутентификация: POST https://iam.api.cloud.ru/api/v1/auth/token  {keyId, secret}
    -> {"access_token": "..."}  (TTL 1 час).
  - Потребление:  GET https://billing.api.cloud.ru/v1/consumption  (Authorization: Bearer)
    Доступны данные за последние 90 дней; параметр page_filter.limit <= 30000.

Баланс отдельного публичного эндпоинта не имеет, поэтому пробуем получить его
недокументированными способами; при неудаче — возвращаем ручное значение из конфига.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

import requests

from .config import CloudruConfig

logger = logging.getLogger(__name__)

IAM_TOKEN_URL = "https://iam.api.cloud.ru/api/v1/auth/token"
BILLING_BASE = "https://billing.api.cloud.ru"


class CloudruError(Exception):
    """Ошибка API Cloud.ru."""


@dataclass
class CloudruReport:
    """Итоговая сводка по Cloud.ru для еженедельного письма."""

    balance: float | None = None
    balance_source: str = "none"  # "api" | "manual" | "none"
    weekly_total: float | None = None
    currency: str = "RUB"
    days: int = 7
    error: str | None = None


class CloudruClient:
    def __init__(self, config: CloudruConfig, session: requests.Session | None = None) -> None:
        self.config = config
        self.session = session or requests.Session()
        self._token: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(
            self.config.enabled
            and self.config.key_id
            and self.config.secret
        )

    def get_token(self, timeout: int = 30) -> str:
        """Получает IAM access_token (кэшируется на время жизни процесса)."""
        if self._token:
            return self._token
        payload = {"keyId": self.config.key_id, "secret": self.config.secret}
        try:
            resp = self.session.post(IAM_TOKEN_URL, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise CloudruError(f"не удалось получить IAM-токен: {exc}") from exc
        token = data.get("access_token") or data.get("token") or data.get("accessToken")
        if not token:
            raise CloudruError(f"IAM не вернул access_token: {data}")
        self._token = str(token)
        logger.info("IAM-токен Cloud.ru получен")
        return self._token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}

    def get_consumption(
        self,
        start: date,
        end: date,
        timeout: int = 60,
    ) -> list[dict[str, Any]]:
        """Возвращает записи потребления за период [start; end]."""
        if not self.config.agreement_id:
            raise CloudruError("не задан agreement_id")
        params = {
            "agreement_id": self.config.agreement_id,
            "start_date": start.isoformat(),
            "end_date": end.isoformat(),
            "page_filter.limit": 30000,
        }
        url = f"{BILLING_BASE}/v1/consumption"
        try:
            resp = self.session.get(url, params=params, headers=self._headers(), timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise CloudruError(f"consumption запрос провалился: {exc}") from exc
        if isinstance(data, dict) and isinstance(data.get("records"), list):
            return data["records"]
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return data["data"]
        raise CloudruError(f"consumption: неожиданный формат ответа: {type(data)}")

    def get_weekly_consumption(
        self, days: int = 7, timeout: int = 60
    ) -> tuple[float | None, str, int]:
        """Суммарный расход за последние `days` дней.

        Возвращает (сумма, валюта, дней). При ошибке — (None, "RUB", days).
        """
        end = date.today()
        start = end - timedelta(days=days - 1)
        try:
            records = self.get_consumption(start, end, timeout=timeout)
        except CloudruError as exc:
            logger.error("не удалось получить потребление: %s", exc)
            return None, "RUB", days

        total = 0.0
        currency = "RUB"
        for rec in records:
            total += _extract_amount(rec)
            cur = _extract_currency(rec)
            if cur:
                currency = cur
        return total, currency, days

    def get_balance(self) -> tuple[float | None, str]:
        """Пытается получить баланс. Возвращает (значение, источник).

        Источник: "api" — получен через API, "manual" — ручное значение из конфига,
        "none" — баланс недоступен.
        """
        if not self.enabled:
            return None, "none"
        try:
            value = self._fetch_balance_api()
        except CloudruError as exc:
            logger.info("баланс через API недоступен (%s); используем ручное значение", exc)
            value = None
        if value is not None:
            return value, "api"
        if self.config.manual_balance is not None:
            return self.config.manual_balance, "manual"
        return None, "none"

    def _fetch_balance_api(self) -> float | None:
        """Недокументированный способ получить баланс по договору.

        Возвращает None, если баланс недоступен (не ошибка), иначе бросает CloudruError.
        """
        if not self.config.agreement_id:
            return None
        url = f"{BILLING_BASE}/v1/agreements/{self.config.agreement_id}"
        try:
            resp = self.session.get(url, headers=self._headers(), timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise CloudruError(f"запрос баланса провалился: {exc}") from exc
        for key in ("balance", "available_balance", "bonus_balance"):
            if key in data and data[key] is not None:
                try:
                    return float(data[key])
                except (TypeError, ValueError):
                    pass
        return None


def _extract_amount(record: dict[str, Any]) -> float:
    """Извлекает денежную сумму из одной записи потребления."""
    for key in ("amount", "cost", "price", "total", "sum", "charge"):
        if key in record and record[key] is not None:
            try:
                return float(record[key])
            except (TypeError, ValueError):
                pass
    # Возможная вложенная структура {"cost": {"value": "12.5", "currency": "RUB"}}.
    for key in ("cost", "amount", "total"):
        val = record.get(key)
        if isinstance(val, dict):
            for sub in ("value", "amount"):
                if sub in val and val[sub] is not None:
                    try:
                        return float(val[sub])
                    except (TypeError, ValueError):
                        pass
    return 0.0


def _extract_currency(record: dict[str, Any]) -> str | None:
    for key in ("currency", "currency_code"):
        if record.get(key):
            return str(record[key])
    for key in ("cost", "amount", "total"):
        val = record.get(key)
        if isinstance(val, dict) and val.get("currency"):
            return str(val["currency"])
    return None


def build_report(client: CloudruClient, days: int = 7) -> CloudruReport:
    """Собирает сводку: баланс + расход за неделю."""
    report = CloudruReport(days=days)
    if not client.enabled:
        report.error = "Cloud.ru отключён в конфиге"
        return report
    report.balance, report.balance_source = client.get_balance()
    report.weekly_total, report.currency, report.days = client.get_weekly_consumption(days=days)
    return report
