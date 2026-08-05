"""Отправка email-уведомлений через SMTP (российский сервис SMTP.BZ)."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable

from .config import SMTPConfig

logger = logging.getLogger(__name__)


class NotifyError(Exception):
    """Ошибка отправки email."""


class Notifier:
    def __init__(self, smtp: SMTPConfig | None) -> None:
        self.smtp = smtp

    @property
    def enabled(self) -> bool:
        return bool(self.smtp and self.smtp.host and self.smtp.from_addr and self.smtp.to)

    def send(self, subject: str, body: str) -> bool:
        """Отправляет письмо. True при успехе, False если уведомления отключены."""
        if not self.enabled:
            logger.info("SMTP не настроен, письмо пропущено: %s", subject)
            return False
        assert self.smtp is not None
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.smtp.from_addr
        msg["To"] = ", ".join(self.smtp.to)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        try:
            if self.smtp.use_ssl:
                server = smtplib.SMTP_SSL(
                    self.smtp.host, self.smtp.port, timeout=30
                )
            else:
                server = smtplib.SMTP(self.smtp.host, self.smtp.port, timeout=30)
                if self.smtp.use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
            with server:
                server.login(self.smtp.username, self.smtp.password)
                server.sendmail(self.smtp.from_addr, self.smtp.to, msg.as_string())
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("не удалось отправить email: %s", exc)
            return False
        logger.info("отправлено письмо: %s -> %s", subject, self.smtp.to)
        return True


def format_domains_line(domains: Iterable[str]) -> str:
    return ", ".join(sorted(domains))
