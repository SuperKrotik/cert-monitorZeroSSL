"""Настройка логирования."""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys

_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def setup_logging(log_file: str | None = None, level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)

    if not root.handlers:
        handler: logging.Handler
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
        else:
            handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_FORMAT))
        root.addHandler(handler)

    # Чтобы PyYAML/urllib не засоряли лог.
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
