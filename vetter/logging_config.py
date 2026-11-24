"""Shared logging setup: console + logs/vetter.log, used by the API, the
runtime proxy and the CLI so there is one place operators look for what
vetter has been doing.
"""

from __future__ import annotations

import logging

from vetter.config import LOG_DIR, LOG_FILE

_configured = False


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    global _configured
    logger = logging.getLogger("vetter")
    if _configured:
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.setLevel(level)
    logger.propagate = False
    _configured = True
    return logger
