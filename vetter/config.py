"""Shared paths and constants for the vetter backend.

DB_PATH/LOCK_FILE_PATH can be overridden with VETTER_DB_PATH/VETTER_LOCK_PATH
env vars. This matters because vetter.proxy runs as its own OS process (not
imported by the backend), so a test that wants it to see an isolated
database/lock file has no in-process object to monkeypatch - it has to pass
the override via the subprocess's environment instead.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DB_PATH = Path(os.environ["VETTER_DB_PATH"]) if "VETTER_DB_PATH" in os.environ else BASE_DIR / "vetter.db"
LOCK_FILE_PATH = (
    Path(os.environ["VETTER_LOCK_PATH"]) if "VETTER_LOCK_PATH" in os.environ else BASE_DIR / "vetter-lock.json"
)

ALLOWED_ORIGINS = ["http://localhost:5173"]
