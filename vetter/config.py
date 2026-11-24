"""Shared paths and constants for the vetter backend.

DB_PATH/LOCK_FILE_PATH can be overridden with VETTER_DB_PATH/VETTER_LOCK_PATH
env vars. This matters because vetter.proxy runs as its own OS process (not
imported by the backend), so a test that wants it to see an isolated
database/lock file has no in-process object to monkeypatch - it has to pass
the override via the subprocess's environment instead.

A ``.env`` file at the repo root (see .env.example), if present, is loaded
before any env var below is read - real environment variables always win
over it, matching standard dotenv precedence.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(BASE_DIR / ".env")

DB_PATH = Path(os.environ["VETTER_DB_PATH"]) if "VETTER_DB_PATH" in os.environ else BASE_DIR / "vetter.db"
LOCK_FILE_PATH = (
    Path(os.environ["VETTER_LOCK_PATH"]) if "VETTER_LOCK_PATH" in os.environ else BASE_DIR / "vetter-lock.json"
)

_DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://localhost:5174"
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("VETTER_CORS_ORIGINS", _DEFAULT_CORS_ORIGINS).split(",")
    if origin.strip()
]

LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "vetter.log"

BACKEND_PORT = int(os.environ.get("VETTER_BACKEND_PORT", "8000"))
