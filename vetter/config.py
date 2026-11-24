"""Shared paths and constants for the vetter backend."""

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DB_PATH = BASE_DIR / "vetter.db"
LOCK_FILE_PATH = BASE_DIR / "vetter-lock.json"

ALLOWED_ORIGINS = ["http://localhost:5173"]
