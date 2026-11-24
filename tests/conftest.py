"""Shared pytest fixtures: isolate every test from the real home directory
and from any vetter.db / vetter-lock.json left over on disk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vetter.config as config


@pytest.fixture
def isolated_paths(tmp_path, monkeypatch) -> dict[str, Path]:
    db_path = tmp_path / "vetter.db"
    lock_path = tmp_path / "vetter-lock.json"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    monkeypatch.setattr(config, "LOCK_FILE_PATH", lock_path)
    return {"db": db_path, "lock": lock_path}


@pytest.fixture
def rugpull_marker():
    """Toggle the real ``~/.vetter-demo/rugpull`` marker file.

    notes_rugpull.py is always launched as a fresh subprocess (over stdio),
    so there is no in-process object to monkeypatch; the marker's path is
    part of the demo's documented contract. The fixture guarantees cleanup
    either way.
    """
    from demo_servers.notes_rugpull import RUGPULL_MARKER as marker

    def turn_on() -> None:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()

    def turn_off() -> None:
        marker.unlink(missing_ok=True)

    turn_off()
    yield turn_on, turn_off
    turn_off()
