"""Merges the static demo registry with servers discovered by POST /api/import.

Lives separately from both ``registry`` and ``db`` to avoid a circular
import: ``db`` already imports ``registry`` (to seed the ``servers`` table),
so the merge has to happen one level up.
"""

from __future__ import annotations

import json
from pathlib import Path

from vetter import db
from vetter.registry import SERVERS_BY_ID, ServerEntry


def _imported_row_to_entry(row: dict) -> ServerEntry:
    return ServerEntry(
        id=row["id"],
        name=row["name"],
        kind="imported",
        command=json.loads(row["command"]),
        source_path=row.get("source_path"),
        stated_purpose=row["stated_purpose"],
        language=row["language"],
        env=json.loads(row["env"]) if row["env"] else None,
    )


def all_entries(db_path: Path | None = None) -> dict[str, ServerEntry]:
    entries = dict(SERVERS_BY_ID)
    for row in db.list_imported_servers(db_path):
        entry = _imported_row_to_entry(row)
        entries[entry.id] = entry
    return entries


def get_entry(server_id: str, db_path: Path | None = None) -> ServerEntry | None:
    if server_id in SERVERS_BY_ID:
        return SERVERS_BY_ID[server_id]
    for row in db.list_imported_servers(db_path):
        if row["id"] == server_id:
            return _imported_row_to_entry(row)
    return None
