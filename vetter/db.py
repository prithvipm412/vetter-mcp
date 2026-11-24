"""SQLite persistence for server scan state.

Deliberately plain ``sqlite3`` rather than an ORM: the schema is small and
this keeps the dependency list short.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from vetter import config
from vetter.registry import SERVERS

_SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    verdict TEXT,
    labels TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'new',
    static_findings TEXT,
    behaviour TEXT,
    claim_vs_behaviour TEXT,
    scanned_at TEXT
);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_connection(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    db_path = db_path or config.DB_PATH
    conn = _connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path | None = None) -> None:
    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute(_SCHEMA)
        existing_ids = {row["id"] for row in conn.execute("SELECT id FROM servers")}
        for entry in SERVERS:
            if entry.id not in existing_ids:
                conn.execute(
                    "INSERT INTO servers (id, name, verdict, labels, status) "
                    "VALUES (?, ?, NULL, '[]', 'new')",
                    (entry.id, entry.name),
                )


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "verdict": row["verdict"],
        "labels": json.loads(row["labels"]),
        "status": row["status"],
        "static_findings": json.loads(row["static_findings"]) if row["static_findings"] else [],
        "behaviour": json.loads(row["behaviour"]) if row["behaviour"] else None,
        "claim_vs_behaviour": json.loads(row["claim_vs_behaviour"]) if row["claim_vs_behaviour"] else None,
        "scanned_at": row["scanned_at"],
    }


def list_servers(db_path: Path | None = None) -> list[dict[str, Any]]:
    with get_connection(db_path or config.DB_PATH) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY id").fetchall()
        return [_row_to_dict(row) for row in rows]


def get_server(server_id: str, db_path: Path | None = None) -> dict[str, Any] | None:
    with get_connection(db_path or config.DB_PATH) as conn:
        row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        return _row_to_dict(row) if row else None


def save_scan_result(
    server_id: str,
    verdict: str,
    labels: list[str],
    static_findings: list[dict],
    behaviour: dict,
    claim_vs_behaviour: dict,
    scanned_at: str,
    db_path: Path | None = None,
) -> None:
    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute(
            """
            UPDATE servers
            SET verdict = ?, labels = ?, static_findings = ?, behaviour = ?,
                claim_vs_behaviour = ?, scanned_at = ?
            WHERE id = ?
            """,
            (
                verdict,
                json.dumps(labels),
                json.dumps(static_findings),
                json.dumps(behaviour),
                json.dumps(claim_vs_behaviour),
                scanned_at,
                server_id,
            ),
        )


def set_status(server_id: str, status: str, db_path: Path | None = None) -> None:
    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute("UPDATE servers SET status = ? WHERE id = ?", (status, server_id))
