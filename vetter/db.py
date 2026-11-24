"""SQLite persistence for server scan state.

Deliberately plain ``sqlite3`` rather than an ORM: the schema is small and
this keeps the dependency list short.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC
from pathlib import Path
from typing import Any

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

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    time TEXT NOT NULL,
    type TEXT NOT NULL,
    tool TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS imported_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    command TEXT NOT NULL,
    env TEXT,
    source TEXT NOT NULL,
    language TEXT NOT NULL,
    stated_purpose TEXT NOT NULL,
    source_path TEXT,
    imported_at TEXT NOT NULL
);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
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
        conn.executescript(_SCHEMA)
        existing_ids = {row["id"] for row in conn.execute("SELECT id FROM servers")}
        for entry in SERVERS:
            if entry.id not in existing_ids:
                conn.execute(
                    "INSERT INTO servers (id, name, verdict, labels, status) VALUES (?, ?, NULL, '[]', 'new')",
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


def ensure_server_row(server_id: str, name: str, db_path: Path | None = None) -> None:
    """Make sure a `servers` tracking row exists (verdict/status/etc.), e.g.
    right after an import discovers a new server."""
    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO servers (id, name, verdict, labels, status) VALUES (?, ?, NULL, '[]', 'new')",
            (server_id, name),
        )


def upsert_imported_server(entry: dict[str, Any], db_path: Path | None = None) -> None:
    entry = {**entry, "source_path": entry.get("source_path")}
    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO imported_servers
                (id, name, command, env, source, language, stated_purpose, source_path, imported_at)
            VALUES
                (:id, :name, :command, :env, :source, :language, :stated_purpose, :source_path, :imported_at)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                command = excluded.command,
                env = excluded.env,
                source = excluded.source,
                language = excluded.language,
                stated_purpose = excluded.stated_purpose,
                source_path = excluded.source_path,
                imported_at = excluded.imported_at
            """,
            entry,
        )


def list_imported_servers(db_path: Path | None = None) -> list[dict[str, Any]]:
    with get_connection(db_path or config.DB_PATH) as conn:
        rows = conn.execute("SELECT * FROM imported_servers ORDER BY id").fetchall()
        return [dict(row) for row in rows]


def log_incident(
    server_id: str,
    type_: str,
    tool: str | None,
    detail: str,
    time: str | None = None,
    db_path: Path | None = None,
) -> None:
    from datetime import datetime

    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute(
            "INSERT INTO incidents (server_id, time, type, tool, detail) VALUES (?, ?, ?, ?, ?)",
            (server_id, time or datetime.now(UTC).isoformat(), type_, tool, detail),
        )


def list_incidents(server_id: str | None = None, db_path: Path | None = None) -> list[dict[str, Any]]:
    with get_connection(db_path or config.DB_PATH) as conn:
        if server_id is not None:
            rows = conn.execute(
                "SELECT time, type, tool, detail FROM incidents WHERE server_id = ? ORDER BY id",
                (server_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT time, type, tool, detail FROM incidents ORDER BY id").fetchall()
        return [dict(row) for row in rows]


def reset_demo_state(db_path: Path | None = None) -> None:
    """Reset the 3 built-in demo servers (and their incidents) to the seed
    state. Deliberately scoped to just the demo ids, not any real server a
    user has imported via POST /api/import.
    """
    demo_ids = [entry.id for entry in SERVERS]
    placeholders = ",".join("?" for _ in demo_ids)
    with get_connection(db_path or config.DB_PATH) as conn:
        conn.execute(f"DELETE FROM incidents WHERE server_id IN ({placeholders})", demo_ids)
        conn.execute(
            f"""
            UPDATE servers SET verdict = NULL, labels = '[]', status = 'new',
                static_findings = NULL, behaviour = NULL, claim_vs_behaviour = NULL, scanned_at = NULL
            WHERE id IN ({placeholders})
            """,
            demo_ids,
        )
