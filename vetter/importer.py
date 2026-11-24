"""Import real MCP servers from a Claude Desktop / Cursor style config.

Both assistants describe their servers the same way:
``{"mcpServers": {"<name>": {"command": "...", "args": [...], "env": {...}}}}``.
By default this reads the user's real Claude Desktop config (the same path
POST /api/protect backs up); any additional paths - e.g. a Cursor
``mcp.json`` - are read the same way. A missing file is reported back as
data, never a crash, since most machines won't have every assistant
installed.

Every server found is registered as an "imported" ServerEntry, alongside
the 3 demo servers, then static-scanned (and sandboxed too, if it looks
like a Python process) exactly like a demo server would be - this is what
proves vetter works on real tools, not just the fixtures it ships with.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vetter import db
from vetter.mcp_client import MCPIntrospectionError
from vetter import protect as protect_module
from vetter.registry import ServerEntry, guess_language
from vetter.scan_service import scan_and_store

NO_STATED_PURPOSE_NOTE = (
    "no stated purpose was provided by the import source, so claim-vs-"
    "behaviour comparisons here are weaker than for a server with a known purpose"
)


def _sanitize_id(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", name.strip()).strip("_").lower()
    return f"imported_{slug or 'server'}"


def _guess_source_path(command: list[str], language: str) -> str | None:
    """If this looks like `python /some/local/script.py`, point the static
    scanner's source-level checks at that file too - real-tool imports get
    the same depth of analysis as the demo servers when we can manage it.
    """
    if language != "python":
        return None
    for part in command:
        if part.endswith(".py"):
            candidate = Path(part)
            if candidate.is_file():
                return str(candidate.resolve())
    return None


def entry_from_config(name: str, raw: dict[str, Any], source: str) -> ServerEntry | None:
    command_str = raw.get("command")
    if not command_str or not isinstance(command_str, str):
        return None
    command = [command_str, *[str(a) for a in raw.get("args", []) or []]]
    language = guess_language(command)
    env = raw.get("env") if isinstance(raw.get("env"), dict) else None
    return ServerEntry(
        id=_sanitize_id(name),
        name=name,
        kind="imported",
        command=command,
        source_path=_guess_source_path(command, language),
        stated_purpose=f"Imported MCP server '{name}' from {source}; {NO_STATED_PURPOSE_NOTE}.",
        language=language,
        env=env,
    )


def _read_config(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _persist_entry(entry: ServerEntry, source: str, imported_at: str, db_path: Path | None = None) -> None:
    db.upsert_imported_server(
        {
            "id": entry.id,
            "name": entry.name,
            "command": json.dumps(entry.command),
            "env": json.dumps(entry.env) if entry.env else None,
            "source": source,
            "language": entry.language,
            "stated_purpose": entry.stated_purpose,
            "source_path": entry.source_path,
            "imported_at": imported_at,
        },
        db_path=db_path,
    )
    db.ensure_server_row(entry.id, entry.name, db_path=db_path)


async def import_from_configs(
    extra_config_paths: list[str] | None = None, db_path: Path | None = None
) -> dict[str, Any]:
    """Read the default Claude Desktop config plus any extra config paths,
    register every MCP server found, scan each one, and report what
    happened. Never raises for a missing/invalid config file or a server
    that fails to start - those are reported per-item instead.
    """
    from datetime import datetime, timezone

    imported_at = datetime.now(timezone.utc).isoformat()
    candidate_paths = [
        protect_module.DEFAULT_CONFIG_PATH,
        *[Path(p) for p in (extra_config_paths or [])],
    ]

    sources: list[dict[str, Any]] = []
    servers_report: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for path in candidate_paths:
        parsed = _read_config(path)
        if parsed is None:
            sources.append(
                {
                    "path": str(path),
                    "found": False,
                    "servers_imported": [],
                }
            )
            continue

        mcp_servers = parsed.get("mcpServers", {})
        imported_ids: list[str] = []
        for name, raw in mcp_servers.items():
            if not isinstance(raw, dict):
                continue
            entry = entry_from_config(name, raw, source=str(path))
            if entry is None:
                continue
            if entry.id in seen_ids:
                continue  # same server named the same way in two config files
            seen_ids.add(entry.id)
            imported_ids.append(entry.id)
            _persist_entry(entry, source=str(path), imported_at=imported_at, db_path=db_path)

            try:
                row = await scan_and_store(entry, with_sandbox=True, db_path=db_path)
                servers_report.append(
                    {
                        "id": entry.id,
                        "name": entry.name,
                        "language": entry.language,
                        "verdict": row["verdict"],
                        "status": row["status"],
                        "sandbox": "ran" if entry.language == "python" else "not supported yet (static scan only)",
                        "error": None,
                    }
                )
            except MCPIntrospectionError as exc:
                servers_report.append(
                    {
                        "id": entry.id,
                        "name": entry.name,
                        "language": entry.language,
                        "verdict": None,
                        "status": "new",
                        "sandbox": "not run (server failed to start)",
                        "error": str(exc),
                    }
                )

        sources.append({"path": str(path), "found": True, "servers_imported": imported_ids})

    return {
        "sources": sources,
        "servers": servers_report,
        "imported_count": len(servers_report),
    }
