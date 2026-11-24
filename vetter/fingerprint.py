"""SHA-256 tool fingerprinting and the on-disk approval lock file.

``vetter-lock.json`` records, per server, the fingerprint of each tool at
the moment it was approved. Fingerprinting the tool's name, description and
input schema together means any change to any of those - including a
"rug pull" that only edits the description - produces a different hash and
can be detected by :func:`verify_server`.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

from vetter import config
from vetter.mcp_client import ToolInfo

_lock = threading.Lock()


class VerifyResult(TypedDict):
    approved: bool
    changed_tools: list[str]
    new_tools: list[str]
    missing_tools: list[str]


def compute_tool_fingerprint(tool: ToolInfo) -> str:
    """Hash a tool's identity: its name, description and input schema."""
    canonical = json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_lock_file(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_lock_file(path: Path, data: dict) -> None:
    tmp_path = path.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    tmp_path.replace(path)


def approve_server(server_id: str, tools: list[ToolInfo], path: Path | None = None) -> dict[str, dict]:
    """Record the current fingerprint (and a description/schema snapshot) of
    every tool as the approved baseline. The snapshot - not just the hash -
    is kept so a later change can be diffed in plain text, not just flagged.
    """
    path = path or config.LOCK_FILE_PATH
    snapshot = {
        tool.name: {
            "fingerprint": compute_tool_fingerprint(tool),
            "description": tool.description,
            "input_schema": tool.input_schema,
        }
        for tool in tools
    }
    with _lock:
        data = _read_lock_file(path)
        data[server_id] = {
            "approved_at": datetime.now(UTC).isoformat(),
            "tools": snapshot,
        }
        _write_lock_file(path, data)
    return snapshot


def reset_lock_file(path: Path | None = None) -> None:
    """Wipe every approved baseline by deleting the lock file outright
    (``_read_lock_file`` already treats a missing file as empty). Used by
    POST /api/demo/reset.
    """
    path = path or config.LOCK_FILE_PATH
    with _lock:
        path.unlink(missing_ok=True)
        path.with_suffix(".tmp").unlink(missing_ok=True)


def get_approved_snapshot(server_id: str, path: Path | None = None) -> dict[str, dict] | None:
    """Return the approved {tool_name: {fingerprint, description, input_schema}}
    snapshot for a server, or None if it has never been approved.
    """
    path = path or config.LOCK_FILE_PATH
    with _lock:
        data = _read_lock_file(path)
    entry = data.get(server_id)
    return entry["tools"] if entry else None


def revoke_server(server_id: str, path: Path | None = None) -> bool:
    """Remove a server's approved baseline. Returns True if it existed."""
    path = path or config.LOCK_FILE_PATH
    with _lock:
        data = _read_lock_file(path)
        if server_id not in data:
            return False
        del data[server_id]
        _write_lock_file(path, data)
        return True


def verify_server(server_id: str, tools: list[ToolInfo], path: Path | None = None) -> VerifyResult:
    """Compare live tool fingerprints against the approved baseline, if any."""
    path = path or config.LOCK_FILE_PATH
    with _lock:
        data = _read_lock_file(path)

    entry = data.get(server_id)
    if entry is None:
        return VerifyResult(approved=False, changed_tools=[], new_tools=[], missing_tools=[])

    approved_snapshot: dict[str, dict] = entry.get("tools", {})
    live_fingerprints = {tool.name: compute_tool_fingerprint(tool) for tool in tools}

    changed_tools = [
        name
        for name, live_fp in live_fingerprints.items()
        if name in approved_snapshot and approved_snapshot[name]["fingerprint"] != live_fp
    ]
    new_tools = [name for name in live_fingerprints if name not in approved_snapshot]
    missing_tools = [name for name in approved_snapshot if name not in live_fingerprints]

    return VerifyResult(
        approved=True,
        changed_tools=changed_tools,
        new_tools=new_tools,
        missing_tools=missing_tools,
    )
