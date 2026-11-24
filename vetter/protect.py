"""Wrap every server in the Claude Desktop config behind the vetter proxy.

POST /api/protect backs up ``claude_desktop_config.json`` with a timestamp,
rewrites each ``mcpServers`` entry's command/args so it launches through
``python -m vetter.proxy --server <name> -- <original command>`` instead of
running directly, and returns exactly what changed. POST /api/protect/undo
restores the most recent backup. Neither call ever touches the real file
without a backup existing first, and a missing config file is reported back
as data, never a crash.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = (
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
)
BACKUP_DIR_NAME = ".vetter-protect-backups"
_WRAPPED_MARKER = "_vetter_wrapped"


def _backup_dir(config_path: Path) -> Path:
    return config_path.parent / BACKUP_DIR_NAME


def _state_file(config_path: Path) -> Path:
    return _backup_dir(config_path) / "state.json"


def _read_state(config_path: Path) -> dict[str, Any]:
    state_file = _state_file(config_path)
    if not state_file.exists():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_state(config_path: Path, state: dict[str, Any]) -> None:
    state_file = _state_file(config_path)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _wrap_entry(server_name: str, entry: dict[str, Any]) -> dict[str, Any]:
    original_command = entry.get("command")
    original_args = entry.get("args", [])
    wrapped = dict(entry)
    wrapped["command"] = sys.executable
    wrapped["args"] = [
        "-m",
        "vetter.proxy",
        "--server",
        server_name,
        "--",
        original_command,
        *original_args,
    ]
    wrapped[_WRAPPED_MARKER] = True
    return wrapped


def protect(config_path: Path | None = None) -> dict[str, Any]:
    """Back up and wrap every server in the Claude Desktop config."""
    config_path = config_path or DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return {
            "status": "no_config",
            "message": f"No Claude Desktop config found at {config_path}; nothing to protect.",
            "path": str(config_path),
            "changed": [],
        }

    original_text = config_path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(original_text)
    except json.JSONDecodeError as exc:
        return {
            "status": "invalid_config",
            "message": f"{config_path} is not valid JSON: {exc}",
            "path": str(config_path),
            "changed": [],
        }

    servers: dict[str, Any] = parsed.get("mcpServers", {})
    changed: list[dict[str, Any]] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict) or entry.get(_WRAPPED_MARKER):
            continue
        before = {"command": entry.get("command"), "args": entry.get("args", [])}
        servers[name] = _wrap_entry(name, entry)
        after = {"command": servers[name]["command"], "args": servers[name]["args"]}
        changed.append({"server": name, "before": before, "after": after})

    if not changed:
        return {
            "status": "already_protected",
            "message": "Every server in the config is already wrapped by the vetter proxy.",
            "path": str(config_path),
            "changed": [],
        }

    backup_dir = _backup_dir(config_path)
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = backup_dir / f"claude_desktop_config.{timestamp}.json"
    backup_path.write_text(original_text, encoding="utf-8")

    config_path.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
    _write_state(config_path, {"backup_path": str(backup_path)})

    return {
        "status": "protected",
        "path": str(config_path),
        "backup_path": str(backup_path),
        "changed": changed,
    }


def undo(config_path: Path | None = None) -> dict[str, Any]:
    """Restore the most recent backup made by :func:`protect`."""
    config_path = config_path or DEFAULT_CONFIG_PATH
    state = _read_state(config_path)
    backup_path_str = state.get("backup_path")

    if not backup_path_str:
        return {
            "status": "no_backup",
            "message": "No vetter protect backup is on record; nothing to restore.",
            "path": str(config_path),
        }

    backup_path = Path(backup_path_str)
    if not backup_path.exists():
        return {
            "status": "backup_missing",
            "message": f"Recorded backup {backup_path} no longer exists.",
            "path": str(config_path),
        }

    config_path.write_text(backup_path.read_text(encoding="utf-8"), encoding="utf-8")
    _write_state(config_path, {})
    return {"status": "restored", "path": str(config_path), "backup_path": str(backup_path)}
