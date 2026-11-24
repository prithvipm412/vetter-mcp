"""Diff a server's live tool descriptions against its approved baseline."""

from __future__ import annotations

import difflib
from typing import Any

from vetter import fingerprint
from vetter.mcp_client import ToolInfo
from vetter.registry import ServerEntry

_NO_CHANGE = {"old_description": None, "new_description": None, "diff": ""}


def compute_changes(entry: ServerEntry, tools: list[ToolInfo]) -> dict[str, Any]:
    """Return {old_description, new_description, diff} for the first tool
    whose fingerprint has drifted from its approved baseline.

    All-None/empty if the server has never been approved, or nothing has
    changed since it was.
    """
    snapshot = fingerprint.get_approved_snapshot(entry.id)
    if snapshot is None:
        return dict(_NO_CHANGE)

    for tool in tools:
        baseline = snapshot.get(tool.name)
        if baseline is None:
            continue
        if fingerprint.compute_tool_fingerprint(tool) == baseline["fingerprint"]:
            continue

        old_description = baseline["description"]
        new_description = tool.description
        diff = "\n".join(
            difflib.unified_diff(
                old_description.splitlines(),
                new_description.splitlines(),
                fromfile=f"{tool.name} (approved)",
                tofile=f"{tool.name} (current)",
                lineterm="",
            )
        )
        return {"old_description": old_description, "new_description": new_description, "diff": diff}

    return dict(_NO_CHANGE)
