"""Diff a server's live tool descriptions against its approved baseline."""

from __future__ import annotations

import difflib
from typing import Any

from vetter import fingerprint
from vetter.mcp_client import ToolInfo
from vetter.registry import ServerEntry

_NO_CHANGE = {"old_description": None, "new_description": None, "diff": ""}


def compute_changes(entry: ServerEntry, tools: list[ToolInfo]) -> dict[str, Any]:
    """Return {old_description, new_description, diff} covering every tool
    that drifted from its approved baseline (changed, newly added, or
    missing). With more than one drifted tool, each side is joined as
    multiple "tool_name: description" lines, in the same order, so the diff
    stays aligned line-for-line.

    All-None/empty if the server has never been approved, or nothing has
    changed since it was.
    """
    snapshot = fingerprint.get_approved_snapshot(entry.id)
    if snapshot is None:
        return dict(_NO_CHANGE)

    live_by_name = {tool.name: tool for tool in tools}
    drifted_names = [
        name
        for name in sorted(set(snapshot) | set(live_by_name))
        if name not in snapshot
        or name not in live_by_name
        or fingerprint.compute_tool_fingerprint(live_by_name[name]) != snapshot[name]["fingerprint"]
    ]
    if not drifted_names:
        return dict(_NO_CHANGE)

    def _old_line(name: str) -> str:
        baseline = snapshot.get(name)
        return f"{name}: {baseline['description']}" if baseline else f"{name}: (new tool, not previously approved)"

    def _new_line(name: str) -> str:
        tool = live_by_name.get(name)
        return f"{name}: {tool.description}" if tool else f"{name}: (tool removed)"

    old_description = "\n".join(_old_line(name) for name in drifted_names)
    new_description = "\n".join(_new_line(name) for name in drifted_names)
    diff = "\n".join(
        difflib.unified_diff(
            old_description.splitlines(),
            new_description.splitlines(),
            fromfile=f"{entry.id} (approved)",
            tofile=f"{entry.id} (current)",
            lineterm="",
        )
    )
    return {"old_description": old_description, "new_description": new_description, "diff": diff}
