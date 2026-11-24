"""Shared "scan a server and persist the result" logic.

Used by the API's POST /scan endpoint, the eager startup scan, POST
/api/import (scanning every newly-discovered real server), and the CLI's
``vetter scan`` command, so there is exactly one place that decides what a
scan means.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vetter import db, fingerprint
from vetter.mcp_client import list_server_tools
from vetter.registry import ServerEntry
from vetter.sandbox.runner import run_sandbox
from vetter.scanner import merge_sandbox_results, scan_server

SANDBOX_NOT_SUPPORTED_MESSAGE = "sandbox: not supported yet (static scan only)"


async def scan_and_store(
    entry: ServerEntry, with_sandbox: bool = True, db_path: Path | None = None
) -> dict[str, Any]:
    """Static-scan ``entry`` (and sandbox it, if requested and it's Python),
    persist the result, and return the refreshed server row.

    May raise :class:`vetter.mcp_client.MCPIntrospectionError` if the server
    can't even be started for introspection; callers decide how to surface
    that (an HTTP 502 for the API, a CLI error message, a per-server failure
    note for a bulk import).
    """
    db.ensure_server_row(entry.id, entry.name, db_path=db_path)
    tools = await list_server_tools(entry.command, env=entry.env)

    verdict, labels, report = scan_server(entry, tools)
    if with_sandbox:
        if entry.language == "python":
            sandbox_report = await run_sandbox(entry, tools)
            verdict, labels, report = merge_sandbox_results(verdict, labels, report, sandbox_report)
        else:
            report.behaviour.sandbox_error = SANDBOX_NOT_SUPPORTED_MESSAGE

    scanned_at = datetime.now(UTC).isoformat()
    report_dict = report.model_dump()

    db.save_scan_result(
        server_id=entry.id,
        verdict=verdict,
        labels=labels,
        static_findings=report_dict["static_findings"],
        behaviour=report_dict["behaviour"],
        claim_vs_behaviour=report_dict["claim_vs_behaviour"],
        scanned_at=scanned_at,
        db_path=db_path,
    )
    db.log_incident(entry.id, "scan_completed", None, f"verdict: {verdict}", db_path=db_path)

    canary_leak = report_dict["behaviour"].get("canary_leak")
    if canary_leak and canary_leak.get("leaked"):
        db.log_incident(
            entry.id,
            "canary_leak",
            None,
            f"a canary secret ({canary_leak.get('secret')}) was sent to {canary_leak.get('destination')}",
            db_path=db_path,
        )

    current = db.get_server(entry.id, db_path=db_path)
    if current and current["status"] == "approved":
        verify = fingerprint.verify_server(entry.id, tools)
        if verify["changed_tools"] or verify["missing_tools"] or verify["new_tools"]:
            db.set_status(entry.id, "paused_changed", db_path=db_path)
            db.log_incident(
                entry.id,
                "change_detected",
                None,
                (
                    f"tool definitions changed since approval - changed: {verify['changed_tools']}, "
                    f"new: {verify['new_tools']}, missing: {verify['missing_tools']}"
                ),
                db_path=db_path,
            )

    row = db.get_server(entry.id, db_path=db_path)
    assert row is not None
    return row
