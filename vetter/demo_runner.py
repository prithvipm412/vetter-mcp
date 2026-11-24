"""The `vetter demo` / demo.sh script: a fresh reset, then all 3 demo
scenarios run end to end against the real vetter.db / vetter-lock.json, so
what you see afterward in the dashboard matches exactly what this printed.
"""

from __future__ import annotations

from dataclasses import dataclass

from vetter import changes as changes_module
from vetter import db, fingerprint
from vetter.mcp_client import list_server_tools
from vetter.registry import SERVERS_BY_ID
from vetter.scan_service import scan_and_store


@dataclass
class DemoStep:
    scenario: str
    step: str
    expected: str
    verdict: str | None
    status: str | None
    passed: bool
    detail: str = ""


async def _approve(server_id: str) -> None:
    entry = SERVERS_BY_ID[server_id]
    tools = await list_server_tools(entry.command, env=entry.env)
    fingerprint.approve_server(server_id, tools)
    db.set_status(server_id, "approved")


async def run_demo() -> list[DemoStep]:
    from demo_servers.notes_rugpull import RUGPULL_MARKER

    steps: list[DemoStep] = []

    # Fresh reset.
    db.init_db()
    db.reset_demo_state()
    fingerprint.reset_lock_file()
    RUGPULL_MARKER.unlink(missing_ok=True)

    # Scenario A: weather_ok - the honest tool.
    row = await scan_and_store(SERVERS_BY_ID["weather_ok"])
    await _approve("weather_ok")
    verify = fingerprint.verify_server("weather_ok", await list_server_tools(SERVERS_BY_ID["weather_ok"].command))
    passed = row["verdict"] == "looks_ok" and verify["approved"] and not verify["changed_tools"]
    steps.append(
        DemoStep(
            scenario="weather_ok (honest tool)",
            step="scan + approve",
            expected="looks_ok, approved, no drift",
            verdict=row["verdict"],
            status="approved" if verify["approved"] else "new",
            passed=passed,
        )
    )

    # Scenario B: travel_overreach - the malicious tool.
    row = await scan_and_store(SERVERS_BY_ID["travel_overreach"])
    canary_leak = (row["behaviour"] or {}).get("canary_leak") or {}
    passed = row["verdict"] == "high_risk" and canary_leak.get("leaked") is True
    steps.append(
        DemoStep(
            scenario="travel_overreach (malicious tool)",
            step="scan (static + sandbox)",
            expected="high_risk, canary secret leaked",
            verdict=row["verdict"],
            status=row["status"],
            passed=passed,
            detail=f"leaked secret: {canary_leak.get('secret')} -> {canary_leak.get('destination')}",
        )
    )

    # Scenario C: notes_rugpull - approved, then changes after the fact.
    row = await scan_and_store(SERVERS_BY_ID["notes_rugpull"])
    await _approve("notes_rugpull")
    passed = row["verdict"] == "looks_ok"
    steps.append(
        DemoStep(
            scenario="notes_rugpull (rug pull)",
            step="scan + approve while clean",
            expected="looks_ok, approved",
            verdict=row["verdict"],
            status="approved",
            passed=passed,
        )
    )

    RUGPULL_MARKER.parent.mkdir(parents=True, exist_ok=True)
    RUGPULL_MARKER.touch()
    row = await scan_and_store(SERVERS_BY_ID["notes_rugpull"])
    passed = row["status"] == "paused_changed" and row["verdict"] == "high_risk"
    steps.append(
        DemoStep(
            scenario="notes_rugpull (rug pull)",
            step="description quietly changes; re-scan",
            expected="high_risk, paused_changed",
            verdict=row["verdict"],
            status=row["status"],
            passed=passed,
        )
    )

    tools = await list_server_tools(SERVERS_BY_ID["notes_rugpull"].command)
    diff = changes_module.compute_changes(SERVERS_BY_ID["notes_rugpull"], tools)
    passed = bool(diff["diff"]) and "sync.example.net" in (diff["new_description"] or "")
    steps.append(
        DemoStep(
            scenario="notes_rugpull (rug pull)",
            step="GET .../changes",
            expected="a non-empty diff naming the new exfil URL",
            verdict=None,
            status=None,
            passed=passed,
            detail=diff["diff"].splitlines()[-1] if diff["diff"] else "(no diff)",
        )
    )

    await _approve("notes_rugpull")  # POST .../changes/allow, in effect
    db.log_incident("notes_rugpull", "reapproved_after_change", None, "demo: baseline updated")
    current = db.get_server("notes_rugpull")
    assert current is not None
    passed = current["status"] == "approved"
    steps.append(
        DemoStep(
            scenario="notes_rugpull (rug pull)",
            step="changes/allow (re-approve)",
            expected="approved again at the new baseline",
            verdict=current["verdict"],
            status=current["status"],
            passed=passed,
        )
    )

    RUGPULL_MARKER.unlink(missing_ok=True)

    return steps
