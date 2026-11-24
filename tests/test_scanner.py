from __future__ import annotations

import pytest

from vetter.mcp_client import list_server_tools
from vetter.registry import SERVERS_BY_ID
from vetter.scanner import scan_server


@pytest.mark.asyncio
async def test_weather_ok_is_looks_ok():
    entry = SERVERS_BY_ID["weather_ok"]
    tools = await list_server_tools(entry.module)
    verdict, labels, report = scan_server(entry, tools)

    assert verdict == "looks_ok"
    assert labels == []
    assert report.static_findings == []
    assert report.claim_vs_behaviour.capability_match is True
    assert report.behaviour.extra_tools == []


@pytest.mark.asyncio
async def test_travel_overreach_is_high_risk():
    entry = SERVERS_BY_ID["travel_overreach"]
    tools = await list_server_tools(entry.module)
    verdict, labels, report = scan_server(entry, tools)

    assert verdict == "high_risk"
    categories = {f.category for f in report.static_findings}
    assert "hidden_instruction" in categories
    assert "invisible_unicode" in categories
    assert "sensitive_path" in categories
    assert "undeclared_capability" in categories
    assert "read_inbox" in report.behaviour.extra_tools
    assert report.claim_vs_behaviour.capability_match is False


@pytest.mark.asyncio
async def test_notes_rugpull_starts_looks_ok(rugpull_marker):
    turn_on, turn_off = rugpull_marker
    entry = SERVERS_BY_ID["notes_rugpull"]

    tools = await list_server_tools(entry.module)
    verdict, labels, report = scan_server(entry, tools)
    assert verdict == "looks_ok"
    assert report.static_findings == []


@pytest.mark.asyncio
async def test_notes_rugpull_flips_to_high_risk_when_marker_present(rugpull_marker):
    turn_on, turn_off = rugpull_marker
    entry = SERVERS_BY_ID["notes_rugpull"]

    turn_on()
    tools = await list_server_tools(entry.module)
    verdict, labels, report = scan_server(entry, tools)

    assert verdict == "high_risk"
    categories = {f.category for f in report.static_findings}
    assert "hidden_instruction" in categories or "external_url_in_description" in categories
