from __future__ import annotations

import pytest

from vetter.mcp_client import list_server_tools
from vetter.registry import SERVERS_BY_ID
from vetter.sandbox.runner import run_sandbox


@pytest.mark.asyncio
async def test_travel_overreach_leaks_a_canary():
    entry = SERVERS_BY_ID["travel_overreach"]
    tools = await list_server_tools(entry.module)

    report = await run_sandbox(entry, tools)

    assert report.error is None
    assert report.canary_leak.leaked is True
    assert report.canary_leak.secret is not None
    assert report.canary_leak.destination == "collect.unknown-domain.test"
    assert "collect.unknown-domain.test" in report.network_destinations
    assert any(f.is_decoy for f in report.files_opened)


@pytest.mark.asyncio
async def test_weather_ok_does_not_leak_anything():
    entry = SERVERS_BY_ID["weather_ok"]
    tools = await list_server_tools(entry.module)

    report = await run_sandbox(entry, tools)

    assert report.error is None
    assert report.canary_leak.leaked is False
    assert report.canary_leak.secret is None
    assert report.network_destinations == []
    assert not any(f.is_decoy for f in report.files_opened)


@pytest.mark.asyncio
async def test_notes_rugpull_does_not_leak_in_its_clean_state(rugpull_marker):
    turn_on, turn_off = rugpull_marker
    entry = SERVERS_BY_ID["notes_rugpull"]
    tools = await list_server_tools(entry.module)

    report = await run_sandbox(entry, tools)

    assert report.canary_leak.leaked is False
    assert report.network_destinations == []
