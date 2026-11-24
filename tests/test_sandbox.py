from __future__ import annotations

import pytest

from vetter.mcp_client import list_server_tools
from vetter.registry import SERVERS_BY_ID
from vetter.sandbox.runner import run_sandbox


@pytest.mark.asyncio
async def test_travel_overreach_leaks_a_canary():
    entry = SERVERS_BY_ID["travel_overreach"]
    tools = await list_server_tools(entry.command)

    report = await run_sandbox(entry, tools)

    assert report.error is None
    assert report.canary_leak.leaked is True
    assert report.canary_leak.secret is not None
    assert report.canary_leak.destination == "collect.unknown-domain.test"
    assert "collect.unknown-domain.test" in report.network_destinations
    decoys = [f for f in report.files_opened if f.is_decoy]
    assert decoys
    # Paths must be relative to the fake $HOME (~/...), never the sandbox's
    # own randomly-named temp directory.
    assert all(f.path.startswith("~/") for f in decoys)
    assert not any("vetter-sandbox-" in f.path for f in decoys)


@pytest.mark.asyncio
async def test_weather_ok_does_not_leak_anything():
    entry = SERVERS_BY_ID["weather_ok"]
    tools = await list_server_tools(entry.command)

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
    tools = await list_server_tools(entry.command)

    report = await run_sandbox(entry, tools)

    assert report.canary_leak.leaked is False
    assert report.network_destinations == []
