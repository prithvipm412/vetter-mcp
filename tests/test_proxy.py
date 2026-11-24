"""End-to-end tests for vetter.proxy, run as a real subprocess over stdio.

vetter.proxy isn't imported in-process - it's always launched as
`python -m vetter.proxy --server <id> -- <real command>`, exactly as it
would be by Claude Desktop after POST /protect. These tests drive it with
the official MCP client (the same approach scripts/fake_client.py uses),
pointing VETTER_DB_PATH/VETTER_LOCK_PATH env vars at a scratch directory so
nothing here touches the real vetter.db / vetter-lock.json.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vetter import db, fingerprint
from vetter.config import BASE_DIR
from vetter.mcp_client import list_server_tools
from vetter.registry import SERVERS_BY_ID


def _proxy_params(server_id: str, db_path: Path, lock_path: Path) -> StdioServerParameters:
    entry = SERVERS_BY_ID[server_id]
    env = {**os.environ, "VETTER_DB_PATH": str(db_path), "VETTER_LOCK_PATH": str(lock_path)}
    args = ["-m", "vetter.proxy", "--server", server_id, "--", *entry.command]
    return StdioServerParameters(command=sys.executable, args=args, env=env, cwd=str(BASE_DIR))


async def _call_through_proxy(server_id: str, db_path: Path, lock_path: Path, tool: str, arguments: dict):
    params = _proxy_params(server_id, db_path, lock_path)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        await session.list_tools()
        return await session.call_tool(tool, arguments)


@pytest.mark.asyncio
async def test_proxy_forwards_calls_for_an_approved_unchanged_server(isolated_paths):
    db.init_db(isolated_paths["db"])
    entry = SERVERS_BY_ID["weather_ok"]
    tools = await list_server_tools(entry.command)
    fingerprint.approve_server("weather_ok", tools, path=isolated_paths["lock"])
    db.set_status("weather_ok", "approved", db_path=isolated_paths["db"])

    result = await _call_through_proxy(
        "weather_ok", isolated_paths["db"], isolated_paths["lock"], "get_weather", {"city": "Paris"}
    )

    assert getattr(result, "isError", False) is False


@pytest.mark.asyncio
async def test_proxy_blocks_calls_for_a_never_approved_server(isolated_paths):
    db.init_db(isolated_paths["db"])

    result = await _call_through_proxy(
        "weather_ok", isolated_paths["db"], isolated_paths["lock"], "get_weather", {"city": "Paris"}
    )

    assert result.isError is True
    assert "paused" in result.content[0].text.lower()
    assert db.get_server("weather_ok", db_path=isolated_paths["db"])["status"] == "paused_changed"


@pytest.mark.asyncio
async def test_proxy_blocks_after_a_rug_pull(isolated_paths, rugpull_marker):
    turn_on, turn_off = rugpull_marker
    db.init_db(isolated_paths["db"])
    entry = SERVERS_BY_ID["notes_rugpull"]

    tools = await list_server_tools(entry.command)
    fingerprint.approve_server("notes_rugpull", tools, path=isolated_paths["lock"])
    db.set_status("notes_rugpull", "approved", db_path=isolated_paths["db"])

    first = await _call_through_proxy(
        "notes_rugpull", isolated_paths["db"], isolated_paths["lock"], "add_note", {"text": "hello"}
    )
    assert getattr(first, "isError", False) is False
    assert db.get_server("notes_rugpull", db_path=isolated_paths["db"])["status"] == "approved"

    turn_on()
    second = await _call_through_proxy(
        "notes_rugpull", isolated_paths["db"], isolated_paths["lock"], "add_note", {"text": "hello again"}
    )

    assert second.isError is True
    assert "changed since you approved it" in second.content[0].text
    assert db.get_server("notes_rugpull", db_path=isolated_paths["db"])["status"] == "paused_changed"

    incidents = db.list_incidents("notes_rugpull", db_path=isolated_paths["db"])
    assert any(i["type"] == "drift_detected" for i in incidents)
    assert any(i["type"] == "call_blocked" for i in incidents)
