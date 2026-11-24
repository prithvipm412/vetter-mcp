from __future__ import annotations

import json
import sys

import pytest
from fastapi.testclient import TestClient

import vetter.protect as protect_module
from vetter import db, importer
from vetter.main import app


@pytest.fixture(autouse=True)
def _no_real_claude_desktop_config(tmp_path, monkeypatch):
    """Every test in this file must never touch the developer's real Claude
    Desktop config - point the default at a scratch path that doesn't exist.
    """
    monkeypatch.setattr(protect_module, "DEFAULT_CONFIG_PATH", tmp_path / "claude_desktop_config.json")


def test_entry_from_config_sanitizes_id_and_guesses_language():
    entry = importer.entry_from_config(
        "My Cool Server!!", {"command": "node", "args": ["server.js"]}, source="cursor"
    )
    assert entry is not None
    assert entry.id == "imported_my_cool_server"
    assert entry.language == "node"
    assert entry.command == ["node", "server.js"]
    assert "cursor" in entry.stated_purpose


def test_entry_from_config_requires_a_command():
    assert importer.entry_from_config("nope", {}, source="x") is None
    assert importer.entry_from_config("nope", {"command": None}, source="x") is None


@pytest.mark.asyncio
async def test_import_reports_missing_config_without_crashing(isolated_paths):
    db.init_db(isolated_paths["db"])
    result = await importer.import_from_configs([], db_path=isolated_paths["db"])
    assert result["sources"] == [
        {"path": str(protect_module.DEFAULT_CONFIG_PATH), "found": False, "servers_imported": []}
    ]
    assert result["servers"] == []


@pytest.mark.asyncio
async def test_import_scans_a_real_python_server_end_to_end(tmp_path, isolated_paths):
    config_path = tmp_path / "cursor_mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "weather-clone": {
                        "command": sys.executable,
                        "args": ["-m", "demo_servers.weather_ok"],
                    }
                }
            }
        )
    )

    db.init_db(isolated_paths["db"])
    result = await importer.import_from_configs([str(config_path)], db_path=isolated_paths["db"])

    assert result["imported_count"] == 1
    server = result["servers"][0]
    assert server["id"] == "imported_weather_clone"
    assert server["language"] == "python"
    assert server["sandbox"] == "ran"
    assert server["verdict"] == "looks_ok"
    assert server["error"] is None


@pytest.mark.asyncio
async def test_import_handles_a_server_that_fails_to_start(tmp_path, isolated_paths):
    config_path = tmp_path / "cursor_mcp.json"
    config_path.write_text(json.dumps({"mcpServers": {"broken": {"command": "/no/such/binary", "args": []}}}))

    db.init_db(isolated_paths["db"])
    result = await importer.import_from_configs([str(config_path)], db_path=isolated_paths["db"])

    assert result["imported_count"] == 1
    server = result["servers"][0]
    assert server["verdict"] is None
    assert server["error"] is not None
    assert "not run" in server["sandbox"]


def test_import_endpoint_end_to_end(tmp_path, isolated_paths):
    config_path = tmp_path / "cursor_mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "weather-clone": {"command": sys.executable, "args": ["-m", "demo_servers.weather_ok"]}
                }
            }
        )
    )

    with TestClient(app) as client:
        response = client.post("/api/import", json={"config_paths": [str(config_path)]})
        assert response.status_code == 200
        body = response.json()
        assert body["imported_count"] == 1

        servers = {row["id"]: row for row in client.get("/api/servers").json()}
        assert "imported_weather_clone" in servers
        assert servers["imported_weather_clone"]["verdict"] == "looks_ok"

        detail = client.get("/api/servers/imported_weather_clone").json()
        assert detail["behaviour"]["sandbox_error"] is None


def test_import_marks_non_python_servers_as_sandbox_unsupported(isolated_paths):
    import dataclasses

    from vetter.registry import SERVERS_BY_ID
    from vetter.scan_service import scan_and_store

    db.init_db(isolated_paths["db"])
    base = SERVERS_BY_ID["weather_ok"]
    fake_entry = dataclasses.replace(base, id="fake_node_server", name="fake-node-server", language="other")

    import asyncio

    row = asyncio.run(scan_and_store(fake_entry, with_sandbox=True, db_path=isolated_paths["db"]))
    assert row["behaviour"]["sandbox_error"] == "sandbox: not supported yet (static scan only)"
