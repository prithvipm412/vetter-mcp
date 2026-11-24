from __future__ import annotations

import json

import vetter.protect as protect_module


def test_protect_with_no_config_file_present(tmp_path, monkeypatch):
    fake_config = tmp_path / "claude_desktop_config.json"
    monkeypatch.setattr(protect_module, "DEFAULT_CONFIG_PATH", fake_config)

    result = protect_module.protect()

    assert result["status"] == "no_config"
    assert str(fake_config) in result["message"]
    assert not fake_config.exists()


def test_protect_wraps_servers_and_undo_restores(tmp_path, monkeypatch):
    fake_config = tmp_path / "claude_desktop_config.json"
    monkeypatch.setattr(protect_module, "DEFAULT_CONFIG_PATH", fake_config)

    original = {
        "mcpServers": {
            "weather": {"command": "python", "args": ["-m", "demo_servers.weather_ok"]},
        }
    }
    fake_config.write_text(json.dumps(original))

    result = protect_module.protect()
    assert result["status"] == "protected"
    assert len(result["changed"]) == 1
    assert result["changed"][0]["server"] == "weather"
    assert result["changed"][0]["before"]["command"] == "python"

    wrapped = json.loads(fake_config.read_text())
    wrapped_entry = wrapped["mcpServers"]["weather"]
    assert wrapped_entry["args"][:4] == ["-m", "vetter.proxy", "--server", "weather"]
    assert wrapped_entry["args"][5:] == ["python", "-m", "demo_servers.weather_ok"]
    assert wrapped_entry["_vetter_wrapped"] is True

    again = protect_module.protect()
    assert again["status"] == "already_protected"

    undo_result = protect_module.undo()
    assert undo_result["status"] == "restored"
    assert json.loads(fake_config.read_text()) == original

    second_undo = protect_module.undo()
    assert second_undo["status"] == "no_backup"
