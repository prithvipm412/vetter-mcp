from __future__ import annotations

from fastapi.testclient import TestClient

from vetter.main import app


def _client(isolated_paths) -> TestClient:
    # Entering the TestClient context runs the app's lifespan, which calls
    # init_db()/scan at startup against whatever vetter.config currently
    # points at - isolated_paths (an autouse-free fixture) must already have
    # monkeypatched DB_PATH/LOCK_FILE_PATH before this is called.
    return TestClient(app)


def test_list_servers_has_all_three_demo_servers(isolated_paths):
    with _client(isolated_paths) as client:
        response = client.get("/api/servers")
        assert response.status_code == 200
        ids = {row["id"] for row in response.json()}
        assert ids == {"weather_ok", "travel_overreach", "notes_rugpull"}


def test_weather_ok_looks_ok_travel_overreach_high_risk(isolated_paths):
    with _client(isolated_paths) as client:
        response = client.get("/api/servers")
        by_id = {row["id"]: row for row in response.json()}
        assert by_id["weather_ok"]["verdict"] == "looks_ok"
        assert by_id["weather_ok"]["status"] == "new"
        assert by_id["travel_overreach"]["verdict"] == "high_risk"
        assert len(by_id["travel_overreach"]["labels"]) > 0


def test_server_detail_has_static_findings_behaviour_and_claim(isolated_paths):
    with _client(isolated_paths) as client:
        response = client.get("/api/servers/travel_overreach")
        assert response.status_code == 200
        body = response.json()
        assert set(body.keys()) == {"static_findings", "behaviour", "claim_vs_behaviour"}
        assert len(body["static_findings"]) > 0
        assert body["claim_vs_behaviour"]["capability_match"] is False


def test_unknown_server_is_404(isolated_paths):
    with _client(isolated_paths) as client:
        assert client.get("/api/servers/does-not-exist").status_code == 404
        assert client.post("/api/servers/does-not-exist/scan").status_code == 404
        assert client.post("/api/servers/does-not-exist/approve").status_code == 404
        assert client.post("/api/servers/does-not-exist/block").status_code == 404
        assert client.post("/api/servers/does-not-exist/revoke").status_code == 404


def test_approve_block_revoke_lifecycle(isolated_paths):
    with _client(isolated_paths) as client:
        approve = client.post("/api/servers/weather_ok/approve")
        assert approve.status_code == 200
        assert approve.json()["status"] == "approved"

        block = client.post("/api/servers/weather_ok/block")
        assert block.status_code == 200
        assert block.json()["status"] == "blocked"

        revoke = client.post("/api/servers/weather_ok/revoke")
        assert revoke.status_code == 200
        assert revoke.json()["status"] == "new"


def test_rescan_after_approval_flags_rugpull_as_paused_changed(isolated_paths, rugpull_marker):
    turn_on, turn_off = rugpull_marker
    with _client(isolated_paths) as client:
        approve = client.post("/api/servers/notes_rugpull/approve")
        assert approve.json()["status"] == "approved"

        turn_on()
        rescan = client.post("/api/servers/notes_rugpull/scan")
        body = rescan.json()
        assert body["status"] == "paused_changed"
        assert body["verdict"] == "high_risk"


def test_scan_sandbox_results_show_canary_leak_for_travel_overreach(isolated_paths):
    with _client(isolated_paths) as client:
        body = client.post("/api/servers/travel_overreach/scan").json()
        assert body["verdict"] == "high_risk"
        assert body["behaviour"]["canary_leak"]["leaked"] is True
        assert "collect.unknown-domain.test" in body["behaviour"]["network_destinations"]
        assert any(f["is_decoy"] for f in body["behaviour"]["files_opened"])


def test_changes_and_allow_end_to_end(isolated_paths, rugpull_marker):
    turn_on, turn_off = rugpull_marker
    with _client(isolated_paths) as client:
        no_baseline = client.get("/api/servers/notes_rugpull/changes").json()
        assert no_baseline == {"old_description": None, "new_description": None, "diff": ""}

        assert client.post("/api/servers/notes_rugpull/approve").json()["status"] == "approved"

        unchanged = client.get("/api/servers/notes_rugpull/changes").json()
        assert unchanged == {"old_description": None, "new_description": None, "diff": ""}

        turn_on()
        changed = client.get("/api/servers/notes_rugpull/changes").json()
        assert changed["old_description"] is not None
        assert "sync.example.net" in changed["new_description"]
        assert "+++ " in changed["diff"]
        assert "-" in changed["diff"] and "+" in changed["diff"]

        allow = client.post("/api/servers/notes_rugpull/changes/allow")
        assert allow.json()["status"] == "approved"

        after_allow = client.get("/api/servers/notes_rugpull/changes").json()
        assert after_allow == {"old_description": None, "new_description": None, "diff": ""}

        incidents = client.get("/api/incidents?server=notes_rugpull").json()
        assert any(i["type"] == "reapproved_after_change" for i in incidents)


def test_demo_rugpull_toggle_endpoints_and_reset(isolated_paths, rugpull_marker):
    turn_on, turn_off = rugpull_marker
    with _client(isolated_paths) as client:
        assert client.post("/api/demo/rugpull/on").json() == {"rugpull": True}
        changed = client.get("/api/servers/notes_rugpull/changes").json()
        # no approval yet, so still no baseline to diff against
        assert changed == {"old_description": None, "new_description": None, "diff": ""}

        assert client.post("/api/demo/rugpull/off").json() == {"rugpull": False}

        client.post("/api/servers/weather_ok/approve")
        client.post("/api/servers/weather_ok/block")
        assert client.post("/api/demo/reset").json() == {"status": "reset"}

        rows = {row["id"]: row for row in client.get("/api/servers").json()}
        assert rows["weather_ok"]["status"] == "new"
        assert rows["weather_ok"]["verdict"] is None
        assert client.get("/api/incidents").json() == []
