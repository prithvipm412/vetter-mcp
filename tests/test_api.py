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


def test_server_actions_are_logged_as_incidents(isolated_paths):
    with _client(isolated_paths) as client:
        client.post("/api/servers/weather_ok/scan")
        scan_incidents = client.get("/api/incidents?server=weather_ok").json()
        scan_completed = [i for i in scan_incidents if i["type"] == "scan_completed"]
        assert scan_completed
        assert "looks_ok" in scan_completed[-1]["detail"]

        client.post("/api/servers/weather_ok/approve")
        approved = client.get("/api/incidents?server=weather_ok").json()
        assert any(i["type"] == "approved" for i in approved)

        client.post("/api/servers/weather_ok/block")
        blocked = client.get("/api/incidents?server=weather_ok").json()
        assert any(i["type"] == "blocked" for i in blocked)

        client.post("/api/servers/weather_ok/revoke")
        revoked = client.get("/api/incidents?server=weather_ok").json()
        assert any(i["type"] == "revoked" for i in revoked)

        leak_scan = client.post("/api/servers/travel_overreach/scan").json()
        assert leak_scan["behaviour"]["canary_leak"]["leaked"] is True
        travel_incidents = client.get("/api/incidents?server=travel_overreach").json()
        leak_incidents = [i for i in travel_incidents if i["type"] == "canary_leak"]
        assert leak_incidents
        assert "collect.unknown-domain.test" in leak_incidents[-1]["detail"]


def test_rescan_after_approval_logs_change_detected(isolated_paths, rugpull_marker):
    turn_on, turn_off = rugpull_marker
    with _client(isolated_paths) as client:
        assert client.post("/api/servers/notes_rugpull/approve").json()["status"] == "approved"

        turn_on()
        rescan = client.post("/api/servers/notes_rugpull/scan")
        assert rescan.json()["status"] == "paused_changed"

        incidents = client.get("/api/incidents?server=notes_rugpull").json()
        assert any(i["type"] == "change_detected" for i in incidents)


def test_demo_reset_recreates_schema_if_db_file_went_missing(isolated_paths):
    """Regression test: if the .db file is ever deleted out from under a
    running backend (or simply never existed yet), POST /api/demo/reset must
    recreate the schema and re-register the 3 demo servers itself - callers
    shouldn't need to restart the server to recover from "no such table:
    servers".
    """
    with _client(isolated_paths) as client:
        isolated_paths["db"].unlink(missing_ok=True)

        assert client.post("/api/demo/reset").json() == {"status": "reset"}
        assert client.post("/api/demo/reset").json() == {"status": "reset"}

        response = client.get("/api/servers")
        assert response.status_code == 200
        ids = {row["id"] for row in response.json()}
        assert ids == {"weather_ok", "travel_overreach", "notes_rugpull"}
