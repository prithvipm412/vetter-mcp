"""FastAPI backend for vetter: the "app-store review" dashboard API.

Implements the Phase 1 slice of API.md: listing servers, fetching a
server's static-scan report, and the scan/approve/block/revoke actions.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from vetter import db, fingerprint
from vetter.config import ALLOWED_ORIGINS
from vetter.mcp_client import MCPIntrospectionError, list_server_tools
from vetter.models import ServerScanResult, ServerSummary
from vetter.registry import SERVERS_BY_ID
from vetter.scanner import scan_server


async def _scan_and_store(server_id: str) -> dict[str, Any]:
    entry = SERVERS_BY_ID[server_id]
    try:
        tools = await list_server_tools(entry.module)
    except MCPIntrospectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    verdict, labels, report = scan_server(entry, tools)
    scanned_at = datetime.now(timezone.utc).isoformat()
    report_dict = report.model_dump()

    db.save_scan_result(
        server_id=server_id,
        verdict=verdict,
        labels=labels,
        static_findings=report_dict["static_findings"],
        behaviour=report_dict["behaviour"],
        claim_vs_behaviour=report_dict["claim_vs_behaviour"],
        scanned_at=scanned_at,
    )

    current = db.get_server(server_id)
    if current and current["status"] == "approved":
        verify = fingerprint.verify_server(server_id, tools)
        if verify["changed_tools"] or verify["missing_tools"] or verify["new_tools"]:
            db.set_status(server_id, "paused_changed")

    return db.get_server(server_id)  # type: ignore[return-value]


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    for server_id in SERVERS_BY_ID:
        try:
            await _scan_and_store(server_id)
        except HTTPException:
            # A demo server failing to start shouldn't take the whole API down;
            # it will simply show up with no verdict yet until re-scanned.
            pass
    yield


app = FastAPI(title="vetter-mcp API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _require_entry(server_id: str) -> None:
    if server_id not in SERVERS_BY_ID:
        raise HTTPException(status_code=404, detail=f"unknown server id: {server_id}")


def _require_row(server_id: str) -> dict[str, Any]:
    _require_entry(server_id)
    row = db.get_server(server_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown server id: {server_id}")
    return row


def _to_summary(row: dict[str, Any]) -> ServerSummary:
    return ServerSummary(
        id=row["id"],
        name=row["name"],
        verdict=row["verdict"],
        labels=row["labels"],
        status=row["status"],
    )


@app.get("/api/servers", response_model=list[ServerSummary])
def get_servers() -> list[ServerSummary]:
    return [_to_summary(row) for row in db.list_servers()]


@app.get("/api/servers/{server_id}")
def get_server_detail(server_id: str) -> dict[str, Any]:
    row = _require_row(server_id)
    return {
        "static_findings": row["static_findings"],
        "behaviour": row["behaviour"],
        "claim_vs_behaviour": row["claim_vs_behaviour"],
    }


@app.post("/api/servers/{server_id}/scan", response_model=ServerScanResult)
async def scan_server_endpoint(server_id: str) -> ServerScanResult:
    _require_entry(server_id)
    row = await _scan_and_store(server_id)
    return ServerScanResult(
        id=row["id"],
        name=row["name"],
        verdict=row["verdict"],
        labels=row["labels"],
        status=row["status"],
        static_findings=row["static_findings"],
        behaviour=row["behaviour"],
        claim_vs_behaviour=row["claim_vs_behaviour"],
    )


@app.post("/api/servers/{server_id}/approve", response_model=ServerSummary)
async def approve_server_endpoint(server_id: str) -> ServerSummary:
    entry = SERVERS_BY_ID.get(server_id)
    _require_row(server_id)
    assert entry is not None
    try:
        tools = await list_server_tools(entry.module)
    except MCPIntrospectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    fingerprint.approve_server(server_id, tools)
    db.set_status(server_id, "approved")
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]


@app.post("/api/servers/{server_id}/block", response_model=ServerSummary)
def block_server_endpoint(server_id: str) -> ServerSummary:
    _require_row(server_id)
    db.set_status(server_id, "blocked")
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]


@app.post("/api/servers/{server_id}/revoke", response_model=ServerSummary)
def revoke_server_endpoint(server_id: str) -> ServerSummary:
    _require_row(server_id)
    fingerprint.revoke_server(server_id)
    db.set_status(server_id, "new")
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]
