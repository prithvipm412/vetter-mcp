"""FastAPI backend for vetter: the "app-store review" dashboard API.

Implements API.md: listing/scanning/approving servers, the change-diff and
incident endpoints, Claude Desktop config protection, the demo controls,
and importing real MCP servers from a real assistant's config.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from vetter import changes as changes_module
from vetter import db, fingerprint, importer, server_lookup
from vetter import protect as protect_module
from vetter.config import ALLOWED_ORIGINS
from vetter.logging_config import configure_logging
from vetter.mcp_client import MCPIntrospectionError, list_server_tools
from vetter.models import ServerScanResult, ServerSummary
from vetter.registry import SERVERS_BY_ID
from vetter.scan_service import scan_and_store

logger = configure_logging()


async def _scan_and_store(server_id: str, with_sandbox: bool = True) -> dict[str, Any]:
    entry = server_lookup.get_entry(server_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"unknown server id: {server_id}")
    try:
        return await scan_and_store(entry, with_sandbox=with_sandbox)
    except MCPIntrospectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    logger.info("vetter backend starting up; running eager static scans for demo servers")
    for server_id in SERVERS_BY_ID:
        try:
            # Startup only runs the fast static pass; POST /scan is what
            # triggers the (slower) sandbox run.
            await _scan_and_store(server_id, with_sandbox=False)
        except HTTPException as exc:
            # A demo server failing to start shouldn't take the whole API down;
            # it will simply show up with no verdict yet until re-scanned.
            logger.warning("startup scan failed for %s: %s", server_id, exc.detail)
    yield
    logger.info("vetter backend shutting down")


app = FastAPI(title="vetter-mcp API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _error_response(status_code: int, error_type: str, detail: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"type": error_type, "detail": detail}})


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return _error_response(422, "validation_error", exc.errors())


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return _error_response(exc.status_code, "http_error", exc.detail)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Full traceback goes to logs/vetter.log; the client only ever sees a
    # short, generic message - never a stack trace.
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return _error_response(500, "internal_error", "An unexpected error occurred.")


def _require_entry(server_id: str) -> Any:
    entry = server_lookup.get_entry(server_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"unknown server id: {server_id}")
    return entry


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
    entry = _require_entry(server_id)
    _require_row(server_id)
    try:
        tools = await list_server_tools(entry.command, env=entry.env)
    except MCPIntrospectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    fingerprint.approve_server(server_id, tools)
    db.set_status(server_id, "approved")
    logger.info("server %s approved", server_id)
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]


@app.post("/api/servers/{server_id}/block", response_model=ServerSummary)
def block_server_endpoint(server_id: str) -> ServerSummary:
    _require_row(server_id)
    db.set_status(server_id, "blocked")
    logger.info("server %s blocked", server_id)
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]


@app.post("/api/servers/{server_id}/revoke", response_model=ServerSummary)
def revoke_server_endpoint(server_id: str) -> ServerSummary:
    _require_row(server_id)
    fingerprint.revoke_server(server_id)
    db.set_status(server_id, "new")
    logger.info("server %s approval revoked", server_id)
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]


@app.get("/api/servers/{server_id}/changes")
async def get_server_changes(server_id: str) -> dict[str, Any]:
    entry = _require_entry(server_id)
    _require_row(server_id)
    try:
        tools = await list_server_tools(entry.command, env=entry.env)
    except MCPIntrospectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return changes_module.compute_changes(entry, tools)


@app.post("/api/servers/{server_id}/changes/allow", response_model=ServerSummary)
async def allow_server_changes(server_id: str) -> ServerSummary:
    entry = _require_entry(server_id)
    _require_row(server_id)
    try:
        tools = await list_server_tools(entry.command, env=entry.env)
    except MCPIntrospectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    fingerprint.approve_server(server_id, tools)
    db.set_status(server_id, "approved")
    db.log_incident(server_id, "reapproved_after_change", None, "baseline updated to the current tool definitions")
    logger.info("server %s changes allowed; re-approved", server_id)
    return _to_summary(db.get_server(server_id))  # type: ignore[arg-type]


@app.get("/api/incidents")
def get_incidents(server: str | None = None) -> list[dict[str, Any]]:
    return db.list_incidents(server)


@app.post("/api/protect")
def protect_endpoint() -> dict[str, Any]:
    result = protect_module.protect()
    logger.info("protect: %s", result.get("status"))
    return result


@app.post("/api/protect/undo")
def protect_undo_endpoint() -> dict[str, Any]:
    result = protect_module.undo()
    logger.info("protect/undo: %s", result.get("status"))
    return result


class ImportRequest(BaseModel):
    config_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Extra MCP config file paths to import in addition to the default "
            "Claude Desktop config, e.g. a Cursor mcp.json."
        ),
    )


_DEFAULT_IMPORT_REQUEST = ImportRequest()


@app.post("/api/import")
async def import_servers_endpoint(payload: ImportRequest = _DEFAULT_IMPORT_REQUEST) -> dict[str, Any]:
    result = await importer.import_from_configs(payload.config_paths)
    logger.info(
        "import: %d server(s) discovered across %d config(s)", result["imported_count"], len(result["sources"])
    )
    return result


@app.post("/api/demo/reset")
def demo_reset_endpoint() -> dict[str, str]:
    from demo_servers.notes_rugpull import RUGPULL_MARKER

    db.reset_demo_state()
    fingerprint.reset_lock_file()
    RUGPULL_MARKER.unlink(missing_ok=True)
    logger.info("demo state reset")
    return {"status": "reset"}


@app.post("/api/demo/rugpull/on")
def demo_rugpull_on_endpoint() -> dict[str, bool]:
    from demo_servers.notes_rugpull import RUGPULL_MARKER

    RUGPULL_MARKER.parent.mkdir(parents=True, exist_ok=True)
    RUGPULL_MARKER.touch()
    return {"rugpull": True}


@app.post("/api/demo/rugpull/off")
def demo_rugpull_off_endpoint() -> dict[str, bool]:
    from demo_servers.notes_rugpull import RUGPULL_MARKER

    RUGPULL_MARKER.unlink(missing_ok=True)
    return {"rugpull": False}
