"""Sandbox orchestrator: wires up a fake HOME, audit hook and logging HTTP
proxy, calls every advertised tool once with harmless sample arguments, and
reports what the server actually did.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio

from vetter.config import BASE_DIR
from vetter.mcp_client import ToolInfo, open_server_session
from vetter.registry import ServerEntry
from vetter.sandbox.fake_home import create_fake_home
from vetter.sandbox.logging_proxy import LoggingHTTPProxy
from vetter.sandbox.sitecustomize_template import SITECUSTOMIZE_SOURCE

CALL_TIMEOUT_SECONDS = 10.0


@dataclass
class ToolCallOutcome:
    tool: str
    arguments: dict[str, Any]
    ok: bool
    error: str | None = None


@dataclass
class FileAccess:
    path: str
    is_decoy: bool


@dataclass
class CanaryLeak:
    leaked: bool
    secret: str | None = None
    destination: str | None = None


@dataclass
class SandboxReport:
    files_opened: list[FileAccess] = field(default_factory=list)
    network_destinations: list[str] = field(default_factory=list)
    canary_leak: CanaryLeak = field(default_factory=lambda: CanaryLeak(leaked=False))
    tool_calls: list[ToolCallOutcome] = field(default_factory=list)
    error: str | None = None


def _sample_value(schema: dict) -> Any:
    schema_type = schema.get("type")
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    return "vetter-sandbox-sample"


def build_sample_args(input_schema: dict) -> dict[str, Any]:
    """Build harmless placeholder arguments for a tool's required fields."""
    properties = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or properties.keys())
    return {name: _sample_value(prop or {}) for name, prop in properties.items() if name in required}


def _extract_text(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return " ".join(parts)


def _read_audit_events(audit_log_path: Path) -> list[dict]:
    if not audit_log_path.exists():
        return []
    events = []
    for line in audit_log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _build_sandbox_env(
    fake_home_dir: Path, sitecustomize_dir: Path, audit_log_path: Path, proxy_url: str
) -> dict[str, str]:
    return {
        "HOME": str(fake_home_dir),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": f"{sitecustomize_dir}{os.pathsep}{BASE_DIR}",
        "VETTER_AUDIT_LOG": str(audit_log_path),
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": "",
        "no_proxy": "",
    }


async def run_sandbox(entry: ServerEntry, tools: list[ToolInfo]) -> SandboxReport:
    """Launch ``entry`` inside the lite sandbox and exercise every tool once."""
    report = SandboxReport()

    with tempfile.TemporaryDirectory(prefix="vetter-sandbox-") as scratch:
        scratch_path = Path(scratch)

        fake_home_dir = scratch_path / "home"
        fake_home_dir.mkdir()
        fake_home = create_fake_home(fake_home_dir)

        sitecustomize_dir = scratch_path / "sitecustomize"
        sitecustomize_dir.mkdir()
        (sitecustomize_dir / "sitecustomize.py").write_text(SITECUSTOMIZE_SOURCE)

        audit_log_path = scratch_path / "audit.ndjson"
        audit_log_path.touch()

        proxy = LoggingHTTPProxy(canary_tokens=set(fake_home.canaries.values()))
        port = proxy.start()
        env = _build_sandbox_env(fake_home_dir, sitecustomize_dir, audit_log_path, f"http://127.0.0.1:{port}")

        try:
            async with open_server_session(entry.command, env=env) as session:
                for tool in tools:
                    args = build_sample_args(tool.input_schema)
                    try:
                        with anyio.fail_after(CALL_TIMEOUT_SECONDS):
                            result = await session.call_tool(tool.name, args)
                        is_error = bool(getattr(result, "isError", False))
                        report.tool_calls.append(
                            ToolCallOutcome(
                                tool=tool.name,
                                arguments=args,
                                ok=not is_error,
                                error=_extract_text(result) if is_error else None,
                            )
                        )
                    except TimeoutError:
                        report.tool_calls.append(
                            ToolCallOutcome(
                                tool=tool.name,
                                arguments=args,
                                ok=False,
                                error=f"timed out after {CALL_TIMEOUT_SECONDS}s",
                            )
                        )
                    except Exception as exc:  # noqa: BLE001 - one bad tool call shouldn't abort the sandbox
                        report.tool_calls.append(
                            ToolCallOutcome(tool=tool.name, arguments=args, ok=False, error=str(exc))
                        )
        except Exception as exc:  # noqa: BLE001 - a server that won't even start shouldn't crash /scan
            report.error = f"sandbox failed to run {entry.command}: {exc}"
        finally:
            proxy.stop()

        events = _read_audit_events(audit_log_path)
        # Map each decoy's resolved on-disk path back to a "~/..." path
        # relative to the fake $HOME, so a report never leaks the sandbox's
        # own (otherwise meaningless, and randomly-named) temp directory.
        decoy_relpath_by_resolved = {
            str((fake_home_dir / relpath).resolve()): relpath for relpath in fake_home.canaries
        }

        def _is_noise(path: str) -> bool:
            if path == str(audit_log_path) or path.startswith(str(sitecustomize_dir)):
                return True
            return (
                "__pycache__" in path
                or "site-packages" in path
                or "/lib/python3." in path
                or path.endswith((".pyc", ".pyo", ".zip"))
                or path.startswith("/System/Library/")
                or ".egg-info" in path
                or ".dist-info" in path
            )

        seen_paths: set[str] = set()
        for event in events:
            if event.get("event") != "open":
                continue
            event_args = event.get("args") or []
            if not event_args or not isinstance(event_args[0], str):
                continue
            raw_path = event_args[0]
            if _is_noise(raw_path):
                continue
            try:
                resolved = str(Path(raw_path).resolve())
            except OSError:
                resolved = raw_path
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            decoy_relpath = decoy_relpath_by_resolved.get(resolved)
            path = f"~/{decoy_relpath}" if decoy_relpath is not None else raw_path
            report.files_opened.append(FileAccess(path=path, is_decoy=decoy_relpath is not None))

        report.network_destinations = proxy.distinct_hosts()

        token_to_relpath = fake_home.token_to_relpath()
        leaks = proxy.canary_leaks()
        if leaks:
            leak = leaks[0]
            token = leak.canary_hits[0]
            report.canary_leak = CanaryLeak(
                leaked=True,
                secret=token_to_relpath.get(token, token),
                destination=leak.host or leak.path or None,
            )

    return report
