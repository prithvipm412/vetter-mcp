"""Runtime protection proxy.

Usage:
    python -m vetter.proxy --server <id> -- <server command> [args...]

Sits between an AI client (e.g. Claude Desktop) and the real MCP server,
relaying newline-delimited JSON-RPC over stdio unchanged in both
directions, with one exception: every time it observes the upstream
server's tool manifest (via a ``tools/list`` response, or by re-querying
after a ``notifications/tools/list_changed`` notification) it re-fingerprints
every tool and compares against the approved baseline in
``vetter-lock.json``. If a tool is unapproved or has changed, the proxy
stops forwarding ``tools/call`` requests for it and synthesizes an error
response instead, and flips that server's status to ``paused_changed``.

Only JSON-RPC protocol bytes are ever written to stdout; all logging goes
to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import threading
from typing import Any

from vetter import db, fingerprint
from vetter.mcp_client import ToolInfo

BLOCKED_MESSAGE = "Vetter paused this tool: its definition changed since you approved it."


def _log(*parts: Any) -> None:
    print(*parts, file=sys.stderr, flush=True)


def _raw_tools_to_toolinfo(raw_tools: list[dict]) -> list[ToolInfo]:
    return [
        ToolInfo(
            name=t["name"],
            description=t.get("description") or "",
            input_schema=t.get("inputSchema") or {},
        )
        for t in raw_tools
    ]


class ProxyState:
    """Tracks what we currently believe is safe to call, for one server."""

    def __init__(self, server_id: str) -> None:
        self.server_id = server_id
        self.allowed_tools: set[str] = set()
        self.known = False  # have we ever seen a tool list at all?

    def is_blocked(self, tool_name: str) -> bool:
        return (not self.known) or (tool_name not in self.allowed_tools)

    def refresh(self, raw_tools: list[dict]) -> None:
        tools = _raw_tools_to_toolinfo(raw_tools)
        result = fingerprint.verify_server(self.server_id, tools)
        self.known = True

        blocked_names = set(result["changed_tools"]) | set(result["new_tools"])
        self.allowed_tools = {t.name for t in tools} - blocked_names if result["approved"] else set()

        drifted = result["changed_tools"] or result["new_tools"] or result["missing_tools"]
        if result["approved"] and drifted:
            detail = (
                f"changed={result['changed_tools']} new={result['new_tools']} missing={result['missing_tools']}"
            )
            db.log_incident(self.server_id, "drift_detected", None, detail)
            db.set_status(self.server_id, "paused_changed")
            _log(f"[vetter-proxy] drift detected for {self.server_id}: {detail}")
        elif not result["approved"]:
            _log(f"[vetter-proxy] {self.server_id} has no approved baseline; all calls blocked")


class StdioProxy:
    def __init__(self, server_id: str, command: list[str]) -> None:
        self.state = ProxyState(server_id)
        self.command = command
        self.write_lock = asyncio.Lock()
        self.pending_list_request_ids: set[Any] = set()
        self.internal_futures: dict[str, asyncio.Future] = {}
        self._internal_counter = 0
        self.upstream_stdin: asyncio.StreamWriter | None = None

    async def _write_to_client(self, message: dict) -> None:
        line = json.dumps(message) + "\n"
        async with self.write_lock:
            sys.stdout.write(line)
            sys.stdout.flush()

    async def _write_to_upstream(self, raw_line: str) -> None:
        assert self.upstream_stdin is not None
        self.upstream_stdin.write((raw_line.rstrip("\n") + "\n").encode("utf-8"))
        await self.upstream_stdin.drain()

    def _next_internal_id(self) -> str:
        self._internal_counter += 1
        return f"__vetter_internal_{self._internal_counter}__"

    async def _request_upstream_tools_list(self) -> None:
        """Proactively ask upstream for tools/list after a list_changed notice."""
        request_id = self._next_internal_id()
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self.internal_futures[request_id] = future
        await self._write_to_upstream(
            json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}})
        )
        try:
            result = await asyncio.wait_for(future, timeout=10.0)
        except TimeoutError:
            _log("[vetter-proxy] internal tools/list refresh timed out")
            return
        finally:
            self.internal_futures.pop(request_id, None)
        tools = result.get("tools", []) if isinstance(result, dict) else []
        self.state.refresh(tools)

    def _blocked_response(self, request_id: Any) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": BLOCKED_MESSAGE}],
                "isError": True,
            },
        }

    async def handle_client_message(self, raw_line: str) -> None:
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            _log("[vetter-proxy] dropping non-JSON line from client")
            return

        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            self.pending_list_request_ids.add(msg["id"])
        elif method == "tools/call" and "id" in msg:
            tool_name = (msg.get("params") or {}).get("name")
            if tool_name and self.state.is_blocked(tool_name):
                db.log_incident(
                    self.state.server_id,
                    "call_blocked",
                    tool_name,
                    "blocked a tools/call because the tool is unapproved or changed",
                )
                db.set_status(self.state.server_id, "paused_changed")
                await self._write_to_client(self._blocked_response(msg["id"]))
                _log(f"[vetter-proxy] blocked tools/call for {tool_name!r}")
                return

        await self._write_to_upstream(raw_line)

    async def handle_upstream_message(self, raw_line: str) -> None:
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            _log("[vetter-proxy] dropping non-JSON line from upstream")
            return

        msg_id = msg.get("id")
        if isinstance(msg_id, str) and msg_id in self.internal_futures:
            future = self.internal_futures[msg_id]
            if not future.done():
                future.set_result(msg.get("result"))
            return  # never forward our own internal traffic to the client

        if msg_id in self.pending_list_request_ids and "result" in msg:
            self.pending_list_request_ids.discard(msg_id)
            tools = msg["result"].get("tools", [])
            self.state.refresh(tools)

        await self._write_to_client(msg)

        if msg.get("method") == "notifications/tools/list_changed":
            asyncio.create_task(self._request_upstream_tools_list())

    async def run(self) -> None:
        db.init_db()
        db.log_incident(self.state.server_id, "proxy_started", None, f"command={self.command}")

        proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
        )
        self.upstream_stdin = proc.stdin

        stdin_queue: asyncio.Queue[str | None] = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def read_stdin_blocking() -> None:
            for line in sys.stdin:
                loop.call_soon_threadsafe(stdin_queue.put_nowait, line)
            loop.call_soon_threadsafe(stdin_queue.put_nowait, None)

        reader_thread = threading.Thread(target=read_stdin_blocking, daemon=True)
        reader_thread.start()

        async def client_to_upstream() -> None:
            while True:
                line = await stdin_queue.get()
                if line is None:
                    break
                if line.strip():
                    await self.handle_client_message(line)

        async def upstream_to_client() -> None:
            assert proc.stdout is not None
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                decoded = raw.decode("utf-8", errors="replace")
                if decoded.strip():
                    await self.handle_upstream_message(decoded)

        try:
            await asyncio.gather(client_to_upstream(), upstream_to_client())
        finally:
            db.log_incident(self.state.server_id, "proxy_stopped", None, "proxy shutting down")
            if proc.returncode is None:
                proc.terminate()
            await proc.wait()


def parse_args(argv: list[str]) -> tuple[str, list[str]]:
    parser = argparse.ArgumentParser(prog="python -m vetter.proxy")
    parser.add_argument("--server", required=True, help="server id as known to vetter")
    args, remainder = parser.parse_known_args(argv)
    if remainder and remainder[0] == "--":
        remainder = remainder[1:]
    if not remainder:
        parser.error("no server command given after '--'")
    return args.server, remainder


def main() -> None:
    server_id, command = parse_args(sys.argv[1:])
    proxy = StdioProxy(server_id, command)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(proxy.run())


if __name__ == "__main__":
    main()
