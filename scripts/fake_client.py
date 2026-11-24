#!/usr/bin/env python3
"""A tiny stand-in "AI assistant" that talks MCP through the vetter proxy.

This exists so the "a server changes after you approved it" demo can be run
end-to-end from a terminal, without needing Claude Desktop or Cursor
installed. It spawns ``python -m vetter.proxy --server <id> -- <real server
command>`` and talks to it exactly like a real MCP client would: initialize,
list tools, call a tool. It uses the same official MCP SDK client the vetter
backend uses for introspection, just pointed at the proxy instead of
directly at the demo server.

Example - show a tool call succeed, then get blocked once the server has
been approved and its description quietly changes (the rug-pull demo):

    # one-time baseline: with the backend running on :8000,
    curl -X POST http://localhost:8000/api/servers/notes_rugpull/approve

    python scripts/fake_client.py --server notes_rugpull --call add_note \
        --args '{"text": "hello"}'

    mkdir -p ~/.vetter-demo && touch ~/.vetter-demo/rugpull

    python scripts/fake_client.py --server notes_rugpull --call add_note \
        --args '{"text": "hello again"}'   # now blocked
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from vetter.registry import SERVERS_BY_ID  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def build_proxy_params(server_id: str) -> StdioServerParameters:
    entry = SERVERS_BY_ID[server_id]
    proxy_args = ["-m", "vetter.proxy", "--server", server_id, "--", *entry.command]
    return StdioServerParameters(command=sys.executable, args=proxy_args, cwd=str(REPO_ROOT))


async def run(server_id: str, tool_call: str | None, call_args: dict) -> None:
    params = build_proxy_params(server_id)
    print(f"[fake_client] connecting to {server_id!r} through the vetter proxy...")

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        print(f"[fake_client] tools/list -> {[t.name for t in tools.tools]}")

        if tool_call:
            print(f"[fake_client] calling {tool_call}({call_args}) ...")
            result = await session.call_tool(tool_call, call_args)
            is_error = getattr(result, "isError", False)
            text_parts = [block.text for block in result.content if getattr(block, "type", None) == "text"]
            print(f"[fake_client] isError={is_error}")
            for text in text_parts:
                print(f"[fake_client] -> {text}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, choices=sorted(SERVERS_BY_ID))
    parser.add_argument("--call", dest="tool_call", default=None, help="tool name to call")
    parser.add_argument("--args", dest="call_args", default="{}", help="JSON object of tool arguments")
    args = parser.parse_args()

    try:
        call_args = json.loads(args.call_args)
    except json.JSONDecodeError as exc:
        parser.error(f"--args must be a JSON object: {exc}")
        return

    asyncio.run(run(args.server, args.tool_call, call_args))


if __name__ == "__main__":
    main()
