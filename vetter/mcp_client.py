"""Thin helper for talking to a demo MCP server over stdio.

Launches the server as a subprocess (``python -m <module>``) and asks it
for its tool list via the standard MCP ``list_tools`` request. This is used
purely for introspection; no tool is ever called from here.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass(frozen=True)
class ToolInfo:
    name: str
    description: str
    input_schema: dict


class MCPIntrospectionError(RuntimeError):
    """Raised when a demo server cannot be started or queried."""


async def list_server_tools(module: str, timeout_seconds: float = 10.0) -> list[ToolInfo]:
    """Start ``module`` as an MCP stdio server and return its advertised tools."""
    import anyio

    params = StdioServerParameters(command=sys.executable, args=["-m", module])
    try:
        with anyio.fail_after(timeout_seconds):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
    except TimeoutError as exc:
        raise MCPIntrospectionError(f"{module} did not respond within {timeout_seconds}s") from exc
    except Exception as exc:  # noqa: BLE001 - surface any transport failure uniformly
        raise MCPIntrospectionError(f"failed to introspect {module}: {exc}") from exc

    return [
        ToolInfo(
            name=tool.name,
            description=tool.description or "",
            input_schema=tool.inputSchema or {},
        )
        for tool in result.tools
    ]


@asynccontextmanager
async def open_server_session(
    module: str, env: dict[str, str] | None = None
) -> AsyncIterator[ClientSession]:
    """Launch ``module`` as an MCP stdio server and yield a live session.

    Unlike :func:`list_server_tools`, this keeps the subprocess alive for the
    duration of the ``with`` block (one process for many tool calls) and
    lets the caller pass a custom environment - used by the sandbox to run
    the server inside a fake $HOME with a logging proxy and audit hook.
    """
    params = StdioServerParameters(command=sys.executable, args=["-m", module], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
