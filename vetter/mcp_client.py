"""Thin helper for talking to an MCP server over stdio.

Launches a server as a subprocess from an arbitrary argv (``["python", "-m",
"demo_servers.weather_ok"]`` for our own fixtures, or whatever an imported
real server's config says, e.g. ``["npx", "-y", "some-mcp-server"]``) and
asks it for its tool list via the standard MCP ``list_tools`` request, or
opens a longer-lived session for calling tools. Every launch has a timeout;
nothing here is allowed to hang forever.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vetter.config import BASE_DIR

DEFAULT_STARTUP_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class ToolInfo:
    name: str
    description: str
    input_schema: dict


class MCPIntrospectionError(RuntimeError):
    """Raised when a server cannot be started or queried."""


def _params(command: list[str], env: dict[str, str] | None) -> StdioServerParameters:
    if not command:
        raise MCPIntrospectionError("empty command: nothing to launch")
    return StdioServerParameters(command=command[0], args=command[1:], env=env, cwd=str(BASE_DIR))


async def list_server_tools(
    command: list[str],
    env: dict[str, str] | None = None,
    timeout_seconds: float = DEFAULT_STARTUP_TIMEOUT_SECONDS,
) -> list[ToolInfo]:
    """Start ``command`` as an MCP stdio server and return its advertised tools.

    ``env``, if given (e.g. an imported real server's required API keys), is
    layered on top of this process's own environment - full inheritance,
    unlike :func:`open_server_session`'s sandboxed use, which wants
    isolation and builds its own environment from scratch.
    """
    merged_env = {**os.environ, **env} if env else None
    params = _params(command, env=merged_env)
    try:
        with anyio.fail_after(timeout_seconds):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
    except TimeoutError as exc:
        raise MCPIntrospectionError(f"{command} did not respond within {timeout_seconds}s") from exc
    except Exception as exc:  # noqa: BLE001 - surface any transport failure uniformly
        raise MCPIntrospectionError(f"failed to introspect {command}: {exc}") from exc

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
    command: list[str],
    env: dict[str, str] | None = None,
    startup_timeout_seconds: float = DEFAULT_STARTUP_TIMEOUT_SECONDS,
) -> AsyncIterator[ClientSession]:
    """Launch ``command`` as an MCP stdio server and yield a live session.

    Unlike :func:`list_server_tools`, this keeps the subprocess alive for the
    duration of the ``with`` block (one process for many tool calls) and
    lets the caller pass a custom environment - used by the sandbox to run
    the server inside a fake $HOME with a logging proxy and audit hook. Only
    the startup handshake is time-limited here; per-call timeouts are the
    caller's responsibility (the sandbox applies one per tool call).
    """
    params = _params(command, env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            with anyio.fail_after(startup_timeout_seconds):
                await session.initialize()
            yield session
