"""Thin helper for talking to a demo MCP server over stdio.

Launches the server as a subprocess (``python -m <module>``) and asks it
for its tool list via the standard MCP ``list_tools`` request. This is used
purely for introspection; no tool is ever called from here.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

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
