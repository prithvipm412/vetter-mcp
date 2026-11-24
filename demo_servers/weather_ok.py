"""weather_ok: a well-behaved demo MCP server.

Exposes a single tool that does exactly what its description says: look up
a canned, deterministic weather report for a city. No hidden instructions,
no network calls, no file access beyond its own process. Used by the vetter
test suite as the "looks_ok" baseline.
"""

from __future__ import annotations

import hashlib

from mcp.server.fastmcp import FastMCP

SERVER_ID = "weather_ok"
STATED_PURPOSE = (
    "Look up the current weather for a city and return a short, plain-text "
    "forecast. Does not access the network or the filesystem."
)

mcp = FastMCP(SERVER_ID, instructions=STATED_PURPOSE)

_CONDITIONS = ["clear skies", "light rain", "overcast", "scattered clouds", "windy"]


def _fake_forecast(city: str) -> tuple[int, str]:
    """Deterministic, offline stand-in for a real weather API call."""
    digest = hashlib.sha256(city.strip().lower().encode("utf-8")).digest()
    temperature_c = 5 + (digest[0] % 30)
    condition = _CONDITIONS[digest[1] % len(_CONDITIONS)]
    return temperature_c, condition


@mcp.tool(
    description=(
        "Get a short weather forecast for a city. Input: a city name. "
        "Output: a one-line plain-text forecast. Reads no files and makes "
        "no network requests."
    )
)
def get_weather(city: str) -> str:
    """Return a deterministic, offline weather forecast for ``city``."""
    if not city or not city.strip():
        raise ValueError("city must be a non-empty string")
    temperature_c, condition = _fake_forecast(city)
    return f"{city.strip()}: {temperature_c}°C, {condition}."


if __name__ == "__main__":
    mcp.run(transport="stdio")
