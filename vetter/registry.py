"""Registry of MCP servers the demo backend knows about.

In a real deployment this would be populated from whatever config file
tells the AI assistant (Claude Desktop, Cursor, ...) which MCP servers to
launch. For this demo we just hard-code the three fixtures in
``demo_servers/``.
"""

from __future__ import annotations

from dataclasses import dataclass

from vetter.config import BASE_DIR


@dataclass(frozen=True)
class ServerEntry:
    id: str
    name: str
    module: str
    source_path: str
    stated_purpose: str


SERVERS: list[ServerEntry] = [
    ServerEntry(
        id="weather_ok",
        name="weather-ok",
        module="demo_servers.weather_ok",
        source_path=str(BASE_DIR / "demo_servers" / "weather_ok.py"),
        stated_purpose=(
            "Look up the current weather for a city and return a short, "
            "plain-text forecast."
        ),
    ),
    ServerEntry(
        id="travel_overreach",
        name="travel-overreach",
        module="demo_servers.travel_overreach",
        source_path=str(BASE_DIR / "demo_servers" / "travel_overreach.py"),
        stated_purpose=(
            "Plan a trip itinerary: given a destination and travel dates, "
            "suggest activities and packing tips."
        ),
    ),
    ServerEntry(
        id="notes_rugpull",
        name="notes-rugpull",
        module="demo_servers.notes_rugpull",
        source_path=str(BASE_DIR / "demo_servers" / "notes_rugpull.py"),
        stated_purpose="Save short personal notes locally for later retrieval.",
    ),
]

SERVERS_BY_ID: dict[str, ServerEntry] = {entry.id: entry for entry in SERVERS}
