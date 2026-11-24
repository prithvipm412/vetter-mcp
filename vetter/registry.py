"""Known MCP servers: the three built-in demo fixtures, plus (at runtime)
whatever POST /api/import found in a real AI assistant's config.

A ``ServerEntry`` is everything vetter needs to launch and reason about a
server, regardless of where it came from: a Python module shipped in
``demo_servers/`` or an arbitrary command imported from someone's real
Claude Desktop / Cursor config.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Literal

from vetter.config import BASE_DIR

Language = Literal["python", "node", "other"]
Kind = Literal["demo", "imported"]


@dataclass(frozen=True)
class ServerEntry:
    id: str
    name: str
    kind: Kind
    command: list[str]
    source_path: str | None
    stated_purpose: str
    language: Language
    env: dict[str, str] | None = None


def guess_language(command: list[str]) -> Language:
    """Best-effort guess at a server's runtime, from its launch command."""
    if not command:
        return "other"
    exe = command[0].lower()
    rest = " ".join(command[1:]).lower()
    if "python" in exe or exe.endswith(".py"):
        return "python"
    if any(marker in exe for marker in ("node", "npx", "npm", "bun", "deno")) or ".js" in rest or ".mjs" in rest:
        return "node"
    return "other"


SERVERS: list[ServerEntry] = [
    ServerEntry(
        id="weather_ok",
        name="weather-ok",
        kind="demo",
        command=[sys.executable, "-m", "demo_servers.weather_ok"],
        source_path=str(BASE_DIR / "demo_servers" / "weather_ok.py"),
        stated_purpose=("Look up the current weather for a city and return a short, plain-text forecast."),
        language="python",
    ),
    ServerEntry(
        id="travel_overreach",
        name="travel-overreach",
        kind="demo",
        command=[sys.executable, "-m", "demo_servers.travel_overreach"],
        source_path=str(BASE_DIR / "demo_servers" / "travel_overreach.py"),
        stated_purpose=(
            "Plan a trip itinerary: given a destination and travel dates, suggest activities and packing tips."
        ),
        language="python",
    ),
    ServerEntry(
        id="notes_rugpull",
        name="notes-rugpull",
        kind="demo",
        command=[sys.executable, "-m", "demo_servers.notes_rugpull"],
        source_path=str(BASE_DIR / "demo_servers" / "notes_rugpull.py"),
        stated_purpose="Save short personal notes locally for later retrieval.",
        language="python",
    ),
]

SERVERS_BY_ID: dict[str, ServerEntry] = {entry.id: entry for entry in SERVERS}

FRIENDLY_NAMES: dict[str, str] = {
    "weather_ok": "Weather",
    "travel_overreach": "Travel Planner",
    "notes_rugpull": "Notes Saver",
}


def friendly_name_for(entry: ServerEntry) -> str:
    """A short, human-facing name for the server list (id stays the stable
    identifier everywhere else). Known demo servers get a curated name;
    anything else (imported servers) gets its raw name title-cased.
    """
    if entry.id in FRIENDLY_NAMES:
        return FRIENDLY_NAMES[entry.id]
    return entry.name.replace("_", " ").replace("-", " ").strip().title() or entry.id
