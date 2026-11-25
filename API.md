# Vetter API contract (backend ↔ frontend)

Base URL: http://localhost:8000

| Method | Path | Returns |
|---|---|---|
| GET  | /api/servers | `[{id, name, friendly_name, verdict, labels[], status}]` |
| GET  | /api/servers/{id} | `{static_findings[], behaviour, claim_vs_behaviour}` |
| POST | /api/servers/{id}/scan | runs static + sandbox, returns report |
| POST | /api/servers/{id}/approve | updated server |
| POST | /api/servers/{id}/block | updated server |
| POST | /api/servers/{id}/revoke | updated server |
| GET  | /api/servers/{id}/changes | `{old_description, new_description, diff}` |
| POST | /api/servers/{id}/changes/allow | updated server |
| GET  | /api/incidents?server={id} | `[{time, type, tool, detail}]` |
| POST | /api/protect | result of config rewrite |
| POST | /api/protect/undo | result of restore |
| POST | /api/import | `{config_paths?: string[]}` → imports every server from the real Claude Desktop config plus any extra config paths given, scans each one, returns `{sources[], servers[], imported_count}` |
| POST | /api/demo/reset | resets demo state |
| POST | /api/demo/rugpull/on | turns on the notes tool change |
| POST | /api/demo/rugpull/off | turns it off |

**verdict:** `looks_ok` | `review` | `high_risk`
**status:** `new` | `approved` | `blocked` | `paused_changed`

The scan response includes `sandbox_mode` (`docker` or `lite`) at top level and in `behaviour`. Docker is used when available; otherwise Python falls back to lite mode. Imported Node/npx and Python servers run dynamically in Docker.

**name** is the server's raw/technical name (e.g. `weather-ok`). **friendly_name**
is a short human-facing name for the same server (e.g. `Weather`) — use it for
display; **id** is the stable identifier to use in every other call and never
changes.

**labels[]** on `GET /api/servers` (and on the `scan` response, which shares
`ServerSummary`'s shape) are short, plain-language phrases meant for a
non-developer, e.g. `"Hidden instructions to the AI"`, `"Can read your SSH
keys"`, `"Can read your passwords file"`, `"Can access your email"`,
`"Can contact unknown servers"`. The technical version of each finding
(category, severity, exact pattern matched, detail) lives in
`static_findings` on `GET /api/servers/{id}` and the `scan` response —
that's where to drill into specifics, not the summary list.

## Errors

Every error response is JSON, never a raw stack trace:

```json
{"error": {"type": "http_error", "detail": "unknown server id: foo"}}
```

`type` is one of `validation_error` (422, malformed request body),
`http_error` (4xx, e.g. unknown server id or an upstream MCP server that
wouldn't start), or `internal_error` (500, generic message only — the full
traceback goes to `logs/vetter.log`, never to the client).

## CORS

Allowed origins default to `http://localhost:5173` and `http://localhost:5174`
(the Vite dev server's usual port, plus a fallback if that port is taken).
Override with the `VETTER_CORS_ORIGINS` env var (comma-separated) — see
`.env.example`.

## Ownership
- Claude Code → `vetter/`, `demo_servers/`, `tests/` (backend, FastAPI on port 8000)
- Codex → `web/` (React + Vite + TypeScript + Tailwind on port 5173)
- Neither edits the other's folders. Both follow this contract exactly.
