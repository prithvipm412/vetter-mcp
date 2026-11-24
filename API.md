# Vetter API contract (backend ↔ frontend)

Base URL: http://localhost:8000

| Method | Path | Returns |
|---|---|---|
| GET  | /api/servers | `[{id, name, verdict, labels[], status}]` |
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
| POST | /api/demo/reset | resets demo state |
| POST | /api/demo/rugpull/on | turns on the notes tool change |
| POST | /api/demo/rugpull/off | turns it off |

**verdict:** `looks_ok` | `review` | `high_risk`
**status:** `new` | `approved` | `blocked` | `paused_changed`

## Ownership
- Claude Code → `vetter/`, `demo_servers/`, `tests/` (backend, FastAPI on port 8000)
- Codex → `web/` (React + Vite + TypeScript + Tailwind on port 5173)
- Neither edits the other's folders. Both follow this contract exactly.
