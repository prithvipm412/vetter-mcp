#!/usr/bin/env bash
# Start the vetter backend (:8000) and the dashboard frontend (:5173) together.
# Ctrl+C stops both.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[dev]"

if [ -d "web/node_modules" ]; then
    : # already installed
elif [ -d "web" ]; then
    (cd web && npm install --silent)
fi

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    trap - INT TERM EXIT
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

uvicorn vetter.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

if [ -d "web" ]; then
    (cd web && npm run dev) &
    FRONTEND_PID=$!
fi

wait
