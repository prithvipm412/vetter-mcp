#!/usr/bin/env bash
# Set up (if needed) and run the vetter FastAPI backend on port 8000.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

exec uvicorn vetter.main:app --host 0.0.0.0 --port 8000 --reload
