#!/usr/bin/env bash
# Fresh reset, then run all 3 vetter demo scenarios end to end and print a
# summary table. Thin wrapper around `vetter demo` - see vetter/demo_runner.py
# for what each scenario actually does.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[dev]"

exec vetter demo
