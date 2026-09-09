#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHONPATH="$ROOT/app" PYTHONDONTWRITEBYTECODE=1 python3 tests/benchmark.py
