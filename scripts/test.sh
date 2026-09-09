#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PYTHONDONTWRITEBYTECODE=1 python3 -c \
  'from pathlib import Path; [compile(path.read_text(), str(path), "exec") for path in Path("app").glob("*.py")]'
PYTHONPATH="$ROOT/app" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests -v
