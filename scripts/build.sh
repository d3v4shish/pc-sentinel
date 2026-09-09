#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PYTHONDONTWRITEBYTECODE=1 python3 -c \
  'from pathlib import Path; [compile(path.read_text(), str(path), "exec") for path in Path("app").glob("*.py")]'

if ! python3 -c 'import build' >/dev/null 2>&1; then
  echo "build tooling is missing; run: python3 -m pip install -r requirements-build.txt" >&2
  exit 2
fi
python3 -c \
  'from importlib.metadata import version; expected = {"build": "1.2.2", "setuptools": "75.8.0"}; actual = {name: version(name) for name in expected}; assert actual == expected, f"build tools do not match requirements-build.txt: {actual}"'

python3 -m build --wheel --no-isolation
wheel=$(find "$ROOT/dist" -maxdepth 1 -type f -name '*.whl' -print | sort | tail -n 1)
if [ -z "$wheel" ]; then
  echo "no wheel was produced in dist/" >&2
  exit 1
fi
PYTHONDONTWRITEBYTECODE=1 python3 tests/verify_wheel.py "$wheel"
