#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# The collector and installed desktop application use the normal XDG data
# directory.  Keep that database as the default so this source launcher shows
# the user's retained incidents and telemetry too.  An isolated store remains
# available for safe development experiments.
if [ "${1-}" = "--isolated" ]; then
  shift
  exec env \
    XDG_DATA_HOME="$ROOT/.data" \
    GSK_RENDERER=gl \
    PYTHONDONTWRITEBYTECODE=1 \
    python3 "$ROOT/app/pc_diagnostics.py" "$@"
fi

exec env \
  GSK_RENDERER=gl \
  PYTHONDONTWRITEBYTECODE=1 \
  python3 "$ROOT/app/pc_diagnostics.py" "$@"
