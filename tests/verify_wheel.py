#!/usr/bin/env python3
"""Fail the release build when documented deployment assets are absent."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path


EXPECTED_SUFFIXES = {
    "share/applications/io.github.d3v.PCDiagnostics.desktop",
    "share/metainfo/io.github.d3v.PCDiagnostics.metainfo.xml",
    "share/xdg/autostart/io.github.d3v.PCDiagnostics.autostart.desktop",
    "share/pc-diagnostics/helpers/install-helper.sh",
    "share/pc-diagnostics/helpers/pcdiag_helper.py",
    "share/pc-diagnostics/helpers/pcdiag_tuning_helper.py",
    "share/pc-diagnostics/helpers/pc-diagnostics-helper@.service",
    "share/pc-diagnostics/helpers/pc-diagnostics-helper.socket.in",
    "share/pc-diagnostics/helpers/pc-diagnostics-tuning@.service",
    "share/pc-diagnostics/helpers/pc-diagnostics-tuning.socket.in",
    "share/pc-diagnostics/systemd/pc-diagnostics-collector.service.example",
}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} WHEEL", file=sys.stderr)
        return 2
    with zipfile.ZipFile(sys.argv[1]) as archive:
        names = set(archive.namelist())
    missing = sorted(
        suffix for suffix in EXPECTED_SUFFIXES if not any(name.endswith(suffix) for name in names)
    )
    if missing:
        print("Wheel is missing deployment assets:", *missing, sep="\n", file=sys.stderr)
        return 1
    print("Wheel includes all deployment assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
