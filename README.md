# PC Diagnostics development project

This is an editable project copy of the installed PC Diagnostics application.
The maintained application sources are in [`app/`](app/); its feature and
privacy documentation is in [`app/README.md`](app/README.md).

## Run from this checkout

The repository launcher uses the normal XDG data location by default, the same
database as the installed application and background collector. This preserves
the retained incident history and live telemetry:

```sh
./scripts/run.sh
```

For an isolated development database, explicitly request it. It is intentionally
empty until a collector samples the host:

```sh
./scripts/run.sh --isolated
XDG_DATA_HOME="$PWD/.data" PYTHONDONTWRITEBYTECODE=1 python3 app/pcdiag_collector.py --once
```

The GTK GUI depends on the system-provided Python GObject bindings and GTK 4 /
Libadwaita. They are intentionally not declared as PyPI dependencies.

## Release checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -c '\
from pathlib import Path; \
[compile(path.read_text(), str(path), "exec") for path in Path("app").glob("*.py")]'
```

Run the dependency-free regression suite as well:

```sh
PYTHONPATH=app PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Build tooling is not required for normal use, but a release wheel should also
be checked for its desktop, helper, and service assets:

```sh
python3 -m build
python3 tests/verify_wheel.py dist/*.whl
```

`systemd/pc-diagnostics-collector.service.example` is a project-local unit
template. It is not installed or enabled automatically.

## Maintainer workflow

The complete clean-checkout workflow is documented in [`BUILD.md`](BUILD.md).
The repository entry points are deterministic and can be run from any current
working directory:

```sh
./scripts/build.sh
./scripts/run.sh
./scripts/test.sh
./scripts/benchmark.sh
```

The architecture, benchmark method, and recorded hotspots are documented in
[`ARCHITECTURE.md`](ARCHITECTURE.md), [`BENCHMARKS.md`](BENCHMARKS.md), and
[`HOTSPOTS.md`](HOTSPOTS.md).
