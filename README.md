# PC Diagnostics development project

This is an editable project copy of the installed PC Diagnostics application.
The maintained application sources are in [`app/`](app/); its feature and
privacy documentation is in [`app/README.md`](app/README.md).

## Safe local development

Run the GUI with an isolated data directory so development does not write to
the live diagnostic database:

```sh
XDG_DATA_HOME="$PWD/.data" GSK_RENDERER=gl python3 app/pc_diagnostics.py
```

Run the collector once against that same isolated database:

```sh
XDG_DATA_HOME="$PWD/.data" python3 app/pcdiag_collector.py --once
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
