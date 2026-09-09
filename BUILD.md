# Build and run

PC Diagnostics targets Python 3.11 or newer. The GUI additionally requires
the system Python GObject bindings, GTK 4, and Libadwaita. Those system
libraries are intentionally not installed by the Python package.

## Clean checkout

From the repository root, install the pinned build tools in the environment
used for packaging:

```sh
python3 -m pip install -r requirements-build.txt
```

The build entry point uses those tools without creating a second environment.
It compiles the application, creates a wheel, and verifies all packaged
deployment assets:

```sh
./scripts/build.sh
```

The wheel is written to `dist/`. The build does not access the application
database or host diagnostic services.

## Run

Use the repository wrapper to open the normal XDG data directory, shared with
the installed application and background collector:

```sh
./scripts/run.sh
```

The existing schema is migrated before the window opens. To use the ignored
`.data/` development database instead, pass `--isolated`. The collector can be
run against that isolated directory with:

```sh
./scripts/run.sh --isolated
XDG_DATA_HOME="$PWD/.data" PYTHONDONTWRITEBYTECODE=1 \
  python3 app/pcdiag_collector.py --once
```

## Test

The test wrapper compiles every application module and runs the dependency-free
regression suite:

```sh
./scripts/test.sh
```

Tests use fixed inputs, temporary databases, and mocked host boundaries. They
do not require GTK, systemd, journald, root privileges, or network access.

## Benchmark

The benchmark wrapper runs a fixed parser and redaction workload without wall
clock measurements or random input:

```sh
./scripts/benchmark.sh
```

It prints exact workload counts and a digest. This is a deterministic
regression benchmark, not a claim about hardware-specific throughput.
