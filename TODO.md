# TODO

## Repository workflow compliance — completed

- [x] Add the required build, run, test, and benchmark entry points.
- [x] Document the existing architecture, storage boundaries, and concurrency
      model.
- [x] Add a deterministic dependency-free benchmark and record its result.
- [x] Record the current runtime hotspots without claiming an unmeasured
      performance improvement.

Expected contract: a clean checkout can use the documented scripts from any
working directory; tests and benchmarks use fixed inputs and avoid hidden
machine state; documentation describes the implementation that exists.

Validation: `./scripts/test.sh`, `./scripts/benchmark.sh`, and, after the
pinned build tools are installed, `./scripts/build.sh`.

## GUI theme consistency — completed

- [x] Replace fixed status and confidence colors with Libadwaita semantic
      colors that adapt to the active light/dark theme.
- [x] Use namespaced severity classes so application styles do not override
      GTK/Libadwaita's generic `error` and `warning` classes.
- [x] Give event rows the same adaptive card treatment used by metric cards.

Expected contract: severity, confidence, cards, and repeated event rows use a
single theme-aware visual language without hard-coded light-theme colors.

Validation: GTK CSS provider loading, application compilation, and the full
regression suite pass.

## UI/UX and correctness pass — completed

- [x] Make notification delivery idempotent, escalation-aware, and safe when
      the desktop notification service is unavailable.
- [x] Correct incident acknowledgement/filtering and add explicit local
      resolve/acknowledge actions.
- [x] Prevent stale asynchronous results, duplicate refresh work, and window
      lifecycle callbacks from updating closed UI.
- [x] Fix loaded-log filtering and collector anomaly recovery states.
- [x] Add deterministic regression coverage for each corrected contract.

Expected contract: repeated evidence is grouped without duplicate user
notifications; notification failures do not suppress future alerts; incident
state in the UI matches persisted state; and asynchronous UI results are
applied only to the current request and live window.

Validation: focused unit tests, the full regression suite, compilation, and
GTK CSS loading.

## Live data launcher and compatibility — completed

- [x] Make the source launcher use the standard XDG diagnostic database by
      default, matching the installed application and collector.
- [x] Keep an explicit `--isolated` mode for safe development experiments.
- [x] Verify the retained live database is non-empty and that its older metric
      schema is upgraded when the application starts.

Expected contract: `./scripts/run.sh` displays existing incidents and telemetry
from `~/.local/share/pc-diagnostics/events.sqlite3`; `--isolated` deliberately
uses a separate empty-until-collected `.data/` store.

Validation: launcher argument regression test, shell syntax validation, full
regression suite, and inspection of the live database counts.

## One-second live overview metrics — completed

- [x] Sample CPU, memory, swap, and root-disk use in the visible overview once
      per second without invoking expensive sensor or GPU commands.
- [x] Keep charts and retained telemetry on the collector's existing cadence
      so one-second UI sampling does not increase database growth.
- [x] Add deterministic coverage for CPU-delta and memory/disk calculations.

Expected contract: overview CPU, memory, and disk cards refresh once per second
from the host while the page is visible; historical charts and hardware
telemetry continue to come from the collector database.

Validation: deterministic metric parser test, application compilation, and the
full regression suite.
