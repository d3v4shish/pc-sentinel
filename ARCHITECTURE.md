# Architecture

PC Diagnostics is a local Linux application with a GTK/libadwaita GUI, a
user-level collector, and two optional root-owned socket helpers.

## Components and data flow

- `app/pc_diagnostics.py` owns the GUI. It reads current state and paginated
  evidence through `pcdiag_presenters.py`, opens short-lived read-only SQLite
  connections for stored refreshes, and samples inexpensive CPU/memory/disk
  overview values directly from `/proc` once per second while visible.
- `app/pcdiag_collector.py` is the long-running user service. It performs a
  bounded journal backfill, follows new journal records, samples local health
  metrics, and runs scheduled system scans.
- `app/pcdiag_engine.py` contains the v4 SQLite schema, incident correlation,
  metric rollups, retention, helper requests, and report redaction. Shared
  classification and filesystem permissions live in `pcdiag_common.py`.
- `app/pcdiag_helper.py` is the read-only root helper. It accepts one bounded
  JSON request per connection and exposes only allowlisted SMART, dmesg, DMI,
  crash, and protected-log operations.
- `app/pcdiag_tuning_helper.py` is a separate, opt-in privileged helper. Its
  interface is limited to validated CPU policy and NVIDIA factory power-limit
  operations, with a process lock and baseline restoration.

The normal flow is:

```text
journald and local probes
        -> collector -> engine -> private SQLite database
        -> GUI presenters -> GTK views

GUI/collector -> Unix helper socket -> bounded helper response -> database/UI
```

Raw journals remain in journald and protected logs remain in their original
locations. The application stores correlated evidence, current-state scan
snapshots, metric rollups, and audit records in the per-user SQLite database.

## Interfaces and boundaries

- The Python modules communicate through direct function calls and typed
  dictionaries/dataclasses; the packaged console entry points are defined in
  `pyproject.toml`.
- The collector and GUI use SQLite. The collector keeps a persistent writer
  connection; GUI refreshes use read-only connections with a busy timeout.
- Incident fingerprints aggregate repeated evidence. Notification delivery is
  persisted per fingerprint with a cooldown and severity history, while the
  desktop notification carries a stable replacement key so repeated alerts do
  not stack. Failed notification delivery is not recorded as delivered.
- Incident acknowledgement and manual resolution are local database state;
  newer evidence reopens an incident and clears its acknowledgement.
- Root helpers communicate over Unix domain sockets using one newline-delimited
  JSON request and one bounded JSON response. No remote application protocol
  or telemetry endpoint is used.
- System boundaries are explicit subprocess calls to tools such as
  `journalctl`, `systemctl`, `smartctl`, `fwupdmgr`, and `apt`, plus reads from
  `/proc`, `/sys`, and allowlisted log paths.

## Concurrency and design decisions

- The collector schedules scans in its service process and uses background
  threads for journal reading/following so bounded backfill cannot prevent live
  collection.
- GUI background queries carry request generations and discard stale results;
  window timers and callbacks are removed or ignored when the window closes.
- The one-second overview sampler does not invoke sensors or GPU tools and
  does not write to SQLite; high-cost hardware telemetry remains collector
  work at its ten-second storage cadence.
- SQLite WAL mode, checkpointed journal offsets, bounded queues, pagination,
  and response budgets bound startup, memory, and transport pressure.
- Current-state scans update in place when their health state is unchanged;
  transitions retain history. High-resolution metrics and forensic evidence
  have separate retention policies.
- Database, report, helper, and tuning state use owner-only permissions. Raw
  data is not copied into reports without redaction, and privileged actions
  are allowlisted, audited, reversible, and opt-in.
