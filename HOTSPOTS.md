# Hotspots

This is the current runtime hotspot inventory. It is based on the data flow
and bounded interfaces in the implementation, not on an unmeasured claim of
speedup.

- I/O: journal backfill/following and scheduled probes in
  `app/pcdiag_collector.py` are the main host I/O sources. SMART and firmware
  scans can be especially expensive because they invoke external tools.
- CPU: rule matching, message normalization/redaction, and sensor/NVIDIA
  parsing in `app/pcdiag_engine.py` and `app/pcdiag_common.py` process the
  highest-volume text paths. The visible overview also performs bounded
  `/proc` and filesystem reads once per second; it avoids sensor and GPU
  subprocesses and makes no database writes.
- Storage: SQLite incident/evidence inserts and metric rollups are the main
  persistent-write path. WAL mode and retention pruning bound growth.
- Memory/transport: the collector queue, paginated GUI queries, and helper
  response budgets limit burst and multi-device expansion.
- Contention: the collector is the persistent writer; GUI readers are
  read-only, and tuning apply/restore requests share an exclusive process
  lock.
- Network: the application has no remote telemetry client. External system
  commands, particularly firmware/update tooling, may have their own host
  network behavior and remain outside the application protocol.

For future meaningful runtime changes, record a fixed-input baseline, profile
the affected path, identify the hotspot, make the smallest change, and rerun
`./scripts/benchmark.sh` plus the regression suite. This repository-compliance
change did not alter runtime code, so no performance improvement is claimed.
