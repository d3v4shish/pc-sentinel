# Benchmarks

The repository benchmark is a deterministic regression workload, not a
hardware performance claim. It runs 1,000 iterations over fixed sensor,
NVIDIA, and redaction inputs, checks the parsed record counts, and prints a
SHA-256 digest of the canonical outputs. It uses no clock, randomness, host
devices, database, network, or mutable external data.

Run it with:

```sh
./scripts/benchmark.sh
```

Recorded baseline on 2026-09-09:

```text
benchmark=diagnostic-parser-regression
iterations=1000
sensor_records=2
power_records=2
nvidia_metrics=12
redacted_bytes=78
digest=5312f7f7c4928661b9f40afab2d0b2ea82488ecff68f851b132f32c19d3dc84c
```

The digest is intentionally emitted by the script rather than used as a
machine-specific timing threshold. A changed digest or failed count assertion
indicates a behavioral change that should be reviewed alongside the tests.

This compliance change adds documentation and tooling only; it does not claim
a runtime performance improvement or require a profile comparison.

The subsequent UI/UX and collector-correctness pass was rerun with the same
fixed workload on 2026-09-09. Counts and digest were unchanged, so no parser
performance regression was observed; no runtime speedup is claimed.
