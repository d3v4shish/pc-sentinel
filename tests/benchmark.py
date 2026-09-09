#!/usr/bin/env python3
"""Deterministic parser/redaction workload for the repository benchmark."""

from __future__ import annotations

import hashlib
import json

from pcdiag_engine import parse_nvidia_metrics, parse_power_sensor_data, parse_sensor_data, redact


ITERATIONS = 1_000
SENSORS = {
    "nvme-pci-0100": {"Composite": {"temp1_input": 35.0}},
    "nvme-pci-0200": {"Composite": {"temp1_input": 42.0}},
}
POWER = {
    "amdgpu-pci-0100": {"PPT": {"power1_input": 40.0}},
    "amdgpu-pci-0200": {"PPT": {"power1_input": 55.0}},
}
NVIDIA = "0, 10, 60, 100, 1000, 40, 200\n1, 20, 70, 200, 1000, 50, 250\n"
PRIVATE_TEXT = (
    'UUID: 123e4567-e89b-12d3-a456-426614174000\n'
    '"serial_number":"NVME-SECRET-123" alice@example.com token=credential'
)


def main() -> int:
    digest = hashlib.sha256()
    redacted_bytes = 0
    sensor_count = power_count = nvidia_count = 0
    for _ in range(ITERATIONS):
        sensors = parse_sensor_data(SENSORS)
        power = parse_power_sensor_data(POWER)
        nvidia = parse_nvidia_metrics(NVIDIA)
        redacted = redact(PRIVATE_TEXT)
        sensor_count += len(sensors)
        power_count += len(power)
        nvidia_count += len(nvidia)
        redacted_bytes += len(redacted.encode("utf-8"))
        digest.update(json.dumps(
            {"sensors": sensors, "power": power, "nvidia": nvidia, "redacted": redacted},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))

    expected = {
        "sensor_records": ITERATIONS * 2,
        "power_records": ITERATIONS * 2,
        "nvidia_metrics": ITERATIONS * 12,
    }
    actual = {
        "sensor_records": sensor_count,
        "power_records": power_count,
        "nvidia_metrics": nvidia_count,
    }
    if actual != expected:
        raise AssertionError(f"unexpected parser counts: {actual} != {expected}")
    print("benchmark=diagnostic-parser-regression")
    print(f"iterations={ITERATIONS}")
    print("sensor_records=2")
    print("power_records=2")
    print("nvidia_metrics=12")
    print(f"redacted_bytes={redacted_bytes // ITERATIONS}")
    print(f"digest={digest.hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
