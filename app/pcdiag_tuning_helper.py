#!/usr/bin/env python3
"""Root-owned, capability-gated tuning helper for PC Diagnostics.

This deliberately exposes a tiny reversible surface: CPU cpufreq governor and
kernel-reported min/max frequency bounds, plus an NVIDIA power cap only when
the driver reports a factory range.  It does not expose voltage, clock offset,
fan, PBO, firmware, or arbitrary command controls.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
import fcntl
from pathlib import Path
from typing import Any


MAX_REQUEST = 64 * 1024
MAX_RESPONSE = 512 * 1024
CPUFREQ_ROOT = Path("/sys/devices/system/cpu/cpufreq")
BOOST_PATH = CPUFREQ_ROOT / "boost"
BASELINE_PATH = Path("/var/lib/pc-diagnostics/tuning-baseline.json")
LOCK_PATH = BASELINE_PATH.with_suffix(".lock")
NVIDIA_SMI = Path("/usr/bin/nvidia-smi")
POLICY_NAME = re.compile(r"^policy(\d+)$")


class TuningError(ValueError):
    pass


@contextmanager
def exclusive_tuning_lock():
    """Serialize socket-activated apply/restore requests across processes."""
    descriptor = -1
    try:
        BASELINE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(BASELINE_PATH.parent, 0o700)
        descriptor = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
        os.chmod(LOCK_PATH, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise TuningError(f"unable to acquire tuning lock: {exc}") from exc
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def read_int(path: Path) -> int | None:
    try:
        return int(read_text(path))
    except ValueError:
        return None


def write_text(path: Path, value: str) -> None:
    try:
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise TuningError(f"unable to write {path.name}: {exc}") from exc


def run(command: list[str], timeout: int = 12) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout.decode("utf-8", "replace")[:64 * 1024]
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def cpu_policies() -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    try:
        paths = sorted(CPUFREQ_ROOT.glob("policy*"), key=lambda item: item.name)
    except OSError:
        paths = []
    for path in paths:
        match = POLICY_NAME.fullmatch(path.name)
        if not match:
            continue
        cpuinfo_min = read_int(path / "cpuinfo_min_freq")
        cpuinfo_max = read_int(path / "cpuinfo_max_freq")
        minimum = read_int(path / "scaling_min_freq")
        maximum = read_int(path / "scaling_max_freq")
        if None in (cpuinfo_min, cpuinfo_max, minimum, maximum):
            continue
        governors = read_text(path / "scaling_available_governors").split()
        policies.append({
            "id": int(match.group(1)),
            "cpuinfo_min_khz": cpuinfo_min,
            "cpuinfo_max_khz": cpuinfo_max,
            "min_khz": minimum,
            "max_khz": maximum,
            "governor": read_text(path / "scaling_governor"),
            "available_governors": governors,
        })
    return policies


def boost_state() -> dict[str, Any]:
    value = read_text(BOOST_PATH)
    if value not in ("0", "1"):
        return {"available": False, "enabled": None}
    return {"available": os.access(BOOST_PATH, os.W_OK), "enabled": value == "1"}


def parse_watts(value: str) -> float | None:
    value = value.strip()
    if not value or value.upper() in ("N/A", "NOT SUPPORTED", "UNKNOWN"):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def gpu_state() -> dict[str, Any]:
    if not NVIDIA_SMI.is_file():
        return {"available": False, "gpus": [], "error": "nvidia-smi is not installed"}
    status, output = run([
        str(NVIDIA_SMI),
        "--query-gpu=index,name,power.limit,power.default_limit,power.min_limit,power.max_limit",
        "--format=csv,noheader,nounits",
    ])
    if status != 0:
        return {"available": False, "gpus": [], "error": output.strip()[:500] or "NVIDIA driver is unavailable"}
    gpus: list[dict[str, Any]] = []
    for line in output.splitlines():
        values = [part.strip() for part in line.split(",")]
        if len(values) != 6:
            continue
        try:
            index = int(values[0])
        except ValueError:
            continue
        current, default, minimum, maximum = (parse_watts(value) for value in values[2:])
        supported = None not in (current, default, minimum, maximum) and float(minimum) <= float(maximum)
        gpus.append({
            "index": index,
            "name": values[1],
            "power_limit_watts": current,
            "default_power_limit_watts": default,
            "min_power_limit_watts": minimum,
            "max_power_limit_watts": maximum,
            "power_limit_supported": supported,
        })
    if not gpus:
        return {"available": False, "gpus": [], "error": "NVIDIA did not return a readable GPU power state"}
    return {"available": True, "gpus": gpus, "error": ""}


def load_baseline() -> dict[str, Any] | None:
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("state"), dict) else None


def write_baseline(state: dict[str, Any]) -> None:
    BASELINE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BASELINE_PATH.parent, 0o700)
    temporary = BASELINE_PATH.with_suffix(".tmp")
    payload = {"version": 1, "created_us": int(time.time() * 1_000_000), "state": state}
    try:
        temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, BASELINE_PATH)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise TuningError(f"unable to preserve tuning baseline: {exc}") from exc


def state() -> dict[str, Any]:
    baseline = load_baseline()
    policies = cpu_policies()
    return {
        "ok": True,
        "operation": "state",
        "cpu": {"available": bool(policies), "policies": policies, "boost": boost_state()},
        "gpu": gpu_state(),
        "baseline_active": baseline is not None,
        "baseline_created_us": baseline.get("created_us") if baseline else None,
    }


def as_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise TuningError(f"{label} must be an integer")
    try:
        converted = int(value)
    except (TypeError, ValueError) as exc:
        raise TuningError(f"{label} must be an integer") from exc
    if str(converted) != str(value).strip() and not isinstance(value, int):
        raise TuningError(f"{label} must be an integer")
    return converted


def set_cpu_policy(policy: dict[str, Any], governor: str, minimum: int, maximum: int) -> None:
    path = CPUFREQ_ROOT / f"policy{policy['id']}"
    if minimum > maximum:
        raise TuningError("CPU minimum frequency cannot exceed maximum frequency")
    if minimum < int(policy["cpuinfo_min_khz"]) or maximum > int(policy["cpuinfo_max_khz"]):
        raise TuningError(f"CPU frequency request is outside policy{policy['id']}'s hardware range")
    if governor not in policy.get("available_governors", []):
        raise TuningError(f"CPU governor {governor!r} is not available on policy{policy['id']}")
    current_min = int(policy["min_khz"])
    current_max = int(policy["max_khz"])
    # Keep each intermediate kernel setting valid while narrowing or widening.
    if current_min > minimum:
        write_text(path / "scaling_min_freq", str(minimum))
    if current_max < maximum:
        write_text(path / "scaling_max_freq", str(maximum))
    write_text(path / "scaling_governor", governor)
    write_text(path / "scaling_min_freq", str(minimum))
    write_text(path / "scaling_max_freq", str(maximum))


def validate_cpu(request: dict[str, Any], policies: list[dict[str, Any]], boost: dict[str, Any]) -> None:
    if not request:
        return
    if not policies:
        raise TuningError("CPU frequency controls are not exposed by this system")
    governor = request.get("governor")
    minimum = request.get("min_khz")
    maximum = request.get("max_khz")
    if not isinstance(governor, str) or not governor:
        raise TuningError("a CPU governor is required")
    minimum = as_int(minimum, "CPU minimum frequency")
    maximum = as_int(maximum, "CPU maximum frequency")
    for policy in policies:
        if minimum > maximum:
            raise TuningError("CPU minimum frequency cannot exceed maximum frequency")
        if minimum < int(policy["cpuinfo_min_khz"]) or maximum > int(policy["cpuinfo_max_khz"]):
            raise TuningError(f"CPU frequency request is outside policy{policy['id']}'s hardware range")
        if governor not in policy.get("available_governors", []):
            raise TuningError(f"CPU governor {governor!r} is not available on policy{policy['id']}")
    if "boost" in request:
        if not isinstance(request["boost"], bool) or not boost.get("available"):
            raise TuningError("CPU boost control is not available")


def apply_cpu(request: dict[str, Any]) -> None:
    if not request:
        return
    policies = cpu_policies()
    validate_cpu(request, policies, boost_state())
    governor = str(request["governor"])
    minimum = as_int(request["min_khz"], "CPU minimum frequency")
    maximum = as_int(request["max_khz"], "CPU maximum frequency")
    for policy in policies:
        set_cpu_policy(policy, governor, minimum, maximum)
    if "boost" in request:
        write_text(BOOST_PATH, "1" if request["boost"] else "0")


def validate_gpu(request: dict[str, Any], current: dict[str, Any]) -> None:
    if not request:
        return
    index = as_int(request.get("index"), "NVIDIA GPU index")
    limit = as_int(request.get("power_limit_watts"), "NVIDIA power limit")
    gpu = next((item for item in current.get("gpus", []) if item.get("index") == index), None)
    if not current.get("available") or not gpu or not gpu.get("power_limit_supported"):
        raise TuningError("NVIDIA factory power-limit control is unavailable")
    minimum = float(gpu["min_power_limit_watts"])
    maximum = float(gpu["max_power_limit_watts"])
    if not minimum <= limit <= maximum:
        raise TuningError(f"NVIDIA power limit must be within the reported {minimum:.0f}–{maximum:.0f} W range")


def apply_gpu(request: dict[str, Any]) -> None:
    if not request:
        return
    current = gpu_state()
    validate_gpu(request, current)
    index = as_int(request["index"], "NVIDIA GPU index")
    limit = as_int(request["power_limit_watts"], "NVIDIA power limit")
    status, output = run([str(NVIDIA_SMI), "-i", str(index), "-pl", str(limit)])
    if status != 0:
        raise TuningError(output.strip()[:500] or "NVIDIA rejected the requested power limit")


def restore_baseline(baseline: dict[str, Any]) -> list[str]:
    saved = baseline.get("state", {})
    errors: list[str] = []
    saved_cpu = saved.get("cpu", {}) if isinstance(saved, dict) else {}
    saved_policies = saved_cpu.get("policies", []) if isinstance(saved_cpu, dict) else []
    current_by_id = {item["id"]: item for item in cpu_policies()}
    for original in saved_policies if isinstance(saved_policies, list) else []:
        if not isinstance(original, dict):
            continue
        policy = current_by_id.get(original.get("id"))
        if not policy:
            errors.append(f"CPU policy{original.get('id', '?')} is no longer available")
            continue
        try:
            set_cpu_policy(policy, str(original.get("governor", "")), int(original["min_khz"]), int(original["max_khz"]))
        except (KeyError, TypeError, ValueError, TuningError) as exc:
            errors.append(str(exc))
    boost = saved_cpu.get("boost", {}) if isinstance(saved_cpu, dict) else {}
    if isinstance(boost, dict) and isinstance(boost.get("enabled"), bool):
        if boost_state().get("available"):
            try:
                write_text(BOOST_PATH, "1" if boost["enabled"] else "0")
            except TuningError as exc:
                errors.append(str(exc))
        else:
            errors.append("CPU boost control is no longer available")
    saved_gpu = saved.get("gpu", {}) if isinstance(saved, dict) else {}
    for original in saved_gpu.get("gpus", []) if isinstance(saved_gpu, dict) else []:
        if not isinstance(original, dict) or original.get("power_limit_watts") is None:
            continue
        try:
            apply_gpu({"index": original["index"], "power_limit_watts": int(round(float(original["power_limit_watts"])))} )
        except (KeyError, TypeError, ValueError, TuningError) as exc:
            errors.append(str(exc))
    return errors


def _apply_unlocked(parameters: dict[str, Any]) -> dict[str, Any]:
    cpu = parameters.get("cpu", {})
    gpu = parameters.get("gpu", {})
    if not isinstance(cpu, dict) or not isinstance(gpu, dict) or not (cpu or gpu):
        raise TuningError("request must include a CPU and/or NVIDIA configuration")
    current = state()
    # Validate the complete request before creating any persistent baseline or
    # touching a kernel control. A malformed request therefore has no side
    # effects even when issued directly to the socket.
    validate_cpu(cpu, list(current["cpu"].get("policies", [])), dict(current["cpu"].get("boost", {})))
    validate_gpu(gpu, dict(current.get("gpu", {})))
    baseline = load_baseline()
    new_baseline = baseline is None
    if new_baseline:
        write_baseline(current)
        baseline = load_baseline()
    assert baseline is not None
    try:
        apply_cpu(cpu)
        apply_gpu(gpu)
    except TuningError as exc:
        rollback_errors = restore_baseline(baseline)
        if new_baseline and not rollback_errors:
            try:
                BASELINE_PATH.unlink(missing_ok=True)
            except OSError:
                pass
        suffix = f"; rollback warnings: {'; '.join(rollback_errors)}" if rollback_errors else "; restored the prior baseline"
        return {"ok": False, "operation": "apply", "error": f"{exc}{suffix}", "state": state()}
    return {"ok": True, "operation": "apply", "state": state()}


def _restore_unlocked(parameters: dict[str, Any]) -> dict[str, Any]:
    baseline = load_baseline()
    if not baseline:
        return {"ok": True, "operation": "restore", "restored": False, "state": state()}
    errors = restore_baseline(baseline)
    if errors:
        return {"ok": False, "operation": "restore", "error": "; ".join(errors)[:1000], "state": state()}
    try:
        BASELINE_PATH.unlink(missing_ok=True)
    except OSError as exc:
        return {"ok": False, "operation": "restore", "error": f"settings restored but baseline cleanup failed: {exc}", "state": state()}
    return {"ok": True, "operation": "restore", "restored": True, "reason": str(parameters.get("reason", "user-request"))[:240], "state": state()}


def apply(parameters: dict[str, Any]) -> dict[str, Any]:
    with exclusive_tuning_lock():
        return _apply_unlocked(parameters)


def restore(parameters: dict[str, Any]) -> dict[str, Any]:
    with exclusive_tuning_lock():
        return _restore_unlocked(parameters)


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    operation = request.get("operation")
    parameters = request.get("parameters", {})
    if not isinstance(parameters, dict):
        return {"ok": False, "error": "parameters must be an object"}
    try:
        if operation == "state":
            return state()
        if operation == "apply":
            return apply(parameters)
        if operation == "restore":
            return restore(parameters)
        return {"ok": False, "error": "unsupported operation"}
    except TuningError as exc:
        return {"ok": False, "operation": operation, "error": str(exc)}
    except Exception as exc:  # Never leave a socket activation request unanswerable.
        return {"ok": False, "operation": operation, "error": f"helper failure: {exc}"}


def main() -> int:
    raw = sys.stdin.buffer.readline(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        response = {"ok": False, "error": "request too large"}
    else:
        try:
            request = json.loads(raw.decode("utf-8"))
            response = dispatch(request) if isinstance(request, dict) else {"ok": False, "error": "request must be an object"}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            response = {"ok": False, "error": f"invalid JSON: {exc}"}
    encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESPONSE:
        encoded = b'{"ok":false,"error":"response too large"}'
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
