#!/usr/bin/env python3
"""Root-owned, read-only helper for PC Diagnostics.

The helper accepts exactly one size-limited JSON request on stdin and emits one
JSON response. It never accepts commands, arbitrary paths, or write operations.
"""

from __future__ import annotations

import collections
import gzip
import heapq
import json
import lzma
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator


MAX_REQUEST = 64 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
SMART_RESPONSE_BUDGET = MAX_RESPONSE - 512 * 1024
SMART_MIN_DEVICE_OUTPUT = 16 * 1024
SMART_MAX_DEVICE_OUTPUT = 512 * 1024
SMART_RESULT_OVERHEAD = 2 * 1024
CRASH_ENTRY_LIMIT = 2000
CRASH_RESPONSE_BUDGET = 4 * 1024 * 1024
PROTECTED_LOG_RESPONSE_BUDGET = 4 * 1024 * 1024
MAX_LOG_SOURCE_BYTES = 64 * 1024 * 1024
MAX_LOG_LINE_CHARS = 64 * 1024
DEVICE_RE = re.compile(r"^(?:nvme\d+n\d+|sd[a-z]+|vd[a-z]+)$")
LOG_SOURCES = {
    "auth": (Path("/var/log/auth.log"), Path("/var/log/auth.log.1")),
    "apt": (Path("/var/log/apt/term.log"), Path("/var/log/apt/history.log")),
    "dpkg": (Path("/var/log/dpkg.log"), Path("/var/log/dpkg.log.1")),
    "xorg": (Path("/var/log/Xorg.0.log"), Path("/var/log/Xorg.0.log.old")),
}


def run(command: list[str], timeout: int = 20, limit: int = MAX_RESPONSE // 2) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            timeout=timeout,
            check=False,
        )
        output = completed.stdout[:limit].decode("utf-8", "replace")
        return {"exit_status": completed.returncode, "output": output, "truncated": len(completed.stdout) > limit}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"exit_status": 127, "output": "", "error": str(exc)}


def devices() -> list[Path]:
    found = []
    try:
        for item in Path("/sys/class/block").iterdir():
            if DEVICE_RE.fullmatch(item.name) and not (item / "partition").exists():
                device = Path("/dev") / item.name
                if device.exists():
                    found.append(device)
    except OSError:
        return []
    return sorted(found)


def smart() -> dict[str, Any]:
    device_list = devices()
    if not device_list:
        return {"ok": False, "operation": "smart", "results": [], "error": "no supported block devices found"}
    # The transport has one response limit, not one limit per disk.  Budget
    # each invocation from the complete inventory and leave room for JSON
    # structure so a many-drive system still receives usable results.
    device_limit = min(
        SMART_MAX_DEVICE_OUTPUT,
        max(SMART_MIN_DEVICE_OUTPUT, SMART_RESPONSE_BUDGET // len(device_list) - SMART_RESULT_OVERHEAD),
    )
    results: list[dict[str, Any]] = []
    omitted = 0
    for device in device_list:
        result = run(["/usr/sbin/smartctl", "-a", "-j", str(device)], timeout=30, limit=device_limit)
        output = str(result.get("output", ""))[:device_limit]
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"raw_output": output}
        item = {
            "device": str(device),
            "exit_status": result.get("exit_status"),
            "data": data,
            "error": result.get("error", ""),
            "truncated": bool(result.get("truncated")) or len(str(result.get("output", ""))) > len(output),
        }
        # Guard against tool output which expands while parsed as JSON or an
        # unexpectedly large device inventory.  Never turn a partial SMART
        # inventory into an invalid all-or-nothing helper response.
        candidate = {"ok": True, "operation": "smart", "results": [*results, item], "error": ""}
        if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > SMART_RESPONSE_BUDGET:
            omitted += 1
            continue
        results.append(item)
    unavailable = [
        item for item in results
        if int(item.get("exit_status", 127) or 0) & 0b11 or not isinstance(item.get("data"), dict)
    ]
    error_parts = []
    if unavailable:
        error_parts.append(f"SMART unavailable for {len(unavailable)} device(s)")
    if omitted:
        error_parts.append(f"results omitted for {omitted} device(s) to keep the response bounded")
    return {
        "ok": not unavailable,
        "operation": "smart",
        "results": results,
        "error": "; ".join(error_parts),
    }


def dmesg() -> dict[str, Any]:
    # Control characters can expand sixfold when JSON-escaped. Keep enough
    # headroom that even hostile-looking kernel text fits the outer limit.
    result = run(["/usr/bin/dmesg", "--json", "--decode", "--reltime"], timeout=15, limit=1 * 1024 * 1024)
    if result.get("exit_status") != 0:
        result = run(["/usr/bin/dmesg", "--decode", "--ctime"], timeout=15, limit=1 * 1024 * 1024)
    return {"ok": result.get("exit_status") == 0, "operation": "dmesg", **result}


def dmi() -> dict[str, Any]:
    result = run(
        ["/usr/sbin/dmidecode", "--type", "bios", "--type", "system", "--type", "baseboard", "--type", "memory"],
        timeout=15,
        limit=1 * 1024 * 1024,
    )
    return {"ok": result.get("exit_status") == 0, "operation": "dmi", **result}


def open_lines(path: Path) -> Iterator[str]:
    if path.suffix == ".gz":
        stream = gzip.open(path, "rt", encoding="utf-8", errors="replace")
    elif path.suffix in (".xz", ".lzma"):
        stream = lzma.open(path, "rt", encoding="utf-8", errors="replace")
    else:
        stream = path.open("rt", encoding="utf-8", errors="replace")
    with stream:
        consumed = 0
        for _index in range(1_000_000):
            remaining = MAX_LOG_SOURCE_BYTES - consumed
            if remaining <= 0:
                break
            line = stream.readline(min(MAX_LOG_LINE_CHARS + 1, remaining + 1))
            if not line:
                break
            consumed += len(line)
            yield line.rstrip("\n")


def protected_log(parameters: dict[str, Any]) -> dict[str, Any]:
    source = str(parameters.get("source", ""))
    if source not in LOG_SOURCES:
        return {"ok": False, "error": "unsupported log source"}
    query = str(parameters.get("query", ""))[:200].lower()
    try:
        limit = max(1, min(2000, int(parameters.get("lines", 500))))
    except (TypeError, ValueError):
        limit = 500
    selected: collections.deque[tuple[str, int]] = collections.deque()
    selected_bytes = 0
    for path in LOG_SOURCES[source]:
        if not path.is_file():
            continue
        try:
            for line in open_lines(path):
                if not query or query in line.lower():
                    line = line[:MAX_LOG_LINE_CHARS]
                    # Count its serialized representation, not raw UTF-8:
                    # control characters may expand to ``\\u00xx`` in JSON.
                    size = len(json.dumps(line, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                    selected.append((line, size))
                    selected_bytes += size
                    while selected and (len(selected) > limit or selected_bytes > PROTECTED_LOG_RESPONSE_BUDGET):
                        _discarded, discarded_size = selected.popleft()
                        selected_bytes -= discarded_size
        except (OSError, EOFError, lzma.LZMAError):
            continue
    return {"ok": True, "operation": "protected_log", "source": source, "lines": [line for line, _size in selected]}


def crash_metadata(path: Path) -> dict[str, str]:
    fields = {}
    allowed = {
        "ProblemType", "Date", "ExecutablePath", "Package", "Signal", "Title",
        "Failure", "OopsText", "Architecture", "DistroRelease", "ProcCmdline",
    }
    try:
        with path.open("rt", encoding="utf-8", errors="replace") as stream:
            for _index in range(5000):
                line = stream.readline(MAX_LOG_LINE_CHARS + 1)
                if not line:
                    break
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key in allowed:
                    fields[key] = value.strip()[:2000]
    except (OSError, UnicodeError):
        pass
    return fields


def crash_text(parameters: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded preview of an allowlisted captured kernel log."""
    requested = str(parameters.get("path", ""))
    root = Path("/var/crash").resolve()
    try:
        path = Path(requested).resolve(strict=True)
    except (OSError, RuntimeError):
        return {"ok": False, "operation": "crash_text", "error": "crash log does not exist"}
    if root not in path.parents or not path.is_file() or not path.name.startswith("dmesg."):
        return {"ok": False, "operation": "crash_text", "error": "unsupported crash log path"}
    # As with dmesg, reserve room for worst-case JSON escaping.
    limit = 1 * 1024 * 1024
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        return {"ok": False, "operation": "crash_text", "error": str(exc)}
    return {
        "ok": True,
        "operation": "crash_text",
        "path": str(path),
        "output": raw[:limit].decode("utf-8", "replace"),
        "truncated": len(raw) > limit,
    }


def crashes() -> dict[str, Any]:
    root = Path("/var/crash")
    candidates: list[tuple[float, str, Path]] = []
    try:
        for path in root.rglob("*"):
            try:
                if not path.is_file():
                    continue
                stamp = path.stat().st_mtime
            except OSError:
                continue
            candidate = (stamp, str(path), path)
            if len(candidates) < CRASH_ENTRY_LIMIT:
                heapq.heappush(candidates, candidate)
            elif candidate[:2] > candidates[0][:2]:
                heapq.heapreplace(candidates, candidate)
    except OSError:
        pass
    entries = []
    response_bytes = 0
    omitted = 0
    for _stamp, _name, path in sorted(candidates, reverse=True):
        try:
            if not path.is_file():
                continue
            stat = path.stat()
            entry: dict[str, Any] = {
                "path": str(path),
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
                "kind": "incomplete" if "incomplete" in path.name else path.suffix.lstrip(".") or "dump",
            }
            if path.suffix == ".crash" and stat.st_size <= 50 * 1024 * 1024:
                entry["metadata"] = crash_metadata(path)
            encoded_size = len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if response_bytes + encoded_size > CRASH_RESPONSE_BUDGET:
                omitted += 1
                continue
            entries.append(entry)
            response_bytes += encoded_size
        except OSError:
            continue
    return {"ok": True, "operation": "crashes", "entries": entries, "omitted": omitted}


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    operation = request.get("operation")
    parameters = request.get("parameters", {})
    if not isinstance(parameters, dict):
        return {"ok": False, "error": "parameters must be an object"}
    if operation == "ping":
        return {"ok": True, "operation": "ping", "version": 1}
    if operation == "smart":
        return smart()
    if operation == "dmesg":
        return dmesg()
    if operation == "dmi":
        return dmi()
    if operation == "crashes":
        return crashes()
    if operation == "crash_text":
        return crash_text(parameters)
    if operation == "protected_log":
        return protected_log(parameters)
    return {"ok": False, "error": "unsupported operation"}


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
        encoded = json.dumps({"ok": False, "error": "response too large"}).encode()
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
