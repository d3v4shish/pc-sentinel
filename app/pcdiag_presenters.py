#!/usr/bin/env python3
"""Pure presentation/query helpers shared by the GTK UI and tests.

This module deliberately contains no GTK code.  Potentially large database
operations stay paged, diagnoses carry their provenance, and every executable
action is built from a closed allowlist.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from pcdiag_engine import TOP_CRITICAL_RULE_IDS, normalized_message


EVENT_PAGE_SIZE = 200
TIMELINE_PAGE_SIZE = 250
CONTEXT_LIMIT = 500
BURST_WINDOW_US = 30_000_000
SEVERITY_ORDER = {"Critical": 5, "Error": 4, "Warning": 3, "Notice": 2, "Activity": 1}
SEVERITY_ICONS = {
    "Critical": "dialog-error-symbolic",
    "Error": "dialog-error-symbolic",
    "Warning": "dialog-warning-symbolic",
    "Notice": "dialog-information-symbolic",
    "Activity": "emblem-system-symbolic",
}
_TOP_RULE_SQL = ",".join("'" + item.replace("'", "''") + "'" for item in sorted(TOP_CRITICAL_RULE_IDS))
INCIDENT_PRIORITY_SQL = (
    f"CASE WHEN category='Hardware' OR rule_id IN ({_TOP_RULE_SQL}) THEN 100 "
    "WHEN severity='Critical' THEN 80 WHEN severity='Error' THEN 60 "
    "WHEN severity='Warning' THEN 40 WHEN severity='Notice' THEN 20 ELSE 10 END"
)


def is_top_critical(record: sqlite3.Row | dict[str, Any]) -> bool:
    row = _dict(record)
    return str(row.get("category", "")) == "Hardware" or str(row.get("rule_id", "")) in TOP_CRITICAL_RULE_IDS


def _dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return dict(row)


def fetch_event_page(
    conn: sqlite3.Connection,
    *,
    before: tuple[int, int] | None = None,
    limit: int = EVENT_PAGE_SIZE,
    severity: str | None = None,
    category: str | None = None,
    search: str = "",
) -> list[dict[str, Any]]:
    """Fetch one bounded evidence page, newest first."""
    limit = max(1, min(int(limit), 1000))
    where: list[str] = []
    values: list[Any] = []
    if before is not None:
        occurred_us, evidence_id = (int(value) for value in before)
        where.append("(e.occurred_us < ? OR (e.occurred_us = ? AND e.id < ?))")
        values.extend((occurred_us, occurred_us, evidence_id))
    if severity and severity != "All severities":
        where.append("i.severity = ?")
        values.append(severity)
    if category and category != "All categories":
        where.append("i.category = ?")
        values.append(category)
    if search.strip():
        token = f"%{search.strip()}%"
        where.append("(e.message LIKE ? OR i.title LIKE ? OR i.likely_cause LIKE ?)")
        values.extend((token, token, token))
    clause = "WHERE " + " AND ".join(where) if where else ""
    rows = conn.execute(
        f"""
        SELECT e.id AS evidence_id,e.incident_id,e.occurred_us,e.boot_id,e.cursor,
               e.priority,e.source,e.unit_name,e.message,e.details_json,
               i.rule_id,i.severity,i.category,i.title,i.summary,i.likely_cause,
               i.impact,i.remediation_json,i.status,i.occurrences,i.first_us,i.last_us
          FROM evidence e JOIN incidents i ON i.id=e.incident_id
          {clause}
         ORDER BY e.occurred_us DESC,e.id DESC LIMIT ?
        """,
        (*values, limit),
    ).fetchall()
    return [_dict(row) for row in rows]


def collapse_event_bursts(
    records: Iterable[sqlite3.Row | dict[str, Any]],
    window_us: int = BURST_WINDOW_US,
) -> list[dict[str, Any]]:
    """Collapse adjacent repeated evidence without hiding its member IDs."""
    bursts: list[dict[str, Any]] = []
    for original in records:
        row = _dict(original)
        stamp = int(row.get("occurred_us", 0))
        key = (int(row.get("incident_id", 0)), normalized_message(str(row.get("message", ""))))
        if bursts:
            previous = bursts[-1]
            # Bound the complete burst span.  Comparing only adjacent records
            # would let a steady stream chain into one unbounded burst.
            if previous["burst_key"] == key and int(previous["newest_us"]) - stamp <= window_us:
                previous["count"] += 1
                previous["oldest_us"] = stamp
                previous["evidence_ids"].append(int(row.get("evidence_id", 0)))
                continue
        burst = dict(row)
        burst.update(
            burst_key=key,
            count=1,
            newest_us=stamp,
            oldest_us=stamp,
            evidence_ids=[int(row.get("evidence_id", 0))],
        )
        bursts.append(burst)
    return bursts


def fetch_incident_evidence(
    conn: sqlite3.Connection,
    incident_id: int,
    *,
    before: tuple[int, int] | None = None,
    limit: int = TIMELINE_PAGE_SIZE,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    values: list[Any] = [int(incident_id)]
    extra = ""
    if before is not None:
        occurred_us, evidence_id = (int(value) for value in before)
        extra = "AND (occurred_us < ? OR (occurred_us = ? AND id < ?))"
        values.extend((occurred_us, occurred_us, evidence_id))
    values.append(limit)
    rows = conn.execute(
        f"SELECT * FROM evidence WHERE incident_id=? {extra} ORDER BY occurred_us DESC,id DESC LIMIT ?",
        values,
    ).fetchall()
    return [_dict(row) for row in rows]


def diagnosis_for(record: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Return an explicit offline inference and how strongly it is supported."""
    row = _dict(record)
    rule_id = str(row.get("rule_id", "generic"))
    source = str(row.get("source", ""))
    message = str(row.get("message") or row.get("sample_message") or "")
    title = str(row.get("title", "Recorded system event"))
    if source == "pc-diagnostics" or rule_id in {
        "failed-unit", "smart-health", "cpu-saturation", "io-saturation",
        "memory-pressure", "disk-space", "temperature-high", "network-errors",
    }:
        confidence = "High"
        basis = "A direct health check or threshold produced this incident."
    elif rule_id.startswith("generic-") or rule_id == "generic":
        confidence = "Low"
        basis = "No specific diagnostic rule matched; this explanation is based on log priority and context."
    elif rule_id == "xhci-resume" and not re.search(r"USBSTS\s+0x401|xHC error in resume", message, re.I):
        confidence = "Medium"
        basis = "This event is temporally associated with the controller-resume incident, but is not the controller error itself."
    else:
        confidence = "High"
        basis = f"The message matched the offline diagnostic rule “{rule_id}”."
    try:
        steps = json.loads(str(row.get("remediation_json") or "[]"))
    except (TypeError, json.JSONDecodeError):
        steps = []
    if not isinstance(steps, list):
        steps = []
    cause = str(row.get("likely_cause") or "The log records a failure, but does not identify a unique root cause.")
    impact = str(row.get("impact") or "The effect depends on the component that emitted the message.")
    return {
        "title": title,
        "confidence": confidence,
        "basis": basis,
        "cause": cause,
        "impact": impact,
        "steps": [str(step) for step in steps],
    }


def journal_context_argv(record: sqlite3.Row | dict[str, Any], seconds: int = 30) -> list[str]:
    """Build the exact read-only journal command for an event time window."""
    row = _dict(record)
    seconds = seconds if seconds in (5, 30, 120) else 30
    occurred = int(row.get("occurred_us", 0)) / 1_000_000
    since = datetime.fromtimestamp(max(0, occurred - seconds), timezone.utc).isoformat()
    until = datetime.fromtimestamp(occurred + seconds, timezone.utc).isoformat()
    argv = [
        "journalctl", "--no-pager", "--all", "-o", "json",
        "--since", since, "--until", until, "-n", str(CONTEXT_LIMIT),
    ]
    boot_id = str(row.get("boot_id", "")).strip()
    if boot_id and boot_id != "unknown":
        argv.extend(["-b", boot_id])
    return argv


def parse_journal_json_lines(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            stamp = int(item.get("__REALTIME_TIMESTAMP", 0))
            priority = int(item.get("PRIORITY", 6))
        except (TypeError, ValueError):
            stamp, priority = 0, 6
        records.append({
            "occurred_us": stamp,
            "priority": priority,
            "source": str(item.get("SYSLOG_IDENTIFIER") or item.get("_COMM") or item.get("_TRANSPORT") or "unknown"),
            "unit_name": str(item.get("_SYSTEMD_UNIT") or item.get("_SYSTEMD_USER_UNIT") or ""),
            "message": str(item.get("MESSAGE") or ""),
            "raw": item,
        })
    return records


UNIT_RE = re.compile(r"^[A-Za-z0-9_.:@\\-]{1,240}\.(?:service|socket|timer|path|target|mount)$")
USER_ACTIONS = {
    "restart": "restart",
    "reset-failed": "reset-failed",
}


def service_action_argv(action: str, unit: str, scope: str) -> list[str]:
    """Validate a state-changing service action against a strict argv allowlist."""
    if scope != "user":
        raise ValueError("Only user-session services can be changed from this app")
    verb = USER_ACTIONS.get(action)
    if not verb or not UNIT_RE.fullmatch(unit):
        raise ValueError("Unsupported service action or invalid unit name")
    return ["systemctl", "--user", verb, unit]


def service_read_argv(action: str, unit: str, scope: str) -> list[str]:
    if scope not in ("user", "system") or not UNIT_RE.fullmatch(unit):
        raise ValueError("Invalid service scope or unit name")
    prefix = ["systemctl", "--user"] if scope == "user" else ["systemctl"]
    if action == "status":
        return [*prefix, "status", unit, "--no-pager", "--full"]
    if action == "logs":
        return ["journalctl", *( ["--user"] if scope == "user" else []), "-u", unit, "-n", "500", "--no-pager", "-o", "short-precise"]
    raise ValueError("Unsupported read-only service action")


def parse_package_upgrade(line: str) -> dict[str, str] | None:
    match = re.match(r"^([^/\s]+)/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[upgradable from: ([^\]]+)\]", line)
    if not match:
        return None
    name, repository, new_version, architecture, current_version = match.groups()
    return {
        "name": name,
        "repository": repository,
        "new_version": new_version,
        "architecture": architecture,
        "current_version": current_version,
    }


def scan_payload(details: Any, scan_type: str = "") -> dict[str, Any]:
    """Normalize legacy scan snapshots into the version-2 presentation shape."""
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            return {"payload_version": 1, "raw": details}
    if not isinstance(details, dict):
        return {"payload_version": 1, "raw": details}
    if int(details.get("payload_version", 1)) >= 2:
        return details
    result = dict(details)
    result["payload_version"] = 1
    if scan_type == "hardware" and isinstance(result.get("lsblk"), str):
        try:
            result["blockdevices"] = json.loads(result["lsblk"]).get("blockdevices", [])
        except (json.JSONDecodeError, AttributeError):
            result["blockdevices"] = []
    if scan_type == "updates":
        result["packages"] = [item for line in result.get("upgradable_packages", []) if (item := parse_package_upgrade(str(line)))]
    return result
