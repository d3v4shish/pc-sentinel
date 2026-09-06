#!/usr/bin/env python3
"""Continuous incident, journal, health-metric, and deep-scan collector."""

from __future__ import annotations

import argparse
import collections
import heapq
import json
import os
import queue
import re
import signal
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from pcdiag_common import DB_PATH, run_command
from pcdiag_engine import (
    RULES,
    backup_database,
    connect_v2,
    fingerprint_for,
    helper_request,
    ingest_journal_record,
    is_high_resolution_metric,
    journal_timestamp_us,
    local_metrics,
    migrate_legacy_events,
    promote_top_critical_incidents,
    prune_v2,
    record_incident,
    record_forensic_case,
    record_scan,
    record_tuning_audit,
    reconcile_forensic_cases,
    resolve_incident,
    tuning_request,
    update_metric,
    validated_sensors,
)


BOOT_ID = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
try:
    BOOT_STARTED_US = int((time.time() - float(Path("/proc/uptime").read_text().split()[0])) * 1_000_000)
except (OSError, ValueError, IndexError):
    BOOT_STARTED_US = int(time.time() * 1_000_000)
UNIT_SUFFIXES = (".service", ".socket", ".mount", ".timer", ".target", ".path")
# Keep a first launch responsive even on hosts with months of persistent
# journals. The live follower resumes from each checkpoint in the background.
BACKFILL_RECORD_LIMIT = 1_000
BACKFILL_TIME_LIMIT_SECONDS = 8.0
BACKFILL_CHECKPOINT_RECORDS = 100
BACKFILL_QUEUE_LIMIT = 32
MAX_JOURNAL_RECORD_CHARS = 1024 * 1024
CRASH_FALLBACK_ENTRY_LIMIT = 2_000


def failed_unit_name(line: str) -> str:
    tokens = line.replace("●", " ").split()
    return next(
        (token for token in tokens if token.endswith(UNIT_SUFFIXES)),
        tokens[0] if tokens else "unknown-unit",
    )


def parse_failed_services(output: str, scope: str) -> list[dict[str, Any]]:
    """Accept systemctl JSON when available and its stable plain fallback."""
    try:
        items = json.loads(output)
    except json.JSONDecodeError:
        items = None
    parsed: list[dict[str, Any]] = []
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            unit = str(item.get("unit") or item.get("UNIT") or "")
            active = str(item.get("active") or item.get("ACTIVE") or "")
            if unit and active == "failed":
                parsed.append({
                    "unit": unit,
                    "scope": scope,
                    "load": str(item.get("load") or item.get("LOAD") or ""),
                    "active": active,
                    "sub": str(item.get("sub") or item.get("SUB") or ""),
                    "description": str(item.get("description") or item.get("DESCRIPTION") or ""),
                })
        return parsed
    for line in output.splitlines():
        if " loaded " not in line or " failed " not in line:
            continue
        parsed.append({
            "unit": failed_unit_name(line), "scope": scope, "load": "loaded",
            "active": "failed", "sub": "failed", "description": line,
        })
    return parsed


def parse_pci_inventory(output: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in output.splitlines():
        if line and not line[0].isspace():
            if current:
                devices.append(current)
            slot, _, description = line.partition(" ")
            current = {"slot": slot, "description": description, "driver": "", "modules": []}
        elif current and ":" in line:
            key, value = line.strip().split(":", 1)
            value = value.strip()
            if key == "Kernel driver in use":
                current["driver"] = value
            elif key == "Kernel modules":
                current["modules"] = [part.strip() for part in value.split(",")]
    if current:
        devices.append(current)
    return devices


def parse_usb_tree(output: str) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for line in output.splitlines():
        stripped = line.lstrip()
        if not stripped:
            continue
        depth = max(0, (len(line) - len(stripped)) // 4)
        nodes.append({"depth": depth, "label": stripped, "is_root": stripped.startswith("/:")})
    return nodes


def parse_listeners(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    lines = output.splitlines()
    for line in lines[1:] if lines and lines[0].startswith("Netid") else lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        rows.append({
            "protocol": parts[0], "state": parts[1], "recv_q": parts[2],
            "send_q": parts[3], "local": parts[4], "peer": parts[5],
            "process": parts[6] if len(parts) > 6 else "",
        })
    return rows


def parse_package_upgrade(line: str) -> dict[str, str] | None:
    match = re.match(r"^([^/\s]+)/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[upgradable from: ([^\]]+)\]", line)
    if not match:
        return None
    name, repository, new_version, architecture, current_version = match.groups()
    return {
        "name": name, "repository": repository, "new_version": new_version,
        "architecture": architecture, "current_version": current_version,
    }


def crash_occurred_seconds(item: dict[str, Any]) -> int:
    """Prefer an apport crash's event date over the report file write time."""
    metadata = item.get("metadata")
    if isinstance(metadata, dict) and metadata.get("Date"):
        try:
            parsed = time.strptime(str(metadata["Date"]), "%a %b %d %H:%M:%S %Y")
            return int(time.mktime(parsed))
        except ValueError:
            pass
    try:
        return int(item.get("mtime", 0))
    except (TypeError, ValueError):
        return 0


class Collector:
    def __init__(self, db_path: Path, once: bool = False):
        self.db_path = db_path
        self.once = once
        self.stop = threading.Event()
        self.conn = connect_v2(db_path)
        self.previous_cpu: tuple[int, int, int] | None = None
        self.threshold_counts: collections.Counter[str] = collections.Counter()
        self.threshold_seen: set[str] = set()
        self.previous_network: dict[str, float] = {}
        self.last_run: dict[str, float] = {}
        self.journal_thread: threading.Thread | None = None
        self.journal_process: subprocess.Popen[str] | None = None

    def initialize(self) -> None:
        backup_key = self.conn.execute(
            "SELECT value FROM settings WHERE key='v2_backup_created'"
        ).fetchone()
        if not backup_key:
            backup = backup_database(self.db_path)
            self.conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('v2_backup_created',?)",
                (str(backup or "new-database"),),
            )
            self.conn.commit()
        migrated = migrate_legacy_events(self.conn)
        if migrated:
            print(f"Migrated {migrated} legacy event records into v2 incidents", flush=True)
        promoted = promote_top_critical_incidents(self.conn)
        if promoted:
            print(f"Promoted {promoted} hardware/kernel incidents to top criticality", flush=True)
        forensic_cases = reconcile_forensic_cases(self.conn)
        if forensic_cases:
            print(f"Indexed {forensic_cases} retained forensic case window(s)", flush=True)
        self.conn.execute(
            "UPDATE incidents SET status='historical' WHERE status='open' AND last_boot_id<>?",
            (BOOT_ID,),
        )
        self.conn.commit()
        prune_v2(self.conn)
        self.backfill()

    def backfill(
        self,
        *,
        record_limit: int = BACKFILL_RECORD_LIMIT,
        time_limit_seconds: float = BACKFILL_TIME_LIMIT_SECONDS,
    ) -> None:
        """Import one bounded, checkpointed journal batch before going live.

        A long historical replay must never prevent metrics, scans, or the
        live follower from starting. Every committed batch stores its progress,
        so an interrupted launch resumes near its previous position.
        """
        offset = self.conn.execute(
            "SELECT cursor,occurred_us FROM source_offsets WHERE source='journal'"
        ).fetchone()
        saved_cursor = str(offset["cursor"]) if offset and offset["cursor"] else ""
        if saved_cursor:
            command = ["journalctl", f"--after-cursor={saved_cursor}", "-o", "json", "--no-pager", "--all"]
            since = max(0, int(offset["occurred_us"]) // 1_000_000 - 60)
        else:
            latest = self.conn.execute("SELECT COALESCE(MAX(occurred_us),0) FROM evidence").fetchone()[0]
            since = max(0, int(latest) // 1_000_000 - 60) if latest else int(time.time() - 30 * 86400)
            command = ["journalctl", "--since", f"@{since}", "-o", "json", "--no-pager", "--all"]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
        except OSError as exc:
            record_scan(self.conn, "journal", "error", "Unable to start journal backfill", {"error": str(exc), "command": command})
            return
        assert process.stdout is not None
        lines: queue.Queue[str] = queue.Queue(maxsize=BACKFILL_QUEUE_LIMIT)
        reader_stop = threading.Event()
        reader_done = threading.Event()

        def read_backfill_lines() -> None:
            try:
                for line in process.stdout:
                    if len(line) > MAX_JOURNAL_RECORD_CHARS:
                        # Keep a corrupt/oversized journal field from tying up
                        # the initial startup batch or exhausting its queue.
                        continue
                    while not reader_stop.is_set():
                        try:
                            lines.put(line, timeout=0.1)
                            break
                        except queue.Full:
                            continue
            finally:
                reader_done.set()

        reader = threading.Thread(target=read_backfill_lines, name="journal-backfill-reader", daemon=True)
        reader.start()
        imported = 0
        pending = 0
        processed = 0
        bounded = False
        deadline = time.monotonic() + max(0.1, time_limit_seconds)
        last_cursor = ""
        last_us = since * 1_000_000
        try:
            while True:
                if processed >= record_limit or time.monotonic() >= deadline:
                    bounded = True
                    break
                try:
                    line = lines.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
                except queue.Empty:
                    if reader_done.is_set():
                        break
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                processed += 1
                result = ingest_journal_record(self.conn, record, commit=False)
                last_us = journal_timestamp_us(record.get("__REALTIME_TIMESTAMP"), last_us)
                cursor = record.get("__CURSOR")
                if cursor:
                    last_cursor = str(cursor)
                if result and result[1]:
                    imported += 1
                    record_forensic_case(
                        self.conn,
                        result[0],
                        last_us,
                        str(record.get("_BOOT_ID", BOOT_ID)),
                        commit=False,
                    )
                pending += 1
                if pending >= BACKFILL_CHECKPOINT_RECORDS and last_cursor:
                    self._store_journal_offset(self.conn, last_cursor, last_us)
                    self.conn.commit()
                    pending = 0
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            self.conn.rollback()
            record_scan(self.conn, "journal", "error", "Journal backfill interrupted", {"error": str(exc), "command": command})
            return
        finally:
            reader_stop.set()
            if process.poll() is None:
                process.terminate()
            reader.join(timeout=1)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        # Cursors can be pruned when the persistent journal rotates.  Retain
        # the timestamp and fall back to its small overlap window next run;
        # evidence cursors keep that fallback idempotent.
        if saved_cursor and processed == 0 and process.returncode not in (0, None):
            self.conn.execute("UPDATE source_offsets SET cursor='' WHERE source='journal'")
            self.conn.commit()
            print("Journal cursor expired; falling back to timestamp resume", flush=True)
            return
        if last_cursor:
            self._store_journal_offset(self.conn, last_cursor, last_us)
        self.conn.commit()
        suffix = " (checkpointed; live follower will continue)" if bounded else ""
        print(f"Journal backfill indexed {imported} new evidence records{suffix}", flush=True)

    def start_journal(self) -> None:
        self.journal_thread = threading.Thread(target=self._journal_loop, name="journal-follow", daemon=True)
        self.journal_thread.start()

    def _journal_loop(self) -> None:
        conn = connect_v2(self.db_path)
        try:
            while not self.stop.is_set():
                offset = conn.execute(
                    "SELECT cursor,occurred_us FROM source_offsets WHERE source='journal'"
                ).fetchone()
                saved_cursor = str(offset["cursor"]) if offset and offset["cursor"] else ""
                since = max(0, int(offset["occurred_us"]) // 1_000_000 - 2) if offset else int(time.time() - 2)
                pending = 0
                last_commit = time.monotonic() - 1
                last_cursor = ""
                last_us = since * 1_000_000
                try:
                    command = (
                        ["journalctl", "-f", f"--after-cursor={saved_cursor}", "-o", "json", "--all"]
                        if saved_cursor else
                        ["journalctl", "-f", "--since", f"@{since}", "-o", "json", "--all"]
                    )
                    self.journal_process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                        errors="replace",
                        bufsize=1,
                    )
                    assert self.journal_process.stdout is not None
                    for line in self.journal_process.stdout:
                        if self.stop.is_set():
                            break
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(record, dict):
                            continue
                        result = ingest_journal_record(conn, record, commit=False)
                        if result and result[1]:
                            record_forensic_case(
                                conn,
                                result[0],
                                journal_timestamp_us(record.get("__REALTIME_TIMESTAMP"), last_us),
                                str(record.get("_BOOT_ID", BOOT_ID)),
                                commit=False,
                            )
                            self.maybe_notify(conn, result[0])
                        cursor = record.get("__CURSOR")
                        if cursor:
                            last_cursor = str(cursor)
                        last_us = journal_timestamp_us(record.get("__REALTIME_TIMESTAMP"), last_us)
                        pending += 1
                        now = time.monotonic()
                        if pending >= 100 or now - last_commit >= 1:
                            if last_cursor:
                                self._store_journal_offset(conn, last_cursor, last_us)
                            conn.commit()
                            pending = 0
                            last_commit = now
                    if pending:
                        if last_cursor:
                            self._store_journal_offset(conn, last_cursor, last_us)
                        conn.commit()
                    if saved_cursor and not self.stop.is_set() and self.journal_process.poll() not in (0, None):
                        conn.execute("UPDATE source_offsets SET cursor='' WHERE source='journal'")
                        conn.commit()
                        print("journal follower cursor expired; falling back to timestamp resume", flush=True)
                except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
                    conn.rollback()
                    print(f"journal follower error: {exc}; retrying", flush=True)
                finally:
                    if self.journal_process and self.journal_process.poll() is None:
                        self.journal_process.terminate()
                    self.journal_process = None
                if not self.stop.wait(2):
                    print("journal follower restarting", flush=True)
        finally:
            conn.close()

    @staticmethod
    def _store_journal_offset(conn: sqlite3.Connection, cursor: str, occurred_us: int) -> None:
        conn.execute(
            "INSERT INTO source_offsets(source,cursor,occurred_us) VALUES('journal',?,?) "
            "ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor,occurred_us=excluded.occurred_us",
            (cursor, occurred_us),
        )

    def maybe_notify(self, conn: sqlite3.Connection, incident_id: int) -> None:
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row or row["severity"] not in ("Warning", "Error", "Critical"):
            return
        now = int(time.time() * 1_000_000)
        previous = conn.execute(
            "SELECT last_us,total FROM notifications WHERE fingerprint=?", (row["fingerprint"],)
        ).fetchone()
        if previous and now - int(previous[0]) < 30 * 60 * 1_000_000:
            return
        recent = conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE last_us>=?",
            (now - 10 * 60 * 1_000_000,),
        ).fetchone()[0]
        if recent >= 6 and row["severity"] != "Critical":
            return
        urgency = "critical" if row["severity"] in ("Error", "Critical") else "normal"
        try:
            subprocess.Popen(
                ["notify-send", "-u", urgency, f"PC Diagnostics · {row['severity']}", row["title"]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            # Notifications are optional.  Evidence and the incident state must
            # still be durable when a desktop notification service is absent.
            pass
        conn.execute(
            "INSERT INTO notifications(fingerprint,last_us,total) VALUES(?,?,1) "
            "ON CONFLICT(fingerprint) DO UPDATE SET last_us=excluded.last_us,total=notifications.total+1",
            (row["fingerprint"], now),
        )
        conn.commit()

    def synthetic_issue(
        self,
        rule_id: str,
        severity: str,
        category: str,
        title: str,
        summary: str,
        cause: str,
        impact: str,
        remediation: tuple[str, ...],
        scope: str = "global",
        details: dict[str, Any] | None = None,
        cooldown_seconds: int = 300,
        observation_key: str | None = None,
        occurred_us: int | None = None,
        notify: bool = True,
    ) -> None:
        observation = str(int(time.time() // cooldown_seconds))
        if observation_key is not None:
            observation = fingerprint_for("synthetic-observation", observation_key)
        result = record_incident(
            self.conn,
            rule_id=rule_id,
            severity=severity,
            category=category,
            title=title,
            summary=summary,
            likely_cause=cause,
            impact=impact,
            remediation=remediation,
            occurred_us=occurred_us or int(time.time() * 1_000_000),
            boot_id=BOOT_ID,
            cursor=f"synthetic:{rule_id}:{scope}:{observation}",
            priority={"Critical": 2, "Error": 3, "Warning": 4}.get(severity, 5),
            source="pc-diagnostics",
            unit="pc-diagnostics-collector.service",
            message=summary,
            details=details or {},
            scope=scope,
        )
        if observation_key is not None:
            # Stable observations can outlive wording derived from their latest
            # probe. Keep that wording current without creating new evidence.
            self.conn.execute(
                "UPDATE incidents SET title=?,summary=?,likely_cause=?,impact=?,remediation_json=? WHERE id=?",
                (title, summary, cause, impact, json.dumps(remediation, ensure_ascii=False), result[0]),
            )
            self.conn.commit()
        if result[1] and notify:
            record_forensic_case(self.conn, result[0], occurred_us or int(time.time() * 1_000_000), BOOT_ID)
            self.maybe_notify(self.conn, result[0])

    def _restore_tuning_for_safety(self, trigger: str, details: dict[str, Any]) -> bool:
        """Restore a user-tuned baseline after a credible live safety signal."""
        response = tuning_request("restore", reason=f"automatic safety rollback: {trigger}")
        if not response.get("ok") or not response.get("restored"):
            return False
        record_tuning_audit(self.conn, "automatic-restore", response, reason=f"safety:{trigger}")
        self.synthetic_issue(
            "tuning-rollback", "Critical", "Thermal", "Temporary tuning safety rollback completed",
            f"PC Diagnostics restored the saved pre-tuning baseline after {trigger}.",
            "A sustained critical thermal or hardware-fault signal occurred while a temporary tuning baseline was active.",
            "The pre-tuning CPU/GPU settings were restored to reduce further instability risk.",
            ("Inspect the triggering forensic case and surrounding telemetry.", "Do not reapply tuning until the hardware warning is understood."),
            details={"trigger": trigger, "trigger_details": details, "restore": response},
            cooldown_seconds=3600,
        )
        return True

    def sample_metrics(self) -> None:
        started = int(time.time() * 1_000_000)
        try:
            metrics, self.previous_cpu = local_metrics(self.previous_cpu)
        except Exception as exc:
            record_scan(self.conn, "metrics", "error", "Unable to read live metrics", {"error": str(exc)}, started)
            return
        for metric, value in metrics.items():
            unit = "percent" if metric.endswith("percent") or metric in ("cpu.iowait",) else "value"
            if metric.startswith("temperature."):
                unit = "°C"
            elif metric.endswith(".watts"):
                unit = "W"
            elif metric.endswith(".volts"):
                unit = "V"
            elif metric.endswith("free_gib"):
                unit = "GiB"
            if is_high_resolution_metric(metric):
                # The collector is paced at ten seconds.  A ten-second bucket
                # preserves the exact reading needed to reconstruct a recent
                # power, thermal, or GPU-related hardware incident.
                update_metric(self.conn, metric, float(value), unit, interval_seconds=10, commit=False)
            update_metric(self.conn, metric, float(value), unit, interval_seconds=60, commit=False)
            update_metric(self.conn, metric, float(value), unit, interval_seconds=900, commit=False)
        self.conn.commit()
        self._metric_anomalies(metrics)

    def _count_threshold(self, key: str, active: bool) -> tuple[int, bool]:
        previous = self.threshold_counts[key]
        first_observation = key not in self.threshold_seen
        self.threshold_seen.add(key)
        self.threshold_counts[key] = previous + 1 if active else 0
        return self.threshold_counts[key], bool(not active and (previous or first_observation))

    def _metric_anomalies(self, metrics: dict[str, float]) -> None:
        cpu = metrics.get("cpu.percent", 0)
        cpu_count, cpu_cleared = self._count_threshold("cpu", cpu >= 90)
        if cpu_count >= 3:
            self.synthetic_issue(
                "cpu-saturation", "Warning", "Performance", "Sustained CPU saturation",
                f"CPU utilization remained at {cpu:.1f}% for at least 30 seconds.",
                "One or more processes are consuming nearly all available CPU time.",
                "Interactive input, audio, and desktop rendering may temporarily stall.",
                ("Open the Performance page to identify the workload.", "Reduce or pause the responsible process if unexpected."),
                details=metrics,
            )
        elif cpu_cleared:
            resolve_incident(self.conn, "cpu-saturation")
        iowait = metrics.get("cpu.iowait", 0)
        iowait_count, iowait_cleared = self._count_threshold("iowait", iowait >= 20)
        if iowait_count >= 2:
            self.synthetic_issue(
                "io-saturation", "Warning", "Performance", "High storage I/O wait",
                f"CPU I/O wait reached {iowait:.1f}% for at least 20 seconds.",
                "Storage requests are taking long enough to leave CPUs waiting.",
                "Applications and pointer movement can feel frozen even when CPU usage is moderate.",
                ("Inspect disk activity and SMART health.", "Check for backup, indexing, or swapping workloads."),
                details=metrics,
            )
        elif iowait_cleared:
            resolve_incident(self.conn, "io-saturation")
        memory = metrics.get("memory.percent", 0)
        memory_count, memory_cleared = self._count_threshold("memory", memory >= 90)
        if memory_count >= 2:
            self.synthetic_issue(
                "memory-pressure", "Warning", "Performance", "High memory pressure",
                f"Memory usage remained at {memory:.1f}% for at least 20 seconds.",
                "Running applications are close to exhausting available memory.",
                "The system may swap heavily or invoke the OOM killer.",
                ("Identify high-memory processes.", "Close unexpected workloads before the system reaches OOM."),
                details=metrics,
            )
        elif memory_cleared:
            resolve_incident(self.conn, "memory-pressure")
        disk = metrics.get("disk.root.percent", 0)
        _disk_count, disk_cleared = self._count_threshold("disk", disk >= 85)
        if disk >= 85:
            severity = "Critical" if disk >= 95 else "Warning"
            self.synthetic_issue(
                "disk-space", severity, "Storage", "Root filesystem is running out of space",
                f"The root filesystem is {disk:.1f}% full with {metrics.get('disk.root.free_gib', 0):.1f} GiB free.",
                "Logs, crash dumps, applications, or user data are consuming most available space.",
                "Updates and applications can fail; at 100% usage the system may become unstable.",
                ("Review crash dumps and large files.", "Remove data only after confirming it is no longer needed."),
                details=metrics,
                cooldown_seconds=1800,
            )
        elif disk_cleared:
            resolve_incident(self.conn, "disk-space")
        for metric, value in metrics.items():
            if not metric.startswith("temperature."):
                continue
            sensor = metric.removeprefix("temperature.")
            warning = 85.0
            critical = 95.0
            if "NVIDIA" in sensor:
                warning, critical = 82.0, 90.0
            elif "NVMe" in sensor:
                warning, critical = 75.0, 85.0
            elif "Memory" in sensor:
                warning, critical = 60.0, 80.0
            elif "Coolant" in sensor:
                warning, critical = 45.0, 55.0
            temperature_count, temperature_cleared = self._count_threshold(f"temp:{sensor}", value >= warning)
            if temperature_count >= 2:
                severity = "Critical" if value >= critical else "Warning"
                self.synthetic_issue(
                    "temperature-high", severity, "Thermal", f"High temperature: {sensor}",
                    f"Validated sensor {sensor} reached {value:.1f}°C.",
                    "The component is under heavy load or its cooling path is insufficient.",
                    "Sustained heat can cause throttling, instability, or protective shutdown.",
                    ("Reduce load and confirm fans/pump operation.", "Check heatsink contact, dust, and airflow."),
                    scope=sensor,
                    details={"sensor": sensor, "temperature": value},
                )
                if severity == "Critical":
                    self._restore_tuning_for_safety(
                        f"sustained critical temperature at {sensor}",
                        {"sensor": sensor, "temperature": value, "threshold": critical, "samples": temperature_count},
                    )
            elif temperature_cleared:
                resolve_incident(self.conn, "temperature-high", sensor)
        for metric, value in metrics.items():
            if not metric.startswith("network."):
                continue
            previous = self.previous_network.get(metric, value)
            if value > previous:
                interface = metric.split(".")[1]
                counter = metric.rsplit(".", 1)[-1]
                self.synthetic_issue(
                    "network-errors", "Warning", "Network", f"Network {counter.replace('_', ' ')} increased on {interface}",
                    f"{metric} increased from {previous:.0f} to {value:.0f}.",
                    "The interface or driver dropped or failed one or more packets.",
                    "Connections can become slow or unreliable if the counter continues rising.",
                    ("Check link quality, cable/signal, interface statistics, and driver events.",),
                    scope=f"{interface}:{counter}",
                    details={"previous": previous, "current": value},
                )
            self.previous_network[metric] = value

    def scan_failed_services(self) -> None:
        started = int(time.time() * 1_000_000)
        system = run_command(["systemctl", "--failed", "--no-pager", "--output=json"], 8)
        user = run_command(["systemctl", "--user", "--failed", "--no-pager", "--output=json"], 8)
        failed = parse_failed_services(system, "system") + parse_failed_services(user, "user")
        details = {"payload_version": 2, "units": failed, "raw": {"system": system, "user": user}}
        record_scan(self.conn, "services", "warning" if failed else "ok", f"{len(failed)} failed services", details, started)
        active_fingerprints = set()
        for item in failed:
            unit = item["unit"]
            line = item["description"]
            active_fingerprints.add(fingerprint_for("failed-unit", unit))
            self.synthetic_issue(
                "failed-unit", "Warning", "Services", f"Failed service: {unit}", line,
                "The systemd unit is currently in the failed state.",
                "The feature provided by this service may not work.",
                (f"Review: systemctl status {unit}", f"Inspect: journalctl -u {unit}"),
                scope=unit,
                cooldown_seconds=1800,
            )
        open_failures = self.conn.execute(
            "SELECT fingerprint FROM incidents WHERE rule_id='failed-unit' AND status='open'"
        ).fetchall()
        stale = [row[0] for row in open_failures if row[0] not in active_fingerprints]
        if stale:
            self.conn.executemany(
                "UPDATE incidents SET status='resolved' WHERE fingerprint=?",
                ((fingerprint,) for fingerprint in stale),
            )
            self.conn.commit()

    def scan_crashes(self) -> None:
        started = int(time.time() * 1_000_000)
        response = helper_request("crashes")
        if not response.get("ok"):
            crash_root = Path("/var/crash")
            candidates: list[tuple[float, str, Path]] = []
            try:
                for path in crash_root.rglob("*"):
                    try:
                        if not path.is_file():
                            continue
                        stat = path.stat()
                    except OSError:
                        continue
                    candidate = (stat.st_mtime, str(path), path)
                    if len(candidates) < CRASH_FALLBACK_ENTRY_LIMIT:
                        heapq.heappush(candidates, candidate)
                    elif candidate[:2] > candidates[0][:2]:
                        heapq.heapreplace(candidates, candidate)
            except OSError:
                pass
            entries = []
            for _stamp, _name, path in sorted(candidates, reverse=True):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                entries.append({"path": str(path), "size": stat.st_size, "mtime": int(stat.st_mtime), "kind": path.suffix})
            response = {"ok": bool(entries), "entries": entries, "error": response.get("error", "")}
        entries = response.get("entries", [])
        total = sum(int(item.get("size", 0)) for item in entries)
        incomplete = [item for item in entries if "incomplete" in str(item.get("path", ""))]
        kernel_entries = [
            item for item in entries
            if Path(str(item.get("path", ""))).name.startswith(("linux-image-", "dump.", "dump-incomplete", "dmesg."))
        ]
        kernel_sessions = {
            str(Path(str(item.get("path", ""))).parent)
            if Path(str(item.get("path", ""))).name.startswith(("dump.", "dump-incomplete", "dmesg."))
            else Path(str(item.get("path", ""))).name
            for item in kernel_entries
        }
        newest_entry_us = max((int(item.get("mtime", 0)) for item in entries), default=0) * 1_000_000
        newest_kernel_us = max((crash_occurred_seconds(item) for item in kernel_entries), default=0) * 1_000_000
        status = "warning" if total >= 2 * 1024**3 or incomplete else "ok"
        summary = f"{len(entries)} crash files using {total / 1024**3:.1f} GiB; {len(incomplete)} incomplete dumps; {len(kernel_sessions)} kernel crash records"
        record_scan(self.conn, "crashes", status, summary, {**response, "payload_version": 2}, started)
        if kernel_sessions:
            newest_label = time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(newest_kernel_us / 1_000_000))
            historical = newest_kernel_us < BOOT_STARTED_US - 5 * 60 * 1_000_000
            kernel_title = "Historical kernel crash dumps retained" if historical else "New kernel crash dump detected"
            kernel_summary = (
                f"Crash storage contains {len(kernel_sessions)} kernel crash record(s), including "
                f"{len(incomplete)} incomplete dump(s). Newest dump: {newest_label}."
            )
            previous = self.conn.execute(
                "SELECT last_us FROM notifications WHERE fingerprint=?",
                (fingerprint_for("kernel-crash-artifact", "global"),),
            ).fetchone()
            self.synthetic_issue(
                "kernel-crash-artifact", "Critical", "Kernel", kernel_title, kernel_summary,
                "kdump or the kernel crash handler preserved evidence from one or more whole-system kernel failures.",
                "Each record represents a previous system-wide crash; incomplete dumps may limit root-cause analysis and consume substantial disk space.",
                ("Inspect the newest dmesg/vmcore pair first.", "Preserve a copy before deleting crash artifacts.", "Correlate the crash time with firmware, driver, memory, and hardware errors."),
                details={"sessions": sorted(kernel_sessions), "incomplete": len(incomplete), "total_bytes": total},
                observation_key="\n".join(sorted(kernel_sessions)),
                occurred_us=newest_kernel_us,
                notify=not previous or newest_kernel_us > int(previous[0]),
            )
            self.conn.execute(
                "UPDATE incidents SET status=? WHERE fingerprint=?",
                ("historical" if historical else "open", fingerprint_for("kernel-crash-artifact", "global")),
            )
            self.conn.commit()
        else:
            resolve_incident(self.conn, "kernel-crash-artifact")
        if status == "warning":
            artifact_paths = sorted(str(item.get("path", "")) for item in entries)
            previous = self.conn.execute(
                "SELECT last_us FROM notifications WHERE fingerprint=?",
                (fingerprint_for("crash-storage", "global"),),
            ).fetchone()
            self.synthetic_issue(
                "crash-storage", "Warning", "Crashes", "Crash dumps require attention", summary,
                "Kernel or application crashes created large or incomplete diagnostic dumps.",
                "Crash artifacts consume disk space and indicate previous instability.",
                ("Review crash dates and metadata in the Crashes page.", "Delete dumps only after preserving any evidence you need."),
                details={"total_bytes": total, "incomplete": len(incomplete)},
                observation_key="\n".join(artifact_paths),
                occurred_us=newest_entry_us,
                notify=not previous or newest_entry_us > int(previous[0]),
            )
        else:
            resolve_incident(self.conn, "crash-storage")

    def scan_smart(self) -> None:
        started = int(time.time() * 1_000_000)
        response = helper_request("smart")
        results = response.get("results", [])
        bad = []
        unavailable = []
        for result in results:
            data = result.get("data", {})
            device = result.get("device", "unknown")
            exit_status = int(result.get("exit_status", 127) or 0)
            if exit_status & 0b11 or not isinstance(data, dict):
                unavailable.append(device)
                continue
            passed = data.get("smart_status", {}).get("passed")
            nvme = data.get("nvme_smart_health_information_log", {})
            critical_warning = int(nvme.get("critical_warning", 0) or 0)
            media_errors = int(nvme.get("media_errors", 0) or 0)
            used = int(nvme.get("percentage_used", 0) or 0)
            attributes = data.get("ata_smart_attributes", {}).get("table", [])
            risky_attributes = {
                item.get("name"): int(item.get("raw", {}).get("value", 0) or 0)
                for item in attributes if item.get("name") in {
                    "Reallocated_Sector_Ct", "Current_Pending_Sector", "Offline_Uncorrectable"
                }
            }
            risky_sectors = sum(risky_attributes.values())
            if passed is False or critical_warning or media_errors or used >= 100 or risky_sectors:
                bad.append({
                    "device": device, "passed": passed, "critical_warning": critical_warning,
                    "media_errors": media_errors, "percentage_used": used,
                    "risky_attributes": risky_attributes,
                })
                self.synthetic_issue(
                    "smart-health", "Critical", "Storage", f"Drive health failure: {device}",
                    f"SMART reports passed={passed}, critical_warning={critical_warning}, media_errors={media_errors}, endurance_used={used}%, risky_sectors={risky_sectors}.",
                    "The drive firmware has recorded a health or media reliability problem.",
                    "Data loss risk is elevated.",
                    ("Back up important data immediately.", "Avoid destructive tests until the backup is verified.", "Plan drive replacement if the health failure persists."),
                    scope=device,
                    details=data,
                    cooldown_seconds=3600,
                )
        record_scan(
            self.conn,
            "smart",
            "error" if not response.get("ok") or unavailable else ("critical" if bad else "ok"),
            (response.get("error") or f"Checked {len(results)} drives; {len(bad)} unhealthy; {len(unavailable)} unavailable"),
            {**response, "payload_version": 2, "health_findings": bad, "unavailable": unavailable},
            started,
        )

    def scan_hardware(self) -> None:
        started = int(time.time() * 1_000_000)
        lsblk_raw = run_command(["lsblk", "-J", "-o", "NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,TRAN,ROTA,STATE"], 8)
        lspci_raw = run_command(["lspci", "-nnk"], 8)
        lsusb_raw = run_command(["lsusb", "-t"], 8)
        try:
            blockdevices = json.loads(lsblk_raw).get("blockdevices", [])
        except (json.JSONDecodeError, AttributeError):
            blockdevices = []
        details = {
            "payload_version": 2,
            "blockdevices": blockdevices,
            "pci_devices": parse_pci_inventory(lspci_raw),
            "usb_tree": parse_usb_tree(lsusb_raw),
            "sensors": validated_sensors(),
            "dmi": helper_request("dmi"),
            "raw": {"lsblk": lsblk_raw, "lspci": lspci_raw, "lsusb": lsusb_raw},
        }
        record_scan(self.conn, "hardware", "ok", "Hardware inventory and validated sensors refreshed", details, started)

    def scan_network(self) -> None:
        started = int(time.time() * 1_000_000)
        addresses_raw = run_command(["ip", "-j", "address"], 5)
        links_raw = run_command(["ip", "-j", "-s", "link"], 5)
        routes_raw = run_command(["ip", "-j", "route"], 5)
        listeners_raw = run_command(["ss", "-lntup"], 8)
        def parsed(raw: str) -> list[Any]:
            try:
                value = json.loads(raw)
                return value if isinstance(value, list) else []
            except json.JSONDecodeError:
                return []
        details = {
            "payload_version": 2,
            "addresses": parsed(addresses_raw), "links": parsed(links_raw),
            "routes": parsed(routes_raw), "listeners": parse_listeners(listeners_raw),
            "raw": {"addresses": addresses_raw, "links": links_raw, "routes": routes_raw, "listeners": listeners_raw},
        }
        record_scan(self.conn, "network", "ok", "Network interfaces and listeners refreshed", details, started)

    def scan_sysstat(self) -> None:
        started = int(time.time() * 1_000_000)
        path = Path("/var/log/sysstat") / time.strftime("sa%d")
        raw = run_command(["sadf", "-j", str(path), "--", "-u", "-r", "-d", "-n", "DEV"], 30)
        try:
            history = json.loads(raw)
            status, summary = "ok", "Imported structured sysstat CPU, memory, disk and network history"
        except json.JSONDecodeError:
            history = {}
            status, summary = "error", "Unable to parse today's sysstat archive"
        details = {"payload_version": 2, "history": history, "raw": raw}
        record_scan(self.conn, "sysstat", status, summary, details, started)

    def scan_updates(self) -> None:
        started = int(time.time() * 1_000_000)
        apt = run_command(["apt", "list", "--upgradable"], 30)
        package_lines = [line for line in apt.splitlines() if "/" in line and not line.startswith("Listing")]
        packages = [item for line in package_lines if (item := parse_package_upgrade(line))]
        firmware_raw = run_command(["fwupdmgr", "get-updates", "--json", "--no-unreported-check"], 45)
        try:
            firmware = json.loads(firmware_raw)
        except json.JSONDecodeError:
            firmware = {}
        details = {
            "payload_version": 2, "packages": packages, "firmware": firmware,
            "raw": {"apt": apt, "firmware": firmware_raw},
        }
        status = "warning" if packages or bool(firmware) else "ok"
        record_scan(self.conn, "updates", status, f"{len(packages)} packages report available upgrades", details, started)

    def run_due_scans(self, force: bool = False) -> None:
        schedule = (
            ("services", 60, self.scan_failed_services),
            ("crashes", 300, self.scan_crashes),
            ("network", 300, self.scan_network),
            ("sysstat", 600, self.scan_sysstat),
            ("hardware", 600, self.scan_hardware),
            ("smart", 1800, self.scan_smart),
            ("updates", 86400, self.scan_updates),
        )
        now = time.time()
        for name, interval, callback in schedule:
            if force or now - self.last_run.get(name, 0) >= interval:
                try:
                    callback()
                except Exception as exc:
                    record_scan(self.conn, name, "error", f"{name} scan failed", {"error": str(exc)})
                self.last_run[name] = now

    def run(self) -> None:
        self.initialize()
        self.sample_metrics()
        if not self.once:
            # Start tailing before potentially slow hardware and update scans.
            # The bounded initial replay above has already persisted a resume
            # point, so this does not delay continuous monitoring.
            self.start_journal()
        self.run_due_scans(force=True)
        if self.once:
            return
        next_prune = time.time() + 3600
        while not self.stop.wait(10):
            self.sample_metrics()
            self.run_due_scans()
            if time.time() >= next_prune:
                prune_v2(self.conn)
                next_prune = time.time() + 3600

    def shutdown(self) -> None:
        self.stop.set()
        if self.journal_process and self.journal_process.poll() is None:
            self.journal_process.terminate()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    collector = Collector(args.db, once=args.once)
    signal.signal(signal.SIGTERM, lambda *_args: collector.shutdown())
    signal.signal(signal.SIGINT, lambda *_args: collector.shutdown())
    collector.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
