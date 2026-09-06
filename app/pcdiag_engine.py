#!/usr/bin/env python3
"""Incident engine, v2 database, health probes, and privacy helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from pcdiag_common import (
    DATA_DIR,
    DB_PATH,
    create_private_file_if_missing,
    ensure_database_parent,
    ensure_private_file,
    safe_text,
)


SCHEMA_VERSION = 3
HELPER_SOCKET = Path("/run/pc-diagnostics/helper.sock")
TUNING_SOCKET = Path("/run/pc-diagnostics/tuning.sock")

# Exact hardware telemetry is high-volume and primarily useful for recent
# incident reconstruction.  Fault evidence remains useful much longer.
FORENSIC_RETENTION_DAYS = 365
HIGH_RESOLUTION_RETENTION_DAYS = 7
MINUTE_METRIC_RETENTION_DAYS = 7
AGGREGATE_METRIC_RETENTION_DAYS = 90
HIGH_RESOLUTION_METRIC_PREFIXES = ("temperature.", "gpu.", "power.", "voltage.")
MIN_JOURNAL_TIMESTAMP_US = 100_000_000_000_000  # 1973-03-03; rejects seconds/milliseconds.
MAX_JOURNAL_FUTURE_SECONDS = 24 * 60 * 60


def is_high_resolution_metric(metric: str) -> bool:
    """Whether a metric must retain every ten-second collector sample."""
    return metric.startswith(HIGH_RESOLUTION_METRIC_PREFIXES)


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: str
    category: str
    title: str
    cause: str
    impact: str
    remediation: tuple[str, ...] = ()
    scope: str = "global"


def _rule(
    rule_id: str,
    pattern: str,
    severity: str,
    category: str,
    title: str,
    cause: str,
    impact: str,
    remediation: tuple[str, ...] = (),
    scope: str = "global",
) -> Rule:
    return Rule(
        rule_id,
        re.compile(pattern, re.I),
        severity,
        category,
        title,
        cause,
        impact,
        remediation,
        scope,
    )


RULES: tuple[Rule, ...] = (
    _rule(
        "xhci-resume",
        r"xHC error in resume|USBSTS\s+0x401",
        "Critical",
        "USB",
        "USB controller failed to resume",
        "The platform firmware could not restore an xHCI controller after system sleep.",
        "Linux reinitializes the entire controller, temporarily disconnecting every device on it; mounted USB storage may be at risk.",
        ("Update the motherboard UEFI/BIOS.", "Test s2idle instead of deep S3 sleep.", "Unmount external storage before suspend tests."),
    ),
    _rule(
        "usb-protocol",
        r"device descriptor read.*error|device not responding to setup|unable to enumerate USB|reset (?:high-speed|SuperSpeed).*USB device",
        "Warning",
        "USB",
        "USB communication failure",
        "A USB device, hub, cable, port, or controller did not complete a protocol operation.",
        "The affected device may freeze, reconnect, or lose in-flight data.",
        ("Reconnect the device directly to another port.", "Check the cable and powered-hub supply.", "Inspect nearby USB controller events."),
        "device",
    ),
    _rule(
        "usb-disconnect",
        r"USB disconnect, device number",
        "Activity",
        "USB",
        "USB device disconnected",
        "The kernel observed a physical or controller-driven USB disconnect.",
        "Input, storage, audio, or other USB functionality may briefly disappear.",
        ("Check whether the disconnect was intentional.", "Correlate it with controller-reset and power events."),
        "device",
    ),
    _rule(
        "gpu-xid",
        r"NVRM:.*Xid|GPU has fallen off the bus",
        "Critical",
        "Graphics",
        "NVIDIA GPU hardware/driver fault",
        "The NVIDIA driver reported an Xid or lost communication with the GPU.",
        "Applications or the entire desktop may freeze, crash, or lose display output.",
        ("Record the Xid number and workload.", "Check GPU power, seating, temperature, driver and firmware versions."),
        "device",
    ),
    _rule(
        "nvidia-register",
        r"gpuHandleSanityCheckRegReadError|Possible bad register read",
        "Error",
        "Graphics",
        "NVIDIA register-read failure",
        "The NVIDIA driver received an invalid register response from the GPU.",
        "Repeated failures can accompany GPU stalls or PCIe/power instability.",
        ("Check for nearby NVRM Xid entries.", "Verify GPU power and driver health."),
        "device",
    ),
    _rule(
        "gpu-reset",
        r"amdgpu.*(?:ring .* timeout|GPU reset|failed to reset)|drm.*GPU HANG",
        "Critical",
        "Graphics",
        "GPU timeout or reset",
        "The graphics driver stopped receiving timely responses from the GPU.",
        "The desktop and hardware-accelerated applications may pause or crash.",
        ("Capture the affected workload.", "Review driver, firmware, temperatures, and power stability."),
        "device",
    ),
    _rule(
        "wifi-mt7925",
        r"mt7925e.*(?:driver own failed|chip reset failed|timeout)",
        "Error",
        "Network",
        "MediaTek Wi-Fi driver/controller failure",
        "The mt7925e driver could not take ownership of or communicate with the wireless controller.",
        "Wi-Fi can stall, disconnect, or require a device reset.",
        ("Update UEFI, kernel, and linux-firmware.", "Cold-boot the machine if resets continue.", "Prefer Ethernet while collecting evidence."),
        "device",
    ),
    _rule(
        "storage-io",
        r"Buffer I/O error|blk_update_request.*error|I/O error.*dev|nvme.*(?:timeout|reset|I/O)",
        "Critical",
        "Storage",
        "Storage I/O failure",
        "A disk, controller, cable, or storage driver failed an input/output request.",
        "Data may be unavailable or corrupted; continuing writes can worsen damage.",
        ("Back up important data immediately.", "Review SMART/NVMe health.", "Avoid filesystem repair until a backup exists."),
        "device",
    ),
    _rule(
        "filesystem-error",
        r"EXT[234]-fs error|BTRFS.*(?:error|corrupt)|XFS.*Corruption|filesystem.*(?:corrupt|error)",
        "Critical",
        "Storage",
        "Filesystem error",
        "The filesystem detected inconsistent metadata or failed storage operations.",
        "Files may be damaged and the filesystem may remount read-only.",
        ("Stop unnecessary writes.", "Back up readable data.", "Run the filesystem-specific offline check only after backup."),
        "device",
    ),
    _rule(
        "oom",
        r"Out of memory|oom-kill|Killed process .* total-vm",
        "Critical",
        "Memory/CPU",
        "Out-of-memory termination",
        "Available RAM and swap were exhausted, so the kernel killed a process.",
        "Applications can abruptly close and unsaved work can be lost.",
        ("Identify the process with growing memory usage.", "Check swap configuration and workload limits."),
    ),
    _rule(
        "unclean-shutdown",
        r"(?:system|user)(?:-[\w-]+)?\.journal.*(?:corrupted|uncleanly shut down)|"
        r"journal.*unclean shutdown|previous boot.*(?:unclean|abrupt)",
        "Critical",
        "Power",
        "Unclean shutdown or hard-reset evidence",
        "The previous boot ended without a normal journal shutdown sequence. This can follow a forced reset, power interruption, hardware lockup, or kernel failure.",
        "In-flight work and journal records may be lost. The surviving power, thermal, GPU, and kernel evidence immediately before the interruption is especially important.",
        ("Open the previous-boot timeline.", "Review the preceding hardware warnings and recent telemetry.", "Check power delivery and hardware stability if this repeats."),
    ),
    _rule(
        "kernel-crash",
        r"Kernel panic|not syncing|Oops(?:[:\s])|BUG: unable to handle|BUG: kernel NULL pointer|general protection fault.*(?:kernel|RIP)|Fatal exception in interrupt|double fault|kernel BUG at",
        "Critical",
        "Kernel",
        "Kernel crash",
        "The Linux kernel encountered a fatal exception or invariant violation and could not continue safely.",
        "The whole system may freeze or reboot, and unsaved work or in-flight writes can be lost.",
        ("Preserve the complete kernel trace and previous-boot journal.", "Check firmware, memory stability, drivers, and recent kernel changes."),
    ),
    _rule(
        "kernel-lockup",
        r"soft lockup|hard LOCKUP|watchdog: BUG|rcu.*stall|hung task",
        "Critical",
        "Memory/CPU",
        "Kernel or CPU stall",
        "A CPU or kernel task stopped making forward progress.",
        "The machine can become unresponsive or require a forced reboot.",
        ("Preserve the complete kernel trace.", "Check firmware, overclocking, memory stability, and kernel regressions."),
    ),
    _rule(
        "hardware-ras",
        r"Machine check|Hardware Error|EDAC.*(?:error|CE|UE)|AER:.*error",
        "Critical",
        "Hardware",
        "Hardware reliability error",
        "CPU, memory, PCIe, or platform reliability reporting detected an error.",
        "Uncorrected errors can crash the system or corrupt data.",
        ("Return BIOS settings to defaults.", "Run memory and hardware diagnostics.", "Inspect the full RAS/AER record."),
        "device",
    ),
    _rule(
        "thermal",
        r"temperature above threshold|thermal throttling|critical temperature|overheat",
        "Critical",
        "Thermal",
        "Thermal limit reached",
        "A validated hardware sensor or driver reported an unsafe temperature.",
        "Hardware will throttle and may shut down to prevent damage.",
        ("Reduce workload.", "Check fans, pump, dust, heatsink contact, and ambient temperature."),
        "device",
    ),
    _rule(
        "service-failed",
        r"Failed with result|Main process exited.*(?:FAILURE|status=[1-9])|Failed to start",
        "Warning",
        "Services",
        "Service failed",
        "A systemd service exited unsuccessfully or could not start.",
        "Features provided by the service may be unavailable.",
        ("Review the unit status and its surrounding journal entries.", "Restart only after identifying why it failed."),
        "unit",
    ),
    _rule(
        "process-crash",
        r"segfault at|core dumped|trap .* error|Process .* dumped core",
        "Error",
        "Crashes",
        "Application or process crashed",
        "A process terminated because of an invalid memory access or fatal signal.",
        "The application may lose work or repeatedly fail to start.",
        ("Inspect crash metadata and the preceding application log.", "Update or isolate the responsible application."),
        "process",
    ),
    _rule(
        "deskflow-restart",
        r"deskflow.*(?:stopping core|desktop process exited with code|starting server process)",
        "Warning",
        "Input",
        "Deskflow input service restarted",
        "Deskflow stopped and restarted the component that captures and forwards keyboard/mouse input.",
        "The local pointer can freeze or disappear for several seconds.",
        ("Temporarily quit Deskflow to confirm the symptom.", "Review client connectivity and Deskflow configuration."),
    ),
    _rule(
        "network-link",
        r"link is down|carrier lost|deauthenticated|disconnected from AP",
        "Warning",
        "Network",
        "Network link dropped",
        "The network interface lost physical carrier or wireless association.",
        "Connections may pause or terminate.",
        ("Check cable/signal quality and nearby driver resets.",),
        "device",
    ),
    _rule(
        "authentication",
        r"authentication failure|FAILED LOGIN|Failed password|pam_unix.*failure",
        "Warning",
        "Security",
        "Authentication failure",
        "A login or privileged authentication attempt failed.",
        "Repeated unexpected failures can indicate a configuration problem or unauthorized attempts.",
        ("Verify whether the account and source are expected.", "Inspect authentication logs for repetition."),
        "message",
    ),
)

SEVERITY_RANK = {"Activity": 0, "Notice": 1, "Warning": 2, "Error": 3, "Critical": 4}

# These represent machine-wide failure or credible hardware/data-loss risk.  In
# the UI they rank above ordinary Critical incidents, but the persisted severity
# remains the standard, interoperable "Critical" value.
TOP_CRITICAL_RULE_IDS = frozenset({
    "kernel-crash", "kernel-crash-artifact", "kernel-lockup", "hardware-ras", "smart-health",
    "storage-io", "filesystem-error", "gpu-xid", "gpu-reset", "unclean-shutdown",
    "xhci-resume", "thermal",
})
FORENSIC_RULE_IDS = TOP_CRITICAL_RULE_IDS | frozenset({"temperature-high", "oom", "process-crash", "tuning-rollback"})


def connect_v2(path: Path = DB_PATH) -> sqlite3.Connection:
    ensure_database_parent(path)
    create_private_file_if_missing(path)
    create_private_file_if_missing(path.with_name(path.name + "-wal"))
    create_private_file_if_missing(path.with_name(path.name + "-shm"))
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    ensure_private_file(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=1000")
    conn.execute("PRAGMA journal_size_limit=16777216")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            likely_cause TEXT NOT NULL,
            impact TEXT NOT NULL,
            remediation_json TEXT NOT NULL,
            first_us INTEGER NOT NULL,
            last_us INTEGER NOT NULL,
            occurrences INTEGER NOT NULL DEFAULT 1,
            last_boot_id TEXT NOT NULL,
            source TEXT NOT NULL,
            unit_name TEXT NOT NULL,
            sample_message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_last ON incidents(last_us DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, last_us DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_category ON incidents(category, last_us DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_status_last ON incidents(status, last_us DESC);

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            occurred_us INTEGER NOT NULL,
            boot_id TEXT NOT NULL,
            cursor TEXT NOT NULL UNIQUE,
            priority INTEGER NOT NULL,
            source TEXT NOT NULL,
            unit_name TEXT NOT NULL,
            message TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id, occurred_us DESC);
        CREATE INDEX IF NOT EXISTS idx_evidence_time ON evidence(occurred_us DESC);

        CREATE TABLE IF NOT EXISTS metric_rollups (
            bucket_us INTEGER NOT NULL,
            interval_seconds INTEGER NOT NULL,
            metric TEXT NOT NULL,
            labels_json TEXT NOT NULL DEFAULT '{}',
            minimum REAL NOT NULL,
            maximum REAL NOT NULL,
            average REAL NOT NULL,
            last_value REAL NOT NULL,
            last_sample_us INTEGER NOT NULL,
            samples INTEGER NOT NULL,
            unit TEXT NOT NULL,
            PRIMARY KEY(bucket_us, interval_seconds, metric, labels_json)
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON metric_rollups(metric, bucket_us DESC);

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            started_us INTEGER NOT NULL,
            finished_us INTEGER NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_type_time ON scans(scan_type, finished_us DESC);

        CREATE TABLE IF NOT EXISTS notifications (
            fingerprint TEXT PRIMARY KEY,
            last_us INTEGER NOT NULL,
            total INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS forensic_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            boot_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            occurred_us INTEGER NOT NULL,
            window_start_us INTEGER NOT NULL,
            window_end_us INTEGER NOT NULL,
            analysis_json TEXT NOT NULL,
            created_us INTEGER NOT NULL,
            updated_us INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_forensic_cases_time ON forensic_cases(occurred_us DESC);
        CREATE INDEX IF NOT EXISTS idx_forensic_cases_boot ON forensic_cases(boot_id, occurred_us DESC);
        CREATE TABLE IF NOT EXISTS tuning_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_us INTEGER NOT NULL,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            reason TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tuning_audit_time ON tuning_audit(occurred_us DESC);
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_offsets (
            source TEXT PRIMARY KEY,
            cursor TEXT NOT NULL DEFAULT '',
            occurred_us INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    metric_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(metric_rollups)")}
    if "last_sample_us" not in metric_columns:
        conn.execute("ALTER TABLE metric_rollups ADD COLUMN last_sample_us INTEGER NOT NULL DEFAULT 0")
        # Legacy rollups have no sub-bucket ordering information. Treat their
        # bucket boundary as the last known sample so the first fresh sample
        # wins deterministically.
        conn.execute("UPDATE metric_rollups SET last_sample_us=bucket_us WHERE last_sample_us=0")
    defaults = {
        "retention_days": str(FORENSIC_RETENTION_DAYS),
        "notification_policy": "errors-warnings",
        "anomaly_profile": "aggressive",
        "export_privacy": "ask",
        "remediation_mode": "guided",
    }
    conn.executemany("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", defaults.items())
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    conn.commit()
    ensure_private_file(path)
    ensure_private_file(path.with_name(path.name + "-wal"))
    ensure_private_file(path.with_name(path.name + "-shm"))
    return conn


@contextmanager
def open_v2(path: Path = DB_PATH, *, readonly: bool = False):
    """Open a v2 database connection and always close it on scope exit.

    GUI refreshes use read-only connections so they neither repeat schema writes
    nor hold WAL descriptors beyond one refresh cycle.  Long-running collectors
    can continue to use ``connect_v2`` for their intentionally persistent
    connections.
    """
    if readonly:
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # UI refreshes should degrade gracefully rather than freezing the GTK
        # main loop behind a long writer transaction.
        conn.execute("PRAGMA busy_timeout=2000")
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA foreign_keys=ON")
    else:
        conn = connect_v2(path)
    try:
        yield conn
    finally:
        conn.close()


def incident_change_token(conn: sqlite3.Connection) -> tuple[int, int, int, int]:
    """Return a cheap token that changes for new evidence and status updates."""
    row = conn.execute(
        "SELECT COALESCE((SELECT MAX(id) FROM evidence),0),"
        "COALESCE((SELECT MAX(last_us) FROM incidents),0),"
        "COALESCE((SELECT SUM(acknowledged) FROM incidents),0),"
        "COALESCE((SELECT COUNT(*) FROM incidents WHERE status='open'),0)"
    ).fetchone()
    return tuple(int(value) for value in row)


def backup_database(path: Path = DB_PATH) -> Path | None:
    if not path.exists():
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"events-v1-backup-{stamp}.sqlite3")
    for index in range(1_000):
        candidate = backup if index == 0 else path.with_name(f"events-v1-backup-{stamp}-{index}.sqlite3")
        if create_private_file_if_missing(candidate):
            backup = candidate
            break
    else:
        raise sqlite3.OperationalError("unable to allocate a unique database backup path")
    source = sqlite3.connect(path)
    target = sqlite3.connect(backup)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    ensure_private_file(backup)
    return backup


def normalized_message(message: str) -> str:
    text = message.lower()
    text = re.sub(r"audit\([^)]*\)", "audit(*)", text)
    text = re.sub(r"\b(pid|uid|gid|ino|seq|device number|status)=?\s*[0-9a-fx:-]+", r"\1=*", text)
    text = re.sub(r"\b[0-9a-f]{8,}\b", "#", text)
    text = re.sub(r"\b\d{3,}\b", "#", text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def find_rule(message: str, source: str = "", unit: str = "") -> Rule | None:
    haystack = f"{source} {unit} {message}"
    for rule in RULES:
        if rule.pattern.search(haystack):
            return rule
    return None


def priority_severity(priority: int) -> str:
    if priority <= 2:
        return "Critical"
    if priority == 3:
        return "Error"
    if priority == 4:
        return "Warning"
    return "Activity"


def generic_category(message: str, source: str, unit: str) -> str:
    text = f"{source} {unit} {message}".lower()
    mappings = (
        ("USB", ("usb", "xhci", "hid")),
        ("Graphics", ("nvidia", "nvrm", "amdgpu", "drm", "gpu", "kwin", "xorg")),
        ("Storage", ("nvme", "ata", "scsi", "filesystem", "ext4", "btrfs", "disk")),
        ("Network", ("network", "wifi", "wlan", "ethernet", "bluetooth", "r8169", "mt7925")),
        ("Power", ("suspend", "resume", "sleep", "acpi", "power")),
        ("Security", ("audit", "apparmor", "denied", "authentication")),
        ("Services", ("systemd", "service", "daemon")),
    )
    for category, terms in mappings:
        if any(term in text for term in terms):
            return category
    return "Kernel" if source == "kernel" else "System"


def scope_value(rule: Rule | None, message: str, source: str, unit: str) -> str:
    if not rule:
        return normalized_message(message)
    if rule.scope == "unit":
        return unit or source
    if rule.scope == "process":
        return source
    if rule.scope == "device":
        match = re.search(r"(?:\b\d{4}:\d{2}:\d{2}\.\d\b|\busb\s+\d+(?:-[\d.]+)+|\b(?:nvme\d+n\d+|sd[a-z]+)\b)", message, re.I)
        return match.group(0).lower() if match else source
    if rule.scope == "message":
        return normalized_message(message)
    return "global"


def fingerprint_for(rule_id: str, scope: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{scope}".encode()).hexdigest()


def record_incident(
    conn: sqlite3.Connection,
    *,
    rule_id: str,
    severity: str,
    category: str,
    title: str,
    summary: str,
    likely_cause: str,
    impact: str,
    remediation: Iterable[str],
    occurred_us: int,
    boot_id: str,
    cursor: str,
    priority: int,
    source: str,
    unit: str,
    message: str,
    details: dict[str, Any] | str | None = None,
    scope: str = "global",
    commit: bool = True,
) -> tuple[int, bool]:
    if category == "Hardware" or rule_id in TOP_CRITICAL_RULE_IDS:
        severity = "Critical"
    existing = conn.execute("SELECT incident_id FROM evidence WHERE cursor=?", (cursor,)).fetchone()
    if existing:
        return int(existing[0]), False
    fingerprint = fingerprint_for(rule_id, scope)
    details_json = details if isinstance(details, str) else json.dumps(details or {}, ensure_ascii=False, sort_keys=True)
    conn.execute(
        """
        INSERT INTO incidents
        (fingerprint, rule_id, severity, category, title, summary, likely_cause,
         impact, remediation_json, first_us, last_us, occurrences, last_boot_id,
         source, unit_name, sample_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            severity=CASE
                WHEN excluded.severity='Critical' THEN 'Critical'
                WHEN excluded.severity='Error' AND incidents.severity NOT IN ('Critical') THEN 'Error'
                WHEN excluded.severity='Warning' AND incidents.severity IN ('Activity','Notice') THEN 'Warning'
                ELSE incidents.severity END,
            last_us=MAX(incidents.last_us, excluded.last_us),
            first_us=MIN(incidents.first_us, excluded.first_us),
            occurrences=incidents.occurrences+1,
            last_boot_id=CASE WHEN excluded.last_us>=incidents.last_us THEN excluded.last_boot_id ELSE incidents.last_boot_id END,
            source=CASE WHEN excluded.last_us>=incidents.last_us THEN excluded.source ELSE incidents.source END,
            unit_name=CASE WHEN excluded.last_us>=incidents.last_us THEN excluded.unit_name ELSE incidents.unit_name END,
            sample_message=CASE WHEN excluded.last_us>=incidents.last_us THEN excluded.sample_message ELSE incidents.sample_message END,
            status=CASE WHEN excluded.last_us>=incidents.last_us THEN 'open' ELSE incidents.status END
        """,
        (
            fingerprint,
            rule_id,
            severity,
            category,
            title,
            summary,
            likely_cause,
            impact,
            json.dumps(tuple(remediation), ensure_ascii=False),
            occurred_us,
            occurred_us,
            boot_id,
            source,
            unit,
            message,
        ),
    )
    incident_id = int(conn.execute("SELECT id FROM incidents WHERE fingerprint=?", (fingerprint,)).fetchone()[0])
    conn.execute(
        """
        INSERT INTO evidence
        (incident_id, occurred_us, boot_id, cursor, priority, source, unit_name, message, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (incident_id, occurred_us, boot_id, cursor, priority, source, unit, message, details_json),
    )
    if commit:
        conn.commit()
    return incident_id, True


def record_forensic_case(
    conn: sqlite3.Connection,
    incident_id: int,
    occurred_us: int,
    boot_id: str,
    *,
    commit: bool = True,
) -> bool:
    """Persist a stable investigation window; return whether it was created."""
    incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not incident or incident["rule_id"] not in FORENSIC_RULE_IDS:
        return False
    now = int(time.time() * 1_000_000)
    window_start_us = max(0, occurred_us - 30 * 60 * 1_000_000)
    window_end_us = occurred_us + 10 * 60 * 1_000_000
    fingerprint = fingerprint_for("forensic-case", f"{incident_id}:{boot_id}")
    created = conn.execute("SELECT 1 FROM forensic_cases WHERE fingerprint=?", (fingerprint,)).fetchone() is None
    analysis = {
        "observed": incident["summary"],
        "rule_id": incident["rule_id"],
        "source": incident["source"],
        "window": {"before_seconds": 1800, "after_seconds": 600},
    }
    conn.execute(
        """
        INSERT INTO forensic_cases
        (fingerprint,incident_id,boot_id,kind,severity,title,occurred_us,window_start_us,
         window_end_us,analysis_json,created_us,updated_us)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            kind=excluded.kind,
            severity=excluded.severity,
            title=excluded.title,
            occurred_us=MAX(forensic_cases.occurred_us,excluded.occurred_us),
            window_start_us=MIN(forensic_cases.window_start_us,excluded.window_start_us),
            window_end_us=MAX(forensic_cases.window_end_us,excluded.window_end_us),
            analysis_json=excluded.analysis_json,
            updated_us=excluded.updated_us
        """,
        (
            fingerprint, incident_id, boot_id, incident["rule_id"], incident["severity"], incident["title"],
            occurred_us, window_start_us, window_end_us, json.dumps(analysis, ensure_ascii=False, sort_keys=True), now, now,
        ),
    )
    if commit:
        conn.commit()
    return created


def reconcile_forensic_cases(conn: sqlite3.Connection) -> int:
    """Create investigation records for retained historical fault evidence."""
    placeholders = ",".join("?" for _item in FORENSIC_RULE_IDS)
    rows = conn.execute(
        "SELECT e.incident_id,e.occurred_us,e.boot_id FROM evidence e "
        "JOIN incidents i ON i.id=e.incident_id "
        f"WHERE i.rule_id IN ({placeholders}) ORDER BY e.occurred_us",
        tuple(sorted(FORENSIC_RULE_IDS)),
    ).fetchall()
    created = 0
    for row in rows:
        if record_forensic_case(
            conn, int(row["incident_id"]), int(row["occurred_us"]), str(row["boot_id"]), commit=False,
        ):
            created += 1
    if rows:
        conn.commit()
    return created


def promote_top_critical_incidents(conn: sqlite3.Connection) -> int:
    """Promote historical hardware faults and kernel-crash signatures."""
    changed = conn.execute(
        "UPDATE incidents SET severity='Critical' WHERE severity<>'Critical' "
        "AND (category='Hardware' OR rule_id IN ({operations}))".format(
            operations=",".join("?" for _item in TOP_CRITICAL_RULE_IDS)
        ),
        tuple(sorted(TOP_CRITICAL_RULE_IDS)),
    ).rowcount
    candidates = conn.execute(
        "SELECT id,sample_message,severity,rule_id FROM incidents WHERE rule_id<>'kernel-crash'"
    ).fetchall()
    promotions = []
    for row in candidates:
        rule = find_rule(str(row["sample_message"]))
        if not rule or rule.rule_id not in TOP_CRITICAL_RULE_IDS or row["rule_id"] == rule.rule_id:
            continue
        promotions.append((
            rule.rule_id, rule.severity, rule.category, rule.title,
            rule.cause, rule.impact, json.dumps(rule.remediation), row["id"],
        ))
    if promotions:
        conn.executemany(
            "UPDATE incidents SET rule_id=?,severity=?,category=?,title=?,likely_cause=?,impact=?,remediation_json=? WHERE id=?",
            promotions,
        )
        changed += len(promotions)
    conn.commit()
    return changed


def resolve_incident(conn: sqlite3.Connection, rule_id: str, scope: str = "global") -> bool:
    """Resolve an active synthetic incident after its measured condition clears."""
    result = conn.execute(
        "UPDATE incidents SET status='resolved' WHERE fingerprint=? AND status='open'",
        (fingerprint_for(rule_id, scope),),
    )
    changed = result.rowcount > 0
    conn.commit()
    return changed


def ingest_journal_record(
    conn: sqlite3.Connection, record: dict[str, Any], *, commit: bool = True
) -> tuple[int, bool] | None:
    message = safe_text(record.get("MESSAGE")).strip()
    if not message:
        return None
    try:
        priority = int(record.get("PRIORITY", 6))
    except (TypeError, ValueError):
        priority = 6
    source = safe_text(record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or record.get("_TRANSPORT") or "unknown")
    unit = safe_text(record.get("_SYSTEMD_UNIT") or record.get("_SYSTEMD_USER_UNIT"))
    rule = find_rule(message, source, unit)
    if priority > 4 and not rule:
        return None
    occurred_us = journal_timestamp_us(record.get("__REALTIME_TIMESTAMP"))
    boot_id = safe_text(record.get("_BOOT_ID"), "unknown")
    if rule and rule.rule_id in ("usb-disconnect", "usb-protocol"):
        recent_xhci = conn.execute(
            "SELECT id FROM incidents WHERE rule_id='xhci-resume' AND last_boot_id=? "
            "AND last_us BETWEEN ? AND ? ORDER BY last_us DESC LIMIT 1",
            (boot_id, occurred_us - 30_000_000, occurred_us + 5_000_000),
        ).fetchone()
        if recent_xhci:
            rule = next(candidate for candidate in RULES if candidate.rule_id == "xhci-resume")
    cursor = safe_text(record.get("__CURSOR")) or "synthetic:" + hashlib.sha256(
        f"{occurred_us}\0{source}\0{message}".encode()
    ).hexdigest()
    if rule:
        severity = rule.severity
        category = rule.category
        title = rule.title
        cause = rule.cause
        impact = rule.impact
        remediation = rule.remediation
        rule_id = rule.rule_id
        scope = scope_value(rule, message, source, unit)
    else:
        severity = priority_severity(priority)
        category = generic_category(message, source, unit)
        title = f"{category} {severity.lower()} from {source}"
        cause = "The source logged a warning or error without a more specific matching diagnostic rule."
        impact = "Review the complete message and surrounding entries to determine user-visible impact."
        remediation = ("Inspect surrounding journal entries and the responsible service or driver.",)
        rule_id = "generic-" + category.lower().replace("/", "-")
        scope = f"{source}:{unit}:{normalized_message(message)}"
    details = {
        key: safe_text(record.get(key))
        for key in (
            "_HOSTNAME", "_PID", "_COMM", "_EXE", "_CMDLINE", "_TRANSPORT",
            "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT", "CODE_FILE", "CODE_LINE", "CODE_FUNC",
        )
        if record.get(key) is not None
    }
    return record_incident(
        conn,
        rule_id=rule_id,
        severity=severity,
        category=category,
        title=title,
        summary=message,
        likely_cause=cause,
        impact=impact,
        remediation=remediation,
        occurred_us=occurred_us,
        boot_id=boot_id,
        cursor=cursor,
        priority=priority,
        source=source,
        unit=unit,
        message=message,
        details=details,
        scope=scope,
        commit=commit,
    )


def journal_timestamp_us(value: Any, default: int | None = None) -> int:
    """Return a usable journal timestamp without letting malformed fields stop collection.

    Journald normally emits an integer microsecond timestamp, but retained or
    forwarded records are external input.  Treat an invalid value as an event
    observed now (or at the supplied checkpoint) rather than crashing the
    backfill process or its follower thread.
    """
    now = int(time.time() * 1_000_000)
    fallback = now if default is None else int(default)
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return fallback
    if not MIN_JOURNAL_TIMESTAMP_US <= timestamp <= now + MAX_JOURNAL_FUTURE_SECONDS * 1_000_000:
        return fallback
    return timestamp


def migrate_legacy_events(conn: sqlite3.Connection) -> int:
    table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
    if not table:
        return 0
    done = conn.execute("SELECT value FROM settings WHERE key='legacy_migration_complete'").fetchone()
    if done and done[0] == "1":
        return 0
    migrated = 0
    last_id = 0
    while True:
        rows = conn.execute(
            "SELECT * FROM events WHERE id>? ORDER BY id LIMIT 1000", (last_id,)
        ).fetchall()
        if not rows:
            break
        for row in rows:
            record = {
                "MESSAGE": row["message"],
                "PRIORITY": row["priority"],
                "__REALTIME_TIMESTAMP": row["occurred_us"],
                "_BOOT_ID": row["boot_id"],
                "__CURSOR": "legacy:" + row["cursor"],
                "SYSLOG_IDENTIFIER": row["source"],
                "_SYSTEMD_UNIT": row["unit_name"],
                "_TRANSPORT": row["transport"],
            }
            if ingest_journal_record(conn, record, commit=False):
                migrated += 1
            last_id = row["id"]
        conn.commit()
    conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('legacy_migration_complete','1')")
    conn.commit()
    conn.execute("DROP TABLE events")
    conn.execute("DROP TABLE IF EXISTS meta")
    conn.commit()
    conn.execute("VACUUM")
    return migrated


def update_metric(
    conn: sqlite3.Connection,
    metric: str,
    value: float,
    unit: str,
    labels: dict[str, str] | None = None,
    timestamp_us: int | None = None,
    interval_seconds: int = 60,
    commit: bool = True,
) -> None:
    timestamp_us = int(time.time() * 1_000_000) if timestamp_us is None else int(timestamp_us)
    bucket_size = interval_seconds * 1_000_000
    bucket = timestamp_us - timestamp_us % bucket_size
    labels_json = json.dumps(labels or {}, sort_keys=True, separators=(",", ":"))
    conn.execute(
        """
        INSERT INTO metric_rollups
        (bucket_us, interval_seconds, metric, labels_json, minimum, maximum, average,
         last_value, last_sample_us, samples, unit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(bucket_us, interval_seconds, metric, labels_json) DO UPDATE SET
            minimum=MIN(metric_rollups.minimum, excluded.minimum),
            maximum=MAX(metric_rollups.maximum, excluded.maximum),
            average=((metric_rollups.average*metric_rollups.samples)+excluded.last_value)/(metric_rollups.samples+1),
            last_value=CASE WHEN excluded.last_sample_us>=metric_rollups.last_sample_us THEN excluded.last_value ELSE metric_rollups.last_value END,
            last_sample_us=MAX(metric_rollups.last_sample_us, excluded.last_sample_us),
            samples=metric_rollups.samples+1
        """,
        (bucket, interval_seconds, metric, labels_json, value, value, value, value, timestamp_us, unit),
    )
    if commit:
        conn.commit()


def record_scan(conn: sqlite3.Connection, scan_type: str, status: str, summary: str, details: Any, started_us: int | None = None) -> None:
    now = int(time.time() * 1_000_000)
    details_json = json.dumps(details, ensure_ascii=False, sort_keys=True)
    previous = conn.execute(
        "SELECT id,status,summary,details_json,finished_us FROM scans WHERE scan_type=? ORDER BY finished_us DESC LIMIT 1",
        (scan_type,),
    ).fetchone()
    if previous and previous["status"] == status and previous["summary"] == summary:
        # Scans are current-state snapshots.  Update an unchanged health state in
        # place even when counters or temperatures in its details have changed;
        # retain a new row only for a status/summary transition.
        conn.execute(
            "UPDATE scans SET started_us=?,finished_us=?,details_json=? WHERE id=?",
            (started_us or now, now, details_json, previous["id"]),
        )
        conn.commit()
        return
    conn.execute(
        "INSERT INTO scans(scan_type,started_us,finished_us,status,summary,details_json) VALUES(?,?,?,?,?,?)",
        (scan_type, started_us or now, now, status, summary, details_json),
    )
    conn.commit()


def _socket_request(socket_path: Path, operation: str, **parameters: Any) -> dict[str, Any]:
    request = json.dumps({"operation": operation, "parameters": parameters}, separators=(",", ":")) + "\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            # SMART may legitimately take tens of seconds per physical drive;
            # tuning still gets a bounded connection timeout.
            client.settimeout(90 if operation == "smart" else 30)
            client.connect(str(socket_path))
            client.sendall(request.encode())
            chunks = []
            total = 0
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > 8 * 1024 * 1024:
                    raise ValueError("helper response exceeded 8 MiB")
                chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8", "replace"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc), "operation": operation}


def helper_request(operation: str, **parameters: Any) -> dict[str, Any]:
    """Make a read-only request to the diagnostics helper."""
    return _socket_request(HELPER_SOCKET, operation, **parameters)


def tuning_request(operation: str, **parameters: Any) -> dict[str, Any]:
    """Make a constrained request to the separate privileged tuning helper."""
    return _socket_request(TUNING_SOCKET, operation, **parameters)


def record_tuning_audit(
    conn: sqlite3.Connection,
    action: str,
    response: dict[str, Any],
    *,
    reason: str = "user-request",
) -> None:
    """Persist an append-only account of a requested tuning state change."""
    safe_action = action[:80]
    safe_reason = reason[:240]
    result = "ok" if response.get("ok") else "error"
    details = json.dumps(response, ensure_ascii=False, default=str)[:64 * 1024]
    conn.execute(
        "INSERT INTO tuning_audit(occurred_us,action,result,reason,details_json) VALUES(?,?,?,?,?)",
        (int(time.time() * 1_000_000), safe_action, result, safe_reason, details),
    )
    conn.commit()


def parse_sensor_data(data: dict[str, Any]) -> dict[str, dict[str, float | str]]:
    accepted: dict[str, dict[str, float | str]] = {}

    def unique_name(base: str, chip: str) -> str:
        """Keep readings from identical feature names on separate devices."""
        return base if base not in accepted else f"{base} [{chip}]"

    chip_rules = (
        (re.compile(r"k10temp", re.I), re.compile(r"Tctl|Tccd", re.I), "CPU"),
        (re.compile(r"nvme", re.I), re.compile(r"Composite|Sensor 1", re.I), "NVMe"),
        (re.compile(r"spd5118", re.I), re.compile(r"temp1", re.I), "Memory"),
        (re.compile(r"z53", re.I), re.compile(r"Coolant", re.I), "Coolant"),
        (re.compile(r"amdgpu", re.I), re.compile(r"edge", re.I), "AMD iGPU"),
        (re.compile(r"nct6799", re.I), re.compile(r"^(?:CPUTIN|SYSTIN|SMBUSMASTER 0)$", re.I), "Board"),
        (re.compile(r"r8169", re.I), re.compile(r"temp1", re.I), "Ethernet"),
    )
    for chip, features in data.items():
        if not isinstance(features, dict):
            continue
        for chip_pattern, feature_pattern, group in chip_rules:
            if not chip_pattern.search(chip):
                continue
            for feature, values in features.items():
                if not feature_pattern.search(feature) or not isinstance(values, dict):
                    continue
                for key, raw in values.items():
                    if not key.endswith("_input") or not isinstance(raw, (int, float)):
                        continue
                    value = float(raw)
                    if -20 <= value <= 150:
                        name = unique_name(f"{group} {feature}".strip(), chip)
                        accepted[name] = {"value": value, "unit": "°C", "chip": chip}
    return accepted


def validated_sensors() -> dict[str, dict[str, float | str]]:
    try:
        proc = subprocess.run(["sensors", "-j"], capture_output=True, text=True, timeout=5, check=False)
        data = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}
    return parse_sensor_data(data)


def parse_power_sensor_data(data: dict[str, Any]) -> dict[str, dict[str, float | str]]:
    """Return only power and voltage readings whose source labels are meaningful.

    Super-I/O chips commonly expose anonymous ``in0`` through ``in17`` channels.
    Their scaling and rail mapping are motherboard-specific, so reporting those as
    12 V, 5 V, or 3.3 V would be misleading.  Keep those raw values out of the
    health view unless lm-sensors provides an explicit rail name.
    """
    accepted: dict[str, dict[str, float | str]] = {}

    def unique_metric(base: str, chip: str) -> str:
        if base not in accepted:
            return base
        for suffix in (".watts", ".volts"):
            if base.endswith(suffix):
                return f"{base.removesuffix(suffix)} [{chip}]{suffix}"
        return f"{base} [{chip}]"

    def metric_for_named_rail(feature: str) -> str | None:
        """Classify only a rail whose driver/config explicitly names its role."""
        compact = re.sub(r"[^a-z0-9]+", "", feature.lower())
        if compact in {"vcore", "cpuvcore", "vddcpu", "vddcrcpu", "vddsoc", "vddcrsoc", "vsoc", "cpusoc", "vddio"}:
            return f"voltage.CPU {feature}.volts"
        if compact in {"dram", "vdram", "vdimm", "dimm", "vddq", "vdd2", "vpp", "memvdd", "memvddq"}:
            return f"voltage.Memory {feature}.volts"
        if compact in {"nvme", "m2", "m21", "m22", "m23", "m24"}:
            return f"voltage.NVMe {feature}.volts"
        if compact in {"12v", "5v", "33v", "vdd", "vddgfx", "vddnb"}:
            return f"voltage.Board {feature}.volts"
        return None

    for chip, features in data.items():
        if not isinstance(features, dict):
            continue
        for feature, values in features.items():
            if not isinstance(values, dict):
                continue
            lower_feature = feature.lower()
            if re.search(r"amdgpu", chip, re.I):
                if lower_feature == "ppt":
                    raw = values.get("power1_input")
                    if isinstance(raw, (int, float)) and 0 <= raw <= 1_000:
                        metric = unique_metric("power.AMD graphics PPT.watts", chip)
                        accepted[metric] = {
                            "value": float(raw), "unit": "W", "chip": chip,
                        }
                elif lower_feature in {"vddgfx", "vddnb"}:
                    raw = values.get("in0_input") if lower_feature == "vddgfx" else values.get("in1_input")
                    if isinstance(raw, (int, float)) and 0 < raw <= 5:
                        metric = unique_metric(f"voltage.AMD graphics {feature.upper()}.volts", chip)
                        accepted[metric] = {
                            "value": float(raw), "unit": "V", "chip": chip,
                        }
                # AMD GPU telemetry is handled above; do not report it again as
                # a generic motherboard rail.
                continue
            metric = metric_for_named_rail(feature)
            if metric is None:
                continue
            raw = next((value for key, value in values.items() if key.endswith("_input") and isinstance(value, (int, float))), None)
            if isinstance(raw, (int, float)) and 0 < raw <= 20:
                accepted[unique_metric(metric, chip)] = {
                    "value": float(raw), "unit": "V", "chip": chip,
                }
    return accepted


def validated_power_sensors() -> dict[str, dict[str, float | str]]:
    try:
        proc = subprocess.run(["sensors", "-j"], capture_output=True, text=True, timeout=5, check=False)
        data = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}
    return parse_power_sensor_data(data)


def parse_nvidia_metrics(output: str) -> dict[str, float]:
    """Parse every usable ``nvidia-smi`` CSV row without losing extra GPUs."""
    metrics: dict[str, float] = {}
    primary_gpu = True
    for line in output.splitlines():
        values = [value.strip() for value in line.split(",")]
        if len(values) != 7:
            continue
        try:
            gpu_id = int(values[0])
            utilization, temperature, memory_used, memory_total, power_draw, power_limit = (
                float(value) for value in values[1:]
            )
        except ValueError:
            # ``nvidia-smi`` emits N/A for unsupported sensors.  One missing
            # row must not suppress telemetry from the other GPUs.
            continue
        prefix = "gpu" if primary_gpu else f"gpu.{gpu_id}"
        temperature_name = "temperature.NVIDIA GPU" if primary_gpu else f"temperature.NVIDIA GPU {gpu_id}"
        metrics[f"{prefix}.percent"] = utilization
        metrics[temperature_name] = temperature
        metrics[f"{prefix}.memory.percent"] = 100 * memory_used / max(1, memory_total)
        metrics[f"{prefix}.power.draw.watts"] = power_draw
        metrics[f"{prefix}.power.limit.watts"] = power_limit
        metrics[f"{prefix}.power.percent"] = 100 * power_draw / max(1, power_limit)
        primary_gpu = False
    return metrics


def local_metrics(previous_cpu: tuple[int, int, int] | None = None) -> tuple[dict[str, float], tuple[int, int, int]]:
    metrics: dict[str, float] = {}
    parts = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    iowait = parts[4] if len(parts) > 4 else 0
    total = sum(parts)
    state = (idle, iowait, total)
    if previous_cpu:
        old_idle, old_iowait, old_total = previous_cpu
        delta = max(1, total - old_total)
        metrics["cpu.percent"] = max(0.0, min(100.0, 100 * (1 - (idle - old_idle) / delta)))
        metrics["cpu.iowait"] = max(0.0, min(100.0, 100 * (iowait - old_iowait) / delta))
    load1, load5, load15 = os.getloadavg()
    metrics.update({"load.1": load1, "load.5": load5, "load.15": load15})
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        mem[key] = int(value.strip().split()[0])
    metrics["memory.percent"] = 100 * (mem["MemTotal"] - mem["MemAvailable"]) / mem["MemTotal"]
    metrics["swap.percent"] = 0 if not mem.get("SwapTotal") else 100 * (mem["SwapTotal"] - mem["SwapFree"]) / mem["SwapTotal"]
    disk = shutil.disk_usage("/")
    metrics["disk.root.percent"] = 100 * disk.used / disk.total
    metrics["disk.root.free_gib"] = disk.free / 1073741824
    try:
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            interface, values_text = line.split(":", 1)
            interface = interface.strip()
            if interface == "lo":
                continue
            values = [int(value) for value in values_text.split()]
            metrics[f"network.{interface}.rx_errors"] = float(values[2])
            metrics[f"network.{interface}.rx_dropped"] = float(values[3])
            metrics[f"network.{interface}.tx_errors"] = float(values[10])
            metrics[f"network.{interface}.tx_dropped"] = float(values[11])
    except (OSError, ValueError, IndexError):
        pass
    for name, item in validated_sensors().items():
        metrics[f"temperature.{name}"] = float(item["value"])
    for metric, item in validated_power_sensors().items():
        metrics[metric] = float(item["value"])
    try:
        output = subprocess.run(
            ["nvidia-smi", "--query-gpu=index,utilization.gpu,temperature.gpu,memory.used,memory.total,power.draw,power.limit", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=4, check=False,
        ).stdout
        metrics.update(parse_nvidia_metrics(output))
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return metrics, state


def prune_v2(conn: sqlite3.Connection, retention_days: int = FORENSIC_RETENTION_DAYS) -> None:
    cutoff = int((time.time() - retention_days * 86400) * 1_000_000)
    high_resolution_cutoff = int((time.time() - HIGH_RESOLUTION_RETENTION_DAYS * 86400) * 1_000_000)
    minute_metric_cutoff = int((time.time() - MINUTE_METRIC_RETENTION_DAYS * 86400) * 1_000_000)
    aggregate_metric_cutoff = int((time.time() - AGGREGATE_METRIC_RETENTION_DAYS * 86400) * 1_000_000)
    conn.execute("DELETE FROM evidence WHERE occurred_us < ?", (cutoff,))
    conn.execute("DELETE FROM incidents WHERE last_us < ?", (cutoff,))
    conn.execute("DELETE FROM scans WHERE finished_us < ?", (cutoff,))
    conn.execute("DELETE FROM tuning_audit WHERE occurred_us < ?", (cutoff,))
    conn.execute("DELETE FROM metric_rollups WHERE interval_seconds=10 AND bucket_us < ?", (high_resolution_cutoff,))
    conn.execute("DELETE FROM metric_rollups WHERE interval_seconds=60 AND bucket_us < ?", (minute_metric_cutoff,))
    conn.execute("DELETE FROM metric_rollups WHERE interval_seconds>60 AND bucket_us < ?", (aggregate_metric_cutoff,))
    conn.execute("DELETE FROM notifications WHERE last_us < ?", (cutoff,))
    conn.execute("PRAGMA incremental_vacuum")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(PASSIVE)")


_IDENTIFIER_FIELD = r"(?:serial[ _-]?number|serial|uuid|machine[ _-]?id|wwn|wwid|eui[ _-]?64|nguid|asset[ _-]?tag|device[ _-]?id)"
_SECRET_FIELD = r"(?:token|password|secret|authorization|api[ _-]?key|access[ _-]?key|private[ _-]?key|session[ _-]?id)"
_IPV6_CANDIDATE = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])", re.I)

REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/(?:home/[^/\s\"']+|root)(?=/|\b)"), "/<user>"),
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "<ip-address>"),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I), "<mac-address>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I), "<email-address>"),
    # Covers both DMI's ``Serial Number: value`` and JSON-style
    # ``\"serial_number\": \"value\"`` fields from SMART tools.
    (re.compile(rf"(?im)(^\s*{_IDENTIFIER_FIELD}\s*:\s*).*$"), r"\1<redacted>"),
    (re.compile(rf"(?i)(\b{_IDENTIFIER_FIELD}[=: ]+)[\"']?[^,\s\"'}}]+"), r"\1<redacted>"),
    (re.compile(rf"(?i)([\"']?{_IDENTIFIER_FIELD}[\"']?\s*:\s*[\"'])[^\"']*"), r"\1<redacted>"),
    (re.compile(rf"(?i)(\b{_SECRET_FIELD})([=: ]+)[\"']?\S+"), r"\1\2<redacted>"),
    (re.compile(rf"(?i)([\"']?{_SECRET_FIELD}[\"']?\s*:\s*[\"'])[^\"']*"), r"\1<redacted>"),
)


def redact(text: str) -> str:
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    user = os.environ.get("USER")
    if user:
        text = re.sub(rf"\b{re.escape(user)}\b", "<user>", text)
    # A broad regular expression alone mistakes values such as timestamps for
    # IPv6 addresses.  Let the standard parser confirm candidates first.
    def redact_ipv6(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            return "<ip-address>" if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv6Address) else candidate
        except ValueError:
            return candidate

    return _IPV6_CANDIDATE.sub(redact_ipv6, text)
