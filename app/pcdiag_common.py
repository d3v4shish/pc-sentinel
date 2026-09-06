#!/usr/bin/env python3
"""Shared storage, classification, and system helpers for PC Diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


APP_ID = "io.github.d3v.PCDiagnostics"
APP_NAME = "PC Diagnostics"
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "pc-diagnostics"
DB_PATH = DATA_DIR / "events.sqlite3"
REPORT_DIR = Path.home() / "Documents" / "PC-Diagnostic-Reports"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

PRIORITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Info",
    7: "Debug",
}

CATEGORY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("USB", re.compile(r"\b(?:usb|xhci|ehci|ohci|hidraw|usbhid|USBSTS)\b", re.I)),
    ("Graphics", re.compile(r"\b(?:nvrm|nvidia|xid|amdgpu|drm|gpu|kwin|xorg|nouveau)\b", re.I)),
    ("Storage", re.compile(r"\b(?:nvme|ata\d*|scsi|sd[a-z]\d*|ext[234]|btrfs|xfs|zfs|i/o error|blk_update|filesystem)\b", re.I)),
    ("Power", re.compile(r"\b(?:suspend|resume|sleep|wakeup|acpi|power state|PM:)\b", re.I)),
    ("Network", re.compile(r"\b(?:networkmanager|wlan|wifi|wi-fi|ethernet|r8169|iwlwifi|mt\d|bluetooth|btusb|link is down)\b", re.I)),
    ("Security", re.compile(r"\b(?:apparmor|selinux|audit|denied|authentication failure|segfault)\b", re.I)),
    ("Memory/CPU", re.compile(r"\b(?:mce|machine check|edac|ras:|oom|out of memory|watchdog|soft lockup|hard lockup|cpu stall)\b", re.I)),
    ("Services", re.compile(r"\b(?:systemd|service|daemon|failed with result|main process exited)\b", re.I)),
)

IMPORTANT_ACTIVITY = re.compile(
    r"USBSTS|xHC error|USB disconnect|new (?:SuperSpeed|high-speed|full-speed|low-speed) USB device|"
    r"reset (?:high-speed|SuperSpeed|full-speed) USB device|suspend entry|suspend exit|"
    r"PM: suspend|systemd-sleep|NVRM: Xid|GPU has fallen off|I/O error|Buffer I/O|"
    r"EXT[234]-fs error|BTRFS.*error|nvme.*(?:reset|timeout)|watchdog|soft lockup|"
    r"Out of memory|oom-kill|segfault|temperature above threshold|thermal throttling|"
    r"deskflow.*(?:stopping core|exited with code|starting server)",
    re.I,
)

SERIOUS_PATTERNS = re.compile(
    r"USBSTS|xHC error|NVRM: Xid|GPU has fallen off|I/O error|Buffer I/O|"
    r"filesystem.*(?:corrupt|error)|EXT[234]-fs error|BTRFS.*error|"
    r"machine check|hardware error|soft lockup|hard lockup|Out of memory|oom-kill",
    re.I,
)

BENIGN_WARNING_PATTERNS = re.compile(
    r"callbacks suppressed|optional .* (?:is not available|ucode)|"
    r"failed name lookup - disconnected path|module verification failed|"
    r"unit configures an IP firewall, but not running as root",
    re.I,
)


@dataclass(slots=True)
class Event:
    occurred_us: int
    boot_id: str
    cursor: str
    priority: int
    severity: str
    category: str
    source: str
    unit: str
    message: str
    transport: str
    details: str


def ensure_private_directory(path: Path) -> None:
    """Create a per-user data directory and enforce owner-only access."""
    path.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    os.chmod(path, PRIVATE_DIRECTORY_MODE)


def ensure_database_parent(path: Path) -> None:
    """Prepare a database parent without changing permissions on caller-owned paths.

    The normal application data directory is private by design.  A caller may
    also supply an explicit database path (for example, ``/tmp/check.sqlite``)
    for a one-off run; chmod'ing an existing parent such as ``/tmp`` would be
    both surprising and unsafe.  We secure the known application directory and
    a newly-created custom parent, while relying on the database file's 0600
    mode for existing caller-owned directories.
    """
    parent = path.parent
    if parent == DATA_DIR or not parent.exists():
        ensure_private_directory(parent)
    else:
        parent.mkdir(parents=True, exist_ok=True)


def ensure_private_file(path: Path) -> None:
    """Enforce owner-only access for a file created by this application."""
    if path.exists():
        os.chmod(path, PRIVATE_FILE_MODE)


def create_private_file_if_missing(path: Path) -> bool:
    """Create a file with mode 0600 before a library can apply the umask.

    SQLite otherwise creates its database (and, depending on the journal mode,
    sidecars) with the process umask and only receives a restrictive chmod
    afterwards.  Pre-creating empty files closes that exposure window.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
    except FileExistsError:
        ensure_private_file(path)
        return False
    else:
        os.close(descriptor)
        return True


def write_private_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write a report without relying on the caller's umask for privacy."""
    ensure_private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding) as stream:
            stream.write(text)
    finally:
        # ``fdopen`` owns and closes the descriptor on normal and error paths.
        # chmod also repairs a pre-existing report created by an older release.
        ensure_private_file(path)


def connect_db(path: Path = DB_PATH) -> sqlite3.Connection:
    ensure_database_parent(path)
    create_private_file_if_missing(path)
    create_private_file_if_missing(path.with_name(path.name + "-wal"))
    create_private_file_if_missing(path.with_name(path.name + "-shm"))
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    ensure_private_file(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_us INTEGER NOT NULL,
            boot_id TEXT NOT NULL,
            cursor TEXT NOT NULL UNIQUE,
            priority INTEGER NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL,
            unit_name TEXT NOT NULL,
            message TEXT NOT NULL,
            transport TEXT NOT NULL,
            details TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_us DESC);
        CREATE INDEX IF NOT EXISTS idx_events_boot_time ON events(boot_id, occurred_us DESC);
        CREATE INDEX IF NOT EXISTS idx_events_severity_time ON events(severity, occurred_us DESC);
        CREATE INDEX IF NOT EXISTS idx_events_category_time ON events(category, occurred_us DESC);

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    ensure_private_file(path.with_name(path.name + "-wal"))
    ensure_private_file(path.with_name(path.name + "-shm"))
    return conn


def safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return str(value).replace("\x00", "�")


def classify_category(message: str, source: str, unit: str) -> str:
    haystack = f"{source} {unit} {message}"
    for category, pattern in CATEGORY_PATTERNS:
        if pattern.search(haystack):
            return category
    if source == "kernel":
        return "Kernel"
    return "System"


def classify_severity(priority: int, message: str) -> str:
    if SERIOUS_PATTERNS.search(message):
        return "Critical" if priority <= 3 else "Error"
    if priority <= 2:
        return "Critical"
    if priority == 3:
        return "Error"
    if priority == 4:
        return "Notice" if BENIGN_WARNING_PATTERNS.search(message) else "Warning"
    return "Activity"


def should_store(priority: int, message: str, source: str, unit: str) -> bool:
    if priority <= 4:
        return True
    return bool(IMPORTANT_ACTIVITY.search(f"{source} {unit} {message}"))


def event_from_journal(record: dict[str, Any]) -> Event | None:
    message = safe_text(record.get("MESSAGE")).strip()
    if not message:
        return None
    try:
        priority = int(record.get("PRIORITY", 6))
    except (TypeError, ValueError):
        priority = 6
    source = safe_text(
        record.get("SYSLOG_IDENTIFIER")
        or record.get("_COMM")
        or record.get("_EXE")
        or record.get("_TRANSPORT")
        or "unknown"
    )
    unit = safe_text(record.get("_SYSTEMD_UNIT") or record.get("_SYSTEMD_USER_UNIT"))
    if not should_store(priority, message, source, unit):
        return None
    try:
        occurred_us = int(record.get("__REALTIME_TIMESTAMP", int(time.time() * 1_000_000)))
    except (TypeError, ValueError):
        occurred_us = int(time.time() * 1_000_000)
    boot_id = safe_text(record.get("_BOOT_ID"), "unknown")
    cursor = safe_text(record.get("__CURSOR"))
    if not cursor:
        digest = hashlib.sha256(
            f"{occurred_us}\0{boot_id}\0{source}\0{message}".encode("utf-8", "replace")
        ).hexdigest()
        cursor = f"synthetic:{digest}"
    category = classify_category(message, source, unit)
    severity = classify_severity(priority, message)
    useful_details = {
        key: safe_text(record.get(key))
        for key in (
            "_HOSTNAME",
            "_PID",
            "_UID",
            "_GID",
            "_COMM",
            "_EXE",
            "_CMDLINE",
            "_SYSTEMD_UNIT",
            "_SYSTEMD_USER_UNIT",
            "_TRANSPORT",
            "SYSLOG_IDENTIFIER",
            "CODE_FILE",
            "CODE_LINE",
            "CODE_FUNC",
        )
        if record.get(key) is not None
    }
    return Event(
        occurred_us=occurred_us,
        boot_id=boot_id,
        cursor=cursor,
        priority=priority,
        severity=severity,
        category=category,
        source=source,
        unit=unit,
        message=message,
        transport=safe_text(record.get("_TRANSPORT")),
        details=json.dumps(useful_details, ensure_ascii=False, sort_keys=True),
    )


def insert_events(conn: sqlite3.Connection, events: Iterable[Event]) -> int:
    rows = [
        (
            event.occurred_us,
            event.boot_id,
            event.cursor,
            event.priority,
            event.severity,
            event.category,
            event.source,
            event.unit,
            event.message,
            event.transport,
            event.details,
        )
        for event in events
    ]
    if not rows:
        return 0
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO events
        (occurred_us, boot_id, cursor, priority, severity, category, source,
         unit_name, message, transport, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    return conn.total_changes - before


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return safe_text(row[0]) if row else default


def run_command(command: list[str], timeout: float = 8.0) -> str:
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"Unable to run {' '.join(command)}: {exc}"


def format_time(timestamp_us: int, include_date: bool = True) -> str:
    pattern = "%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S"
    return time.strftime(pattern, time.localtime(timestamp_us / 1_000_000))


def priority_label(priority: int) -> str:
    return PRIORITY_NAMES.get(priority, str(priority))
