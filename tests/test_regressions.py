"""Regression coverage for production-safety boundaries.

The suite intentionally uses only the standard library so contributors can run
it on the same Python installation used by the systemd collector.
"""

from __future__ import annotations

from contextlib import nullcontext
import json
import stat
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import pcdiag_helper as helper
import pcdiag_tuning_helper as tuning
from pcdiag_collector import Collector
from pcdiag_presenters import fetch_event_page, fetch_incident_evidence, scan_payload, service_action_argv
from pcdiag_common import write_private_text
from pcdiag_engine import (
    acknowledge_incident,
    connect_v2,
    ingest_journal_record,
    journal_timestamp_us,
    live_overview_metrics,
    parse_nvidia_metrics,
    parse_power_sensor_data,
    parse_sensor_data,
    record_incident,
    redact,
    resolve_incident_id,
    update_metric,
)


class _Process:
    """Minimal journalctl process fake for bounded-backfill tests."""

    def __init__(self, lines: list[str]):
        self.stdout = iter(lines)
        self.returncode: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode


class RegressionTests(unittest.TestCase):
    def test_live_overview_metrics_uses_a_cpu_delta_without_persisting_samples(self) -> None:
        reads = iter((
            "cpu  100 0 0 100 0 0 0 0 0 0\n",
            "MemTotal:       1000 kB\nMemAvailable:    250 kB\nSwapTotal:        200 kB\nSwapFree:         100 kB\n",
            "cpu  130 0 0 110 10 0 0 0 0 0\n",
            "MemTotal:       1000 kB\nMemAvailable:    250 kB\nSwapTotal:        200 kB\nSwapFree:         100 kB\n",
        ))
        disk = SimpleNamespace(total=1_000, used=250, free=750)
        with patch("pcdiag_engine.Path.read_text", side_effect=lambda *_args, **_kwargs: next(reads)), \
             patch("pcdiag_engine.shutil.disk_usage", return_value=disk):
            first, state = live_overview_metrics()
            second, _state = live_overview_metrics(state)
        self.assertNotIn("cpu.percent", first)
        self.assertEqual(second["cpu.percent"], 60.0)
        self.assertEqual(second["cpu.iowait"], 20.0)
        self.assertEqual(second["memory.percent"], 75.0)
        self.assertEqual(second["swap.percent"], 50.0)
        self.assertEqual(second["disk.root.percent"], 25.0)

    def test_malformed_journal_timestamps_are_stored_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            conn = connect_v2(Path(directory) / "events.sqlite3")
            for index, malformed in enumerate((None, "", "not-a-timestamp", [], {})):
                result = ingest_journal_record(
                    conn,
                    {
                        "MESSAGE": "Kernel panic",
                        "PRIORITY": 2,
                        "__REALTIME_TIMESTAMP": malformed,
                        "__CURSOR": f"bad-time-{index}",
                    },
                )
            self.assertIsNotNone(result)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 5)
            self.assertEqual(journal_timestamp_us("1700000000", default=123), 123)
            self.assertEqual(journal_timestamp_us("999999999999999999", default=123), 123)
            conn.close()

    def test_backfill_is_bounded_and_persists_its_checkpoint(self) -> None:
        records = [
            json.dumps({
                "MESSAGE": "Kernel panic",
                "PRIORITY": 2,
                "__REALTIME_TIMESTAMP": str(1_700_000_000_000_000 + index),
                "__CURSOR": f"cursor-{index}",
                "_BOOT_ID": "test-boot",
            }) + "\n"
            for index in range(3)
        ]
        process = _Process(records)
        with tempfile.TemporaryDirectory() as directory:
            collector = Collector(Path(directory) / "events.sqlite3", once=True)
            with patch("pcdiag_collector.subprocess.Popen", return_value=process):
                collector.backfill(record_limit=2, time_limit_seconds=10)
            offset = collector.conn.execute(
                "SELECT cursor,occurred_us FROM source_offsets WHERE source='journal'"
            ).fetchone()
            self.assertEqual(tuple(offset), ("cursor-1", 1_700_000_000_000_001))
            self.assertEqual(collector.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 2)
            self.assertTrue(process.terminated)
            collector.conn.close()

    def test_backfill_prefers_the_persisted_journal_cursor(self) -> None:
        process = _Process([])
        process.returncode = 0
        commands: list[list[str]] = []

        def fake_popen(command: list[str], **_kwargs: object) -> _Process:
            commands.append(command)
            return process

        with tempfile.TemporaryDirectory() as directory:
            collector = Collector(Path(directory) / "events.sqlite3", once=True)
            collector._store_journal_offset(collector.conn, "cursor-to-resume", 1_700_000_000_000_000)
            collector.conn.commit()
            with patch("pcdiag_collector.subprocess.Popen", side_effect=fake_popen):
                collector.backfill(record_limit=2, time_limit_seconds=10)
            self.assertIn("--after-cursor=cursor-to-resume", commands[0])
            collector.conn.close()

    def test_redaction_removes_machine_identifiers_and_personal_data(self) -> None:
        source = (
            'UUID: 123e4567-e89b-12d3-a456-426614174000\n'
            '"serial_number":"NVME-SECRET-123"\n'
            'WWN: 0x5000CCA123456789\nEUI64=0011223344556677\n'
            'NGUID: 1234567890ABCDEF\nAsset Tag: DESK-42\n'
            '/root/.ssh/id_ed25519 alice@example.com token=credential '
            'api_key=another-secret "access_key":"json-secret" 2001:db8::dead'
        )
        result = redact(source)
        for secret in (
            "123e4567-e89b-12d3-a456-426614174000", "NVME-SECRET-123",
            "0x5000CCA123456789", "0011223344556677", "1234567890ABCDEF",
            "DESK-42", "/root", "alice@example.com", "credential",
            "another-secret", "json-secret", "2001:db8::dead",
        ):
            self.assertNotIn(secret, result)
        self.assertEqual(redact("time=12:34:56"), "time=12:34:56")

    def test_database_and_reports_use_owner_only_modes_without_chmodding_custom_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            existing_parent = base / "existing-parent"
            existing_parent.mkdir()
            existing_parent.chmod(0o755)
            database = existing_parent / "events.sqlite3"
            conn = connect_v2(database)
            conn.close()
            self.assertEqual(stat.S_IMODE(existing_parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)

            private_parent = base / "new-private-parent"
            second = connect_v2(private_parent / "events.sqlite3")
            second.close()
            self.assertEqual(stat.S_IMODE(private_parent.stat().st_mode), 0o700)

            report = base / "reports" / "report.txt"
            write_private_text(report, "private diagnostic report")
            self.assertEqual(stat.S_IMODE(report.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

    def test_incident_metadata_and_metric_last_value_follow_event_time_not_ingest_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            conn = connect_v2(Path(directory) / "events.sqlite3")
            common = {
                "rule_id": "test-order", "severity": "Warning", "category": "System",
                "title": "Ordering test", "summary": "Ordering test", "likely_cause": "test",
                "impact": "test", "remediation": (), "priority": 4, "unit": "test.service",
                "details": {}, "scope": "global",
            }
            record_incident(
                conn, **common, occurred_us=2_000, boot_id="new-boot", cursor="new", source="new-source", message="new message",
            )
            record_incident(
                conn, **common, occurred_us=1_000, boot_id="old-boot", cursor="old", source="old-source", message="old message",
            )
            incident = conn.execute("SELECT last_us,last_boot_id,source,sample_message FROM incidents").fetchone()
            self.assertEqual(tuple(incident), (2_000, "new-boot", "new-source", "new message"))

            newest = 1_800_000_050_000_000
            older = 1_800_000_010_000_000
            update_metric(conn, "cpu.percent", 90, "percent", timestamp_us=newest)
            update_metric(conn, "cpu.percent", 10, "percent", timestamp_us=older)
            metric = conn.execute(
                "SELECT last_value,last_sample_us,samples FROM metric_rollups WHERE metric='cpu.percent'"
            ).fetchone()
            self.assertEqual(tuple(metric), (90.0, newest, 2))
            conn.close()

    def test_incident_acknowledgement_and_resolution_are_local_and_reopen_on_new_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            conn = connect_v2(Path(directory) / "events.sqlite3")
            common = {
                "rule_id": "state-test", "severity": "Warning", "category": "System",
                "title": "State test", "summary": "State test", "likely_cause": "test",
                "impact": "test", "remediation": (), "priority": 4, "unit": "test.service",
                "details": {}, "scope": "global", "source": "test", "boot_id": "test-boot",
            }
            incident_id, created = record_incident(conn, **common, occurred_us=1_000, cursor="state-1", message="first")
            self.assertTrue(created)
            self.assertTrue(acknowledge_incident(conn, incident_id))
            state = conn.execute("SELECT status,acknowledged FROM incidents WHERE id=?", (incident_id,)).fetchone()
            self.assertEqual(tuple(state), ("open", 1))

            record_incident(conn, **common, occurred_us=2_000, cursor="state-2", message="new evidence")
            state = conn.execute("SELECT status,acknowledged FROM incidents WHERE id=?", (incident_id,)).fetchone()
            self.assertEqual(tuple(state), ("open", 0))
            self.assertTrue(resolve_incident_id(conn, incident_id))
            state = conn.execute("SELECT status,acknowledged FROM incidents WHERE id=?", (incident_id,)).fetchone()
            self.assertEqual(tuple(state), ("resolved", 0))
            conn.close()

    def test_notifications_are_deduplicated_failed_delivery_is_not_recorded_and_escalation_bypasses_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            collector = Collector(Path(directory) / "events.sqlite3", once=True)
            conn = collector.conn
            common = {
                "rule_id": "notification-test", "severity": "Warning", "category": "System",
                "title": "Notification test", "summary": "Notification test", "likely_cause": "test",
                "impact": "test", "remediation": (), "priority": 4, "unit": "test.service",
                "details": {}, "scope": "global", "source": "test", "boot_id": "test-boot",
            }
            incident_id, _created = record_incident(conn, **common, occurred_us=1_000, cursor="notify-1", message="warning")
            success = subprocess.CompletedProcess(["notify-send"], 0)
            with patch("pcdiag_collector.time.time", side_effect=[1_000.0, 1_001.0, 1_002.0]), \
                 patch("pcdiag_collector.subprocess.run", return_value=success) as notify:
                collector.maybe_notify(conn, incident_id)
                collector.maybe_notify(conn, incident_id)
                record_incident(
                    conn, **{**common, "severity": "Critical", "priority": 2},
                    occurred_us=2_000, cursor="notify-2", message="critical escalation",
                )
                collector.maybe_notify(conn, incident_id)
            self.assertEqual(notify.call_count, 2)
            self.assertEqual(tuple(conn.execute("SELECT last_severity,total FROM notifications").fetchone()), ("Critical", 2))
            command = notify.call_args_list[1].args[0]
            self.assertTrue(any("x-canonical-private-synchronous:pc-diagnostics-" in item for item in command))

            failed_id, _created = record_incident(
                conn, **{**common, "rule_id": "notification-failure", "severity": "Warning"},
                occurred_us=3_000, cursor="notify-failure", message="failed delivery",
            )
            notify.return_value = subprocess.CompletedProcess(["notify-send"], 1)
            with patch("pcdiag_collector.time.time", return_value=1_003.0):
                collector.maybe_notify(conn, failed_id)
            failure_fingerprint = conn.execute(
                "SELECT fingerprint FROM incidents WHERE id=?", (failed_id,)
            ).fetchone()[0]
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM notifications WHERE fingerprint=?", (failure_fingerprint,)).fetchone()[0],
                0,
            )
            conn.close()

    def test_network_counter_reset_resolves_the_previous_network_incident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            collector = Collector(Path(directory) / "events.sqlite3", once=True)
            collector.previous_network["network.eth0.rx_errors"] = 10
            with patch("pcdiag_collector.resolve_incident", return_value=True) as resolve:
                collector._metric_anomalies({"network.eth0.rx_errors": 2})
            resolve.assert_any_call(collector.conn, "network-errors", "eth0:rx_errors")
            collector.conn.close()

    def test_service_actions_reject_backslash_and_malformed_scan_versions(self) -> None:
        with self.assertRaises(ValueError):
            service_action_argv("restart", r"bad\name.service", "user")
        self.assertEqual(scan_payload({"payload_version": "not-a-number"})["payload_version"], 1)

    def test_notification_schema_migrates_existing_databases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            legacy = sqlite3.connect(path)
            legacy.execute(
                "CREATE TABLE notifications (fingerprint TEXT PRIMARY KEY,last_us INTEGER NOT NULL,total INTEGER NOT NULL DEFAULT 1)"
            )
            legacy.commit()
            legacy.close()
            conn = connect_v2(path)
            columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(notifications)")}
            self.assertIn("last_severity", columns)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 4)
            conn.close()

    def test_multi_device_sensor_and_nvidia_metrics_are_not_overwritten(self) -> None:
        sensors = parse_sensor_data({
            "nvme-pci-0100": {"Composite": {"temp1_input": 35.0}},
            "nvme-pci-0200": {"Composite": {"temp1_input": 42.0}},
        })
        self.assertEqual(len(sensors), 2)
        self.assertEqual(sorted(item["value"] for item in sensors.values()), [35.0, 42.0])

        power = parse_power_sensor_data({
            "amdgpu-pci-0100": {"PPT": {"power1_input": 40.0}},
            "amdgpu-pci-0200": {"PPT": {"power1_input": 55.0}},
        })
        self.assertEqual(len(power), 2)
        self.assertEqual(sorted(item["value"] for item in power.values()), [40.0, 55.0])

        nvidia = parse_nvidia_metrics(
            "unavailable,row\n0, 10, 60, 100, 1000, 40, 200\n1, 20, 70, 200, 1000, 50, 250\n"
        )
        self.assertEqual(nvidia["gpu.percent"], 10.0)
        self.assertEqual(nvidia["gpu.1.percent"], 20.0)
        self.assertEqual(nvidia["gpu.1.power.draw.watts"], 50.0)

    def test_tuning_apply_and_restore_take_the_process_lock(self) -> None:
        with patch.object(tuning, "exclusive_tuning_lock", return_value=nullcontext()) as lock, \
             patch.object(tuning, "_apply_unlocked", return_value={"ok": True}) as unlocked:
            self.assertEqual(tuning.apply({}), {"ok": True})
            lock.assert_called_once_with()
            unlocked.assert_called_once_with({})

    def test_event_and_timeline_pagination_follow_event_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            conn = connect_v2(Path(directory) / "events.sqlite3")
            common = {
                "rule_id": "timeline-order", "severity": "Warning", "category": "System",
                "title": "Timeline ordering", "summary": "Timeline ordering", "likely_cause": "test",
                "impact": "test", "remediation": (), "boot_id": "test-boot", "priority": 4,
                "source": "test", "unit": "test.service", "details": {}, "scope": "global",
            }
            for timestamp in (1_000, 3_000, 2_000):
                record_incident(
                    conn, **common, occurred_us=timestamp, cursor=f"timeline-{timestamp}", message=f"event-{timestamp}",
                )
            first_page = fetch_event_page(conn, limit=2)
            self.assertEqual([item["occurred_us"] for item in first_page], [3_000, 2_000])
            second_page = fetch_event_page(
                conn, before=(first_page[-1]["occurred_us"], first_page[-1]["evidence_id"]), limit=2,
            )
            self.assertEqual([item["occurred_us"] for item in second_page], [1_000])

            incident_id = first_page[0]["incident_id"]
            timeline = fetch_incident_evidence(conn, incident_id, limit=2)
            self.assertEqual([item["occurred_us"] for item in timeline], [3_000, 2_000])
            conn.close()
        with patch.object(tuning, "exclusive_tuning_lock", return_value=nullcontext()) as lock, \
             patch.object(tuning, "_restore_unlocked", return_value={"ok": True}) as unlocked:
            self.assertEqual(tuning.restore({}), {"ok": True})
            lock.assert_called_once_with()
            unlocked.assert_called_once_with({})

    def test_smart_inventory_stays_within_the_transport_limit(self) -> None:
        device_list = [Path(f"/dev/sd{chr(ord('a') + index)}") for index in range(20)]

        def fake_run(_command: list[str], timeout: int = 20, limit: int = 0) -> dict[str, object]:
            return {
                "exit_status": 0,
                "output": json.dumps({"smart_status": {"passed": True}, "padding": "x" * (limit * 2)}),
                "truncated": True,
            }

        with patch.object(helper, "devices", return_value=device_list), patch.object(helper, "run", side_effect=fake_run):
            response = helper.smart()
        self.assertEqual(len(response["results"]), len(device_list))
        self.assertLessEqual(len(json.dumps(response, ensure_ascii=False).encode()), helper.MAX_RESPONSE)

    def test_protected_log_and_dmesg_stay_below_their_response_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "auth.log"
            source.write_text(("x" * helper.MAX_LOG_LINE_CHARS + "\n") * 80, encoding="utf-8")
            with patch.object(helper, "LOG_SOURCES", {"test": (source,)}):
                response = helper.protected_log({"source": "test", "lines": 2000})
            self.assertLessEqual(
                sum(len(line.encode("utf-8")) for line in response["lines"]),
                helper.PROTECTED_LOG_RESPONSE_BUDGET,
            )
        with patch.object(helper, "run", return_value={"exit_status": 0, "output": "", "truncated": False}) as run:
            helper.dmesg()
        self.assertEqual(run.call_args.kwargs["limit"], 1 * 1024 * 1024)

    def test_deployment_assets_include_opt_in_tuning_and_portable_collector_path(self) -> None:
        installer = (ROOT / "app" / "install-helper.sh").read_text(encoding="utf-8")
        tuning_socket = ROOT / "app" / "pc-diagnostics-tuning.socket.in"
        tuning_service = ROOT / "app" / "pc-diagnostics-tuning@.service"
        collector_unit = (ROOT / "systemd" / "pc-diagnostics-collector.service.example").read_text(encoding="utf-8")
        self.assertIn("--with-tuning", installer)
        self.assertTrue(tuning_socket.is_file())
        self.assertTrue(tuning_service.is_file())
        self.assertIn("ProtectKernelTunables=true", tuning_service.read_text(encoding="utf-8"))
        self.assertIn("pc-diagnostics-collector", collector_unit)
        self.assertNotIn("Workspace/Temp", collector_unit)

    def test_source_launcher_uses_live_data_unless_isolated_requested(self) -> None:
        launcher = (ROOT / "scripts" / "run.sh").read_text(encoding="utf-8")
        self.assertIn('[ "${1-}" = "--isolated" ]', launcher)
        self.assertIn('XDG_DATA_HOME="$ROOT/.data"', launcher)
        self.assertEqual(launcher.count("XDG_DATA_HOME="), 1)


if __name__ == "__main__":
    unittest.main()
