#!/usr/bin/env python3
"""Adaptive Libadwaita diagnostic dashboard for a systemd Linux workstation."""

from __future__ import annotations

import concurrent.futures
import json
import math
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

from pcdiag_common import APP_ID, APP_NAME, DB_PATH, REPORT_DIR, format_time, run_command, write_private_text
from pcdiag_engine import (
    acknowledge_incident,
    connect_v2,
    helper_request,
    incident_change_token,
    live_overview_metrics,
    open_v2,
    record_tuning_audit,
    redact,
    resolve_incident_id,
    tuning_request,
)
from pcdiag_presenters import (
    EVENT_PAGE_SIZE,
    INCIDENT_PRIORITY_SQL,
    SEVERITY_ICONS,
    collapse_event_bursts,
    diagnosis_for,
    fetch_event_page,
    fetch_incident_evidence,
    journal_context_argv,
    is_top_critical,
    parse_journal_json_lines,
    scan_payload,
    service_action_argv,
    service_read_argv,
)


CSS = b"""
.page-title { font-size: 24px; font-weight: 700; }
.section-title { font-size: 16px; font-weight: 700; }
.metric-value { font-size: 28px; font-weight: 700; }
.dim { opacity: .68; }
.card-pad { padding: 16px; }
.event-card {
    background-color: @card_bg_color;
    border-radius: 12px;
    margin: 4px 8px;
    padding: 10px 12px;
}
.severity-critical,
.severity-error { color: @error_color; }
.severity-warning,
.confidence-medium { color: @warning_color; }
.severity-activity,
.severity-notice { color: @accent_color; }
.confidence-high { color: @success_color; font-weight: 700; }
.confidence-medium,
.confidence-low { font-weight: 700; }
.confidence-low { color: @insensitive_fg_color; }
.monospace { font-family: monospace; }
"""

SEVERITIES = ["All severities", "Critical", "Error", "Warning", "Notice", "Activity"]
CATEGORIES = [
    "All categories", "USB", "Graphics", "Storage", "Power", "Network", "Security",
    "Memory/CPU", "Hardware", "Thermal", "Services", "Crashes", "Performance",
    "Input", "Kernel", "System",
]


def format_file_size(value: int) -> str:
    size = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def is_kernel_crash_artifact(item: dict[str, Any]) -> bool:
    path = Path(str(item.get("path", "")))
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return (
        path.name.startswith(("linux-image-", "dump.", "dump-incomplete", "dmesg."))
        or str(metadata.get("ProblemType", "")) == "KernelCrash"
    )


def add_css() -> None:
    provider = Gtk.CssProvider()
    provider.load_from_data(CSS)
    display = Gdk.Display.get_default()
    if display:
        Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)


def label(text: str = "", css: str | None = None, wrap: bool = False) -> Gtk.Label:
    widget = Gtk.Label(label=text, xalign=0)
    widget.set_wrap(wrap)
    if wrap:
        widget.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        widget.add_css_class(css)
    return widget


def clear_list(box: Gtk.ListBox) -> None:
    while child := box.get_first_child():
        box.remove(child)


def status_icon(severity: str) -> Gtk.Image:
    image = Gtk.Image.new_from_icon_name(SEVERITY_ICONS.get(severity, "dialog-information-symbolic"))
    image.add_css_class(f"severity-{severity.lower()}")
    return image


def action_row(title: str, subtitle: str = "", icon: str | None = None) -> Adw.ActionRow:
    row = Adw.ActionRow()
    row.set_use_markup(False)
    row.set_title(title)
    row.set_subtitle(subtitle)
    if icon:
        row.add_prefix(Gtk.Image.new_from_icon_name(icon))
    return row


def advanced_raw(data: Any) -> Adw.ExpanderRow:
    expander = Adw.ExpanderRow(title="Advanced", subtitle="Original collected data")
    view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
    view.get_buffer().set_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    scroll = Gtk.ScrolledWindow(min_content_height=180, max_content_height=420, child=view)
    row = Adw.ActionRow()
    row.set_child(scroll)
    expander.add_row(row)
    return expander


def page_shell(title: str, subtitle: str) -> tuple[Gtk.ScrolledWindow, Gtk.Box]:
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
    body.set_margin_top(24)
    body.set_margin_bottom(28)
    body.set_margin_start(18)
    body.set_margin_end(18)
    body.append(label(title, "page-title"))
    body.append(label(subtitle, "dim", True))
    clamp = Adw.Clamp(maximum_size=1050, tightening_threshold=700, child=body)
    return Gtk.ScrolledWindow(child=clamp), body


class RecordObject(GObject.Object):
    def __init__(self, record: dict[str, Any]):
        super().__init__()
        self.record = record


class EventFeedRow(Gtk.Box):
    def __init__(self, compact: bool = False):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.add_css_class("event-card")
        self.icon = Gtk.Image()
        self.icon.set_valign(Gtk.Align.START)
        self.append(self.icon)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.title = label("", None, True)
        self.title.set_ellipsize(Pango.EllipsizeMode.END)
        self.title.set_lines(2 if compact else 3)
        self.meta = label("", "dim")
        self.reason = label("", "dim", True)
        self.reason.set_lines(1 if compact else 2)
        body.append(self.title)
        body.append(self.meta)
        body.append(self.reason)
        self.append(body)
        body.set_hexpand(True)
        self.count = Gtk.Label()
        self.count.add_css_class("numeric")
        self.count.set_valign(Gtk.Align.CENTER)
        self.append(self.count)

    def set_record(self, record: dict[str, Any]) -> None:
        severity = str(record.get("severity", "Activity"))
        self.icon.set_from_icon_name(SEVERITY_ICONS.get(severity, "dialog-information-symbolic"))
        for css in ("severity-critical", "severity-error", "severity-warning", "severity-activity", "severity-notice"):
            self.icon.remove_css_class(css)
        self.icon.add_css_class(f"severity-{severity.lower()}")
        self.title.set_text(str(record.get("message") or record.get("title") or "Unknown event"))
        stamp = int(record.get("newest_us") or record.get("occurred_us") or record.get("last_us") or 0)
        tier = "TOP CRITICAL  ·  " if is_top_critical(record) else ""
        self.meta.set_text(f"{tier}{format_time(stamp)}  ·  {severity}  ·  {record.get('category', 'System')}  ·  {record.get('source', 'unknown')}")
        diagnosis = diagnosis_for(record)
        self.reason.set_text(f"Probable reason ({diagnosis['confidence'].lower()} confidence): {diagnosis['cause']}")
        count = int(record.get("count", 1))
        self.count.set_text(f"×{count}" if count > 1 else "›")


def record_list_view(store: Gio.ListStore, activated: Callable[[dict[str, Any]], None], compact: bool = False) -> Gtk.ListView:
    factory = Gtk.SignalListItemFactory()
    factory.connect("setup", lambda _f, item: item.set_child(EventFeedRow(compact)))
    factory.connect("bind", lambda _f, item: item.get_child().set_record(item.get_item().record))
    selection = Gtk.SingleSelection(model=store, autoselect=False, can_unselect=True)
    view = Gtk.ListView(model=selection, factory=factory, single_click_activate=True)
    view.connect("activate", lambda _v, position: activated(store.get_item(position).record))
    return view


class Sparkline(Gtk.Box):
    def __init__(self, height: int = 52, slots: int = 48):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=2, homogeneous=True)
        self.bars: list[Gtk.LevelBar] = []
        self.set_size_request(-1, height)
        self.set_hexpand(True)
        for _index in range(slots):
            bar = Gtk.LevelBar(orientation=Gtk.Orientation.VERTICAL, min_value=0, max_value=100)
            bar.set_mode(Gtk.LevelBarMode.CONTINUOUS)
            bar.set_valign(Gtk.Align.FILL)
            bar.set_vexpand(True)
            bar.add_css_class("sparkbar")
            self.bars.append(bar)
            self.append(bar)

    def set_values(self, values: list[float]) -> None:
        if len(values) > len(self.bars):
            step = len(values) / len(self.bars)
            values = [values[min(len(values) - 1, math.floor(index * step))] for index in range(len(self.bars))]
        values = values[-len(self.bars):]
        scale = max(100.0, max(values, default=100.0))
        offset = len(self.bars) - len(values)
        for index, bar in enumerate(self.bars):
            if index < offset:
                bar.set_opacity(.15)
                bar.set_value(0)
            else:
                bar.set_opacity(1)
                bar.set_value(max(0.0, min(100.0, values[index - offset] / scale * 100)))


class MetricCard(Gtk.Box):
    def __init__(self, title: str, icon: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add_css_class("card")
        self.add_css_class("card-pad")
        self.set_size_request(230, 145)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        head.append(Gtk.Image.new_from_icon_name(icon))
        head.append(label(title, "dim"))
        self.value = label("—", "metric-value")
        self.note = label("Waiting for collector", "dim")
        self.progress = Gtk.ProgressBar()
        self.chart = Sparkline(36, 16)
        self.append(head)
        self.append(self.value)
        self.append(self.note)
        self.append(self.progress)
        self.append(self.chart)

    def update(self, value: float | None, suffix: str, note: str, history: list[float]) -> None:
        self.update_live(value, suffix, note)
        self.chart.set_values(history)

    def update_live(self, value: float | None, suffix: str, note: str) -> None:
        self.value.set_text("—" if value is None else f"{value:.0f}{suffix}")
        self.note.set_text(note)
        self.progress.set_fraction(max(0.0, min(1.0, (value or 0) / 100)))


class EventInspector(Adw.Dialog):
    def __init__(self, owner: "DiagnosticsWindow", record: dict[str, Any]):
        super().__init__(title="Event details", content_width=860, content_height=720)
        self.owner = owner
        self.record = record
        self.timeline_cursor: tuple[int, int] | None = None
        self.context_request_id = 0
        self.timeline_store = Gio.ListStore.new(RecordObject)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        toolbar.add_top_bar(switcher)
        toolbar.set_content(stack)
        self.set_child(toolbar)
        stack.add_titled_with_icon(self._diagnosis_page(), "diagnosis", "Diagnosis", "medical-symbolic")
        stack.add_titled_with_icon(self._timeline_page(), "timeline", "Timeline", "view-list-symbolic")
        stack.add_titled_with_icon(self._context_page(), "context", "Nearby logs", "system-search-symbolic")
        stack.add_titled_with_icon(self._technical_page(), "technical", "Technical", "applications-engineering-symbolic")
        self._load_timeline(reset=True)
        self._load_context()

    def _diagnosis_page(self) -> Gtk.Widget:
        page, body = page_shell(str(self.record.get("title", "Event diagnosis")), str(self.record.get("message", "")))
        data = diagnosis_for(self.record)
        group = Adw.PreferencesGroup(title="Probable reason")
        confidence = action_row(f"{data['confidence']} confidence", data["basis"], "emblem-ok-symbolic")
        confidence.add_css_class(f"confidence-{data['confidence'].lower()}")
        group.add(confidence)
        group.add(action_row("Likely cause", data["cause"], "system-search-symbolic"))
        group.add(action_row("Expected impact", data["impact"], "dialog-warning-symbolic"))
        body.append(group)
        steps = Adw.PreferencesGroup(title="Suggested checks")
        for index, item in enumerate(data["steps"], 1):
            steps.add(action_row(str(item), f"Step {index}", "go-next-symbolic"))
        if not data["steps"]:
            steps.add(action_row("Inspect the timeline and nearby raw logs", "No rule-specific repair is available."))
        body.append(steps)
        copy = Gtk.Button(label="Copy diagnosis")
        copy.add_css_class("suggested-action")
        copy.connect("clicked", self._copy_diagnosis)
        body.append(copy)
        return page

    def _copy_diagnosis(self, _button: Gtk.Button) -> None:
        data = diagnosis_for(self.record)
        text = f"{data['title']}\nConfidence: {data['confidence']} — {data['basis']}\nCause: {data['cause']}\nImpact: {data['impact']}\n"
        if data["steps"]:
            text += "Checks:\n" + "\n".join(f"{i}. {step}" for i, step in enumerate(data["steps"], 1))
        Gdk.Display.get_default().get_clipboard().set(text)
        self.owner.toast("Diagnosis copied")

    def _timeline_page(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        view = record_list_view(self.timeline_store, self._replace_record, compact=True)
        root.append(Gtk.ScrolledWindow(child=view, vexpand=True))
        self.timeline_more = Gtk.Button(label="Load 250 older events")
        self.timeline_more.set_margin_top(8)
        self.timeline_more.set_margin_bottom(8)
        self.timeline_more.set_margin_start(12)
        self.timeline_more.set_margin_end(12)
        self.timeline_more.connect("clicked", lambda _b: self._load_timeline(False))
        root.append(self.timeline_more)
        return root

    def _replace_record(self, record: dict[str, Any]) -> None:
        self.record = {**self.record, **record}

    def _load_timeline(self, reset: bool = False) -> None:
        if reset:
            self.timeline_store.remove_all()
            self.timeline_cursor = None
        try:
            with open_v2(readonly=True) as conn:
                rows = fetch_incident_evidence(conn, int(self.record["incident_id"]), before=self.timeline_cursor)
        except (sqlite3.Error, KeyError):
            rows = []
        for row in rows:
            combined = {**self.record, **row, "count": 1}
            self.timeline_store.append(RecordObject(combined))
        if rows:
            last = rows[-1]
            self.timeline_cursor = (int(last["occurred_us"]), int(last["id"]))
        self.timeline_more.set_sensitive(len(rows) == 250)
        self.timeline_more.set_label("Load 250 older events" if rows else "No older events")

    def _context_page(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(10)
        controls.set_margin_start(12)
        controls.append(label("Window"))
        self.context_range = Gtk.DropDown.new_from_strings(["±5 seconds", "±30 seconds", "±120 seconds"])
        self.context_range.set_selected(1)
        self.context_range.connect("notify::selected", lambda *_a: self._load_context())
        controls.append(self.context_range)
        self.context_status = label("Loading nearby journal entries…", "dim")
        controls.append(self.context_status)
        root.append(controls)
        self.context_store = Gio.ListStore.new(RecordObject)
        root.append(Gtk.ScrolledWindow(child=record_list_view(self.context_store, lambda _r: None, compact=True), vexpand=True))
        return root

    def _load_context(self) -> None:
        self.context_request_id += 1
        request_id = self.context_request_id
        seconds = (5, 30, 120)[self.context_range.get_selected()]
        self.context_status.set_text("Loading…")
        argv = journal_context_argv(self.record, seconds)
        future = self.owner.executor.submit(run_command, argv, 20)
        future.add_done_callback(lambda done: GLib.idle_add(self._context_ready, done, argv, request_id))

    def _context_ready(self, future: concurrent.futures.Future[str], argv: list[str], request_id: int) -> bool:
        if self.owner.closed or request_id != self.context_request_id:
            return GLib.SOURCE_REMOVE
        try:
            records = parse_journal_json_lines(future.result())
        except Exception as exc:
            records = []
            self.context_status.set_text(f"Unable to read journal: {exc}")
        else:
            self.context_status.set_text(f"{len(records)} entries · maximum 500")
        self.context_store.remove_all()
        for record in records:
            record.update(severity={0: "Critical", 1: "Critical", 2: "Critical", 3: "Error", 4: "Warning"}.get(record["priority"], "Activity"), category="Journal", rule_id="generic")
            self.context_store.append(RecordObject(record))
        return GLib.SOURCE_REMOVE

    def _technical_page(self) -> Gtk.Widget:
        page, body = page_shell("Technical metadata", "Exact identifiers retained for troubleshooting and correlation.")
        group = Adw.PreferencesGroup()
        fields = (
            ("Time", format_time(int(self.record.get("occurred_us") or self.record.get("last_us") or 0))),
            ("Source", str(self.record.get("source", "unknown"))),
            ("Unit", str(self.record.get("unit_name", "—") or "—")),
            ("Rule", str(self.record.get("rule_id", "generic"))),
            ("Boot ID", str(self.record.get("boot_id") or self.record.get("last_boot_id") or "unknown")),
            ("Journal cursor", str(self.record.get("cursor", "—"))),
            ("Evidence ID", str(self.record.get("evidence_id", self.record.get("id", "—")))),
        )
        for title, value in fields:
            group.add(action_row(title, value))
        body.append(group)
        body.append(advanced_raw(self.record))
        return page


class DiagnosticsWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application):
        super().__init__(application=app, title=APP_NAME, default_width=1380, default_height=880)
        self.app = app
        self.closed = False
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="pcdiag-ui")
        self.timeout_ids: list[int] = []
        self.last_token: tuple[int, ...] | None = None
        self.live_cursor: tuple[int, int] | None = None
        self.live_raw: list[dict[str, Any]] = []
        self.scan_tokens: dict[str, tuple[int, int]] = {}
        self.metric_cards: dict[str, MetricCard] = {}
        self.live_metric_cpu_state: tuple[int, int, int] | None = None
        self.nav_rows: dict[Gtk.ListBoxRow, str] = {}
        self.page_titles: dict[str, str] = {}
        self.expanded_issue_ids: set[int] = set()
        self.latest_crash_entries: list[dict[str, Any]] = []
        self.tuning_state: dict[str, Any] = {}
        self.tuning_gpu_options: list[dict[str, Any]] = []
        self.tuning_refresh_inflight = False
        self.raw_records: list[dict[str, Any]] = []
        self.raw_status_summary = ""
        self.raw_request_id = 0
        self._build_shell()
        self._build_pages()
        self.navigate("overview")
        self.refresh_all()
        self.timeout_ids.extend((
            GLib.timeout_add_seconds(5, self._poll),
            GLib.timeout_add(1000, self._live_metric_tick),
            GLib.timeout_add_seconds(10, self._metric_tick),
            GLib.timeout_add_seconds(30, self._status_tick),
        ))
        self.connect("close-request", self._close)

    def _build_shell(self) -> None:
        self.toast_overlay = Adw.ToastOverlay()
        self.split = Adw.NavigationSplitView()
        self.toast_overlay.set_child(self.split)
        self.set_content(self.toast_overlay)

        sidebar_toolbar = Adw.ToolbarView()
        side_header = Adw.HeaderBar(title_widget=label(APP_NAME, "section-title"))
        sidebar_toolbar.add_top_bar(side_header)
        side_scroll = Gtk.ScrolledWindow()
        side_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        side_box.set_margin_top(10)
        side_box.set_margin_bottom(10)
        side_box.set_margin_start(8)
        side_box.set_margin_end(8)
        self.nav_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, activate_on_single_click=True)
        self.nav_list.add_css_class("navigation-sidebar")
        self.nav_list.connect("row-selected", self._nav_selected)
        side_box.append(self.nav_list)
        self.collector_row = action_row("Collector", "Checking…", "network-transmit-receive-symbolic")
        self.collector_row.add_css_class("card")
        side_box.append(self.collector_row)
        side_scroll.set_child(side_box)
        sidebar_toolbar.set_content(side_scroll)
        self.split.set_sidebar(Adw.NavigationPage.new(sidebar_toolbar, "Sections"))

        content_toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self.header_title = Adw.WindowTitle(title="Overview", subtitle="Continuous local diagnostics")
        header.set_title_widget(self.header_title)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh visible information")
        refresh.connect("clicked", lambda _b: self.refresh_all())
        header.pack_end(refresh)
        export = Gtk.Button(icon_name="document-save-symbolic", tooltip_text="Export redacted report")
        export.connect("clicked", lambda _b: self._export_report())
        header.pack_end(export)
        content_toolbar.add_top_bar(header)
        self.stack = Adw.ViewStack()
        content_toolbar.set_content(self.stack)
        self.split.set_content(Adw.NavigationPage.new(content_toolbar, "Diagnostics"))
        breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 900px"))
        breakpoint.add_setter(self.split, "collapsed", True)
        self.add_breakpoint(breakpoint)

    def _add_nav(self, group: str, entries: list[tuple[str, str, str]]) -> None:
        header = Gtk.ListBoxRow(selectable=False, activatable=False)
        text = label(group.upper(), "dim")
        text.set_margin_top(12)
        text.set_margin_start(8)
        header.set_child(text)
        self.nav_list.append(header)
        for name, title, icon in entries:
            row = Adw.ActionRow()
            row.set_use_markup(False)
            row.set_title(title)
            row.add_prefix(Gtk.Image.new_from_icon_name(icon))
            self.nav_rows[row] = name
            self.page_titles[name] = title
            self.nav_list.append(row)

    def _build_pages(self) -> None:
        self._add_nav("Command center", [
            ("overview", "Overview", "computer-symbolic"),
            ("forensics", "Forensic cases", "dialog-warning-symbolic"),
            ("issues", "Active issues", "dialog-warning-symbolic"),
        ])
        self._add_nav("Investigate", [
            ("events", "Live events", "view-list-symbolic"),
            ("raw", "Raw logs", "utilities-terminal-symbolic"),
        ])
        self._add_nav("Hardware", [
            ("performance", "Performance", "speedometer-symbolic"),
            ("power", "Power & voltage", "battery-good-symbolic"),
            ("tuning", "Safe tuning", "preferences-system-symbolic"),
            ("hardware", "Hardware", "applications-engineering-symbolic"),
            ("crashes", "Crash history", "face-sick-symbolic"),
            ("boots", "Boot history", "document-open-recent-symbolic"),
        ])
        self._add_nav("Maintenance", [
            ("services", "Services", "system-run-symbolic"),
            ("network", "Network & security", "network-workgroup-symbolic"),
            ("updates", "Updates", "software-update-available-symbolic"),
        ])
        builders = {
            "overview": self._overview_page, "issues": self._issues_page,
            "events": self._events_page, "performance": self._performance_page,
            "power": self._power_page,
            "tuning": self._tuning_page,
            "forensics": self._forensics_page,
            "hardware": self._hardware_page, "services": self._services_page,
            "network": self._network_page, "crashes": self._crashes_page,
            "updates": self._updates_page, "boots": self._boots_page, "raw": self._raw_page,
        }
        for name, builder in builders.items():
            self.stack.add_named(builder(), name)

    def _nav_selected(self, _box: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is not None and (name := self.nav_rows.get(row)):
            self.navigate(name)

    def navigate(self, name: str) -> None:
        self.stack.set_visible_child_name(name)
        self.header_title.set_title(self.page_titles.get(name, APP_NAME))
        if self.split.get_collapsed():
            self.split.set_show_content(True)
        self.refresh_page(name)

    def toast(self, message: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast(title=message, timeout=4))

    def _overview_page(self) -> Gtk.Widget:
        page, body = page_shell("System health", "Live telemetry and the most important unresolved incidents.")
        self.health_banner = Adw.Banner(title="Checking collector and database…")
        self.health_banner.set_revealed(True)
        body.append(self.health_banner)
        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True, min_children_per_line=1, max_children_per_line=3, column_spacing=12, row_spacing=12)
        for key, title, icon in (
            ("cpu", "CPU", "speedometer-symbolic"), ("memory", "Memory", "media-flash-symbolic"),
            ("disk", "Root storage", "drive-harddisk-symbolic"), ("temperature", "CPU temperature", "weather-clear-symbolic"),
            ("gpu", "Graphics", "video-display-symbolic"), ("power", "GPU power", "battery-good-symbolic"),
            ("issues", "Serious issues", "dialog-error-symbolic"),
        ):
            card = MetricCard(title, icon)
            card.set_hexpand(False)
            card.set_hexpand_set(True)
            self.metric_cards[key] = card
            flow.insert(card, -1)
        body.append(flow)
        group = Adw.PreferencesGroup(title="Needs attention", description="Select an incident to see the evidence and probable cause.")
        self.overview_issues = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.overview_issues.set_activate_on_single_click(True)
        self.overview_issues.add_css_class("boxed-list")
        self.overview_issues.connect("row-activated", self._incident_row_activated)
        group.add(self.overview_issues)
        body.append(group)
        return page

    def _issues_page(self) -> Gtk.Widget:
        page, body = page_shell("Active issues", "Correlated incidents, ordered by risk and recency. Select an issue to expand its details.")
        filters = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.issue_severity = Gtk.DropDown.new_from_strings(SEVERITIES)
        self.issue_category = Gtk.DropDown.new_from_strings(CATEGORIES)
        self.issue_status = Gtk.DropDown.new_from_strings(["Open", "All", "Resolved", "Acknowledged", "Historical"])
        self.issue_search = Gtk.SearchEntry(placeholder_text="Search issues")
        for widget in (self.issue_severity, self.issue_category, self.issue_status, self.issue_search):
            filters.append(widget)
        self.issue_search.set_hexpand(True)
        self.issue_severity.connect("notify::selected", lambda *_a: self._refresh_incidents())
        self.issue_category.connect("notify::selected", lambda *_a: self._refresh_incidents())
        self.issue_status.connect("notify::selected", lambda *_a: self._refresh_incidents())
        self.issue_search.connect("search-changed", lambda *_a: self._refresh_incidents())
        body.append(filters)
        self.issue_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.issue_list.set_activate_on_single_click(True)
        self.issue_list.add_css_class("boxed-list")
        body.append(self.issue_list)
        return page

    def _forensics_page(self) -> Gtk.Widget:
        page, body = page_shell(
            "Forensic cases",
            "Retained restart, crash, kernel, and hardware-fault investigations. Each case preserves its surrounding telemetry and evidence window.",
        )
        self.forensics_banner = Adw.Banner(title="Loading retained forensic cases…")
        self.forensics_banner.set_revealed(True)
        body.append(self.forensics_banner)
        self.forensics_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.forensics_content)
        return page

    def _events_page(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(12); controls.set_margin_start(12); controls.set_margin_end(12)
        self.live_search = Gtk.SearchEntry(placeholder_text="Search live evidence")
        self.live_search.set_hexpand(True)
        self.live_severity = Gtk.DropDown.new_from_strings(SEVERITIES)
        self.live_category = Gtk.DropDown.new_from_strings(CATEGORIES)
        self.live_follow = Gtk.Switch(active=True, valign=Gtk.Align.CENTER, tooltip_text="Follow new events")
        controls.append(self.live_search); controls.append(self.live_severity); controls.append(self.live_category)
        controls.append(label("Follow")); controls.append(self.live_follow)
        root.append(controls)
        self.live_search.connect("search-changed", lambda *_a: self._load_live(True))
        self.live_severity.connect("notify::selected", lambda *_a: self._load_live(True))
        self.live_category.connect("notify::selected", lambda *_a: self._load_live(True))
        self.live_store = Gio.ListStore.new(RecordObject)
        root.append(Gtk.ScrolledWindow(child=record_list_view(self.live_store, self.open_inspector), vexpand=True))
        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bottom.set_margin_top(4); bottom.set_margin_bottom(10); bottom.set_margin_start(12); bottom.set_margin_end(12)
        self.live_status = label("Loading events…", "dim")
        self.live_more = Gtk.Button(label="Load older events")
        self.live_more.connect("clicked", lambda _b: self._load_live(False))
        bottom.append(self.live_status); self.live_status.set_hexpand(True); bottom.append(self.live_more)
        root.append(bottom)
        return root

    def _performance_page(self) -> Gtk.Widget:
        page, body = page_shell("Performance", "Validated one-minute history from the local collector.")
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.append(label("Range"))
        self.perf_range = Gtk.DropDown.new_from_strings(["1 hour", "6 hours", "24 hours"])
        self.perf_range.connect("notify::selected", lambda *_a: self._refresh_performance())
        controls.append(self.perf_range)
        body.append(controls)
        self.perf_group = Adw.PreferencesGroup()
        body.append(self.perf_group)
        self.perf_rows: dict[str, tuple[Adw.ActionRow, Sparkline]] = {}
        for metric, title in (("cpu.percent", "CPU utilization"), ("memory.percent", "Memory usage"), ("cpu.iowait", "Storage I/O wait"), ("gpu.percent", "GPU utilization")):
            row = action_row(title, "Waiting for samples")
            chart = Sparkline(72)
            chart.set_size_request(360, 72)
            row.add_suffix(chart)
            self.perf_group.add(row)
            self.perf_rows[metric] = (row, chart)
        return page

    def _power_page(self) -> Gtk.Widget:
        page, body = page_shell(
            "Power & voltage",
            "Exact ten-second telemetry is retained for seven days. GPU watts are board draw, not total PSU draw; only explicitly named voltage rails are shown.",
        )
        self.power_status = Adw.Banner(title="Waiting for collector samples…")
        self.power_status.set_revealed(True)
        body.append(self.power_status)
        self.power_group = Adw.PreferencesGroup(title="Component power")
        body.append(self.power_group)
        self.power_rows: dict[str, tuple[Adw.ActionRow, Sparkline]] = {}
        for metric, title in (
            ("gpu.power.draw.watts", "NVIDIA GPU board power"),
            ("gpu.power.limit.watts", "NVIDIA GPU power cap"),
            ("power.AMD graphics PPT.watts", "AMD graphics PPT"),
        ):
            row = action_row(title, "Waiting for samples", "battery-good-symbolic")
            chart = Sparkline(72)
            chart.set_size_request(360, 72)
            row.add_suffix(chart)
            self.power_group.add(row)
            self.power_rows[metric] = (row, chart)
        self.voltage_group = Adw.PreferencesGroup(
            title="Validated voltage rails",
            description="Anonymous motherboard inN channels are deliberately excluded because their rail mapping and scaling are unknown.",
        )
        self.voltage_empty = action_row("No named voltage rails reported", "This motherboard currently exposes only anonymous rail channels. AMD graphics core rails will appear when collected.")
        self.voltage_group.add(self.voltage_empty)
        self.voltage_rows: dict[str, tuple[Adw.ActionRow, Sparkline]] = {}
        body.append(self.voltage_group)
        self.voltage_coverage = Adw.PreferencesGroup(
            title="CPU, memory, and NVMe rail coverage",
            description="Only a sensor driver or board configuration that explicitly identifies a rail is recorded. Unlabeled inN channels are not guessed.",
        )
        self.voltage_coverage_rows: dict[str, Adw.ActionRow] = {}
        for component, subtitle in (
            ("CPU", "Waiting for a named CPU/SoC voltage rail."),
            ("Memory", "Waiting for a named DIMM/DRAM voltage rail."),
            ("NVMe", "Waiting for a named M.2/NVMe voltage rail."),
        ):
            row = action_row(f"{component} voltage", subtitle, "power-profile-balanced-symbolic")
            self.voltage_coverage.add(row)
            self.voltage_coverage_rows[component] = row
        body.append(self.voltage_coverage)
        return page

    def _tuning_page(self) -> Gtk.Widget:
        page, body = page_shell(
            "Safe tuning",
            "Temporary, factory-bounded controls only. PC Diagnostics preserves the pre-tuning state and restores it automatically after a sustained critical thermal event.",
        )
        self.tuning_banner = Adw.Banner(title="Checking supported controls…")
        self.tuning_banner.set_revealed(True)
        body.append(self.tuning_banner)

        cpu_group = Adw.PreferencesGroup(
            title="CPU policy",
            description="Applies one governor and hardware-valid frequency range to every exposed CPU policy. These settings reset when you restore the saved baseline or reboot.",
        )
        self.tuning_cpu_status = action_row("CPU tuning unavailable", "Waiting for the constrained tuning helper.", "speedometer-symbolic")
        cpu_group.add(self.tuning_cpu_status)
        self.tuning_governor = Gtk.DropDown.new_from_strings(["Unavailable"])
        governor_row = action_row("Governor", "Kernel-reported governors only")
        governor_row.add_suffix(self.tuning_governor)
        cpu_group.add(governor_row)
        self.tuning_cpu_min = Gtk.SpinButton.new_with_range(400, 10000, 25)
        self.tuning_cpu_min.set_digits(0)
        min_row = action_row("Minimum frequency", "MHz · bounded by every CPU policy")
        min_row.add_suffix(self.tuning_cpu_min)
        cpu_group.add(min_row)
        self.tuning_cpu_max = Gtk.SpinButton.new_with_range(400, 10000, 25)
        self.tuning_cpu_max.set_digits(0)
        max_row = action_row("Maximum frequency", "MHz · bounded by every CPU policy")
        max_row.add_suffix(self.tuning_cpu_max)
        cpu_group.add(max_row)
        self.tuning_cpu_boost = Gtk.Switch(valign=Gtk.Align.CENTER)
        boost_row = action_row("CPU boost", "Shown only when the kernel exposes a reversible boost switch")
        boost_row.add_suffix(self.tuning_cpu_boost)
        boost_row.set_activatable_widget(self.tuning_cpu_boost)
        cpu_group.add(boost_row)
        body.append(cpu_group)

        gpu_group = Adw.PreferencesGroup(
            title="NVIDIA factory power cap",
            description="Sets a GPU power limit only inside the NVIDIA driver's reported factory range. It does not alter voltage, clocks, fans, or firmware.",
        )
        self.tuning_gpu_status = action_row("NVIDIA power control unavailable", "Waiting for the constrained tuning helper.", "video-display-symbolic")
        gpu_group.add(self.tuning_gpu_status)
        self.tuning_gpu_select = Gtk.DropDown.new_from_strings(["No compatible NVIDIA GPU"])
        self.tuning_gpu_select.connect("notify::selected", lambda *_args: self._tuning_gpu_selected())
        gpu_select_row = action_row("GPU", "A limit is applied only to the selected compatible GPU")
        gpu_select_row.add_suffix(self.tuning_gpu_select)
        gpu_group.add(gpu_select_row)
        self.tuning_gpu_limit = Gtk.SpinButton.new_with_range(1, 1000, 1)
        self.tuning_gpu_limit.set_digits(0)
        gpu_limit_row = action_row("Power limit", "Watts · factory range enforced by the driver")
        gpu_limit_row.add_suffix(self.tuning_gpu_limit)
        gpu_group.add(gpu_limit_row)
        body.append(gpu_group)

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.tuning_apply = Gtk.Button(label="Apply temporary tuning")
        self.tuning_apply.add_css_class("suggested-action")
        self.tuning_apply.connect("clicked", lambda _button: self._confirm_apply_tuning())
        self.tuning_restore = Gtk.Button(label="Restore saved baseline")
        self.tuning_restore.connect("clicked", lambda _button: self._confirm_restore_tuning())
        controls.append(self.tuning_apply)
        controls.append(self.tuning_restore)
        body.append(controls)

        audit_group = Adw.PreferencesGroup(
            title="Tuning audit",
            description="Every requested apply, restore, rejected request, and automatic safety rollback is retained locally with its result.",
        )
        self.tuning_audit_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        audit_group.add(self.tuning_audit_content)
        body.append(audit_group)
        self._set_tuning_controls_sensitive(False, False)
        return page

    def _set_tuning_controls_sensitive(self, cpu: bool, gpu: bool) -> None:
        self.tuning_governor.set_sensitive(cpu)
        self.tuning_cpu_min.set_sensitive(cpu)
        self.tuning_cpu_max.set_sensitive(cpu)
        cpu_state = self.tuning_state.get("cpu", {})
        boost = cpu_state.get("boost", {}) if isinstance(cpu_state, dict) else {}
        self.tuning_cpu_boost.set_sensitive(cpu and bool(boost.get("available")))
        self.tuning_gpu_select.set_sensitive(gpu)
        self.tuning_gpu_limit.set_sensitive(gpu)
        self.tuning_apply.set_sensitive(cpu or gpu)
        self.tuning_restore.set_sensitive(bool(self.tuning_state.get("baseline_active")))

    def _refresh_tuning(self) -> None:
        if self.tuning_refresh_inflight:
            return
        self.tuning_refresh_inflight = True
        future = self.executor.submit(tuning_request, "state")
        future.add_done_callback(lambda done: GLib.idle_add(self._tuning_state_ready, done))

    def _tuning_state_ready(self, future: concurrent.futures.Future[dict[str, Any]]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        self.tuning_refresh_inflight = False
        try:
            response = future.result()
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        if not response.get("ok"):
            self.tuning_state = {}
            self.tuning_banner.set_title("Safe controls are disabled until the isolated tuning helper is installed")
            self.tuning_cpu_status.set_subtitle(str(response.get("error", "The constrained tuning helper is unavailable."))[:240])
            self.tuning_gpu_status.set_subtitle("NVIDIA controls require the same isolated helper.")
            self._set_tuning_controls_sensitive(False, False)
            self._refresh_tuning_audit()
            return GLib.SOURCE_REMOVE
        self.tuning_state = response
        cpu = response.get("cpu", {}) if isinstance(response.get("cpu"), dict) else {}
        policies = cpu.get("policies", []) if isinstance(cpu.get("policies"), list) else []
        cpu_enabled = bool(cpu.get("available") and policies)
        boost = cpu.get("boost", {}) if isinstance(cpu.get("boost"), dict) else {}
        if cpu_enabled:
            governors = [str(item) for item in policies[0].get("available_governors", [])]
            for policy in policies[1:]:
                governors = [item for item in governors if item in policy.get("available_governors", [])]
            common_min = max(int(policy["cpuinfo_min_khz"]) for policy in policies)
            common_max = min(int(policy["cpuinfo_max_khz"]) for policy in policies)
            selected_min = max(int(policy["min_khz"]) for policy in policies)
            selected_max = min(int(policy["max_khz"]) for policy in policies)
            if selected_min > selected_max:
                # Per-policy settings can differ. Show a universally valid
                # range rather than constructing an invalid combined request.
                selected_min, selected_max = common_min, common_max
            self.tuning_governor.set_model(Gtk.StringList.new(governors or ["Unavailable"]))
            selected_governor = str(policies[0].get("governor", ""))
            self.tuning_governor.set_selected(governors.index(selected_governor) if selected_governor in governors else 0)
            self.tuning_cpu_min.set_range(math.ceil(common_min / 1000), math.floor(common_max / 1000))
            self.tuning_cpu_max.set_range(math.ceil(common_min / 1000), math.floor(common_max / 1000))
            self.tuning_cpu_min.set_value(max(math.ceil(common_min / 1000), min(math.floor(selected_min / 1000), math.floor(common_max / 1000))))
            self.tuning_cpu_max.set_value(max(math.ceil(common_min / 1000), min(math.floor(selected_max / 1000), math.floor(common_max / 1000))))
            self.tuning_cpu_boost.set_active(bool(boost.get("enabled")))
            self.tuning_cpu_boost.set_sensitive(bool(boost.get("available")))
            self.tuning_cpu_status.set_title("CPU governor and frequency range available")
            detail = f"{len(policies)} policy(s) · {math.ceil(common_min / 1000)}–{math.floor(common_max / 1000)} MHz"
            if len({str(policy.get('governor')) for policy in policies}) > 1:
                detail += " · current governors differ"
            self.tuning_cpu_status.set_subtitle(detail)
        else:
            self.tuning_cpu_status.set_title("CPU frequency controls unavailable")
            self.tuning_cpu_status.set_subtitle("This kernel did not expose a complete reversible cpufreq policy.")
            self.tuning_cpu_boost.set_sensitive(False)

        gpu = response.get("gpu", {}) if isinstance(response.get("gpu"), dict) else {}
        entries = [item for item in gpu.get("gpus", []) if isinstance(item, dict) and item.get("power_limit_supported")]
        self.tuning_gpu_options = entries
        gpu_enabled = bool(gpu.get("available") and entries)
        if gpu_enabled:
            labels = [f"GPU {item['index']} · {item.get('name', 'NVIDIA GPU')}" for item in entries]
            self.tuning_gpu_select.set_model(Gtk.StringList.new(labels))
            self.tuning_gpu_select.set_selected(0)
            self.tuning_gpu_status.set_title("NVIDIA factory power cap available")
            self._tuning_gpu_selected()
        else:
            self.tuning_gpu_status.set_title("NVIDIA power cap unavailable")
            self.tuning_gpu_status.set_subtitle(str(gpu.get("error", "The NVIDIA driver did not report a controllable factory power range."))[:240])
        baseline = bool(response.get("baseline_active"))
        self.tuning_banner.set_title(
            "Temporary tuning is active; the saved pre-tuning baseline can be restored at any time."
            if baseline else
            "Only factory-bounded settings are available. Applying them first saves a protected pre-tuning baseline."
        )
        self._set_tuning_controls_sensitive(cpu_enabled, gpu_enabled)
        self._refresh_tuning_audit()
        return GLib.SOURCE_REMOVE

    def _selected_governor(self) -> str:
        item = self.tuning_governor.get_selected_item()
        return item.get_string() if isinstance(item, Gtk.StringObject) else ""

    def _selected_gpu(self) -> dict[str, Any] | None:
        index = self.tuning_gpu_select.get_selected()
        return self.tuning_gpu_options[index] if 0 <= index < len(self.tuning_gpu_options) else None

    def _tuning_gpu_selected(self) -> None:
        selected = self._selected_gpu()
        if not selected:
            return
        minimum = math.ceil(float(selected["min_power_limit_watts"]))
        maximum = math.floor(float(selected["max_power_limit_watts"]))
        self.tuning_gpu_limit.set_range(minimum, maximum)
        self.tuning_gpu_limit.set_value(round(float(selected["power_limit_watts"])))
        self.tuning_gpu_status.set_subtitle(
            f"Current {float(selected['power_limit_watts']):.0f} W · factory range {minimum}–{maximum} W"
        )

    def _confirm_apply_tuning(self) -> None:
        cpu_enabled = self.tuning_governor.get_sensitive()
        gpu_enabled = self.tuning_gpu_limit.get_sensitive()
        if not cpu_enabled and not gpu_enabled:
            self.toast("No factory-bounded tuning control is available")
            return
        dialog = Adw.AlertDialog(
            heading="Apply temporary tuning?",
            body="PC Diagnostics will save the current state before applying only the values shown here. It will automatically restore that baseline after sustained critical temperature readings.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("apply", "Apply temporary tuning")
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda _dialog, response: self._apply_tuning() if response == "apply" else None)
        dialog.present(self)

    def _apply_tuning(self) -> None:
        cpu: dict[str, Any] = {}
        gpu: dict[str, Any] = {}
        if self.tuning_governor.get_sensitive():
            cpu = {
                "governor": self._selected_governor(),
                "min_khz": int(self.tuning_cpu_min.get_value()) * 1000,
                "max_khz": int(self.tuning_cpu_max.get_value()) * 1000,
            }
            if self.tuning_cpu_boost.get_sensitive():
                cpu["boost"] = self.tuning_cpu_boost.get_active()
        if self.tuning_gpu_limit.get_sensitive() and (gpu_item := self._selected_gpu()):
            gpu = {"index": int(gpu_item["index"]), "power_limit_watts": int(self.tuning_gpu_limit.get_value())}
        self._submit_tuning("apply", {"cpu": cpu, "gpu": gpu}, "user-request")

    def _confirm_restore_tuning(self) -> None:
        if not self.tuning_state.get("baseline_active"):
            self.toast("There is no saved tuning baseline to restore")
            return
        dialog = Adw.AlertDialog(
            heading="Restore saved baseline?",
            body="This returns CPU and supported NVIDIA power settings to their state before the first temporary tuning change.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("restore", "Restore baseline")
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _dialog, response: self._submit_tuning("restore", {}, "user-request") if response == "restore" else None)
        dialog.present(self)

    def _submit_tuning(self, operation: str, parameters: dict[str, Any], reason: str) -> None:
        self.tuning_apply.set_sensitive(False)
        self.tuning_restore.set_sensitive(False)
        future = self.executor.submit(tuning_request, operation, **parameters)
        future.add_done_callback(lambda done: GLib.idle_add(self._tuning_action_ready, done, operation, reason))

    def _tuning_action_ready(self, future: concurrent.futures.Future[dict[str, Any]], operation: str, reason: str) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            response = future.result()
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        try:
            with connect_v2() as conn:
                record_tuning_audit(conn, operation, response, reason=reason)
        except sqlite3.Error:
            pass
        self.toast(
            "Temporary tuning applied" if operation == "apply" and response.get("ok") else
            "Saved baseline restored" if operation == "restore" and response.get("ok") else
            f"Tuning request failed: {str(response.get('error', 'unknown error'))[:160]}"
        )
        self._refresh_tuning()
        return GLib.SOURCE_REMOVE

    def _refresh_tuning_audit(self) -> None:
        self._clear_container(self.tuning_audit_content)
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute("SELECT * FROM tuning_audit ORDER BY occurred_us DESC LIMIT 12").fetchall()
        except sqlite3.Error:
            rows = []
        if not rows:
            self.tuning_audit_content.append(action_row("No tuning requests recorded", "Apply, restore, rejected, and automatic-safety actions will appear here.", "document-open-recent-symbolic"))
            return
        for entry in rows:
            icon = "emblem-ok-symbolic" if entry["result"] == "ok" else "dialog-error-symbolic"
            self.tuning_audit_content.append(action_row(
                f"{str(entry['action']).replace('-', ' ').title()} · {entry['result']}",
                f"{format_time(entry['occurred_us'])} · {entry['reason']}",
                icon,
            ))

    def _hardware_page(self) -> Gtk.Widget:
        page, body = page_shell("Hardware health", "Sensors, drive health, buses, and firmware inventory.")
        self.hardware_status = Adw.Banner(title="Waiting for the hardware scan…")
        body.append(self.hardware_status)
        self.hardware_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.hardware_content)
        return page

    def _services_page(self) -> Gtk.Widget:
        page, body = page_shell("Services", "Failed system and user-session units. Only user units can be changed here.")
        self.services_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.services_content)
        return page

    def _network_page(self) -> Gtk.Widget:
        page, body = page_shell("Network & security", "Interface state, routes, listening sockets, and correlated network incidents.")
        self.network_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.network_content)
        return page

    def _crashes_page(self) -> Gtk.Widget:
        page, body = page_shell("Crash history", "Crash artifacts, sizes, timestamps, and completion state.")
        self.crashes_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.crashes_content)
        return page

    def _updates_page(self) -> Gtk.Widget:
        page, body = page_shell("Updates", "Available package and device-firmware updates. Installation remains outside this app.")
        self.updates_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.updates_content)
        return page

    def _boots_page(self) -> Gtk.Widget:
        page, body = page_shell("Boot history", "Indexed incidents and evidence grouped by system boot.")
        self.boot_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.boot_list.add_css_class("boxed-list")
        body.append(self.boot_list)
        return page

    def _raw_page(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(12); controls.set_margin_start(12); controls.set_margin_end(12)
        self.raw_source_names = ["System journal", "Kernel journal", "User journal", "Current dmesg", "Authentication", "APT", "dpkg", "Xorg"]
        self.raw_source = Gtk.DropDown.new_from_strings(self.raw_source_names)
        self.raw_since = Gtk.DropDown.new_from_strings(["15 minutes", "1 hour", "24 hours"])
        self.raw_search = Gtk.SearchEntry(placeholder_text="Filter loaded messages")
        self.raw_search.set_hexpand(True)
        load = Gtk.Button(label="Load logs")
        load.add_css_class("suggested-action")
        load.connect("clicked", lambda _b: self._load_raw())
        controls.append(self.raw_source); controls.append(self.raw_since); controls.append(self.raw_search); controls.append(load)
        root.append(controls)
        self.raw_store = Gio.ListStore.new(RecordObject)
        self.raw_search.connect("search-changed", lambda *_a: self._render_raw_records())
        root.append(Gtk.ScrolledWindow(child=record_list_view(self.raw_store, self._raw_inspector, compact=True), vexpand=True))
        self.raw_status = label("Select a source and load up to 1,000 entries.", "dim")
        self.raw_status.set_margin_start(12); self.raw_status.set_margin_bottom(10)
        root.append(self.raw_status)
        return root

    def open_inspector(self, record: dict[str, Any]) -> None:
        EventInspector(self, record).present(self)

    def _raw_inspector(self, record: dict[str, Any]) -> None:
        self.open_inspector(record)

    def _incident_row(self, record: dict[str, Any]) -> Adw.ActionRow:
        tier = "TOP CRITICAL · " if is_top_critical(record) else ""
        subtitle = f"{tier}{record.get('severity')} · {record.get('category')} · Last seen {format_time(int(record.get('last_us', 0)))} · {record.get('occurrences', 1)} event(s)"
        row = action_row(str(record.get("title", "Unknown issue")), subtitle)
        row.add_prefix(status_icon(str(record.get("severity", "Activity"))))
        row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        row.record = record
        return row

    def _incident_row_activated(self, _box: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        if hasattr(row, "record"):
            self._open_incident(dict(row.record))

    def _open_incident(self, record: dict[str, Any]) -> None:
        record.setdefault("incident_id", record.get("id"))
        record.setdefault("message", record.get("sample_message", ""))
        self.open_inspector(record)

    def _issue_expansion_changed(self, row: Adw.ExpanderRow, _pspec: GObject.ParamSpec, incident_id: int) -> None:
        if row.get_expanded():
            self.expanded_issue_ids.add(incident_id)
        else:
            self.expanded_issue_ids.discard(incident_id)

    def _expandable_incident_row(self, record: dict[str, Any]) -> Adw.ExpanderRow:
        incident_id = int(record.get("id") or record.get("incident_id") or 0)
        tier = "TOP CRITICAL · " if is_top_critical(record) else ""
        subtitle = (
            f"{tier}{record.get('severity')} · {record.get('category')} · "
            f"Last seen {format_time(int(record.get('last_us', 0)))} · "
            f"{record.get('occurrences', 1)} event(s)"
            + (" · Acknowledged" if record.get("acknowledged") else "")
        )
        row = Adw.ExpanderRow()
        row.set_use_markup(False)
        row.set_title(str(record.get("title", "Unknown issue")))
        row.set_subtitle(subtitle)
        row.add_prefix(status_icon(str(record.get("severity", "Activity"))))

        diagnosis = diagnosis_for(record)
        detail_rows: list[Adw.ActionRow] = []
        summary = str(record.get("summary") or "").strip()
        if summary:
            detail_rows.append(action_row("What happened", summary, "dialog-information-symbolic"))
        detail_rows.extend((
            action_row(
                "Likely cause",
                f"{diagnosis['cause']} ({diagnosis['confidence'].lower()} confidence: {diagnosis['basis']})",
                "system-search-symbolic",
            ),
            action_row("Expected impact", diagnosis["impact"], "dialog-warning-symbolic"),
        ))
        sample = str(record.get("sample_message") or "").strip()
        if sample:
            detail_rows.append(action_row("Latest evidence", sample, "utilities-terminal-symbolic"))
        detail_rows.append(action_row(
            "History",
            f"First seen {format_time(int(record.get('first_us', 0)))} · "
            f"Last seen {format_time(int(record.get('last_us', 0)))} · "
            f"Status {record.get('status', 'open')} · {record.get('occurrences', 1)} event(s)",
            "document-open-recent-symbolic",
        ))
        for detail in detail_rows:
            detail.set_subtitle_selectable(True)
            row.add_row(detail)
        if str(record.get("rule_id", "")) in {"kernel-crash-artifact", "crash-storage"}:
            self._append_crash_artifacts(row, record)
        for index, step in enumerate(diagnosis["steps"], 1):
            check = action_row(f"Suggested check {index}", step, "go-next-symbolic")
            check.set_subtitle_selectable(True)
            row.add_row(check)

        full_details = action_row(
            "Full technical details",
            "Open the evidence timeline, nearby logs, diagnosis, and exact metadata.",
            "document-open-symbolic",
        )
        open_button = Gtk.Button(label="Open")
        open_button.set_valign(Gtk.Align.CENTER)
        open_button.connect("clicked", lambda _button, item=dict(record): self._open_incident(item))
        full_details.add_suffix(open_button)
        full_details.set_activatable_widget(open_button)
        row.add_row(full_details)

        if str(record.get("status", "open")) == "open":
            incident_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            acknowledged = bool(record.get("acknowledged"))
            acknowledge = Gtk.Button(label="Unacknowledge" if acknowledged else "Acknowledge")
            acknowledge.set_valign(Gtk.Align.CENTER)
            acknowledge.connect(
                "clicked",
                lambda _button, incident_id=incident_id, value=acknowledged: self._set_incident_acknowledged(incident_id, not value),
            )
            resolve = Gtk.Button(label="Mark resolved")
            resolve.set_valign(Gtk.Align.CENTER)
            resolve.connect("clicked", lambda _button, value=incident_id: self._resolve_incident(value))
            incident_actions.append(acknowledge)
            incident_actions.append(resolve)
            actions = action_row("Local incident state", "These actions change only the local incident record.")
            actions.add_suffix(incident_actions)
            row.add_row(actions)

        row.set_expanded(incident_id in self.expanded_issue_ids)
        row.connect("notify::expanded", self._issue_expansion_changed, incident_id)
        return row

    def _append_crash_artifacts(self, row: Adw.ExpanderRow, record: dict[str, Any]) -> None:
        kernel_only = str(record.get("rule_id", "")) == "kernel-crash-artifact"
        entries = [
            item for item in self.latest_crash_entries
            if not kernel_only or is_kernel_crash_artifact(item)
        ]
        heading = action_row(
            f"Detected {'kernel ' if kernel_only else ''}crash artifacts ({len(entries)})",
            "Select Details to inspect the path, size, completion state, and recorded metadata.",
            "folder-documents-symbolic",
        )
        show_all = Gtk.Button(label="Show all")
        show_all.set_valign(Gtk.Align.CENTER)
        show_all.connect("clicked", lambda _button: self.navigate("crashes"))
        heading.add_suffix(show_all)
        heading.set_activatable_widget(show_all)
        row.add_row(heading)
        if entries:
            for item in entries[:100]:
                row.add_row(self._crash_artifact_row(item))
        else:
            row.add_row(action_row(
                "No current dump inventory",
                "The crash scan has not returned file details yet. Refresh after the collector completes its next scan.",
                "dialog-information-symbolic",
            ))

    def _crash_artifact_row(self, item: dict[str, Any]) -> Adw.ActionRow:
        path = Path(str(item.get("path", "Crash artifact")))
        size = int(item.get("size", 0) or 0)
        stamp = int(item.get("mtime", 0) or 0) * 1_000_000
        incomplete = "incomplete" in path.name.lower()
        kind = "Incomplete dump" if incomplete else str(item.get("kind", "file")).replace("_", " ").title()
        subtitle = f"{kind} · {format_file_size(size)} · {format_time(stamp)}\n{path}"
        artifact = action_row(path.name, subtitle, "dialog-warning-symbolic" if incomplete else "text-x-generic-symbolic")
        artifact.set_subtitle_lines(2)
        artifact.set_subtitle_selectable(True)
        details = Gtk.Button(label="Details")
        details.set_valign(Gtk.Align.CENTER)
        details.connect("clicked", lambda _button, entry=dict(item): self._show_crash_artifact(entry))
        artifact.add_suffix(details)
        artifact.set_activatable_widget(details)
        return artifact

    def _show_crash_artifact(self, item: dict[str, Any]) -> None:
        path = Path(str(item.get("path", "Crash artifact")))
        dialog = Adw.Dialog(title=path.name, content_width=820, content_height=680)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        page, body = page_shell(path.name, str(path))
        toolbar.set_content(page)
        dialog.set_child(toolbar)

        size = int(item.get("size", 0) or 0)
        stamp = int(item.get("mtime", 0) or 0) * 1_000_000
        incomplete = "incomplete" in path.name.lower()
        fields = Adw.PreferencesGroup(title="Dump information")
        for title, value in (
            ("State", "Incomplete" if incomplete else "Complete / recorded"),
            ("Type", str(item.get("kind", "file"))),
            ("Size", format_file_size(size)),
            ("Modified", format_time(stamp)),
            ("Path", str(path)),
        ):
            detail = action_row(title, value)
            detail.set_subtitle_selectable(True)
            fields.add(detail)
        body.append(fields)

        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if metadata:
            metadata_group = Adw.PreferencesGroup(title="Recorded crash metadata")
            for key, value in metadata.items():
                detail = action_row(str(key).replace("_", " "), str(value))
                detail.set_subtitle_selectable(True)
                metadata_group.add(detail)
            body.append(metadata_group)

        guidance = Adw.PreferencesGroup(title="How to inspect it")
        if path.name.startswith("dmesg."):
            guidance.add(action_row(
                "Kernel log captured at the crash",
                "Use View log below to read the captured kernel messages inside PC Diagnostics.",
                "utilities-terminal-symbolic",
            ))
        elif path.name.startswith(("dump.", "dump-incomplete")):
            guidance.add(action_row(
                "Binary kernel memory image",
                "Memory dumps are not rendered as text. Analyze a preserved copy with the matching kernel symbols and the crash utility.",
                "applications-engineering-symbolic",
            ))
        else:
            guidance.add(action_row(
                "Crash report",
                "The safe metadata extracted from this report is shown above.",
                "dialog-information-symbolic",
            ))
        body.append(guidance)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        copy_path = Gtk.Button(label="Copy path")
        copy_path.connect("clicked", lambda _button, value=str(path): self._copy_crash_path(value))
        open_folder = Gtk.Button(label="Open containing folder")
        open_folder.connect("clicked", lambda _button, value=str(path): self._open_crash_folder(value))
        actions.append(copy_path)
        actions.append(open_folder)
        if path.name.startswith("dmesg."):
            view_log = Gtk.Button(label="View kernel log")
            view_log.add_css_class("suggested-action")
            view_log.connect("clicked", lambda _button, entry=dict(item): self._load_crash_log(entry))
            actions.append(view_log)
        body.append(actions)
        body.append(advanced_raw(item))
        dialog.present(self)

    def _copy_crash_path(self, path: str) -> None:
        Gdk.Display.get_default().get_clipboard().set(path)
        self.toast("Crash artifact path copied")

    def _open_crash_folder(self, path: str) -> None:
        try:
            Gio.AppInfo.launch_default_for_uri(Path(path).parent.as_uri(), None)
        except GLib.Error as exc:
            self.toast(f"Unable to open crash folder: {exc.message}")

    def _load_crash_log(self, item: dict[str, Any]) -> None:
        path = str(item.get("path", ""))
        future = self.executor.submit(helper_request, "crash_text", path=path)
        future.add_done_callback(lambda done: GLib.idle_add(self._crash_log_ready, done, Path(path).name))

    def _crash_log_ready(self, future: concurrent.futures.Future[dict[str, Any]], title: str) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            response = future.result()
            output = str(response.get("output", ""))
            if not response.get("ok"):
                output = f"Unable to read the captured kernel log: {response.get('error', 'unknown error')}"
            elif response.get("truncated"):
                output += "\n\n[Preview truncated by the read-only helper.]"
        except Exception as exc:
            output = f"Unable to read the captured kernel log: {exc}"
        self._present_text_dialog(f"Kernel crash log · {title}", output)
        return GLib.SOURCE_REMOVE

    def _refresh_incidents(self) -> None:
        where = []
        args: list[Any] = []
        status_index = self.issue_status.get_selected()
        if status_index != 1:
            status = ("open", "all", "resolved", "acknowledged", "historical")[status_index]
            if status == "acknowledged":
                where.append("((status='open' AND acknowledged=1) OR status='acknowledged')")
                status = ""
            elif status == "open":
                where.append("status='open'")
                status = ""
            elif status:
                where.append("status=?")
                args.append(status)
        severity = SEVERITIES[self.issue_severity.get_selected()]
        category = CATEGORIES[self.issue_category.get_selected()]
        if severity != SEVERITIES[0]: where.append("severity=?"); args.append(severity)
        if category != CATEGORIES[0]: where.append("category=?"); args.append(category)
        if search := self.issue_search.get_text().strip():
            where.append("(title LIKE ? OR sample_message LIKE ? OR likely_cause LIKE ?)")
            args.extend([f"%{search}%"] * 3)
        clause = "WHERE " + " AND ".join(where) if where else ""
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute(
                    f"SELECT * FROM incidents {clause} ORDER BY {INCIDENT_PRIORITY_SQL} DESC,last_us DESC LIMIT 300",
                    args,
                ).fetchall()
        except sqlite3.Error as exc:
            self.toast(f"Database error: {exc}"); return
        _crash_row, crash_data = self._latest_scan("crashes")
        crash_entries = crash_data.get("entries", []) if isinstance(crash_data, dict) else []
        self.latest_crash_entries = [dict(item) for item in crash_entries if isinstance(item, dict)]
        clear_list(self.issue_list)
        for row in rows:
            self.issue_list.append(self._expandable_incident_row(dict(row)))
        if not rows:
            has_filters = bool(
                self.issue_search.get_text().strip()
                or self.issue_severity.get_selected() != 0
                or self.issue_category.get_selected() != 0
                or self.issue_status.get_selected() != 0
            )
            self.issue_list.append(action_row(
                "No matching incidents" if has_filters else "No active incidents",
                "Try a broader filter." if has_filters else "The collector has not recorded an unresolved incident.",
                "edit-find-symbolic" if has_filters else "emblem-ok-symbolic",
            ))

    def _set_incident_acknowledged(self, incident_id: int, acknowledged: bool) -> None:
        try:
            with open_v2() as conn:
                changed = acknowledge_incident(conn, incident_id, acknowledged)
        except sqlite3.Error as exc:
            self.toast(f"Unable to update incident: {exc}")
            return
        if changed:
            self.toast("Incident acknowledged" if acknowledged else "Incident acknowledgement removed")
            self._refresh_incidents()

    def _resolve_incident(self, incident_id: int) -> None:
        try:
            with open_v2() as conn:
                changed = resolve_incident_id(conn, incident_id)
        except sqlite3.Error as exc:
            self.toast(f"Unable to resolve incident: {exc}")
            return
        if changed:
            self.toast("Incident marked resolved")
            self._refresh_incidents()

    def _refresh_overview_issues(self) -> None:
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute(f"SELECT * FROM incidents WHERE status='open' ORDER BY {INCIDENT_PRIORITY_SQL} DESC,last_us DESC LIMIT 6").fetchall()
                counts = dict(conn.execute("SELECT severity,COUNT(*) FROM incidents WHERE status='open' GROUP BY severity").fetchall())
        except sqlite3.Error:
            return
        clear_list(self.overview_issues)
        if not rows:
            self.overview_issues.append(action_row("No active issues", "The collector has no unresolved diagnostic incidents.", "emblem-ok-symbolic"))
        for row in rows:
            self.overview_issues.append(self._incident_row(dict(row)))
        serious = int(counts.get("Critical", 0)) + int(counts.get("Error", 0))
        warnings = int(counts.get("Warning", 0))
        self.metric_cards["issues"].update(float(serious), "", f"{warnings} warning(s)", [])

    def _load_live(self, reset: bool = True) -> None:
        if reset:
            self.live_cursor = None; self.live_raw = []
        severity = SEVERITIES[self.live_severity.get_selected()]
        category = CATEGORIES[self.live_category.get_selected()]
        try:
            with open_v2(readonly=True) as conn:
                rows = fetch_event_page(conn, before=self.live_cursor, limit=EVENT_PAGE_SIZE, severity=severity, category=category, search=self.live_search.get_text())
        except sqlite3.Error as exc:
            self.live_status.set_text(f"Database error: {exc}"); return
        self.live_raw.extend(rows)
        if rows:
            last = rows[-1]
            self.live_cursor = (int(last["occurred_us"]), int(last["evidence_id"]))
        bursts = collapse_event_bursts(self.live_raw)
        self.live_store.remove_all()
        for burst in bursts:
            self.live_store.append(RecordObject(burst))
        self.live_status.set_text(f"{len(bursts)} visible bursts · {len(self.live_raw)} underlying events")
        self.live_more.set_sensitive(len(rows) == EVENT_PAGE_SIZE)

    def _refresh_metrics(self) -> None:
        since = int((time.time() - 3600) * 1_000_000)
        high_resolution = "(metric LIKE 'temperature.%' OR metric LIKE 'gpu.%' OR metric LIKE 'power.%' OR metric LIKE 'voltage.%')"
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute(
                    "SELECT metric,bucket_us,last_value FROM metric_rollups WHERE bucket_us>=? AND "
                    f"((interval_seconds=10 AND {high_resolution}) OR (interval_seconds=60 AND NOT {high_resolution})) "
                    "ORDER BY bucket_us",
                    (since,),
                ).fetchall()
        except sqlite3.Error:
            return
        history: dict[str, list[float]] = {}
        for row in rows:
            history.setdefault(row["metric"], []).append(float(row["last_value"]))
        def last(name: str) -> float | None:
            return history[name][-1] if history.get(name) else None
        self.metric_cards["cpu"].update(last("cpu.percent"), "%", f"I/O wait {(last('cpu.iowait') or 0):.1f}%", history.get("cpu.percent", []))
        self.metric_cards["memory"].update(last("memory.percent"), "%", f"Swap {(last('swap.percent') or 0):.0f}%", history.get("memory.percent", []))
        self.metric_cards["disk"].update(last("disk.root.percent"), "%", f"{(last('disk.root.free_gib') or 0):.1f} GiB free", history.get("disk.root.percent", []))
        temps = [(name, values) for name, values in history.items() if name.startswith("temperature.CPU")]
        temp_values = max(temps, key=lambda item: item[1][-1])[1] if temps else []
        self.metric_cards["temperature"].update(temp_values[-1] if temp_values else None, "°C", "Validated CPU sensor", temp_values)
        self.metric_cards["gpu"].update(last("gpu.percent"), "%", f"GPU temperature {(last('temperature.NVIDIA GPU') or 0):.0f}°C", history.get("gpu.percent", []))
        gpu_draw = last("gpu.power.draw.watts")
        gpu_limit = last("gpu.power.limit.watts")
        power_note = "NVIDIA telemetry unavailable" if gpu_draw is None else f"{gpu_draw:.0f} W of {(gpu_limit or 0):.0f} W cap"
        self.metric_cards["power"].update(last("gpu.power.percent"), "%", power_note, history.get("gpu.power.percent", []))

    def _refresh_live_overview_metrics(self) -> None:
        try:
            metrics, self.live_metric_cpu_state = live_overview_metrics(self.live_metric_cpu_state)
        except (OSError, ValueError, IndexError, KeyError):
            return
        cpu = metrics.get("cpu.percent")
        if cpu is not None:
            self.metric_cards["cpu"].update_live(cpu, "%", f"I/O wait {metrics.get('cpu.iowait', 0):.1f}%")
        self.metric_cards["memory"].update_live(
            metrics["memory.percent"], "%", f"Swap {metrics['swap.percent']:.0f}%"
        )
        self.metric_cards["disk"].update_live(
            metrics["disk.root.percent"], "%", f"{metrics['disk.root.free_gib']:.1f} GiB free"
        )

    def _refresh_performance(self) -> None:
        seconds = (3600, 21600, 86400)[self.perf_range.get_selected()]
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute("SELECT metric,bucket_us,average,minimum,maximum FROM metric_rollups WHERE interval_seconds=60 AND bucket_us>=? ORDER BY bucket_us", (int((time.time() - seconds) * 1_000_000),)).fetchall()
        except sqlite3.Error:
            return
        grouped: dict[str, list[float]] = {}
        bounds: dict[str, list[float]] = {}
        for row in rows:
            grouped.setdefault(row["metric"], []).append(float(row["average"]))
            bounds.setdefault(row["metric"], []).extend((float(row["minimum"]), float(row["maximum"])))
        for metric in sorted(grouped):
            parts = metric.split(".")
            if len(parts) == 3 and parts[0] == "gpu" and parts[1].isdigit() and parts[2] == "percent" and metric not in self.perf_rows:
                row = action_row(f"GPU {parts[1]} utilization", "Waiting for samples")
                chart = Sparkline(72)
                chart.set_size_request(360, 72)
                row.add_suffix(chart)
                self.perf_group.add(row)
                self.perf_rows[metric] = (row, chart)
        for metric, (row, chart) in self.perf_rows.items():
            values = grouped.get(metric, [])
            if values:
                row.set_subtitle(f"Current {values[-1]:.1f}% · minimum {min(bounds[metric]):.1f}% · average {sum(values)/len(values):.1f}% · maximum {max(bounds[metric]):.1f}%")
            else:
                row.set_subtitle("No samples in this range")
            chart.set_values(values)

    def _refresh_power(self) -> None:
        since = int((time.time() - 3600) * 1_000_000)
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute(
                    "SELECT metric,average,minimum,maximum FROM metric_rollups "
                    "WHERE interval_seconds=10 AND bucket_us>=? AND "
                    "(metric LIKE 'gpu.power.%' OR metric LIKE 'gpu.%.power.%' OR metric LIKE 'power.%' OR metric LIKE 'voltage.%') "
                    "ORDER BY bucket_us",
                    (since,),
                ).fetchall()
        except sqlite3.Error:
            return
        grouped: dict[str, list[float]] = {}
        bounds: dict[str, list[float]] = {}
        for row in rows:
            grouped.setdefault(row["metric"], []).append(float(row["average"]))
            bounds.setdefault(row["metric"], []).extend((float(row["minimum"]), float(row["maximum"])))
        power_metrics = sorted(
            metric for metric in grouped
            if metric.startswith("power.") or ".power." in metric
        )
        for metric in power_metrics:
            if metric not in self.power_rows:
                row = action_row(metric.removesuffix(".watts").replace(".", " ").title(), "Waiting for samples", "battery-good-symbolic")
                chart = Sparkline(72)
                chart.set_size_request(360, 72)
                row.add_suffix(chart)
                self.power_group.add(row)
                self.power_rows[metric] = (row, chart)
        for metric, (row, chart) in self.power_rows.items():
            values = grouped.get(metric, [])
            if values:
                row.set_subtitle(f"Current {values[-1]:.1f} W · minimum {min(bounds[metric]):.1f} W · maximum {max(bounds[metric]):.1f} W")
            else:
                row.set_subtitle("No samples in this range")
            chart.set_values(values)
        voltage_metrics = sorted(metric for metric in grouped if metric.startswith("voltage."))
        if voltage_metrics and self.voltage_empty.get_parent() is self.voltage_group:
            self.voltage_group.remove(self.voltage_empty)
        for metric in voltage_metrics:
            if metric not in self.voltage_rows:
                row = action_row(metric.removeprefix("voltage.").removesuffix(".volts"), "Waiting for samples", "power-profile-balanced-symbolic")
                chart = Sparkline(72)
                chart.set_size_request(360, 72)
                row.add_suffix(chart)
                self.voltage_group.add(row)
                self.voltage_rows[metric] = (row, chart)
            row, chart = self.voltage_rows[metric]
            values = grouped[metric]
            row.set_subtitle(f"Current {values[-1]:.3f} V · minimum {min(bounds[metric]):.3f} V · maximum {max(bounds[metric]):.3f} V")
            chart.set_values(values)
        for component, row in self.voltage_coverage_rows.items():
            matching = [metric for metric in voltage_metrics if metric.startswith(f"voltage.{component} ")]
            if matching:
                metric = matching[0]
                values = grouped[metric]
                row.set_title(f"{component} voltage is being recorded")
                row.set_subtitle(f"{metric.removeprefix('voltage.').removesuffix('.volts')} · current {values[-1]:.3f} V")
            else:
                row.set_title(f"{component} voltage is not exposed")
                row.set_subtitle("No explicitly named hardware sensor is available; anonymous motherboard channels are excluded for accuracy.")
        gpu_available = any(metric.endswith(".power.draw.watts") for metric in grouped)
        self.power_status.set_title(
            "GPU power telemetry is being recorded; it does not represent total PSU or wall power."
            if gpu_available else
            "NVIDIA GPU power telemetry is unavailable. Repair the NVIDIA driver/device connection to enable it."
        )

    def _latest_scan(self, scan_type: str) -> tuple[sqlite3.Row | None, dict[str, Any]]:
        try:
            with open_v2(readonly=True) as conn:
                row = conn.execute("SELECT * FROM scans WHERE scan_type=? ORDER BY finished_us DESC LIMIT 1", (scan_type,)).fetchone()
            return row, scan_payload(row["details_json"], scan_type) if row else {}
        except sqlite3.Error:
            return None, {}

    def _clear_container(self, box: Gtk.Box) -> None:
        while child := box.get_first_child():
            box.remove(child)

    def _refresh_hardware(self) -> None:
        row, data = self._latest_scan("hardware")
        self._clear_container(self.hardware_content)
        if not row:
            self.hardware_status.set_title("No hardware scan has completed yet"); return
        self.hardware_status.set_title(f"{row['summary']} · {format_time(row['finished_us'])}")
        sensors = Adw.PreferencesGroup(title="Validated sensors")
        sensor_data = data.get("sensors", {})
        for name, value in sensor_data.items() if isinstance(sensor_data, dict) else []:
            reading = value.get("value", value) if isinstance(value, dict) else value
            sensors.add(action_row(str(name), f"{float(reading):.1f}°C", "weather-clear-symbolic"))
        if not sensor_data: sensors.add(action_row("No validated readings", "Install/configure lm-sensors or check the collector helper."))
        self.hardware_content.append(sensors)
        _smart_row, smart_data = self._latest_scan("smart")
        smart = Adw.PreferencesGroup(title="Drive health (SMART / NVMe)")
        smart_results = smart_data.get("results", []) if isinstance(smart_data, dict) else []
        for result in smart_results:
            device = str(result.get("device", "Storage device"))
            drive = result.get("data", {}) if isinstance(result.get("data", {}), dict) else {}
            passed = drive.get("smart_status", {}).get("passed")
            nvme = drive.get("nvme_smart_health_information_log", {})
            warning = int(nvme.get("critical_warning", 0) or 0)
            errors = int(nvme.get("media_errors", 0) or 0)
            used = int(nvme.get("percentage_used", 0) or 0)
            state = "Healthy" if passed is not False and not warning and not errors else "Needs immediate attention"
            detail = f"{state} · endurance used {used}% · media errors {errors} · critical warning {warning}"
            smart.add(action_row(device, detail, "drive-harddisk-symbolic" if state == "Healthy" else "dialog-error-symbolic"))
        if not smart_results:
            smart.add(action_row("Drive health unavailable", str(smart_data.get("error", "The privileged helper has not returned SMART data."))))
        self.hardware_content.append(smart)
        drives = Adw.PreferencesGroup(title="Storage devices")
        def add_devices(items: list[dict[str, Any]], depth: int = 0) -> None:
            for item in items:
                name = ("↳ " * depth) + str(item.get("model") or item.get("name") or item.get("path") or "Device")
                subtitle = " · ".join(str(v) for v in (item.get("size"), item.get("fstype"), ", ".join(item.get("mountpoints") or []), item.get("state")) if v)
                drives.add(action_row(name, subtitle, "drive-harddisk-symbolic"))
                add_devices(item.get("children") or [], depth + 1)
        add_devices(data.get("blockdevices") or [])
        self.hardware_content.append(drives)
        pci = Adw.PreferencesGroup(title="PCI devices and drivers")
        for item in (data.get("pci_devices") or [])[:100]:
            pci.add(action_row(str(item.get("description", "PCI device")), f"{item.get('slot', '')} · driver {item.get('driver') or 'not bound'}", "application-x-firmware-symbolic"))
        self.hardware_content.append(pci)
        usb = Adw.PreferencesGroup(title="USB topology")
        for item in data.get("usb_tree") or []:
            usb.add(action_row("  " * int(item.get("depth", 0)) + str(item.get("label", "USB node")), "", "usb-symbolic"))
        self.hardware_content.append(usb)
        dmi = data.get("dmi", {})
        if dmi:
            firmware = Adw.PreferencesGroup(title="Firmware / DMI")
            for key, value in dmi.items() if isinstance(dmi, dict) else []:
                if key not in ("raw", "output"):
                    firmware.add(action_row(str(key).replace("_", " ").title(), str(value)))
            self.hardware_content.append(firmware)
        self.hardware_content.append(advanced_raw(data.get("raw", data)))

    def _refresh_services(self) -> None:
        row, data = self._latest_scan("services")
        self._clear_container(self.services_content)
        group = Adw.PreferencesGroup(title=row["summary"] if row else "Service scan unavailable")
        units = data.get("units", []) if data else []
        for unit in units:
            scope, name = str(unit.get("scope", "system")), str(unit.get("unit", "unknown.service"))
            item = action_row(name, f"{scope} · {unit.get('description', '')}", "dialog-error-symbolic")
            logs = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="View recent logs")
            logs.connect("clicked", lambda _b, u=name, s=scope: self._service_logs(u, s))
            item.add_suffix(logs)
            if scope == "user":
                restart = Gtk.Button(label="Restart")
                restart.connect("clicked", lambda _b, u=name: self._confirm_service("restart", u))
                item.add_suffix(restart)
                reset = Gtk.Button(icon_name="edit-clear-all-symbolic", tooltip_text="Reset failed state")
                reset.connect("clicked", lambda _b, u=name: self._confirm_service("reset-failed", u))
                item.add_suffix(reset)
            else:
                guide = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copy system service guidance")
                guide.connect("clicked", lambda _b, u=name: self._copy_service_guidance(u))
                item.add_suffix(guide)
            group.add(item)
        if not units: group.add(action_row("No failed services", "Both system and user-session unit scans are clear.", "emblem-ok-symbolic"))
        self.services_content.append(group)
        self.services_content.append(advanced_raw(data.get("raw", data)))

    def _copy_service_guidance(self, unit: str) -> None:
        text = f"systemctl status {unit} --no-pager --full\njournalctl -u {unit} -n 500 --no-pager"
        Gdk.Display.get_default().get_clipboard().set(text); self.toast("System-service guidance copied")

    def _confirm_service(self, action: str, unit: str) -> None:
        try: argv = service_action_argv(action, unit, "user")
        except ValueError as exc: self.toast(str(exc)); return
        dialog = Adw.AlertDialog(heading=f"{action.replace('-', ' ').title()} {unit}?", body="The app will run exactly:\n\n" + " ".join(argv))
        dialog.add_response("cancel", "Cancel"); dialog.add_response("run", "Run command")
        dialog.set_default_response("cancel"); dialog.set_close_response("cancel")
        dialog.set_response_appearance("run", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda _d, response: self._run_service(argv) if response == "run" else None)
        dialog.present(self)

    def _run_service(self, argv: list[str]) -> None:
        future = self.executor.submit(subprocess.run, argv, capture_output=True, text=True, timeout=15, check=False)
        future.add_done_callback(lambda done: GLib.idle_add(self._service_done, done))

    def _service_done(self, future: concurrent.futures.Future[subprocess.CompletedProcess[str]]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            result = future.result(); self.toast("Command completed" if result.returncode == 0 else f"Command failed: {(result.stderr or result.stdout).strip()[:180]}")
        except Exception as exc: self.toast(f"Command failed: {exc}")
        self._refresh_services(); return GLib.SOURCE_REMOVE

    def _service_logs(self, unit: str, scope: str) -> None:
        try: argv = service_read_argv("logs", unit, scope)
        except ValueError as exc: self.toast(str(exc)); return
        future = self.executor.submit(run_command, argv, 20)
        future.add_done_callback(lambda done: GLib.idle_add(self._show_log_dialog, done, f"Logs · {unit}"))

    def _show_log_dialog(self, future: concurrent.futures.Future[str], title: str) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try: output = future.result()
        except Exception as exc: output = str(exc)
        self._present_text_dialog(title, output)
        return GLib.SOURCE_REMOVE

    def _present_text_dialog(self, title: str, output: str) -> None:
        dialog = Adw.Dialog(title=title, content_width=900, content_height=650)
        toolbar = Adw.ToolbarView(); toolbar.add_top_bar(Adw.HeaderBar())
        view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        view.get_buffer().set_text(output); toolbar.set_content(Gtk.ScrolledWindow(child=view)); dialog.set_child(toolbar); dialog.present(self)

    def _refresh_network(self) -> None:
        row, data = self._latest_scan("network")
        self._clear_container(self.network_content)
        interfaces = Adw.PreferencesGroup(title="Interfaces")
        addresses = {str(item.get("ifname")): item for item in data.get("addresses", [])}
        for item in data.get("links", []):
            name = str(item.get("ifname", "interface")); addr = addresses.get(name, {})
            ips = [str(info.get("local")) for info in addr.get("addr_info", []) if info.get("local")]
            stats = item.get("stats64") or item.get("stats") or {}
            errors = int((stats.get("rx") or {}).get("errors", 0)) + int((stats.get("tx") or {}).get("errors", 0))
            interfaces.add(action_row(name, f"{item.get('operstate', 'unknown')} · {', '.join(ips) or 'no address'} · {errors} errors", "network-wired-symbolic"))
        if not data.get("links"): interfaces.add(action_row("No interface data", "The network scan did not return structured link information."))
        self.network_content.append(interfaces)
        routes = Adw.PreferencesGroup(title="Routes")
        for item in data.get("routes", [])[:100]:
            routes.add(action_row(str(item.get("dst", "default")), " · ".join(str(v) for v in (item.get("gateway"), item.get("dev"), item.get("protocol")) if v), "go-jump-symbolic"))
        self.network_content.append(routes)
        listeners = Adw.PreferencesGroup(title="Listening sockets")
        for item in data.get("listeners", [])[:250]:
            listeners.add(action_row(str(item.get("local", "socket")), f"{item.get('protocol', '')} · {item.get('process') or 'process unavailable'}", "network-server-symbolic"))
        self.network_content.append(listeners)
        self.network_content.append(advanced_raw(data.get("raw", data)))

    def _refresh_crashes(self) -> None:
        row, data = self._latest_scan("crashes")
        self._clear_container(self.crashes_content)
        entries = [dict(item) for item in data.get("entries", []) if isinstance(item, dict)]
        self.latest_crash_entries = entries
        summary = Adw.PreferencesGroup(title=row["summary"] if row else "Crash scan unavailable")
        summary.add(action_row(
            "Crash inventory",
            f"{len(entries)} files · scanned {format_time(int(row['finished_us'])) if row else 'not yet'} · select Details on any entry",
            "face-sick-symbolic" if entries else "emblem-ok-symbolic",
        ))
        self.crashes_content.append(summary)

        kernel_entries = [item for item in entries if is_kernel_crash_artifact(item)]
        other_entries = [item for item in entries if not is_kernel_crash_artifact(item)]
        kernel = Adw.PreferencesGroup(
            title=f"Kernel crash dumps ({len(kernel_entries)})",
            description="Complete and incomplete memory dumps, captured kernel logs, and packaged KernelCrash reports.",
        )
        for item in kernel_entries[:300]:
            kernel.add(self._crash_artifact_row(item))
        if not kernel_entries:
            kernel.add(action_row("No kernel crash dumps found", "The most recent scan found no kernel dump artifacts.", "emblem-ok-symbolic"))
        self.crashes_content.append(kernel)

        other = Adw.PreferencesGroup(
            title=f"Application and supporting crash files ({len(other_entries)})",
            description="Application crash reports and kdump support files retained in crash storage.",
        )
        for item in other_entries[:300]:
            other.add(self._crash_artifact_row(item))
        if not other_entries:
            other.add(action_row("No other crash artifacts found", "No application crash reports were returned.", "emblem-ok-symbolic"))
        self.crashes_content.append(other)
        self.crashes_content.append(advanced_raw(data))

    def _refresh_updates(self) -> None:
        row, data = self._latest_scan("updates")
        self._clear_container(self.updates_content)
        packages = Adw.PreferencesGroup(title=row["summary"] if row else "Update scan unavailable", description="Review and install updates with your normal package manager.")
        for item in data.get("packages", [])[:500]:
            packages.add(action_row(str(item.get("name", "package")), f"{item.get('current_version', '?')} → {item.get('new_version', '?')} · {item.get('architecture', '')} · {item.get('repository', '')}", "software-update-available-symbolic"))
        if not data.get("packages"): packages.add(action_row("No package upgrades reported", "The most recent scan found no parsed package upgrades.", "emblem-ok-symbolic"))
        self.updates_content.append(packages)
        firmware = Adw.PreferencesGroup(title="Firmware updates")
        fw_data = data.get("firmware") or {}
        devices = fw_data.get("Devices", fw_data.get("devices", [])) if isinstance(fw_data, dict) else []
        for device in devices:
            releases = device.get("Releases", device.get("releases", []))
            firmware.add(action_row(str(device.get("Name") or device.get("name") or "Device firmware"), f"{len(releases)} release(s) available", "application-x-firmware-symbolic"))
        if not devices: firmware.add(action_row("No firmware update reported", "Open Advanced to inspect the original fwupd response."))
        self.updates_content.append(firmware); self.updates_content.append(advanced_raw(data.get("raw", data)))

    def _refresh_forensics(self) -> None:
        self._clear_container(self.forensics_content)
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute(
                    "SELECT c.*,i.summary,i.likely_cause,i.impact,i.remediation_json,i.source,i.unit_name "
                    "FROM forensic_cases c JOIN incidents i ON i.id=c.incident_id "
                    "ORDER BY c.occurred_us DESC LIMIT 200"
                ).fetchall()
        except sqlite3.Error as exc:
            self.forensics_banner.set_title(f"Forensic case database unavailable: {exc}")
            return
        self.forensics_banner.set_title(
            f"{len(rows)} retained forensic case(s) · evidence is retained for one year · exact hardware telemetry for seven days"
        )
        cases = Adw.PreferencesGroup(title="Restart, crash, and hardware fault investigations")
        for raw in rows:
            row = dict(raw)
            subtitle = (
                f"{row['severity']} · {format_time(int(row['occurred_us']))} · "
                f"telemetry window {format_time(int(row['window_start_us']))} — {format_time(int(row['window_end_us']))}"
            )
            item = action_row(str(row["title"]), subtitle, "dialog-error-symbolic")
            inspect = Gtk.Button(label="Inspect", valign=Gtk.Align.CENTER)
            record = {
                **row,
                "message": row.get("summary", ""),
                "last_boot_id": row.get("boot_id", "unknown"),
            }
            inspect.connect("clicked", lambda _button, record=record: self._open_incident(record))
            item.add_suffix(inspect)
            cases.add(item)
        if not rows:
            cases.add(action_row("No forensic cases retained", "Future hard resets, crashes, and significant hardware faults will be preserved here.", "emblem-ok-symbolic"))
        self.forensics_content.append(cases)

    def _refresh_boots(self) -> None:
        clear_list(self.boot_list)
        try:
            with open_v2(readonly=True) as conn:
                rows = conn.execute("SELECT boot_id,COUNT(*) evidence,COUNT(DISTINCT incident_id) incidents,MIN(occurred_us) first_us,MAX(occurred_us) last_us FROM evidence GROUP BY boot_id ORDER BY last_us DESC LIMIT 100").fetchall()
        except sqlite3.Error: rows = []
        for index, row in enumerate(rows):
            title = "Current boot" if index == 0 else f"Boot ending {format_time(row['last_us'])}"
            self.boot_list.append(action_row(title, f"{row['incidents']} incidents · {row['evidence']} evidence records · {format_time(row['first_us'])} — {format_time(row['last_us'])}", "document-open-recent-symbolic"))
        if not rows: self.boot_list.append(action_row("No indexed boots", "The collector has not indexed journal evidence yet."))

    def _load_raw(self) -> None:
        self.raw_request_id += 1
        request_id = self.raw_request_id
        source = self.raw_source_names[self.raw_source.get_selected()]
        since = ("-15 minutes", "-1 hour", "-24 hours")[self.raw_since.get_selected()]
        self.raw_status.set_text(f"Loading {source}…")
        self.raw_records = []
        self.raw_status_summary = ""
        self.raw_store.remove_all()
        future = self.executor.submit(self._query_raw_source, source, since)
        future.add_done_callback(lambda done: GLib.idle_add(self._raw_ready, done, request_id))

    @staticmethod
    def _query_raw_source(source: str, since: str) -> tuple[list[dict[str, Any]], str]:
        if source == "Current dmesg":
            response = helper_request("dmesg")
            output = str(response.get("output", ""))
            records = [{"occurred_us": 0, "priority": 6, "source": "kernel", "unit_name": "", "message": line, "raw": {"line": line}} for line in output.splitlines()]
            return records[-1000:], "Current root kernel buffer" if response.get("ok") else str(response.get("error", "dmesg unavailable"))
        protected = {"Authentication": "auth", "APT": "apt", "dpkg": "dpkg", "Xorg": "xorg"}
        if source in protected:
            response = helper_request("protected_log", source=protected[source], query="", lines=1000)
            lines = response.get("lines", []) if response.get("ok") else []
            records = [{"occurred_us": 0, "priority": 6, "source": source, "unit_name": "", "message": str(line), "raw": {"line": line}} for line in lines]
            return records, f"{len(records)} entries from {source}" if response.get("ok") else str(response.get("error", f"{source} unavailable"))
        argv = ["journalctl", "--no-pager", "--all", "-o", "json", "--since", since, "-n", "1000"]
        if source == "Kernel journal": argv.append("-k")
        elif source == "User journal": argv.append("--user")
        records = parse_journal_json_lines(run_command(argv, 25))
        return records, f"{len(records)} parsed entries from {source}"

    def _raw_ready(self, future: concurrent.futures.Future[tuple[list[dict[str, Any]], str]], request_id: int) -> bool:
        if self.closed or request_id != self.raw_request_id:
            return GLib.SOURCE_REMOVE
        try: records, status = future.result()
        except Exception as exc: self.raw_status.set_text(f"Unable to load logs: {exc}"); return GLib.SOURCE_REMOVE
        self.raw_records = [dict(item) for item in records]
        self.raw_status_summary = status
        self._render_raw_records()
        return GLib.SOURCE_REMOVE

    def _render_raw_records(self) -> None:
        search = self.raw_search.get_text().strip().lower()
        records = self.raw_records
        if search:
            records = [
                item for item in records
                if search in str(item.get("message", "")).lower()
                or search in str(item.get("source", "")).lower()
            ]
        self.raw_store.remove_all()
        for original in records:
            record = dict(original)
            record.update(severity={0: "Critical", 1: "Critical", 2: "Critical", 3: "Error", 4: "Warning"}.get(record["priority"], "Activity"), category="Journal", rule_id="generic")
            self.raw_store.append(RecordObject(record))
        if search:
            self.raw_status.set_text(f"{len(records)} matching entries · clear the filter to show all loaded messages")
        elif self.raw_status_summary:
            self.raw_status.set_text(f"{self.raw_status_summary} · select an entry for metadata and context")

    def _status_probe(self) -> tuple[bool, bool, bool, str]:
        collector = run_command(["systemctl", "--user", "is-active", "pc-diagnostics-collector.service"], 3).strip() == "active"
        helper = bool(helper_request("ping").get("ok"))
        try:
            with open_v2(readonly=True) as conn: conn.execute("SELECT 1 FROM incidents LIMIT 1").fetchone()
            return collector, helper, True, ""
        except sqlite3.Error as exc: return collector, helper, False, str(exc)

    def _refresh_status(self) -> None:
        future = self.executor.submit(self._status_probe)
        future.add_done_callback(lambda done: GLib.idle_add(self._status_ready, done))

    def _status_ready(self, future: concurrent.futures.Future[tuple[bool, bool, bool, str]]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try: collector, helper, database, message = future.result()
        except Exception as exc: collector, helper, database, message = False, False, False, str(exc)
        self.collector_row.set_title("Collector live" if collector else "Collector offline")
        self.collector_row.set_subtitle(f"Database {'ready' if database else 'unavailable'} · helper {'ready' if helper else 'limited'}")
        if collector and database:
            self.health_banner.set_title("Continuous monitoring is active" + (" · deep hardware access ready" if helper else " · privileged hardware checks limited"))
        else:
            self.health_banner.set_title(f"Monitoring needs attention · {message or 'collector is not active'}")
        return GLib.SOURCE_REMOVE

    def refresh_page(self, name: str) -> None:
        callbacks: dict[str, Callable[[], None]] = {
            "overview": lambda: (self._refresh_metrics(), self._refresh_overview_issues()),
            "forensics": self._refresh_forensics, "issues": self._refresh_incidents, "events": lambda: self._load_live(True),
            "performance": self._refresh_performance, "power": self._refresh_power, "hardware": self._refresh_hardware,
            "tuning": self._refresh_tuning,
            "services": self._refresh_services, "network": self._refresh_network,
            "crashes": self._refresh_crashes, "updates": self._refresh_updates,
            "boots": self._refresh_boots,
        }
        if callback := callbacks.get(name): callback()

    def refresh_all(self) -> None:
        self._refresh_status(); self.refresh_page(self.stack.get_visible_child_name() or "overview")

    def _poll(self) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            with open_v2(readonly=True) as conn: token = incident_change_token(conn)
        except sqlite3.Error: return GLib.SOURCE_CONTINUE
        if token != self.last_token:
            self.last_token = token
            visible = self.stack.get_visible_child_name() or "overview"
            if visible == "events" and not self.live_follow.get_active(): return GLib.SOURCE_CONTINUE
            if visible == "overview": self._refresh_overview_issues()
            elif visible == "forensics": self._refresh_forensics()
            elif visible == "issues": self._refresh_incidents()
            elif visible == "events": self._load_live(True)
        return GLib.SOURCE_CONTINUE

    def _metric_tick(self) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        visible = self.stack.get_visible_child_name() or "overview"
        if visible == "overview": self._refresh_metrics()
        elif visible == "performance": self._refresh_performance()
        elif visible == "power": self._refresh_power()
        return GLib.SOURCE_CONTINUE

    def _live_metric_tick(self) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        if (self.stack.get_visible_child_name() or "overview") == "overview":
            self._refresh_live_overview_metrics()
        return GLib.SOURCE_CONTINUE

    def _status_tick(self) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        self._refresh_status(); return GLib.SOURCE_CONTINUE

    def _export_report(self) -> None:
        future = self.executor.submit(self._make_report)
        future.add_done_callback(lambda done: GLib.idle_add(self._report_ready, done))

    def _make_report(self) -> Path:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = REPORT_DIR / f"pc-diagnostics-{stamp}-{time.time_ns() % 1_000_000_000:09d}-redacted.txt"
        with open_v2(readonly=True) as conn:
            incidents = conn.execute("SELECT * FROM incidents ORDER BY last_us DESC LIMIT 1000").fetchall()
            scans = conn.execute("SELECT s.* FROM scans s JOIN (SELECT scan_type,MAX(finished_us) latest FROM scans GROUP BY scan_type) x ON x.scan_type=s.scan_type AND x.latest=s.finished_us").fetchall()
        text = "PC DIAGNOSTICS REPORT\n\n" + "\n\n".join(f"{r['severity']} | {r['title']}\n{r['sample_message']}\nCause: {r['likely_cause']}\nImpact: {r['impact']}" for r in incidents)
        text += "\n\nLATEST SCANS\n" + "\n\n".join(f"{r['scan_type']}: {r['summary']}\n{r['details_json']}" for r in scans)
        write_private_text(path, redact(text)); return path

    def _report_ready(self, future: concurrent.futures.Future[Path]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try: self.toast(f"Redacted report saved to {future.result()}")
        except Exception as exc: self.toast(f"Report failed: {exc}")
        return GLib.SOURCE_REMOVE

    def _close(self, _window: Gtk.Window) -> bool:
        self.closed = True
        for source_id in self.timeout_ids:
            GLib.source_remove(source_id)
        self.timeout_ids.clear()
        self.executor.shutdown(wait=False, cancel_futures=True)
        if self.app.window is self:
            self.app.window = None
        return False


class DiagnosticsApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.window: DiagnosticsWindow | None = None
        self.css_loaded = False

    def do_activate(self) -> None:
        if not self.css_loaded:
            add_css()
            self.css_loaded = True
        with open_v2():
            pass
        if not self.window:
            self.window = DiagnosticsWindow(self)
        self.window.present()


def main() -> int:
    return DiagnosticsApplication().run(None)


if __name__ == "__main__":
    raise SystemExit(main())
