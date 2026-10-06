#!/usr/bin/env python3
"""Adaptive Libadwaita diagnostic dashboard for a systemd Linux workstation."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import math
import sqlite3
import subprocess
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

from pcdiag_common import (
    APP_ID, APP_NAME, DATA_DIR, DB_PATH, command_failed, ensure_private_directory,
    format_time, run_command, write_private_text,
)
from pcdiag_engine import (
    acknowledge_incident,
    clear_retained_data,
    helper_request,
    incident_change_token,
    live_hardware_metrics,
    live_overview_metrics,
    open_v2,
    record_tuning_audit,
    redact,
    resolve_incident_id,
    set_setting,
    setting_value,
    tuning_request,
)
from pcdiag_presenters import (
    EVENT_PAGE_SIZE,
    INCIDENT_PRIORITY_SQL,
    SEVERITY_ORDER,
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
.metric-reading { font-variant-numeric: tabular-nums; }
.metric-chart { min-width: 88px; }
.history-panel { min-width: 340px; }
.history-chart { padding: 8px 12px 10px; }
.content-column { min-width: 380px; }
.event-card { margin: 2px 6px; padding: 7px 9px; }
.inspector-panel { margin-left: 8px; padding: 12px; min-width: 310px; }
.resource-chart { padding: 4px; }
.sparkline { min-height: 32px; }
.compact-nav-row { padding: 3px 7px; }
.navigation-sidebar > row { min-height: 28px; padding: 0; }
.guide-card { margin: 6px 10px; padding: 10px 12px; }
.guide-icon { color: @accent_color; }
.nav-row.guide-current { box-shadow: inset 3px 0 @accent_color; }
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
APPEARANCES = ("system", "dark", "light")

# Ordered to match the sidebar. Only the current guide and tab create widgets.
PAGE_GUIDES = {
    "overview": (
        "Get a quick health check",
        "Start here to see how busy your PC is and which problems deserve a closer look. CPU is processing load; memory is working space; root storage is space used on your system drive.",
        "Check the monitoring banner, then look at Needs attention. Select an issue to read its explanation and supporting evidence.",
        "Collector offline? Current resource and supported sensor readings still update, but stored history needs the background collector. Empty history can mean collection has not started yet.",
    ),
    "performance": (
        "Find out when your PC gets busy",
        "Compare processor, memory, graphics, and storage-wait history when your PC feels slow. Storage I/O wait means time spent waiting for a drive.",
        "Choose 1, 6, or 24 hours in Range. Look for a sustained rise around the time you noticed a slowdown, then check Active issues for related evidence.",
        "A brief spike can be normal. These charts use saved collector samples, so a new installation needs time to build a history.",
    ),
    "power": (
        "Understand the readings your hardware exposes",
        "See recorded component power and named voltage readings. Power is measured in watts (W); voltage is measured in volts (V).",
        "Choose a time range and compare current, minimum, and maximum readings. Check the coverage rows to see which components actually provide a voltage sensor.",
        "GPU power is the graphics board’s draw, not your whole PC’s power use. A missing voltage reading usually means the hardware does not expose a named sensor.",
    ),
    "issues": (
        "Turn a warning into a useful next step",
        "Repeated evidence is grouped into incidents so you can investigate a problem without reading every log line. Severity helps you decide where to start.",
        "Use the filters or search, select an issue, and open its evidence. Read the diagnosis and confidence, then compare the timeline and nearby logs.",
        "Acknowledge means you have seen an issue. Mark resolved changes its tracking status; it does not repair your PC. A probable cause is a clue to verify.",
    ),
    "forensics": (
        "Investigate a crash or unexpected restart",
        "A forensic case keeps evidence and measurements around a serious event together, even after your PC has restarted.",
        "Find a case near the time of the problem and select Inspect to read its evidence. Use the listed telemetry window when comparing it with Performance history.",
        "An empty case list means no matching cases have been retained. Missing evidence or an uncertain diagnosis is not proof that nothing happened.",
    ),
    "events": (
        "Watch what happens as a problem occurs",
        "Live events shows collected evidence in time order. Repeated messages are grouped to make a busy feed easier to follow.",
        "Leave Follow on while observing a problem, or turn it off to read at your own pace. Search or filter the feed, then select an event for more context.",
        "Load older events moves back through retained evidence. Notice and Activity entries can describe ordinary system behavior, not faults.",
    ),
    "raw": (
        "Read the original messages",
        "Raw logs gives you the source messages behind a diagnosis. Use this when you need exact wording or more detail about a specific time.",
        "Choose a log source and time window, then select Load logs. Filter the loaded messages and select an entry to inspect its metadata and context.",
        "Each load is limited to 1,000 entries, and the filter searches only those entries. Some sources need the optional read-only helper or additional access.",
    ),
    "crashes": (
        "See what a crash left behind",
        "Crash history lists collected crash-file metadata, including size, time, and whether a dump appears incomplete. A dump is a saved record of a crash.",
        "Open an artifact’s details to check its time and size. Where available, preview its captured log or open its containing folder for further investigation.",
        "The app does not delete system crash files. An incomplete dump may contain only part of the evidence needed to explain a crash.",
    ),
    "boots": (
        "Put problems in the right restart session",
        "Boot history groups retained incidents by system startup. This helps distinguish a current problem from something that happened before a restart.",
        "Find the relevant boot by its time and note its incident count. Use Active issues or Forensic cases to investigate problems from that time.",
        "This is an index of retained diagnostic evidence. A boot without collected evidence may not appear here.",
    ),
    "hardware": (
        "Check temperatures, drives, and devices",
        "Hardware brings together sensors, drive-health checks, connected devices, and firmware information. SMART is a drive’s built-in health reporting.",
        "Check the scan time, then review temperatures and Drive health. If something is unavailable, read the explanation before treating it as a hardware failure.",
        "Some checks need the optional read-only helper or sensor tools. Unavailable means the app could not obtain a reliable reading; it does not mean healthy or broken.",
    ),
    "services": (
        "Understand a failed background service",
        "Services shows failed background jobs from the system and your login session. A service is a program that runs in the background.",
        "Open the failed service’s logs first. For a user-session service, review the confirmation before restarting it or clearing its failed state. System services offer guidance to copy.",
        "Clearing a failed state resets the service’s status, not its underlying cause. The tour does not restart services or run repair commands.",
    ),
    "network": (
        "See how your PC is connected",
        "Review network adapters, their addresses, routes, and listening sockets. A route is a path for traffic; a listening socket belongs to a program waiting for connections.",
        "Find your active adapter and check its state, address, and error count. If you are investigating connectivity, compare this with Network incidents in Active issues.",
        "A listening port is not automatically a security problem. These are collected snapshots, so check the scan time when comparing them with a current problem.",
    ),
    "updates": (
        "Review available software and firmware updates",
        "Updates summarizes what the latest package and device-firmware checks found. Firmware is software built into a hardware device.",
        "Review the available updates and scan results. Use your system’s software updater or firmware tool when you decide to install an update.",
        "PC Diagnostics lists updates but does not install them. A missing or failed scan is different from a successful check that found no updates.",
    ),
    "tuning": (
        "Explore optional controls at your own pace",
        "Safe tuning offers temporary CPU policy and supported GPU power-limit controls within hardware-reported bounds. You can use every monitoring page without changing these.",
        "Read the availability banner and current limits. If you later choose to tune, review the confirmation and use Restore saved baseline to return to the saved settings.",
        "Applying changes requires the separate tuning helper and an active collector for thermal rollback. Simply visiting this tab or advancing the tour changes no hardware settings.",
    ),
    "settings": (
        "Make the app yours and manage its data",
        "Choose an appearance, locate your local database and report folder, and see how much disk space the app’s history and generated files use.",
        "Try the color scheme you prefer and review the storage totals. To share findings, use Export redacted report in the header; Settings lets you choose its folder.",
        "Cleanup requires confirmation and removes only the selected app-owned data. You can reopen this tour from Guide in the header or Guided tour in Settings.",
    ),
}


def apply_appearance(value: str) -> str:
    """Apply the requested color scheme and return the normalized value."""
    scheme = {
        "dark": Adw.ColorScheme.FORCE_DARK,
        "light": Adw.ColorScheme.FORCE_LIGHT,
        "system": Adw.ColorScheme.DEFAULT,
    }.get(value, Adw.ColorScheme.DEFAULT)
    Adw.StyleManager.get_default().set_color_scheme(scheme)
    return value if value in APPEARANCES else "system"


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


def configure_logging() -> logging.Logger:
    """Keep a small local activity log without recording diagnostic payloads."""
    ensure_private_directory(DATA_DIR)
    logger = logging.getLogger("pcdiag.ui")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(DATA_DIR / "pc-diagnostics.log", maxBytes=512 * 1024, backupCount=3)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger


def label(text: str = "", css: str | None = None, wrap: bool = False) -> Gtk.Label:
    widget = Gtk.Label(label=text, xalign=0)
    widget.set_wrap(wrap)
    if wrap:
        widget.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        widget.add_css_class({
            "dim": "dim-label", "page-title": "title-2", "section-title": "heading",
            "metric-value": "heading", "inspector-title": "title-3",
            "sidebar-caption": "caption-heading", "guide-eyebrow": "caption-heading",
            "guide-title": "title-3", "guide-welcome-title": "title-1",
        }.get(css, css))
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
    row.set_title_lines(2)
    row.set_subtitle_lines(2)
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


def page_shell(
    title: str,
    subtitle: str,
    *,
    show_title: bool = False,
    scroll: bool = True,
    maximum_size: int = 1400,
) -> tuple[Gtk.Widget, Gtk.Box]:
    """Create a compact adaptive page while keeping long content scrollable."""
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    body.set_margin_top(16)
    body.set_margin_bottom(18)
    body.set_margin_start(18)
    body.set_margin_end(18)
    if show_title:
        body.append(label(title, "page-title", True))
    if subtitle:
        body.append(label(subtitle, "dim", True))
    content: Gtk.Widget = Adw.Clamp(maximum_size=maximum_size, tightening_threshold=900, child=body)
    if not scroll:
        content.set_vexpand(True)
        return content, body
    return Gtk.ScrolledWindow(child=content), body


def responsive_flow(maximum: int = 2) -> Gtk.FlowBox:
    flow = Gtk.FlowBox(
        selection_mode=Gtk.SelectionMode.NONE,
        homogeneous=True,
        min_children_per_line=1,
        max_children_per_line=maximum,
        column_spacing=12,
        row_spacing=12,
    )
    return flow


def history_panel(title: str, icon: str | None = None) -> tuple[Gtk.ListBox, Adw.ActionRow, Sparkline]:
    panel = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
    panel.add_css_class("boxed-list")
    panel.add_css_class("history-panel")
    row = action_row(title, "Waiting for samples", icon)
    chart = Sparkline(72)
    chart.add_css_class("history-chart")
    chart_row = Gtk.ListBoxRow(selectable=False, activatable=False, child=chart)
    panel.append(row)
    panel.append(chart_row)
    return panel, row, chart


class RecordObject(GObject.Object):
    def __init__(self, record: dict[str, Any]):
        super().__init__()
        self.record = record


class DetailFeedRow(Adw.ActionRow):
    def __init__(self) -> None:
        super().__init__()
        self.set_use_markup(False)
        self.set_title_lines(2)
        self.set_subtitle_lines(2)
        self.icon = Gtk.Image()
        self.add_prefix(self.icon)

    def set_record(self, record: dict[str, Any]) -> None:
        self.set_title(str(record.get("_title", "Unknown item")))
        self.set_subtitle(str(record.get("_subtitle", "")))
        icon = str(record.get("_icon", ""))
        self.icon.set_visible(bool(icon))
        if icon:
            self.icon.set_from_icon_name(icon)


def detail_list(
    records: list[dict[str, Any]],
    *,
    activated: Callable[[dict[str, Any]], None] | None = None,
    maximum_height: int = 320,
) -> Gtk.ScrolledWindow:
    """Show large inventories with only visible rows constructed."""
    store = Gio.ListStore.new(RecordObject)
    for record in records:
        store.append(RecordObject(record))
    factory = Gtk.SignalListItemFactory()
    factory.connect("setup", lambda _factory, item: item.set_child(DetailFeedRow()))
    factory.connect("bind", lambda _factory, item: item.get_child().set_record(item.get_item().record))
    model: Gio.ListModel
    if activated:
        selection = Gtk.SingleSelection(model=store, autoselect=False, can_unselect=True)
        model = selection
    else:
        model = Gtk.NoSelection(model=store)
    view = Gtk.ListView(model=model, factory=factory, single_click_activate=bool(activated))
    view.add_css_class("boxed-list")
    if activated:
        view.connect("activate", lambda _view, position: activated(store.get_item(position).record))
    visible_rows = max(1, min(6, len(records)))
    return Gtk.ScrolledWindow(
        child=view,
        min_content_height=visible_rows * 52,
        max_content_height=maximum_height,
        propagate_natural_height=True,
    )


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
        self.meta.set_ellipsize(Pango.EllipsizeMode.END)
        self.meta.set_single_line_mode(True)
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


class Sparkline(Gtk.DrawingArea):
    def __init__(self, height: int = 52, slots: int = 48):
        super().__init__()
        self.values: list[float] = []
        self.slots = slots
        self.set_size_request(-1, height)
        self.set_hexpand(True)
        self.add_css_class("sparkline")
        self.set_draw_func(self._draw)

    def set_values(self, values: list[float]) -> None:
        if len(values) > self.slots:
            step = len(values) / self.slots
            values = [values[min(len(values) - 1, math.floor(index * step))] for index in range(self.slots)]
        self.values = [float(value) for value in values[-self.slots:]]
        self.queue_draw()

    def _draw(self, _area: Gtk.DrawingArea, cr: Any, width: int, height: int) -> None:
        if len(self.values) < 2:
            return
        minimum, maximum = min(self.values), max(self.values)
        span = max(1.0, maximum - minimum)
        _found, accent = self.get_style_context().lookup_color("accent_color")
        cr.set_source_rgba(accent.red, accent.green, accent.blue, accent.alpha)
        cr.set_line_width(2)
        for index, value in enumerate(self.values):
            x = 1 + index * (width - 2) / max(1, len(self.values) - 1)
            y = height - 2 - (value - minimum) / span * max(1, height - 4)
            if index:
                cr.line_to(x, y)
            else:
                cr.move_to(x, y)
        cr.stroke()


class MetricRow(Adw.ActionRow):
    def __init__(self, title: str, icon: str):
        super().__init__(title=title, subtitle="Waiting for data")
        self.set_activatable(False)
        self.set_title_lines(1)
        self.set_subtitle_lines(2)
        self.add_prefix(Gtk.Image.new_from_icon_name(icon))
        trailing = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.value = label("Unavailable", "metric-value")
        self.value.add_css_class("metric-reading")
        self.value.add_css_class("dim-label")
        self.value.set_width_chars(11)
        self.value.set_xalign(1)
        trailing.append(self.value)
        self.chart = Sparkline(30, 24)
        self.chart.add_css_class("metric-chart")
        self.chart.set_hexpand(False)
        self.chart.set_visible(False)
        trailing.append(self.chart)
        self.add_suffix(trailing)

    def update(self, value: float | None, suffix: str, note: str, history: list[float], decimals: int = 0) -> None:
        self.update_live(value, suffix, note, decimals)
        self.chart.set_values(history)
        self.chart.set_visible(len(history) >= 2)

    def update_live(self, value: float | None, suffix: str, note: str, decimals: int = 0) -> None:
        if value is None:
            self.value.set_text("Unavailable")
            self.value.add_css_class("dim-label")
        else:
            self.value.set_text(f"{value:.{decimals}f}{suffix}")
            self.value.remove_css_class("dim-label")
        self.set_subtitle(note)
        self.set_tooltip_text(note)


def incident_column(title: str, value: Callable[[dict[str, Any]], str], *, expand: bool = False) -> Gtk.ColumnViewColumn:
    """Create one lightweight, virtualized incident-table column."""
    factory = Gtk.SignalListItemFactory()

    def setup(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        cell = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END, single_line_mode=True)
        cell.set_margin_start(8)
        cell.set_margin_end(8)
        item.set_child(cell)

    def bind(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        record = item.get_item().record
        item.get_child().set_text(value(record))

    factory.connect("setup", setup)
    factory.connect("bind", bind)
    column = Gtk.ColumnViewColumn.new(title, factory)
    column.set_expand(expand)
    return column


ISSUE_SORTS = ("Risk & recency", "Newest first", "Severity", "Most events", "Title")


def issue_sorter(index: int) -> Gtk.CustomSorter:
    """Sort incident records using their real numeric severity and time values."""
    def key(record: dict[str, Any]) -> tuple[Any, ...]:
        severity = SEVERITY_ORDER.get(str(record.get("severity", "Activity")), 0)
        stamp = int(record.get("last_us", 0) or 0)
        occurrences = int(record.get("occurrences", 0) or 0)
        if index == 1:
            return (stamp,)
        if index == 2:
            return (severity, stamp)
        if index == 3:
            return (occurrences, stamp)
        if index == 4:
            return (str(record.get("title", "")).casefold(),)
        return (int(is_top_critical(record)), severity, stamp)

    descending = index != 4

    def compare(left: RecordObject, right: RecordObject, _data: Any = None) -> Gtk.Ordering:
        first, second = key(left.record), key(right.record)
        if first == second:
            return Gtk.Ordering.EQUAL
        before = first > second if descending else first < second
        return Gtk.Ordering.SMALLER if before else Gtk.Ordering.LARGER

    return Gtk.CustomSorter.new(compare)


class IncidentInspector(Gtk.Box):
    """Fast side summary; the existing dialog remains the full evidence viewer."""
    def __init__(self, owner: "DiagnosticsWindow"):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.owner = owner
        self.record: dict[str, Any] | None = None
        self.add_css_class("inspector-panel")
        self.add_css_class("card")
        self.title = label("Select an incident", "inspector-title", True)
        self.meta = label("Its diagnosis and safe local actions appear here.", "dim", True)
        self.cause = label("", None, True)
        self.impact = label("", "dim", True)
        self.append(self.title)
        self.append(self.meta)
        self.append(label("Probable cause", "section-title"))
        self.append(self.cause)
        self.append(self.impact)
        self.actions = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.open_button = Gtk.Button(label="Open evidence")
        self.acknowledge_button = Gtk.Button(label="Acknowledge")
        self.resolve_button = Gtk.Button(label="Mark resolved")
        self.open_button.connect("clicked", lambda _button: self._open())
        self.acknowledge_button.connect("clicked", lambda _button: self._acknowledge())
        self.resolve_button.connect("clicked", lambda _button: self._resolve())
        for button in (self.open_button, self.acknowledge_button, self.resolve_button):
            button.set_sensitive(False)
            self.actions.append(button)
        self.append(self.actions)

    def set_record(self, record: dict[str, Any] | None) -> None:
        self.record = dict(record) if record else None
        if not self.record:
            self.title.set_text("Select an incident")
            self.meta.set_text("Its diagnosis and safe local actions appear here.")
            self.cause.set_text("")
            self.impact.set_text("")
            for button in (self.open_button, self.acknowledge_button, self.resolve_button):
                button.set_sensitive(False)
            return
        diagnosis = diagnosis_for(self.record)
        self.title.set_text(str(self.record.get("title", "Unknown issue")))
        self.meta.set_text(
            f"{self.record.get('severity', 'Activity')} · {self.record.get('category', 'System')} · "
            f"{self.record.get('occurrences', 1)} event(s) · last seen {format_time(int(self.record.get('last_us', 0)))}"
        )
        self.cause.set_text(diagnosis["cause"])
        self.impact.set_text(diagnosis["impact"])
        open_state = str(self.record.get("status", "open")) == "open"
        self.open_button.set_sensitive(True)
        self.acknowledge_button.set_sensitive(open_state)
        self.resolve_button.set_sensitive(open_state)
        self.acknowledge_button.set_label("Unacknowledge" if self.record.get("acknowledged") else "Acknowledge")

    def _open(self) -> None:
        if self.record:
            self.owner._open_incident(dict(self.record))

    def _acknowledge(self) -> None:
        if self.record:
            incident_id = int(self.record.get("id") or self.record.get("incident_id") or 0)
            self.owner._set_incident_acknowledged(incident_id, not bool(self.record.get("acknowledged")))

    def _resolve(self) -> None:
        if self.record:
            incident_id = int(self.record.get("id") or self.record.get("incident_id") or 0)
            self.owner._resolve_incident(incident_id)


class EventInspector(Adw.Dialog):
    def __init__(self, owner: "DiagnosticsWindow", record: dict[str, Any]):
        super().__init__(title="Event details", content_width=780, content_height=640)
        self.owner = owner
        self.record = record
        self.timeline_cursor: tuple[int, int] | None = None
        self.timeline_request_id = 0
        self.context_request_id = 0
        self.timeline_store = Gio.ListStore.new(RecordObject)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=stack, policy=Adw.ViewSwitcherPolicy.NARROW)
        toolbar.add_top_bar(switcher)
        toolbar.set_content(stack)
        self.set_child(toolbar)
        stack.add_titled_with_icon(self._diagnosis_page(), "diagnosis", "Diagnosis", "medical-symbolic")
        stack.add_titled_with_icon(self._timeline_page(), "timeline", "Timeline", "view-list-symbolic")
        stack.add_titled_with_icon(self._context_page(), "context", "Nearby logs", "system-search-symbolic")
        stack.add_titled_with_icon(self._technical_page(), "technical", "Technical", "applications-engineering-symbolic")
        self.inspector_loaded: set[str] = {"diagnosis"}
        stack.connect("notify::visible-child-name", self._inspector_page_changed)

    def _inspector_page_changed(self, stack: Adw.ViewStack, _pspec: GObject.ParamSpec) -> None:
        name = stack.get_visible_child_name()
        if name in self.inspector_loaded:
            return
        self.inspector_loaded.add(name)
        if name == "timeline":
            self._load_timeline(reset=True)
        elif name == "context":
            self._load_context()

    def _diagnosis_page(self) -> Gtk.Widget:
        page, body = page_shell(
            str(self.record.get("title", "Event diagnosis")),
            str(self.record.get("message", "")),
            show_title=True,
            maximum_size=900,
        )
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
        incident_id = int(self.record.get("incident_id") or self.record.get("id") or 0)
        if incident_id and str(self.record.get("status", "open")) == "open":
            actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            acknowledge = Gtk.Button(label="Unacknowledge" if self.record.get("acknowledged") else "Acknowledge")
            acknowledge.connect("clicked", lambda _button: self._incident_action("acknowledge"))
            resolve = Gtk.Button(label="Mark resolved")
            resolve.connect("clicked", lambda _button: self._incident_action("resolve"))
            actions.append(acknowledge)
            actions.append(resolve)
            body.append(actions)
        return page

    def _copy_diagnosis(self, _button: Gtk.Button) -> None:
        data = diagnosis_for(self.record)
        text = f"{data['title']}\nConfidence: {data['confidence']} — {data['basis']}\nCause: {data['cause']}\nImpact: {data['impact']}\n"
        if data["steps"]:
            text += "Checks:\n" + "\n".join(f"{i}. {step}" for i, step in enumerate(data["steps"], 1))
        Gdk.Display.get_default().get_clipboard().set(text)
        self.owner.toast("Diagnosis copied")

    def _incident_action(self, action: str) -> None:
        incident_id = int(self.record.get("incident_id") or self.record.get("id") or 0)
        if not incident_id:
            return
        if action == "resolve":
            self.owner._resolve_incident(incident_id)
        else:
            acknowledged = not bool(self.record.get("acknowledged"))
            self.owner._set_incident_acknowledged(incident_id, acknowledged)
            self.record["acknowledged"] = acknowledged

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
        # A timeline activation selects a different evidence record. Reopen a
        # fresh inspector so every page, not merely the stored record, reflects
        # that selection.
        self.close()
        EventInspector(self.owner, {**self.record, **record}).present(self.owner)

    def _load_timeline(self, reset: bool = False) -> None:
        if reset:
            self.timeline_store.remove_all()
            self.timeline_cursor = None
        self.timeline_request_id += 1
        request_id = self.timeline_request_id
        try:
            incident_id = int(self.record["incident_id"])
        except (KeyError, TypeError, ValueError):
            self.timeline_more.set_sensitive(False)
            self.timeline_more.set_label("No timeline available")
            return
        cursor = self.timeline_cursor
        future = self.owner.executor.submit(self._query_timeline, incident_id, cursor)
        future.add_done_callback(lambda done: GLib.idle_add(self._timeline_ready, done, request_id))

    @staticmethod
    def _query_timeline(incident_id: int, cursor: tuple[int, int] | None) -> list[dict[str, Any]]:
        with open_v2(readonly=True) as conn:
            return fetch_incident_evidence(conn, incident_id, before=cursor)

    def _timeline_ready(self, future: concurrent.futures.Future[list[dict[str, Any]]], request_id: int) -> bool:
        if self.owner.closed or request_id != self.timeline_request_id:
            return GLib.SOURCE_REMOVE
        try:
            rows = future.result()
        except sqlite3.Error:
            rows = []
        for row in rows:
            combined = {**self.record, **row, "count": 1}
            self.timeline_store.append(RecordObject(combined))
        if rows:
            last = rows[-1]
            self.timeline_cursor = (int(last["occurred_us"]), int(last["id"]))
        self.timeline_more.set_sensitive(len(rows) == 250)
        self.timeline_more.set_label("Load 250 older events" if rows else "No older events")
        return GLib.SOURCE_REMOVE

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
            output = future.result()
            if command_failed(output):
                raise OSError(output)
            records = parse_journal_json_lines(output)
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
        page, body = page_shell(
            "Technical metadata",
            "Exact identifiers retained for troubleshooting and correlation.",
            show_title=True,
            maximum_size=900,
        )
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
        super().__init__(application=app, title=APP_NAME, default_width=1280, default_height=760)
        self.app = app
        self.logger = configure_logging()
        self.closed = False
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="pcdiag-ui")
        self.timeout_ids: list[int] = []
        self.last_token: tuple[int, ...] | None = None
        self.live_cursor: tuple[int, int] | None = None
        self.live_raw: list[dict[str, Any]] = []
        self.metric_cards: dict[str, MetricRow] = {}
        self.live_metric_cpu_state: tuple[int, int, int] | None = None
        self.live_overview_values: dict[str, float] = {}
        self.collector_active = False
        self.nav_rows: dict[Gtk.ListBoxRow, str] = {}
        self.page_titles: dict[str, str] = {}
        self.syncing_navigation = False
        self.tuning_state: dict[str, Any] = {}
        self.tuning_gpu_options: list[dict[str, Any]] = []
        self.tuning_refresh_inflight = False
        self.raw_records: list[dict[str, Any]] = []
        self.raw_status_summary = ""
        self.raw_request_id = 0
        self.overview_history: dict[str, list[float]] = {}
        self.report_dir = self._default_report_dir()
        self.page_builders: dict[str, Callable[[], Gtk.Widget]] = {}
        self.built_pages: set[str] = set()
        self.storage_request_id = 0
        self.guide_page = "overview"
        self.guide_visible = False
        self.syncing_guide = False
        self.tour_transitioning = False
        self.tutorial_dialog: Adw.Dialog | None = None
        self._build_shell()
        self.style_manager = Adw.StyleManager.get_default()
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
        self._check_tutorial()
        self.logger.info("window opened")

    def _build_shell(self) -> None:
        self.toast_overlay = Adw.ToastOverlay()
        self.split = Adw.NavigationSplitView()
        self.split.set_min_sidebar_width(210)
        self.split.set_max_sidebar_width(260)
        self.split.set_sidebar_width_fraction(0.18)
        self.toast_overlay.set_child(self.split)
        self.set_content(self.toast_overlay)

        sidebar_toolbar = Adw.ToolbarView()
        side_header = Adw.HeaderBar()
        side_header.set_title_widget(Adw.WindowTitle(title="PC Diagnostics", subtitle="Local system health"))
        sidebar_toolbar.add_top_bar(side_header)
        side_scroll = Gtk.ScrolledWindow()
        side_scroll.add_css_class("task-sidebar")
        side_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        side_box.set_margin_top(6)
        side_box.set_margin_bottom(6)
        side_box.set_margin_start(6)
        side_box.set_margin_end(6)
        self.nav_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, activate_on_single_click=True)
        self.nav_list.add_css_class("navigation-sidebar")
        self.nav_list.connect("row-selected", self._nav_selected)
        side_box.append(self.nav_list)
        self.collector_row = action_row("Collector", "Checking…", "network-transmit-receive-symbolic")
        collector_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        collector_list.add_css_class("boxed-list")
        collector_list.append(self.collector_row)
        side_box.append(collector_list)
        side_scroll.set_child(side_box)
        sidebar_toolbar.set_content(side_scroll)
        self.split.set_sidebar(Adw.NavigationPage.new(sidebar_toolbar, "Sections"))

        content_toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self.header_title = Adw.WindowTitle(title="Overview", subtitle="Live local diagnostics")
        header.set_title_widget(self.header_title)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh visible information")
        refresh.connect("clicked", lambda _b: self.refresh_all())
        header.pack_end(refresh)
        export = Gtk.Button(icon_name="document-save-symbolic", tooltip_text="Export redacted report")
        export.connect("clicked", lambda _b: self._export_report())
        header.pack_end(export)
        guide_menu = Gio.Menu()
        for name, title, callback in (
            ("page-guide", "Help for this tab", lambda: self._start_tour(self.stack.get_visible_child_name() or "overview")),
            ("welcome", "Welcome & guided tour", self._show_tutorial),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda _action, _parameter, run=callback: run())
            self.add_action(action)
            guide_menu.append(title, f"win.{name}")
        self.guide_button = Gtk.MenuButton(label="Guide", menu_model=guide_menu, tooltip_text="Tab help and guided tour (F1 for this tab)")
        header.pack_end(self.guide_button)
        self.app.set_accels_for_action("win.page-guide", ["F1"])
        content_toolbar.add_top_bar(header)
        self.stack = Adw.ViewStack()
        self.stack.set_vexpand(True)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.guide_revealer = Gtk.Revealer(transition_type=Gtk.RevealerTransitionType.SLIDE_DOWN)
        content.append(self.guide_revealer)
        content.append(self.stack)
        content_toolbar.set_content(content)
        self.split.set_content(Adw.NavigationPage.new(content_toolbar, "Diagnostics"))
        self.compact_navigation_breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 900px"))
        self.compact_navigation_breakpoint.add_setter(self.split, "collapsed", True)
        self.add_breakpoint(self.compact_navigation_breakpoint)

    def _add_nav(self, group: str, entries: list[tuple[str, str, str]]) -> None:
        header = Gtk.ListBoxRow(selectable=False, activatable=False)
        text = label(group, "sidebar-caption")
        text.set_margin_top(4)
        text.set_margin_bottom(0)
        text.set_margin_start(9)
        header.set_child(text)
        self.nav_list.append(header)
        for name, title, icon in entries:
            row = Gtk.ListBoxRow()
            row.add_css_class("nav-row")
            content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            content.add_css_class("compact-nav-row")
            content.append(Gtk.Image.new_from_icon_name(icon))
            text = label(title)
            text.set_ellipsize(Pango.EllipsizeMode.END)
            text.set_hexpand(True)
            content.append(text)
            row.set_child(content)
            self.nav_rows[row] = name
            self.page_titles[name] = title
            self.nav_list.append(row)

    def _build_pages(self) -> None:
        self._add_nav("Monitor", [
            ("overview", "Overview", "computer-symbolic"),
            ("performance", "Performance", "speedometer-symbolic"),
            ("power", "Power & voltage", "battery-good-symbolic"),
        ])
        self._add_nav("Investigate", [
            ("issues", "Active issues", "dialog-warning-symbolic"),
            ("forensics", "Forensic cases", "folder-documents-symbolic"),
            ("events", "Live events", "view-list-symbolic"),
            ("raw", "Raw logs", "utilities-terminal-symbolic"),
            ("crashes", "Crash history", "face-sick-symbolic"),
            ("boots", "Boot history", "document-open-recent-symbolic"),
        ])
        self._add_nav("System", [
            ("hardware", "Hardware", "applications-engineering-symbolic"),
            ("services", "Services", "system-run-symbolic"),
            ("network", "Network & security", "network-workgroup-symbolic"),
            ("updates", "Updates", "software-update-available-symbolic"),
        ])
        self._add_nav("Controls", [
            ("tuning", "Safe tuning", "preferences-system-symbolic"),
            ("settings", "Settings", "emblem-system-symbolic"),
        ])
        self.page_builders = {
            "overview": self._overview_page, "issues": self._issues_page,
            "events": self._events_page, "performance": self._performance_page,
            "power": self._power_page,
            "tuning": self._tuning_page,
            "forensics": self._forensics_page,
            "hardware": self._hardware_page, "services": self._services_page,
            "network": self._network_page, "crashes": self._crashes_page,
            "updates": self._updates_page, "boots": self._boots_page, "raw": self._raw_page,
            "settings": self._settings_page,
        }

    def _ensure_page(self, name: str) -> bool:
        if name in self.built_pages:
            return True
        builder = self.page_builders.get(name)
        if not builder:
            return False
        self.stack.add_named(builder(), name)
        self.built_pages.add(name)
        return True

    def _nav_selected(self, _box: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if not self.syncing_navigation and row is not None and (name := self.nav_rows.get(row)):
            self.navigate(name)

    def navigate(self, name: str) -> None:
        if not self._ensure_page(name):
            return
        self.stack.set_visible_child_name(name)
        self.header_title.set_title(self.page_titles.get(name, APP_NAME))
        row = next((candidate for candidate, route in self.nav_rows.items() if route == name), None)
        if row is not None and self.nav_list.get_selected_row() is not row:
            self.syncing_navigation = True
            self.nav_list.select_row(row)
            self.syncing_navigation = False
        if self.split.get_collapsed():
            self.split.set_show_content(True)
        if self.guide_visible:
            self._update_guide(name)
        self.refresh_page(name)

    def toast(self, message: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast(title=message, timeout=4))

    def _adaptive_pair(self, first: Gtk.Widget, second: Gtk.Widget) -> Gtk.Box:
        pair = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, homogeneous=True)
        first.set_hexpand(True)
        second.set_hexpand(True)
        pair.append(first)
        pair.append(second)
        breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 1100px"))
        breakpoint.add_setter(pair, "orientation", Gtk.Orientation.VERTICAL)
        self.add_breakpoint(breakpoint)
        return pair

    def _overview_page(self) -> Gtk.Widget:
        page, body = page_shell(
            "System overview",
            "Live resource use, retained telemetry, and the issues that need attention.",
            maximum_size=1600,
        )
        self.health_banner = Adw.Banner(title="Checking collector and database…")
        self.health_banner.set_revealed(True)
        body.append(self.health_banner)
        welcome = action_row("Understand your PC, one step at a time", "Learn what each tab shows and where to start investigating.", "help-browser-symbolic")
        guide = Gtk.Button(label="Open guide", valign=Gtk.Align.CENTER)
        guide.connect("clicked", lambda _button: self._show_tutorial())
        welcome.add_suffix(guide)
        welcome_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        welcome_list.add_css_class("boxed-list")
        welcome_list.append(welcome)
        body.append(welcome_list)

        metrics = Adw.PreferencesGroup(
            title="Current status",
            description="Current readings with one-hour trends when retained samples are available.",
        )
        left_metrics = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        right_metrics = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        left_metrics.add_css_class("boxed-list")
        right_metrics.add_css_class("boxed-list")
        for key, title, icon in (
            ("cpu", "CPU", "speedometer-symbolic"), ("memory", "Memory", "view-grid-symbolic"),
            ("disk", "Storage", "drive-harddisk-symbolic"), ("issues", "Issues", "dialog-error-symbolic"),
            ("temperature", "CPU temperature", "weather-clear-symbolic"),
            ("gpu_temperature", "GPU temperature", "weather-clear-symbolic"),
            ("gpu", "GPU utilization", "video-display-symbolic"),
            ("power", "GPU power", "battery-good-symbolic"),
        ):
            row = MetricRow(title, icon)
            self.metric_cards[key] = row
            (left_metrics if key in {"cpu", "memory", "disk", "issues"} else right_metrics).append(row)
        metrics.add(self._adaptive_pair(left_metrics, right_metrics))
        body.append(metrics)

        history = Adw.PreferencesGroup(
            title="Resource history",
            description="Retained samples from the last hour.",
        )
        history.add_css_class("content-column")
        history_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        history_list.add_css_class("boxed-list")
        chart_control = action_row("Metric", "Choose the resource shown below")
        self.overview_chart_metric = Gtk.DropDown.new_from_strings(["CPU", "Memory", "GPU", "I/O wait"])
        self.overview_chart_metric.set_selected(0)
        self.overview_chart_metric.connect("notify::selected", lambda *_args: self._update_overview_chart())
        chart_control.add_suffix(self.overview_chart_metric)
        history_list.append(chart_control)
        self.overview_chart = Sparkline(104, 180)
        self.overview_chart.add_css_class("resource-chart")
        history_list.append(Gtk.ListBoxRow(selectable=False, activatable=False, child=self.overview_chart))
        history.add(history_list)
        issues = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        issues.add_css_class("content-column")
        group = Adw.PreferencesGroup(title="Needs attention", description="Select an incident to see the evidence and probable cause.")
        self.overview_issues = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.overview_issues.set_activate_on_single_click(True)
        self.overview_issues.add_css_class("boxed-list")
        self.overview_issues.connect("row-activated", self._incident_row_activated)
        group.add(self.overview_issues)
        issues.append(group)
        view_all = Gtk.Button(label="View all active issues", halign=Gtk.Align.END)
        view_all.connect("clicked", lambda _button: self.navigate("issues"))
        issues.append(view_all)
        body.append(self._adaptive_pair(history, issues))
        return page

    def _issues_page(self) -> Gtk.Widget:
        page, body = page_shell(
            "Active issues",
            "Correlated incidents ordered by risk and recency. Select a row to inspect it.",
            scroll=False,
            maximum_size=1600,
        )
        body.set_vexpand(True)
        filters = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        options = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.issue_severity = Gtk.DropDown.new_from_strings(SEVERITIES)
        self.issue_category = Gtk.DropDown.new_from_strings(CATEGORIES)
        self.issue_status = Gtk.DropDown.new_from_strings(["Open", "All", "Resolved", "Acknowledged", "Historical"])
        self.issue_order = Gtk.DropDown.new_from_strings(ISSUE_SORTS)
        self.issue_search = Gtk.SearchEntry(placeholder_text="Search issues")
        self.issue_search.set_hexpand(True)
        filters.append(self.issue_search)
        for widget in (self.issue_severity, self.issue_category, self.issue_status, self.issue_order):
            options.append(widget)
        filters.append(options)
        self.issue_severity.connect("notify::selected", lambda *_a: self._refresh_incidents())
        self.issue_category.connect("notify::selected", lambda *_a: self._refresh_incidents())
        self.issue_status.connect("notify::selected", lambda *_a: self._refresh_incidents())
        self.issue_order.connect("notify::selected", lambda *_a: self._issue_order_changed())
        self.issue_search.connect("search-changed", lambda *_a: self._refresh_incidents())
        body.append(filters)
        self.issue_status_label = label("Loading incidents…", "dim")
        body.append(self.issue_status_label)
        self.issue_store = Gio.ListStore.new(RecordObject)
        self.issue_sort = Gtk.SortListModel.new(self.issue_store, issue_sorter(0))
        self.issue_selection = Gtk.SingleSelection(model=self.issue_sort, autoselect=False, can_unselect=True)
        self.issue_selection.connect("selection-changed", self._issue_selection_changed)
        self.issue_table = Gtk.ColumnView(model=self.issue_selection)
        self.issue_table.append_column(incident_column("Severity", lambda row: str(row.get("severity", "Activity"))))
        self.issue_table.append_column(incident_column("Issue", lambda row: str(row.get("title", "Unknown issue")), expand=True))
        self.issue_table.append_column(incident_column("Category", lambda row: str(row.get("category", "System"))))
        self.issue_table.append_column(incident_column("Status", lambda row: "Acknowledged" if row.get("acknowledged") else str(row.get("status", "open")).title()))
        self.issue_table.append_column(incident_column("Events", lambda row: str(row.get("occurrences", 1))))
        self.issue_table.append_column(incident_column("Last seen", lambda row: format_time(int(row.get("last_us", 0)))))
        self.issue_table.connect("activate", lambda _view, position: self._open_incident(dict(self.issue_selection.get_item(position).record)))
        table_scroll = Gtk.ScrolledWindow(child=self.issue_table, hexpand=True, vexpand=True)
        self.issue_inspector = IncidentInspector(self)
        self.issue_split = Gtk.Paned.new(Gtk.Orientation.HORIZONTAL)
        self.issue_split.set_start_child(table_scroll)
        self.issue_split.set_end_child(self.issue_inspector)
        self.issue_split.set_position(760)
        self.issue_split.set_resize_start_child(True)
        self.issue_split.set_resize_end_child(False)
        self.issue_split.set_vexpand(True)
        body.append(self.issue_split)
        compact_breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("min-width: 901px and max-width: 1450px"))
        compact_breakpoint.add_setter(self.issue_inspector, "visible", False)
        self.add_breakpoint(compact_breakpoint)
        self.compact_navigation_breakpoint.add_setter(self.issue_inspector, "visible", False)
        return page

    def _issue_selection_changed(self, selection: Gtk.SingleSelection, _position: int, _count: int) -> None:
        item = selection.get_selected_item()
        self.issue_inspector.set_record(item.record if item else None)

    def _issue_order_changed(self) -> None:
        self.issue_sort.set_sorter(issue_sorter(self.issue_order.get_selected()))

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
        controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        controls.set_margin_top(12); controls.set_margin_start(12); controls.set_margin_end(12)
        self.live_search = Gtk.SearchEntry(placeholder_text="Search live evidence")
        self.live_search.set_hexpand(True)
        self.live_severity = Gtk.DropDown.new_from_strings(SEVERITIES)
        self.live_category = Gtk.DropDown.new_from_strings(CATEGORIES)
        self.live_follow = Gtk.Switch(active=True, valign=Gtk.Align.CENTER, tooltip_text="Follow new events")
        controls.append(self.live_search)
        options = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options.append(self.live_severity); options.append(self.live_category)
        options.append(label("Follow")); options.append(self.live_follow)
        controls.append(options)
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
        page, body = page_shell("Performance", "Validated one-minute history from the local collector.", maximum_size=1600)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.append(label("Range"))
        self.perf_range = Gtk.DropDown.new_from_strings(["1 hour", "6 hours", "24 hours"])
        self.perf_range.connect("notify::selected", lambda *_a: self._refresh_performance())
        controls.append(self.perf_range)
        body.append(controls)
        self.perf_flow = responsive_flow(2)
        body.append(self.perf_flow)
        self.perf_rows: dict[str, tuple[Adw.ActionRow, Sparkline]] = {}
        for metric, title in (("cpu.percent", "CPU utilization"), ("memory.percent", "Memory usage"), ("cpu.iowait", "Storage I/O wait"), ("gpu.percent", "GPU utilization")):
            panel, row, chart = history_panel(title)
            self.perf_flow.insert(panel, -1)
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
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        left.add_css_class("content-column")
        self.power_group = Adw.PreferencesGroup(title="Component power")
        left.append(self.power_group)
        self.power_rows: dict[str, tuple[Adw.ActionRow, Sparkline]] = {}
        for metric, title in (
            ("gpu.power.draw.watts", "NVIDIA GPU board power"),
            ("gpu.power.limit.watts", "NVIDIA GPU power cap"),
            ("power.AMD graphics PPT.watts", "AMD graphics PPT"),
        ):
            row = action_row(title, "Waiting for samples", "battery-good-symbolic")
            chart = Sparkline(64)
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
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        right.add_css_class("content-column")
        right.append(self.voltage_group)
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
        right.append(self.voltage_coverage)
        body.append(self._adaptive_pair(left, right))
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
        cpu_group.add_css_class("content-column")

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
        gpu_group.add_css_class("content-column")
        body.append(self._adaptive_pair(cpu_group, gpu_group))

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.tuning_apply = Gtk.Button(label="Apply temporary tuning")
        self.tuning_apply.add_css_class("suggested-action")
        self.tuning_apply.connect("clicked", lambda _button: self._confirm_apply_tuning())
        self.tuning_restore = Gtk.Button(label="Restore saved baseline")
        self.tuning_restore.connect("clicked", lambda _button: self._confirm_restore_tuning())
        controls.append(self.tuning_apply)
        controls.append(self.tuning_restore)
        body.append(controls)

        audit_group = Adw.PreferencesGroup()
        audit = Adw.ExpanderRow(
            title="Tuning audit",
            subtitle="Recent apply, restore, rejected, and automatic safety actions",
        )
        self.tuning_audit_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        audit_content = Gtk.ListBoxRow(selectable=False, activatable=False, child=self.tuning_audit_content)
        audit.add_row(audit_content)
        audit_group.add(audit)
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
        self.tuning_apply.set_sensitive((cpu or gpu) and self.collector_active)
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
        if not self.collector_active:
            self.tuning_banner.set_title("Start the collector before applying tuning so automatic thermal safety rollback is available.")
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
        if not self.collector_active:
            self.toast("Start the collector before applying tuning so automatic thermal safety rollback is available")
            return
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
        audit = self.executor.submit(self._record_tuning_audit, operation, response, reason)
        audit.add_done_callback(lambda done: GLib.idle_add(self._tuning_audit_saved, done))
        self.toast(
            "Temporary tuning applied" if operation == "apply" and response.get("ok") else
            "Saved baseline restored" if operation == "restore" and response.get("ok") else
            f"Tuning request failed: {str(response.get('error', 'unknown error'))[:160]}"
        )
        self._refresh_tuning()
        return GLib.SOURCE_REMOVE

    @staticmethod
    def _record_tuning_audit(operation: str, response: dict[str, Any], reason: str) -> None:
        with open_v2() as conn:
            record_tuning_audit(conn, operation, response, reason=reason)

    def _tuning_audit_saved(self, future: concurrent.futures.Future[None]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            future.result()
        except sqlite3.Error as exc:
            self.logger.warning("could not write tuning audit: %s", exc)
        return GLib.SOURCE_REMOVE

    def _refresh_tuning_audit(self) -> None:
        self.tuning_audit_request_id = getattr(self, "tuning_audit_request_id", 0) + 1
        request_id = self.tuning_audit_request_id
        future = self.executor.submit(self._query_tuning_audit)
        future.add_done_callback(lambda done: GLib.idle_add(self._tuning_audit_ready, done, request_id))

    @staticmethod
    def _query_tuning_audit() -> list[dict[str, Any]]:
        with open_v2(readonly=True) as conn:
            rows = conn.execute("SELECT * FROM tuning_audit ORDER BY occurred_us DESC LIMIT 12").fetchall()
        return [dict(row) for row in rows]

    def _tuning_audit_ready(self, future: concurrent.futures.Future[list[dict[str, Any]]], request_id: int) -> bool:
        if self.closed or request_id != self.tuning_audit_request_id:
            return GLib.SOURCE_REMOVE
        self._clear_container(self.tuning_audit_content)
        try:
            rows = future.result()
        except sqlite3.Error:
            rows = []
        if not rows:
            self.tuning_audit_content.append(action_row("No tuning requests recorded", "Apply, restore, rejected, and automatic-safety actions will appear here.", "document-open-recent-symbolic"))
            return GLib.SOURCE_REMOVE
        for entry in rows:
            icon = "emblem-ok-symbolic" if entry["result"] == "ok" else "dialog-error-symbolic"
            self.tuning_audit_content.append(action_row(
                f"{str(entry['action']).replace('-', ' ').title()} · {entry['result']}",
                f"{format_time(entry['occurred_us'])} · {entry['reason']}",
                icon,
            ))
        return GLib.SOURCE_REMOVE

    def _hardware_page(self) -> Gtk.Widget:
        page, body = page_shell("Hardware health", "Sensors, drive health, buses, and firmware inventory.", maximum_size=1600)
        self.hardware_status = Adw.Banner(title="Waiting for the hardware scan…")
        body.append(self.hardware_status)
        self.hardware_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.hardware_left.add_css_class("content-column")
        self.hardware_right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.hardware_right.add_css_class("content-column")
        body.append(self._adaptive_pair(self.hardware_left, self.hardware_right))
        return page

    def _services_page(self) -> Gtk.Widget:
        page, body = page_shell("Services", "Failed system and user-session units. Only user units can be changed here.")
        self.services_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.services_content)
        return page

    def _network_page(self) -> Gtk.Widget:
        page, body = page_shell("Network & security", "Interface state, routes, listening sockets, and correlated network incidents.", maximum_size=1600)
        self.network_status = Adw.Banner(title="Waiting for the network scan…")
        self.network_status.set_revealed(True)
        body.append(self.network_status)
        self.network_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.network_left.add_css_class("content-column")
        self.network_right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.network_right.add_css_class("content-column")
        body.append(self._adaptive_pair(self.network_left, self.network_right))
        return page

    def _crashes_page(self) -> Gtk.Widget:
        page, body = page_shell("Crash history", "Crash artifacts, sizes, timestamps, and completion state.")
        self.crashes_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.append(self.crashes_content)
        return page

    def _updates_page(self) -> Gtk.Widget:
        page, body = page_shell("Updates", "Available package and device-firmware updates. Installation remains outside this app.", maximum_size=1600)
        self.updates_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.updates_left.add_css_class("content-column")
        self.updates_right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.updates_right.add_css_class("content-column")
        body.append(self._adaptive_pair(self.updates_left, self.updates_right))
        return page

    def _boots_page(self) -> Gtk.Widget:
        page, body = page_shell("Boot history", "Indexed incidents and evidence grouped by system boot.")
        self.boot_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        body.append(self.boot_content)
        return page

    def _raw_page(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        controls.set_margin_top(12); controls.set_margin_start(12); controls.set_margin_end(12)
        self.raw_source_names = ["System journal", "Kernel journal", "User journal", "Current dmesg", "Authentication", "APT", "dpkg", "Xorg"]
        self.raw_source = Gtk.DropDown.new_from_strings(self.raw_source_names)
        self.raw_since = Gtk.DropDown.new_from_strings(["15 minutes", "1 hour", "24 hours"])
        self.raw_search = Gtk.SearchEntry(placeholder_text="Filter loaded messages")
        self.raw_search.set_hexpand(True)
        load = Gtk.Button(label="Load logs")
        load.add_css_class("suggested-action")
        load.connect("clicked", lambda _b: self._load_raw())
        controls.append(self.raw_search)
        options = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options.append(self.raw_source); options.append(self.raw_since); options.append(load)
        controls.append(options)
        root.append(controls)
        self.raw_store = Gio.ListStore.new(RecordObject)
        self.raw_search.connect("search-changed", lambda *_a: self._render_raw_records())
        root.append(Gtk.ScrolledWindow(child=record_list_view(self.raw_store, self._raw_inspector, compact=True), vexpand=True))
        self.raw_status = label("Select a source and load up to 1,000 entries.", "dim")
        self.raw_status.set_margin_start(12); self.raw_status.set_margin_bottom(10)
        root.append(self.raw_status)
        return root

    def _settings_page(self) -> Gtk.Widget:
        page, body = page_shell(
            "Settings & storage",
            "Appearance, local data locations, and cleanup for files owned by PC Diagnostics.",
            maximum_size=1600,
        )
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        left.add_css_class("content-column")
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        right.add_css_class("content-column")
        appearance = Adw.PreferencesGroup(title="Appearance")
        appearance_row = action_row("Color scheme", "New installations follow the system appearance.", "preferences-desktop-theme-symbolic")
        self.appearance_choice = Gtk.DropDown.new_from_strings(["System", "Dark", "Light"])
        self.appearance_choice.set_selected(APPEARANCES.index(getattr(self.app, "appearance", "system")))
        self.appearance_choice.connect("notify::selected", self._appearance_changed)
        appearance_row.add_suffix(self.appearance_choice)
        appearance.add(appearance_row)
        replay = action_row("Guided tour", "Learn what every tab does, try a first action, or continue where you left off.", "help-browser-symbolic")
        replay_button = Gtk.Button(label="Open guide")
        replay_button.connect("clicked", lambda _button: self._show_tutorial())
        replay.add_suffix(replay_button)
        appearance.add(replay)
        reset = action_row("Reset UI preferences", "Restores system appearance and the default report folder.", "edit-undo-symbolic")
        reset_button = Gtk.Button(label="Reset")
        reset_button.connect("clicked", lambda _button: self._confirm_reset_preferences())
        reset.add_suffix(reset_button)
        appearance.add(reset)
        left.append(appearance)

        locations = Adw.PreferencesGroup(title="Locations")
        database = action_row("Diagnostic database", str(DB_PATH), "drive-harddisk-symbolic")
        database.set_subtitle_selectable(True)
        copy_database = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copy database path")
        copy_database.connect("clicked", lambda _button: self._copy_text(str(DB_PATH), "Database path copied"))
        database.add_suffix(copy_database)
        locations.add(database)
        self.report_location = action_row("Redacted report folder", str(self.report_dir), "folder-documents-symbolic")
        self.report_location.set_subtitle_selectable(True)
        choose_folder = Gtk.Button(label="Change")
        choose_folder.connect("clicked", lambda _button: self._choose_report_directory())
        self.report_location.add_suffix(choose_folder)
        locations.add(self.report_location)
        settings_location = action_row("Settings", f"SQLite settings table in {DB_PATH}", "emblem-system-symbolic")
        settings_location.set_subtitle_selectable(True)
        locations.add(settings_location)
        left.append(locations)

        storage = Adw.PreferencesGroup(title="Storage use", description="Sizes include only local PC Diagnostics files. System journals and crash files are never removed here.")
        self.storage_rows: dict[str, Adw.ActionRow] = {}
        for key, title, icon in (
            ("database", "Database and journal", "drive-harddisk-symbolic"),
            ("reports", "Redacted reports", "text-x-generic-symbolic"),
            ("backups", "Migration backups", "document-save-symbolic"),
            ("logs", "Application logs", "text-x-generic-symbolic"),
        ):
            row = action_row(title, "Measuring…", icon)
            self.storage_rows[key] = row
            storage.add(row)
        refresh_storage = Gtk.Button(label="Refresh")
        refresh_storage.connect("clicked", lambda _button: self._refresh_storage())
        refresh_row = action_row("Update storage totals", "Measure app-owned files again", "view-refresh-symbolic")
        refresh_row.add_suffix(refresh_storage)
        storage.add(refresh_row)
        right.append(storage)
        body.append(self._adaptive_pair(left, right))

        cleanup = Adw.PreferencesGroup()
        cleanup_expander = Adw.ExpanderRow(
            title="Clear retained data",
            subtitle="Choose stored history to remove; checkpoints and preferences remain",
        )
        self.history_cleanup: dict[str, Gtk.CheckButton] = {}
        for key, title in (
            ("incidents", "Incidents and forensic cases"),
            ("telemetry", "Stored performance and hardware telemetry"),
            ("scans", "Hardware, network, service, crash, and update scan snapshots"),
            ("tuning", "Safe-tuning audit history"),
        ):
            check = Gtk.CheckButton()
            row = action_row(title, "")
            row.add_prefix(check)
            row.set_activatable_widget(check)
            cleanup_expander.add_row(row)
            self.history_cleanup[key] = check
        clear_history = Gtk.Button(label="Clear selected retained data")
        clear_history.add_css_class("destructive-action")
        clear_history.connect("clicked", lambda _button: self._confirm_clear_history())
        clear_row = action_row("Remove selected history", "New evidence can appear after cleanup")
        clear_row.add_suffix(clear_history)
        cleanup_expander.add_row(clear_row)
        cleanup.add(cleanup_expander)
        cleanup.add_css_class("content-column")

        files = Adw.PreferencesGroup()
        files_expander = Adw.ExpanderRow(
            title="Delete generated files",
            subtitle="Reports, migration backups, and the bounded application log",
        )
        self.file_cleanup: dict[str, Gtk.CheckButton] = {}
        for key, title in (("reports", "Redacted reports"), ("backups", "Migration backups"), ("logs", "Application logs")):
            check = Gtk.CheckButton()
            row = action_row(title, "")
            row.add_prefix(check)
            row.set_activatable_widget(check)
            files_expander.add_row(row)
            self.file_cleanup[key] = check
        delete_files = Gtk.Button(label="Delete selected files")
        delete_files.add_css_class("destructive-action")
        delete_files.connect("clicked", lambda _button: self._confirm_delete_files())
        delete_row = action_row("Remove selected files", "Clearing logs starts a fresh local log")
        delete_row.add_suffix(delete_files)
        files_expander.add_row(delete_row)
        files.add(files_expander)
        files.add_css_class("content-column")
        body.append(self._adaptive_pair(cleanup, files))
        self._refresh_storage()
        return page

    def _default_report_dir(self) -> Path:
        documents = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOCUMENTS)
        return (Path(documents) / "PC-Diagnostic-Reports") if documents else DATA_DIR / "reports"

    def _copy_text(self, text: str, message: str) -> None:
        display = Gdk.Display.get_default()
        if display:
            display.get_clipboard().set(text)
            self.toast(message)

    def _appearance_changed(self, dropdown: Gtk.DropDown, _pspec: GObject.ParamSpec) -> None:
        value = APPEARANCES[dropdown.get_selected()]
        self.app.appearance = apply_appearance(value)
        self._save_setting("appearance", value)

    def _save_setting(self, key: str, value: str) -> None:
        def write() -> None:
            with open_v2() as conn:
                set_setting(conn, key, value)
        future = self.executor.submit(write)
        future.add_done_callback(lambda done: GLib.idle_add(self._setting_saved, done, key))

    def _setting_saved(self, future: concurrent.futures.Future[None], key: str) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            future.result()
        except Exception as exc:
            self.logger.warning("could not save %s: %s", key, exc)
            self.toast(f"Unable to save {key}: {exc}")
        return GLib.SOURCE_REMOVE

    def _choose_report_directory(self) -> None:
        dialog = Gtk.FileDialog(title="Choose redacted report folder", initial_folder=Gio.File.new_for_path(str(self.report_dir)))
        dialog.select_folder(self, None, self._report_directory_chosen)

    def _report_directory_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return
        path = folder.get_path()
        if not path:
            self.toast("Choose a local folder for reports")
            return
        self.report_dir = Path(path)
        self.report_location.set_subtitle(str(self.report_dir))
        self._save_setting("report_directory", str(self.report_dir))
        self._refresh_storage()

    def _storage_files(self, report_dir: Path | None = None) -> dict[str, list[Path]]:
        reports = report_dir or self.report_dir
        return {
            "database": [path for path in (DB_PATH, DB_PATH.with_name(DB_PATH.name + "-wal"), DB_PATH.with_name(DB_PATH.name + "-shm")) if path.is_file()],
            "reports": list(reports.glob("pc-diagnostics-*-redacted.txt")) if reports.is_dir() else [],
            "backups": list(DATA_DIR.glob("events-v1-backup-*.sqlite3")),
            "logs": list(DATA_DIR.glob("pc-diagnostics.log*")),
        }

    def _storage_snapshot(self, report_dir: Path) -> dict[str, tuple[int, int]]:
        snapshot: dict[str, tuple[int, int]] = {}
        for key, paths in self._storage_files(report_dir).items():
            sizes = [path.stat().st_size for path in paths if path.is_file()]
            snapshot[key] = (sum(sizes), len(sizes))
        return snapshot

    def _refresh_storage(self) -> None:
        if not hasattr(self, "storage_rows"):
            return
        self.storage_request_id += 1
        request_id = self.storage_request_id
        future = self.executor.submit(self._storage_snapshot, Path(self.report_dir))
        future.add_done_callback(lambda done: GLib.idle_add(self._storage_ready, done, request_id))

    def _storage_ready(self, future: concurrent.futures.Future[dict[str, tuple[int, int]]], request_id: int) -> bool:
        if self.closed or request_id != self.storage_request_id:
            return GLib.SOURCE_REMOVE
        try:
            snapshot = future.result()
        except OSError as exc:
            self.logger.warning("storage measurement failed: %s", exc)
            self.toast(f"Unable to measure storage: {exc}")
            return GLib.SOURCE_REMOVE
        for key, (size, count) in snapshot.items():
            self.storage_rows[key].set_subtitle(f"{format_file_size(size)} · {count} file(s)")
        return GLib.SOURCE_REMOVE

    def _confirm_clear_history(self) -> None:
        selected = {key for key, check in self.history_cleanup.items() if check.get_active()}
        if not selected:
            self.toast("Select at least one retained-data category")
            return
        dialog = Adw.AlertDialog(
            heading="Clear selected retained data?",
            body="The selected local records will be deleted and the database compacted. Collection checkpoints, settings, and system files are kept.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("clear", "Clear data")
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _dialog, response: self._clear_history(selected) if response == "clear" else None)
        dialog.present(self)

    def _clear_history(self, selected: set[str]) -> None:
        def clear() -> None:
            with open_v2() as conn:
                clear_retained_data(conn, selected)
        future = self.executor.submit(clear)
        future.add_done_callback(lambda done: GLib.idle_add(self._history_cleared, done, selected))

    def _history_cleared(self, future: concurrent.futures.Future[bool], selected: set[str]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            compacted = future.result()
        except sqlite3.Error as exc:
            self.logger.warning("history cleanup failed: %s", exc)
            self.toast(f"Unable to clear retained data: {exc}")
            return GLib.SOURCE_REMOVE
        for key in selected:
            self.history_cleanup[key].set_active(False)
        self.logger.info("cleared retained categories: %s", ",".join(sorted(selected)))
        self.toast("Selected retained data cleared" if compacted else "Selected retained data cleared; storage compaction will retry later")
        self._refresh_storage()
        self.refresh_page(self.stack.get_visible_child_name() or "overview")
        return GLib.SOURCE_REMOVE

    def _confirm_delete_files(self) -> None:
        selected = {key for key, check in self.file_cleanup.items() if check.get_active()}
        if not selected:
            self.toast("Select at least one generated-file category")
            return
        dialog = Adw.AlertDialog(
            heading="Delete selected generated files?",
            body="This permanently removes only selected PC Diagnostics reports, migration backups, and local application logs.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete files")
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _dialog, response: self._delete_files(selected) if response == "delete" else None)
        dialog.present(self)

    def _delete_files(self, selected: set[str]) -> None:
        report_dir = Path(self.report_dir)
        if "logs" in selected:
            # Close the active descriptor before unlinking it so the next log
            # message starts a fresh visible file instead of writing to one
            # that has already been deleted from the settings view.
            for handler in self.logger.handlers:
                if isinstance(handler, RotatingFileHandler):
                    handler.close()
                    handler.stream = None
        def delete() -> int:
            count = 0
            for key, paths in self._storage_files(report_dir).items():
                if key not in selected:
                    continue
                for path in paths:
                    path.unlink(missing_ok=True)
                    count += 1
            return count
        future = self.executor.submit(delete)
        future.add_done_callback(lambda done: GLib.idle_add(self._files_deleted, done, selected))

    def _files_deleted(self, future: concurrent.futures.Future[int], selected: set[str]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            count = future.result()
        except OSError as exc:
            self.logger.warning("file cleanup failed: %s", exc)
            self.toast(f"Unable to delete generated files: {exc}")
            return GLib.SOURCE_REMOVE
        for key in selected:
            self.file_cleanup[key].set_active(False)
        self.logger.info("deleted %d generated file(s): %s", count, ",".join(sorted(selected)))
        self.toast(f"Deleted {count} generated file(s)")
        self._refresh_storage()
        return GLib.SOURCE_REMOVE

    def _confirm_reset_preferences(self) -> None:
        dialog = Adw.AlertDialog(
            heading="Reset UI preferences?",
            body="This restores the system appearance and default report folder. Retained diagnostic data is not changed.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("reset", "Reset preferences")
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", lambda _dialog, response: self._reset_preferences() if response == "reset" else None)
        dialog.present(self)

    def _reset_preferences(self) -> None:
        self.report_dir = self._default_report_dir()
        self.report_location.set_subtitle(str(self.report_dir))
        self.appearance_choice.set_selected(0)
        self._save_setting("report_directory", "")
        self._save_setting("appearance", "system")
        self._refresh_storage()

    def _load_startup_preferences(self) -> tuple[bool, str, str]:
        with open_v2(readonly=True) as conn:
            tutorial = setting_value(conn, "guided_tour_seen", "0") == "1"
            report_dir = setting_value(conn, "report_directory", "")
            guide_page = setting_value(conn, "guided_tour_page", "overview")
        return tutorial, report_dir, guide_page

    def _check_tutorial(self) -> None:
        future = self.executor.submit(self._load_startup_preferences)
        future.add_done_callback(lambda done: GLib.idle_add(self._startup_preferences_ready, done))

    def _startup_preferences_ready(self, future: concurrent.futures.Future[tuple[bool, str, str]]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            tutorial_seen, report_dir, guide_page = future.result()
        except Exception as exc:
            self.logger.warning("could not load startup preferences: %s", exc)
            return GLib.SOURCE_REMOVE
        if report_dir:
            self.report_dir = Path(report_dir)
            if hasattr(self, "report_location"):
                self.report_location.set_subtitle(str(self.report_dir))
        if not self.guide_visible and self.tutorial_dialog is None:
            self.guide_page = guide_page if guide_page in PAGE_GUIDES else "overview"
            if not tutorial_seen:
                self._show_tutorial()
        return GLib.SOURCE_REMOVE

    def _show_tutorial(self) -> None:
        if self.tutorial_dialog is not None:
            return
        dialog = Adw.Dialog(title="Welcome to PC Diagnostics", content_width=620, content_height=620)
        self.tutorial_dialog = dialog
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for side in ("top", "bottom", "start", "end"):
            getattr(body, f"set_margin_{side}")(18)
        icon = Gtk.Image.new_from_icon_name("computer-symbolic")
        icon.set_pixel_size(32)
        icon.set_halign(Gtk.Align.START)
        icon.add_css_class("guide-icon")
        body.append(icon)
        body.append(label("Your PC, explained.", "guide-welcome-title", True))
        body.append(label(
            "Understand how your Linux PC is doing, investigate problems, and find the evidence behind a warning—all in one place.",
            None, True,
        ))
        benefits = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        benefits.add_css_class("boxed-list")
        for title, subtitle, icon_name in (
            ("See the big picture", "Start with resource use, temperatures, and issues that need attention.", "computer-symbolic"),
            ("Follow the evidence", "Connect a slowdown, crash, or restart to its timeline and original logs.", "system-search-symbolic"),
            ("Stay in control", "Review local storage and export a redacted report when you need help.", "preferences-system-symbolic"),
        ):
            benefits.append(action_row(title, subtitle, icon_name))
        body.append(benefits)
        details_group = Adw.PreferencesGroup()
        details = Adw.ExpanderRow(title="How the app and tour work")
        details.add_row(action_row(
            "Local monitoring",
            "A background collector gathers measurements and log evidence. History fills while it runs, and closing this window leaves it running.",
            "network-transmit-receive-symbolic",
        ))
        details.add_row(action_row(
            "A safe walkthrough",
            "The tour visits all 15 tabs and suggests what to try. It never applies a control or clears data.",
            "help-browser-symbolic",
        ))
        details_group.add(details)
        body.append(details_group)
        destination: list[str] = []

        def start(page: str) -> None:
            destination.append(page)
            dialog.close()

        def explore(_button: Gtk.Button) -> None:
            if self.guide_visible:
                self._pause_tour()
            dialog.close()

        footer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        footer.set_margin_top(12)
        footer.set_margin_bottom(16)
        footer.set_margin_start(24)
        footer.set_margin_end(24)
        start_button = Gtk.Button(label="Continue tour" if self.guide_page != "overview" else "Start guided tour")
        start_button.add_css_class("suggested-action")
        start_button.add_css_class("pill")
        start_button.connect("clicked", lambda _button: start(self.guide_page))
        footer.append(start_button)
        if self.guide_page != "overview":
            footer.append(label(f"Continue at {self.page_titles[self.guide_page]}. Pause saves your place for next time.", "dim", True))
            restart = Gtk.Button(label="Start again from Overview")
            restart.add_css_class("flat")
            restart.connect("clicked", lambda _button: start("overview"))
            footer.append(restart)
        later = Gtk.Button(label="Explore on my own")
        later.add_css_class("flat")
        later.connect("clicked", explore)
        footer.append(later)
        body.append(label("Need a reminder later? Use Guide in the header for help with any tab.", "dim", True))
        toolbar.set_content(Gtk.ScrolledWindow(child=Adw.Clamp(maximum_size=540, child=body)))
        toolbar.add_bottom_bar(footer)
        dialog.set_child(toolbar)

        def closed(_dialog: Adw.Dialog) -> None:
            self.tutorial_dialog = None
            if not self.closed:
                self._save_setting("guided_tour_seen", "1")
                if destination:
                    self._start_tour(destination[0])

        dialog.connect("closed", closed)
        dialog.present(self)

    def _build_guide(self) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("guide-card")
        card.add_css_class("card")
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.guide_title = label("", "section-title", True)
        self.guide_title.set_hexpand(True)
        top.append(self.guide_title)
        self.guide_counter = label("", "dim")
        top.append(self.guide_counter)
        details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        details_box.set_margin_top(12); details_box.set_margin_bottom(12)
        details_box.set_margin_start(12); details_box.set_margin_end(12)
        self.guide_summary = label("", None, True)
        self.guide_tip = label("", "dim", True)
        details_box.append(self.guide_summary)
        details_box.append(self.guide_tip)
        about = Gtk.MenuButton(label="About", popover=Gtk.Popover(child=details_box))
        about.set_tooltip_text("More about this tab")
        top.append(about)
        pause = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Pause tour and save your place")
        pause.add_css_class("flat")
        pause.connect("clicked", lambda _button: self._pause_tour())
        top.append(pause)
        card.append(top)
        self.guide_progress = Gtk.ProgressBar()
        card.append(self.guide_progress)

        self.guide_action = label("", "guide-step", True)
        self.guide_action.set_lines(2)
        card.append(self.guide_action)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.guide_choice = Gtk.DropDown.new_from_strings(list(self.page_titles.values()))
        self.guide_choice.set_hexpand(True)
        self.guide_choice.set_tooltip_text("Jump to a tab in the tour")
        self.guide_choice.update_property([Gtk.AccessibleProperty.LABEL], ["Jump to tab"])
        self.guide_choice.connect("notify::selected", self._guide_selected)
        controls.append(self.guide_choice)
        self.guide_back = Gtk.Button(label="Back")
        self.guide_back.connect("clicked", lambda _button: self._move_tour(-1))
        controls.append(self.guide_back)
        self.guide_next = Gtk.Button(label="Next tab")
        self.guide_next.add_css_class("suggested-action")
        self.guide_next.connect("clicked", lambda _button: self._move_tour(1))
        controls.append(self.guide_next)
        card.append(controls)
        self.guide_revealer.set_child(card)

    def _start_tour(self, page: str = "overview") -> None:
        if self.guide_revealer.get_child() is None:
            self._build_guide()
        self.guide_visible = True
        self.guide_revealer.set_reveal_child(True)
        self.navigate(page if page in PAGE_GUIDES else "overview")
        self.guide_next.grab_focus()

    def _update_guide(self, name: str) -> None:
        self.guide_page = name
        pages = list(PAGE_GUIDES)
        position = pages.index(name)
        title, summary, action, tip = PAGE_GUIDES[name]
        self.guide_title.set_text(title)
        self.guide_summary.set_text(summary)
        self.guide_action.set_text(f"Try: {action}")
        self.guide_tip.set_text(f"Good to know: {tip}")
        self.guide_counter.set_text(f"Tab {position + 1} of {len(pages)}")
        self.guide_progress.set_fraction((position + 1) / len(pages))
        self.guide_progress.update_property([Gtk.AccessibleProperty.LABEL], [f"Tour: {self.page_titles[name]}"])
        self.syncing_guide = True
        self.guide_choice.set_selected(position)
        self.syncing_guide = False
        self.guide_back.set_sensitive(position > 0)
        self.guide_next.set_label("Finish tour" if position == len(pages) - 1 else "Next tab")
        for row, route in self.nav_rows.items():
            if route == name:
                row.add_css_class("guide-current")
            else:
                row.remove_css_class("guide-current")

    def _guide_selected(self, dropdown: Gtk.DropDown, _pspec: GObject.ParamSpec) -> None:
        if not self.syncing_guide:
            position = dropdown.get_selected()
            if position < len(PAGE_GUIDES):
                self.navigate(list(PAGE_GUIDES)[position])

    def _move_tour(self, delta: int) -> None:
        if self.tour_transitioning:
            return
        self.tour_transitioning = True
        self.guide_next.set_sensitive(False)
        GLib.timeout_add(250, self._tour_transition_done)
        pages = list(PAGE_GUIDES)
        position = pages.index(self.guide_page) + delta
        if position >= len(pages):
            self._pause_tour(completed=True)
        elif position >= 0:
            self.navigate(pages[position])

    def _tour_transition_done(self) -> bool:
        self.tour_transitioning = False
        if not self.closed and self.guide_visible:
            self.guide_next.set_sensitive(True)
        return GLib.SOURCE_REMOVE

    def _pause_tour(self, completed: bool = False) -> None:
        self.guide_visible = False
        self.guide_button.grab_focus()
        self.guide_revealer.set_reveal_child(False)
        for row in self.nav_rows:
            row.remove_css_class("guide-current")
        if completed:
            self.guide_page = "overview"
            self._save_setting("onboarding_complete", "1")
        self._save_setting("guided_tour_seen", "1")
        self._save_setting("guided_tour_page", self.guide_page)
        self.toast("You’re ready to explore. Guide is always here if you need it." if completed else "Tour paused. Open the guided tour from Guide to continue.")

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
        record.setdefault("occurred_us", record.get("last_us", 0))
        record.setdefault("boot_id", record.get("last_boot_id", ""))
        self.open_inspector(record)

    def _show_crash_artifact(self, item: dict[str, Any]) -> None:
        path = Path(str(item.get("path", "Crash artifact")))
        dialog = Adw.Dialog(title=path.name, content_width=760, content_height=620)
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
        self.incident_request_id = getattr(self, "incident_request_id", 0) + 1
        request_id = self.incident_request_id
        status_index = self.issue_status.get_selected()
        severity = SEVERITIES[self.issue_severity.get_selected()]
        category = CATEGORIES[self.issue_category.get_selected()]
        search = self.issue_search.get_text().strip()
        self.issue_status_label.set_text("Loading incidents…")
        future = self.executor.submit(self._query_incidents, status_index, severity, category, search)
        future.add_done_callback(lambda done: GLib.idle_add(self._incidents_ready, done, request_id, bool(search or severity != SEVERITIES[0] or category != CATEGORIES[0] or status_index != 0)))

    @staticmethod
    def _query_incidents(status_index: int, severity: str, category: str, search: str) -> list[dict[str, Any]]:
        where: list[str] = []
        args: list[Any] = []
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
        if severity != SEVERITIES[0]: where.append("severity=?"); args.append(severity)
        if category != CATEGORIES[0]: where.append("category=?"); args.append(category)
        if search:
            where.append("(title LIKE ? OR sample_message LIKE ? OR likely_cause LIKE ?)")
            args.extend([f"%{search}%"] * 3)
        clause = "WHERE " + " AND ".join(where) if where else ""
        with open_v2(readonly=True) as conn:
            rows = conn.execute(
                f"SELECT * FROM incidents {clause} ORDER BY {INCIDENT_PRIORITY_SQL} DESC,last_us DESC LIMIT 300",
                args,
            ).fetchall()
        return [dict(row) for row in rows]

    def _incidents_ready(self, future: concurrent.futures.Future[list[dict[str, Any]]], request_id: int, has_filters: bool) -> bool:
        if self.closed or request_id != self.incident_request_id:
            return GLib.SOURCE_REMOVE
        try:
            rows = future.result()
        except (sqlite3.Error, OSError) as exc:
            self.logger.warning("incident query failed: %s", exc)
            self.issue_status_label.set_text(f"Database error: {exc}")
            return GLib.SOURCE_REMOVE
        selected = self.issue_selection.get_selected_item()
        selected_id = int(selected.record.get("id", 0)) if selected else 0
        self.issue_store.remove_all()
        for row in rows:
            record = dict(row)
            self.issue_store.append(RecordObject(record))
        selected_position = next(
            (position for position in range(self.issue_sort.get_n_items())
             if int(self.issue_sort.get_item(position).record.get("id", 0)) == selected_id),
            None,
        )
        if selected_position is not None:
            self.issue_selection.set_selected(selected_position)
        else:
            self.issue_inspector.set_record(None)
        if rows:
            self.issue_status_label.set_text(f"{len(rows)} incident(s) · ordered by risk and recency")
        else:
            self.issue_status_label.set_text("No matching incidents" if has_filters else "No active incidents")
        return GLib.SOURCE_REMOVE

    def _set_incident_acknowledged(self, incident_id: int, acknowledged: bool) -> None:
        def update() -> bool:
            with open_v2() as conn:
                return acknowledge_incident(conn, incident_id, acknowledged)
        future = self.executor.submit(update)
        future.add_done_callback(lambda done: GLib.idle_add(self._incident_state_ready, done, "acknowledged" if acknowledged else "unacknowledged"))

    def _resolve_incident(self, incident_id: int) -> None:
        def update() -> bool:
            with open_v2() as conn:
                return resolve_incident_id(conn, incident_id)
        future = self.executor.submit(update)
        future.add_done_callback(lambda done: GLib.idle_add(self._incident_state_ready, done, "resolved"))

    def _incident_state_ready(self, future: concurrent.futures.Future[bool], action: str) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            changed = future.result()
        except sqlite3.Error as exc:
            self.logger.warning("incident update failed: %s", exc)
            self.toast(f"Unable to update incident: {exc}")
            return GLib.SOURCE_REMOVE
        if changed:
            self.logger.info("incident %s", action)
            self.toast("Incident marked resolved" if action == "resolved" else f"Incident {action}")
            self._refresh_incidents()
        return GLib.SOURCE_REMOVE

    def _refresh_overview_issues(self) -> None:
        self.overview_request_id = getattr(self, "overview_request_id", 0) + 1
        request_id = self.overview_request_id
        future = self.executor.submit(self._query_overview_issues)
        future.add_done_callback(lambda done: GLib.idle_add(self._overview_issues_ready, done, request_id))

    @staticmethod
    def _query_overview_issues() -> tuple[list[dict[str, Any]], dict[str, int]]:
        with open_v2(readonly=True) as conn:
            rows = conn.execute(f"SELECT * FROM incidents WHERE status='open' ORDER BY {INCIDENT_PRIORITY_SQL} DESC,last_us DESC LIMIT 3").fetchall()
            counts = dict(conn.execute("SELECT severity,COUNT(*) FROM incidents WHERE status='open' GROUP BY severity").fetchall())
        return [dict(row) for row in rows], {str(key): int(value) for key, value in counts.items()}

    def _overview_issues_ready(self, future: concurrent.futures.Future[tuple[list[dict[str, Any]], dict[str, int]]], request_id: int) -> bool:
        if self.closed or request_id != self.overview_request_id:
            return GLib.SOURCE_REMOVE
        try:
            rows, counts = future.result()
        except (sqlite3.Error, OSError) as exc:
            self.logger.debug("overview incident query failed: %s", exc)
            return GLib.SOURCE_REMOVE
        clear_list(self.overview_issues)
        if not rows:
            self.overview_issues.append(action_row("No active issues", "The collector has no unresolved diagnostic incidents.", "emblem-ok-symbolic"))
        for row in rows:
            self.overview_issues.append(self._incident_row(dict(row)))
        serious = int(counts.get("Critical", 0)) + int(counts.get("Error", 0))
        warnings = int(counts.get("Warning", 0))
        self.metric_cards["issues"].update(float(serious), "", f"{warnings} warning(s)", [])
        return GLib.SOURCE_REMOVE

    def _load_live(self, reset: bool = True) -> None:
        self.live_request_id = getattr(self, "live_request_id", 0) + 1
        request_id = self.live_request_id
        if reset:
            self.live_cursor = None; self.live_raw = []
        severity = SEVERITIES[self.live_severity.get_selected()]
        category = CATEGORIES[self.live_category.get_selected()]
        cursor = self.live_cursor
        search = self.live_search.get_text()
        self.live_status.set_text("Loading events…")
        future = self.executor.submit(self._query_live_events, cursor, severity, category, search)
        future.add_done_callback(lambda done: GLib.idle_add(self._live_ready, done, request_id))

    @staticmethod
    def _query_live_events(cursor: tuple[int, int] | None, severity: str, category: str, search: str) -> list[dict[str, Any]]:
        with open_v2(readonly=True) as conn:
            return fetch_event_page(conn, before=cursor, limit=EVENT_PAGE_SIZE, severity=severity, category=category, search=search)

    def _live_ready(self, future: concurrent.futures.Future[list[dict[str, Any]]], request_id: int) -> bool:
        if self.closed or request_id != self.live_request_id:
            return GLib.SOURCE_REMOVE
        try:
            rows = future.result()
        except (sqlite3.Error, OSError) as exc:
            self.logger.debug("event query failed: %s", exc)
            self.live_status.set_text(f"Database error: {exc}")
            return GLib.SOURCE_REMOVE
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
        return GLib.SOURCE_REMOVE

    def _refresh_metrics(self) -> None:
        since = int((time.time() - 3600) * 1_000_000)
        self.metrics_request_id = getattr(self, "metrics_request_id", 0) + 1
        request_id = self.metrics_request_id
        future = self.executor.submit(self._query_metric_history, since)
        future.add_done_callback(lambda done: GLib.idle_add(self._metrics_ready, done, request_id))

    @staticmethod
    def _query_metric_history(since: int) -> tuple[dict[str, list[float]], dict[str, float]]:
        high_resolution = "(metric LIKE 'temperature.%' OR metric LIKE 'gpu.%' OR metric LIKE 'power.%' OR metric LIKE 'voltage.%')"
        with open_v2(readonly=True) as conn:
            rows = conn.execute(
                "SELECT metric,bucket_us,last_value FROM metric_rollups WHERE bucket_us>=? AND "
                f"((interval_seconds=10 AND {high_resolution}) OR (interval_seconds=60 AND NOT {high_resolution})) "
                "ORDER BY bucket_us",
                (since,),
            ).fetchall()
        history: dict[str, list[float]] = {}
        for row in rows:
            history.setdefault(row["metric"], []).append(float(row["last_value"]))
        # Sensor tools can take several seconds. This query already runs on the
        # window executor, keeping the live fallback off GTK's main thread.
        return history, live_hardware_metrics()

    def _metrics_ready(self, future: concurrent.futures.Future[tuple[dict[str, list[float]], dict[str, float]]], request_id: int) -> bool:
        if self.closed or request_id != self.metrics_request_id:
            return GLib.SOURCE_REMOVE
        try:
            history, hardware = future.result()
        except (sqlite3.Error, OSError) as exc:
            self.logger.debug("metric query failed: %s", exc)
            return GLib.SOURCE_REMOVE
        self.overview_history = history

        def last(name: str) -> float | None:
            return history[name][-1] if history.get(name) else None

        current = {name: values[-1] for name, values in history.items() if values}
        current.update(hardware)

        def reading(names: list[str]) -> tuple[str | None, float | None]:
            for name in names:
                if name in current:
                    return name, current[name]
            return None, None

        def sensor_note(metric: str | None, unavailable: str) -> str:
            if metric is None:
                return unavailable
            name = metric.removeprefix("temperature.").removeprefix("power.").removesuffix(".watts")
            source = "live sensor" if metric in hardware else "last recorded"
            return f"{name} · {source}"

        def update_overview_metric(key: str, metric: str, suffix: str, note: str) -> None:
            row = self.metric_cards[key]
            if metric in self.live_overview_values:
                row.chart.set_values(history.get(metric, []))
                row.chart.set_visible(len(history.get(metric, [])) >= 2)
            else:
                row.update(last(metric), suffix, note, history.get(metric, []))

        iowait = last("cpu.iowait")
        swap = last("swap.percent")
        free = last("disk.root.free_gib")
        update_overview_metric("cpu", "cpu.percent", "%", "I/O wait unavailable" if iowait is None else f"I/O wait {iowait:.1f}%")
        update_overview_metric("memory", "memory.percent", "%", "Swap usage unavailable" if swap is None else f"Swap {swap:.0f}%")
        update_overview_metric("disk", "disk.root.percent", "%", "Free space unavailable" if free is None else f"{free:.1f} GiB free")

        cpu_names = sorted(
            (name for name in current if name.startswith("temperature.CPU")),
            key=lambda name: current[name], reverse=True,
        )
        cpu_metric, cpu_temp = reading(cpu_names)
        self.metric_cards["temperature"].update(
            cpu_temp, "°C", sensor_note(cpu_metric, "No validated CPU sensor was found"),
            history.get(cpu_metric or "", []), 1,
        )

        gpu_temp_names = sorted(
            (name for name in current if name.startswith("temperature.") and any(word in name.lower() for word in ("gpu", "graphics"))),
            key=lambda name: current[name], reverse=True,
        )
        gpu_temp_metric, gpu_temp = reading(gpu_temp_names)
        self.metric_cards["gpu_temperature"].update(
            gpu_temp, "°C", sensor_note(gpu_temp_metric, "No validated GPU temperature was found"),
            history.get(gpu_temp_metric or "", []), 1,
        )

        gpu_names = [name for name in current if (
            name == "gpu.percent"
            or (name.startswith("gpu.") and name.endswith(".percent") and ".memory." not in name and ".power." not in name)
        )]
        gpu_names.sort(key=lambda name: (name != "gpu.percent", name))
        gpu_metric, gpu_usage = reading(gpu_names)
        self.metric_cards["gpu"].update(
            gpu_usage, "%", "Current GPU engine load" if gpu_metric in hardware else (
                "Last recorded GPU engine load" if gpu_metric else "Utilization is not exposed by an active GPU driver"
            ), history.get(gpu_metric or "", []),
        )

        power_names = [name for name in current if name.endswith(".watts") and ".limit." not in name and (name.startswith("gpu.") or name.startswith("power."))]
        power_names.sort(key=lambda name: (name != "gpu.power.draw.watts", name))
        power_metric, gpu_power = reading(power_names)
        gpu_limit = current.get("gpu.power.limit.watts")
        if power_metric == "gpu.power.draw.watts" and gpu_limit is not None:
            power_note = f"NVIDIA board draw · {gpu_limit:.0f} W cap"
        else:
            power_note = sensor_note(power_metric, "Power draw is not exposed by an active GPU driver")
        self.metric_cards["power"].update(
            gpu_power, " W", power_note, history.get(power_metric or "", []),
        )
        self._update_overview_chart()
        return GLib.SOURCE_REMOVE

    def _update_overview_chart(self) -> None:
        if not hasattr(self, "overview_chart"):
            return
        metric = ("cpu.percent", "memory.percent", "gpu.percent", "cpu.iowait")[self.overview_chart_metric.get_selected()]
        values = self.overview_history.get(metric, [])
        if metric == "gpu.percent" and not values:
            values = next((items for name, items in self.overview_history.items() if name.startswith("gpu.") and name.endswith(".percent")), [])
        self.overview_chart.set_values(values)

    def _refresh_live_overview_metrics(self) -> None:
        try:
            metrics, self.live_metric_cpu_state = live_overview_metrics(self.live_metric_cpu_state)
        except (OSError, ValueError, IndexError, KeyError):
            return
        self.live_overview_values.update(metrics)
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
        self.performance_request_id = getattr(self, "performance_request_id", 0) + 1
        request_id = self.performance_request_id
        future = self.executor.submit(self._query_performance, int((time.time() - seconds) * 1_000_000))
        future.add_done_callback(lambda done: GLib.idle_add(self._performance_ready, done, request_id))

    @staticmethod
    def _query_performance(since: int) -> tuple[dict[str, list[float]], dict[str, list[float]]]:
        with open_v2(readonly=True) as conn:
            rows = conn.execute("SELECT metric,bucket_us,average,minimum,maximum FROM metric_rollups WHERE interval_seconds=60 AND bucket_us>=? ORDER BY bucket_us", (since,)).fetchall()
        grouped: dict[str, list[float]] = {}
        bounds: dict[str, list[float]] = {}
        for row in rows:
            grouped.setdefault(row["metric"], []).append(float(row["average"]))
            bounds.setdefault(row["metric"], []).extend((float(row["minimum"]), float(row["maximum"])))
        return grouped, bounds

    def _performance_ready(self, future: concurrent.futures.Future[tuple[dict[str, list[float]], dict[str, list[float]]]], request_id: int) -> bool:
        if self.closed or request_id != self.performance_request_id:
            return GLib.SOURCE_REMOVE
        try:
            grouped, bounds = future.result()
        except (sqlite3.Error, OSError) as exc:
            self.logger.debug("performance query failed: %s", exc)
            return GLib.SOURCE_REMOVE
        for metric in sorted(grouped):
            parts = metric.split(".")
            if len(parts) == 3 and parts[0] == "gpu" and parts[1].isdigit() and parts[2] == "percent" and metric not in self.perf_rows:
                panel, row, chart = history_panel(f"GPU {parts[1]} utilization")
                self.perf_flow.insert(panel, -1)
                self.perf_rows[metric] = (row, chart)
        for metric, (row, chart) in self.perf_rows.items():
            values = grouped.get(metric, [])
            if values:
                row.set_subtitle(f"Current {values[-1]:.1f}% · minimum {min(bounds[metric]):.1f}% · average {sum(values)/len(values):.1f}% · maximum {max(bounds[metric]):.1f}%")
            else:
                row.set_subtitle("No samples in this range")
            chart.set_values(values)
        return GLib.SOURCE_REMOVE

    def _refresh_power(self) -> None:
        since = int((time.time() - 3600) * 1_000_000)
        self.power_request_id = getattr(self, "power_request_id", 0) + 1
        request_id = self.power_request_id
        future = self.executor.submit(self._query_power, since)
        future.add_done_callback(lambda done: GLib.idle_add(self._power_ready, done, request_id))

    @staticmethod
    def _query_power(since: int) -> tuple[dict[str, list[float]], dict[str, list[float]]]:
        with open_v2(readonly=True) as conn:
            rows = conn.execute(
                "SELECT metric,average,minimum,maximum FROM metric_rollups "
                "WHERE interval_seconds=10 AND bucket_us>=? AND "
                "(metric LIKE 'gpu.power.%' OR metric LIKE 'gpu.%.power.%' OR metric LIKE 'power.%' OR metric LIKE 'voltage.%') "
                "ORDER BY bucket_us",
                (since,),
            ).fetchall()
        grouped: dict[str, list[float]] = {}
        bounds: dict[str, list[float]] = {}
        for row in rows:
            grouped.setdefault(row["metric"], []).append(float(row["average"]))
            bounds.setdefault(row["metric"], []).extend((float(row["minimum"]), float(row["maximum"])))
        return grouped, bounds

    def _power_ready(self, future: concurrent.futures.Future[tuple[dict[str, list[float]], dict[str, list[float]]]], request_id: int) -> bool:
        if self.closed or request_id != self.power_request_id:
            return GLib.SOURCE_REMOVE
        try:
            grouped, bounds = future.result()
        except (sqlite3.Error, OSError) as exc:
            self.logger.debug("power query failed: %s", exc)
            return GLib.SOURCE_REMOVE
        power_metrics = sorted(
            metric for metric in grouped
            if metric.startswith("power.") or ".power." in metric
        )
        for metric in power_metrics:
            if metric not in self.power_rows:
                row = action_row(metric.removesuffix(".watts").replace(".", " ").title(), "Waiting for samples", "battery-good-symbolic")
                chart = Sparkline(64)
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
                chart = Sparkline(64)
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
        return GLib.SOURCE_REMOVE

    def _refresh_scans(self, key: str, scan_types: tuple[str, ...], render: Callable[[dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]], None]) -> None:
        self.scan_request_ids = getattr(self, "scan_request_ids", {})
        request_id = self.scan_request_ids.get(key, 0) + 1
        self.scan_request_ids[key] = request_id
        future = self.executor.submit(self._query_scans, scan_types)
        future.add_done_callback(lambda done: GLib.idle_add(self._scans_ready, done, key, request_id, render))

    @staticmethod
    def _query_scans(scan_types: tuple[str, ...]) -> dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]:
        result: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]] = {}
        with open_v2(readonly=True) as conn:
            for scan_type in scan_types:
                row = conn.execute("SELECT * FROM scans WHERE scan_type=? ORDER BY finished_us DESC,id DESC LIMIT 1", (scan_type,)).fetchone()
                record = dict(row) if row else None
                result[scan_type] = (record, scan_payload(record["details_json"], scan_type) if record else {})
        return result

    def _scans_ready(self, future: concurrent.futures.Future[dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]], key: str, request_id: int, render: Callable[[dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]], None]) -> bool:
        if self.closed or self.scan_request_ids.get(key) != request_id:
            return GLib.SOURCE_REMOVE
        try:
            render(future.result())
        except Exception as exc:
            self.logger.warning("%s scan presentation failed: %s", key, exc)
            self.toast(f"Unable to load {key}: {exc}")
        return GLib.SOURCE_REMOVE

    def _clear_container(self, box: Gtk.Box) -> None:
        while child := box.get_first_child():
            box.remove(child)

    def _refresh_hardware(self) -> None:
        self._refresh_scans("hardware", ("hardware", "smart"), self._render_hardware)

    def _render_hardware(self, scans: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]) -> None:
        row, data = scans["hardware"]
        self._clear_container(self.hardware_left)
        self._clear_container(self.hardware_right)
        if not row:
            self.hardware_status.set_title("No hardware scan has completed yet"); return
        self.hardware_status.set_title(f"{row['summary']} · {format_time(row['finished_us'])}")
        sensors = Adw.PreferencesGroup(title="Validated sensors")
        sensor_data = data.get("sensors", {})
        for name, value in sensor_data.items() if isinstance(sensor_data, dict) else []:
            reading = value.get("value", value) if isinstance(value, dict) else value
            sensors.add(action_row(str(name), f"{float(reading):.1f}°C", "weather-clear-symbolic"))
        if not sensor_data: sensors.add(action_row("No validated readings", "Install/configure lm-sensors or check the collector helper."))
        self.hardware_left.append(sensors)
        _smart_row, smart_data = scans["smart"]
        smart = Adw.PreferencesGroup(title="Drive health (SMART / NVMe)")
        smart_results = smart_data.get("results", []) if isinstance(smart_data, dict) else []
        unavailable = {str(item) for item in smart_data.get("unavailable", [])} if isinstance(smart_data, dict) else set()
        findings = {
            str(item.get("device")): item
            for item in smart_data.get("health_findings", []) if isinstance(item, dict)
        } if isinstance(smart_data, dict) else {}
        for result in smart_results:
            device = str(result.get("device", "Storage device"))
            drive = result.get("data", {}) if isinstance(result.get("data", {}), dict) else {}
            passed = drive.get("smart_status", {}).get("passed") if isinstance(drive.get("smart_status", {}), dict) else None
            nvme = drive.get("nvme_smart_health_information_log", {}) if isinstance(drive.get("nvme_smart_health_information_log", {}), dict) else {}
            warning = int(nvme.get("critical_warning", 0) or 0)
            errors = int(nvme.get("media_errors", 0) or 0)
            used = int(nvme.get("percentage_used", 0) or 0)
            attributes = drive.get("ata_smart_attributes", {}).get("table", []) if isinstance(drive.get("ata_smart_attributes", {}), dict) else []
            risky = sum(
                int(item.get("raw", {}).get("value", 0) or 0)
                for item in attributes if isinstance(item, dict)
                and item.get("name") in {"Reallocated_Sector_Ct", "Current_Pending_Sector", "Offline_Uncorrectable"}
            )
            exit_status = int(result.get("exit_status", 127) or 0)
            unavailable_result = device in unavailable or bool(exit_status & 0b11) or bool(result.get("truncated"))
            unhealthy = passed is False or bool(warning) or bool(errors) or used >= 100 or bool(risky) or device in findings
            if unavailable_result:
                state = "Unavailable"
                detail = str(result.get("error") or smart_data.get("error") or "SMART did not return a complete, reliable result.")
                icon = "dialog-warning-symbolic"
            elif unhealthy:
                state = "Needs immediate attention"
                detail = f"{state} · endurance used {used}% · media errors {errors} · risky sectors {risky} · critical warning {warning}"
                icon = "dialog-error-symbolic"
            else:
                detail = f"Healthy · endurance used {used}% · media errors {errors} · critical warning {warning}"
                icon = "drive-harddisk-symbolic"
            smart.add(action_row(device, detail, icon))
        if not smart_results:
            smart.add(action_row("Drive health unavailable", str(smart_data.get("error", "The privileged helper has not returned SMART data."))))
        self.hardware_right.append(smart)
        drives = Adw.PreferencesGroup(title="Storage devices")
        drive_records: list[dict[str, Any]] = []
        def add_devices(items: list[dict[str, Any]], depth: int = 0) -> None:
            for item in items:
                name = ("↳ " * depth) + str(item.get("model") or item.get("name") or item.get("path") or "Device")
                subtitle = " · ".join(str(v) for v in (item.get("size"), item.get("fstype"), ", ".join(item.get("mountpoints") or []), item.get("state")) if v)
                drive_records.append({"_title": name, "_subtitle": subtitle, "_icon": "drive-harddisk-symbolic"})
                add_devices(item.get("children") or [], depth + 1)
        add_devices(data.get("blockdevices") or [])
        if drive_records:
            drives.add(detail_list(drive_records))
        else:
            drives.add(action_row("No storage inventory", "The hardware scan returned no block devices."))
        self.hardware_left.append(drives)
        pci = Adw.PreferencesGroup(title="PCI devices and drivers")
        pci_records = [{
            "_title": str(item.get("description", "PCI device")),
            "_subtitle": f"{item.get('slot', '')} · driver {item.get('driver') or 'not bound'}",
            "_icon": "application-x-firmware-symbolic",
        } for item in (data.get("pci_devices") or [])[:100]]
        if pci_records:
            pci.add(detail_list(pci_records))
        else:
            pci.add(action_row("No PCI inventory", "The hardware scan returned no PCI devices."))
        self.hardware_left.append(pci)
        usb = Adw.PreferencesGroup(title="USB topology")
        usb_records = [{
            "_title": "  " * int(item.get("depth", 0)) + str(item.get("label", "USB node")),
            "_subtitle": "",
            "_icon": "usb-symbolic",
        } for item in data.get("usb_tree") or []]
        if usb_records:
            usb.add(detail_list(usb_records))
        else:
            usb.add(action_row("No USB topology", "The hardware scan returned no USB nodes."))
        self.hardware_right.append(usb)
        dmi = data.get("dmi", {})
        if dmi:
            firmware = Adw.PreferencesGroup(title="Firmware / DMI")
            for key, value in dmi.items() if isinstance(dmi, dict) else []:
                if key not in ("raw", "output"):
                    firmware.add(action_row(str(key).replace("_", " ").title(), str(value)))
            self.hardware_right.append(firmware)
        self.hardware_right.append(advanced_raw(data.get("raw", data)))

    def _refresh_services(self) -> None:
        self._refresh_scans("services", ("services",), self._render_services)

    def _render_services(self, scans: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]) -> None:
        row, data = scans["services"]
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
        self._refresh_scans("network", ("network",), self._render_network)

    def _render_network(self, scans: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]) -> None:
        row, data = scans["network"]
        self._clear_container(self.network_left)
        self._clear_container(self.network_right)
        self.network_status.set_title(
            f"{row['summary']} · {format_time(row['finished_us'])}" if row else "No network scan has completed yet"
        )
        interfaces = Adw.PreferencesGroup(title="Interfaces")
        addresses = {str(item.get("ifname")): item for item in data.get("addresses", [])}
        for item in data.get("links", []):
            name = str(item.get("ifname", "interface")); addr = addresses.get(name, {})
            ips = [str(info.get("local")) for info in addr.get("addr_info", []) if info.get("local")]
            stats = item.get("stats64") or item.get("stats") or {}
            errors = int((stats.get("rx") or {}).get("errors", 0)) + int((stats.get("tx") or {}).get("errors", 0))
            interfaces.add(action_row(name, f"{item.get('operstate', 'unknown')} · {', '.join(ips) or 'no address'} · {errors} errors", "network-wired-symbolic"))
        if not data.get("links"): interfaces.add(action_row("No interface data", "The network scan did not return structured link information."))
        self.network_left.append(interfaces)
        routes = Adw.PreferencesGroup(title="Routes")
        route_records = [{
            "_title": str(item.get("dst", "default")),
            "_subtitle": " · ".join(str(v) for v in (item.get("gateway"), item.get("dev"), item.get("protocol")) if v),
            "_icon": "go-jump-symbolic",
        } for item in data.get("routes", [])[:100]]
        if route_records:
            routes.add(detail_list(route_records))
        else:
            routes.add(action_row("No routes", "The network scan returned no route entries."))
        self.network_right.append(routes)
        listeners = Adw.PreferencesGroup(title="Listening sockets")
        listener_records = [{
            "_title": str(item.get("local", "socket")),
            "_subtitle": f"{item.get('protocol', '')} · {item.get('process') or 'process unavailable'}",
            "_icon": "network-server-symbolic",
        } for item in data.get("listeners", [])[:250]]
        if listener_records:
            listeners.add(detail_list(listener_records))
        else:
            listeners.add(action_row("No listening sockets", "The network scan returned no listening sockets."))
        self.network_left.append(listeners)
        self.network_right.append(advanced_raw(data.get("raw", data)))

    def _refresh_crashes(self) -> None:
        self._refresh_scans("crashes", ("crashes",), self._render_crashes)

    def _render_crashes(self, scans: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]) -> None:
        row, data = scans["crashes"]
        self._clear_container(self.crashes_content)
        entries = [dict(item) for item in data.get("entries", []) if isinstance(item, dict)]
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
            description="Select an entry for its path, metadata, and available captured log.",
        )
        if kernel_entries:
            kernel_records = [{
                **item,
                "_title": Path(str(item.get("path", "Crash artifact"))).name,
                "_subtitle": f"{format_file_size(int(item.get('size', 0) or 0))} · {format_time(int(item.get('mtime', 0) or 0) * 1_000_000)}",
                "_icon": "dialog-warning-symbolic" if "incomplete" in Path(str(item.get("path", ""))).name.lower() else "text-x-generic-symbolic",
            } for item in kernel_entries[:300]]
            kernel.add(detail_list(kernel_records, activated=self._show_crash_artifact))
        else:
            kernel.add(action_row("No kernel crash dumps found", "The most recent scan found no kernel dump artifacts.", "emblem-ok-symbolic"))
        self.crashes_content.append(kernel)

        other = Adw.PreferencesGroup(
            title=f"Application and supporting crash files ({len(other_entries)})",
            description="Select an entry for its path and retained metadata.",
        )
        if other_entries:
            other_records = [{
                **item,
                "_title": Path(str(item.get("path", "Crash artifact"))).name,
                "_subtitle": f"{format_file_size(int(item.get('size', 0) or 0))} · {format_time(int(item.get('mtime', 0) or 0) * 1_000_000)}",
                "_icon": "text-x-generic-symbolic",
            } for item in other_entries[:300]]
            other.add(detail_list(other_records, activated=self._show_crash_artifact))
        else:
            other.add(action_row("No other crash artifacts found", "No application crash reports were returned.", "emblem-ok-symbolic"))
        self.crashes_content.append(other)
        self.crashes_content.append(advanced_raw(data))

    def _refresh_updates(self) -> None:
        self._refresh_scans("updates", ("updates",), self._render_updates)

    def _render_updates(self, scans: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]]) -> None:
        row, data = scans["updates"]
        self._clear_container(self.updates_left)
        self._clear_container(self.updates_right)
        packages = Adw.PreferencesGroup(title=row["summary"] if row else "Update scan unavailable", description="Review and install updates with your normal package manager.")
        package_records = [{
            "_title": str(item.get("name", "package")),
            "_subtitle": f"{item.get('current_version', '?')} → {item.get('new_version', '?')} · {item.get('architecture', '')} · {item.get('repository', '')}",
            "_icon": "software-update-available-symbolic",
        } for item in data.get("packages", [])[:500]]
        if package_records:
            packages.add(detail_list(package_records))
        else:
            packages.add(action_row("No package upgrades reported", "The most recent scan found no parsed package upgrades.", "emblem-ok-symbolic"))
        self.updates_left.append(packages)
        firmware = Adw.PreferencesGroup(title="Firmware updates")
        fw_data = data.get("firmware") or {}
        devices = fw_data.get("Devices", fw_data.get("devices", [])) if isinstance(fw_data, dict) else []
        for device in devices:
            releases = device.get("Releases", device.get("releases", []))
            firmware.add(action_row(str(device.get("Name") or device.get("name") or "Device firmware"), f"{len(releases)} release(s) available", "application-x-firmware-symbolic"))
        if not devices: firmware.add(action_row("No firmware update reported", "Open Advanced to inspect the original fwupd response."))
        self.updates_right.append(firmware)
        self.updates_right.append(advanced_raw(data.get("raw", data)))

    def _refresh_forensics(self) -> None:
        self.forensics_request_id = getattr(self, "forensics_request_id", 0) + 1
        request_id = self.forensics_request_id
        future = self.executor.submit(self._query_forensics)
        future.add_done_callback(lambda done: GLib.idle_add(self._forensics_ready, done, request_id))

    @staticmethod
    def _query_forensics() -> list[dict[str, Any]]:
        with open_v2(readonly=True) as conn:
            rows = conn.execute(
                "SELECT c.*,i.summary,i.likely_cause,i.impact,i.remediation_json,i.source,i.unit_name "
                "FROM forensic_cases c JOIN incidents i ON i.id=c.incident_id "
                "ORDER BY c.occurred_us DESC LIMIT 200"
            ).fetchall()
        return [dict(row) for row in rows]

    def _forensics_ready(self, future: concurrent.futures.Future[list[dict[str, Any]]], request_id: int) -> bool:
        if self.closed or request_id != self.forensics_request_id:
            return GLib.SOURCE_REMOVE
        try:
            rows = future.result()
        except sqlite3.Error as exc:
            self.forensics_banner.set_title(f"Forensic case database unavailable: {exc}")
            return GLib.SOURCE_REMOVE
        self._render_forensics(rows)
        return GLib.SOURCE_REMOVE

    def _render_forensics(self, rows: list[dict[str, Any]]) -> None:
        self._clear_container(self.forensics_content)
        self.forensics_banner.set_title(
            f"{len(rows)} retained forensic case(s) · evidence is retained for one year · exact hardware telemetry for seven days"
        )
        cases = Adw.PreferencesGroup(title="Restart, crash, and hardware fault investigations")
        if rows:
            case_records = [{
                **row,
                "message": row.get("summary", ""),
                "last_boot_id": row.get("boot_id", "unknown"),
                "_title": str(row["title"]),
                "_subtitle": (
                    f"{row['severity']} · {format_time(int(row['occurred_us']))} · "
                    f"telemetry {format_time(int(row['window_start_us']))} — {format_time(int(row['window_end_us']))}"
                ),
                "_icon": "dialog-error-symbolic",
            } for row in rows]
            cases.add(detail_list(case_records, activated=self._open_incident, maximum_height=420))
        else:
            cases.add(action_row("No forensic cases retained", "Future hard resets, crashes, and significant hardware faults will be preserved here.", "emblem-ok-symbolic"))
        self.forensics_content.append(cases)

    def _refresh_boots(self) -> None:
        self.boots_request_id = getattr(self, "boots_request_id", 0) + 1
        request_id = self.boots_request_id
        future = self.executor.submit(self._query_boots)
        future.add_done_callback(lambda done: GLib.idle_add(self._boots_ready, done, request_id))

    @staticmethod
    def _query_boots() -> list[dict[str, Any]]:
        with open_v2(readonly=True) as conn:
            rows = conn.execute("SELECT boot_id,COUNT(*) evidence,COUNT(DISTINCT incident_id) incidents,MIN(occurred_us) first_us,MAX(occurred_us) last_us FROM evidence GROUP BY boot_id ORDER BY last_us DESC LIMIT 100").fetchall()
        return [dict(row) for row in rows]

    def _boots_ready(self, future: concurrent.futures.Future[list[dict[str, Any]]], request_id: int) -> bool:
        if self.closed or request_id != self.boots_request_id:
            return GLib.SOURCE_REMOVE
        try:
            rows = future.result()
        except sqlite3.Error:
            rows = []
        self._clear_container(self.boot_content)
        if rows:
            records = [{
                "_title": "Current boot" if index == 0 else f"Boot ending {format_time(row['last_us'])}",
                "_subtitle": f"{row['incidents']} incidents · {row['evidence']} evidence records · {format_time(row['first_us'])} — {format_time(row['last_us'])}",
                "_icon": "document-open-recent-symbolic",
            } for index, row in enumerate(rows)]
            self.boot_content.append(detail_list(records, maximum_height=520))
        else:
            empty = Adw.PreferencesGroup()
            empty.add(action_row("No indexed boots", "The collector has not indexed journal evidence yet."))
            self.boot_content.append(empty)
        return GLib.SOURCE_REMOVE

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
        output = run_command(argv, 25)
        if command_failed(output):
            return [], output
        records = parse_journal_json_lines(output)
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
        self.collector_active = collector
        self.collector_row.set_title("Collector live" if collector else "Collector offline")
        self.collector_row.set_subtitle(f"Database {'ready' if database else 'unavailable'} · helper {'ready' if helper else 'limited'}")
        if collector and database:
            self.health_banner.set_title("Continuous monitoring is active" + (" · deep hardware access ready" if helper else " · privileged hardware checks limited"))
        else:
            self.health_banner.set_title(f"Monitoring needs attention · {message or 'collector is not active'}")
        if hasattr(self, "tuning_apply"):
            self.tuning_apply.set_sensitive(collector and (self.tuning_governor.get_sensitive() or self.tuning_gpu_limit.get_sensitive()))
        return GLib.SOURCE_REMOVE

    def refresh_page(self, name: str) -> None:
        callbacks: dict[str, Callable[[], None]] = {
            "overview": lambda: (self._refresh_metrics(), self._refresh_overview_issues()),
            "forensics": self._refresh_forensics, "issues": self._refresh_incidents, "events": lambda: self._load_live(True),
            "performance": self._refresh_performance, "power": self._refresh_power, "hardware": self._refresh_hardware,
            "tuning": self._refresh_tuning,
            "services": self._refresh_services, "network": self._refresh_network,
            "crashes": self._refresh_crashes, "updates": self._refresh_updates,
            "boots": self._refresh_boots, "settings": self._refresh_storage,
        }
        if callback := callbacks.get(name): callback()

    def refresh_all(self) -> None:
        self._refresh_status(); self.refresh_page(self.stack.get_visible_child_name() or "overview")

    def _poll(self) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        if getattr(self, "poll_inflight", False):
            return GLib.SOURCE_CONTINUE
        self.poll_inflight = True
        future = self.executor.submit(self._incident_token)
        future.add_done_callback(lambda done: GLib.idle_add(self._poll_ready, done))
        return GLib.SOURCE_CONTINUE

    @staticmethod
    def _incident_token() -> tuple[int, ...] | None:
        try:
            with open_v2(readonly=True) as conn:
                return incident_change_token(conn)
        except sqlite3.Error:
            return None

    def _poll_ready(self, future: concurrent.futures.Future[tuple[int, ...] | None]) -> bool:
        self.poll_inflight = False
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            token = future.result()
        except Exception as exc:
            self.logger.debug("incident poll failed: %s", exc)
            return GLib.SOURCE_REMOVE
        if token is None:
            return GLib.SOURCE_REMOVE
        if token != self.last_token:
            self.last_token = token
            visible = self.stack.get_visible_child_name() or "overview"
            if visible == "events" and not self.live_follow.get_active(): return GLib.SOURCE_CONTINUE
            if visible == "overview": self._refresh_overview_issues()
            elif visible == "forensics": self._refresh_forensics()
            elif visible == "issues": self._refresh_incidents()
            elif visible == "events": self._load_live(True)
        return GLib.SOURCE_REMOVE

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
        path = self.report_dir / f"pc-diagnostics-{stamp}-{time.time_ns() % 1_000_000_000:09d}-redacted.txt"
        with open_v2(readonly=True) as conn:
            incidents = conn.execute("SELECT * FROM incidents ORDER BY last_us DESC LIMIT 1000").fetchall()
            scans = conn.execute("SELECT s.* FROM scans s JOIN (SELECT scan_type,MAX(finished_us) latest FROM scans GROUP BY scan_type) x ON x.scan_type=s.scan_type AND x.latest=s.finished_us").fetchall()
        text = "PC DIAGNOSTICS REPORT\n\n" + "\n\n".join(f"{r['severity']} | {r['title']}\n{r['sample_message']}\nCause: {r['likely_cause']}\nImpact: {r['impact']}" for r in incidents)
        text += "\n\nLATEST SCANS\n" + "\n\n".join(f"{r['scan_type']}: {r['summary']}\n{r['details_json']}" for r in scans)
        write_private_text(path, redact(text)); return path

    def _report_ready(self, future: concurrent.futures.Future[Path]) -> bool:
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            path = future.result()
            self.logger.info("redacted report exported")
            self.toast(f"Redacted report saved to {path}")
            self._refresh_storage()
        except Exception as exc:
            self.logger.warning("report export failed: %s", exc)
            self.toast(f"Report failed: {exc}")
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
        self.appearance = "system"
        self.starting = False
        self.startup_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="pcdiag-startup")

    @staticmethod
    def _load_startup_state() -> str:
        # Creating/upgrading the database can wait behind the collector. Keep
        # that work off GTK's main thread so activation remains responsive.
        with open_v2() as conn:
            return setting_value(conn, "appearance", "system")

    def _startup_ready(self, future: concurrent.futures.Future[str]) -> bool:
        self.starting = False
        try:
            self.appearance = apply_appearance(future.result())
            startup_error = ""
        except Exception as exc:
            # A visible window with an actionable health banner is more useful
            # than an activation traceback when storage is temporarily broken.
            startup_error = str(exc)
        if not self.window:
            self.window = DiagnosticsWindow(self)
        self.window.present()
        if startup_error:
            self.window.toast(f"Diagnostic storage is unavailable: {startup_error}")
        self.release()
        return GLib.SOURCE_REMOVE

    def do_activate(self) -> None:
        if not self.css_loaded:
            add_css()
            self.css_loaded = True
        if self.window:
            self.window.present()
            return
        if self.starting:
            return
        self.starting = True
        self.hold()
        future = self.startup_executor.submit(self._load_startup_state)
        future.add_done_callback(lambda done: GLib.idle_add(self._startup_ready, done))

    def do_shutdown(self) -> None:
        self.startup_executor.shutdown(wait=False, cancel_futures=True)
        Adw.Application.do_shutdown(self)


def main() -> int:
    return DiagnosticsApplication().run(None)


if __name__ == "__main__":
    raise SystemExit(main())
