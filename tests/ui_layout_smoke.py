"""Interactive GTK geometry checks for the adaptive desktop layout.

Run this on a graphical session; it uses an isolated temporary data directory
and never reads or changes the user's retained diagnostics.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))


def pump(ui: object, seconds: float = 0.2) -> None:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        while ui.GLib.MainContext.default().pending():
            ui.GLib.MainContext.default().iteration(False)
        time.sleep(0.01)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="pcdiag-layout-") as directory:
        os.environ["XDG_DATA_HOME"] = directory
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        import pc_diagnostics as ui

        ui.Adw.init()
        if ui.Gdk.Display.get_default() is None:
            raise SystemExit("A graphical GTK session is required")
        ui.add_css()
        ui.apply_appearance("system")
        with ui.open_v2():
            pass
        app = ui.Adw.Application(
            application_id="io.github.d3v.PCDiagnostics.LayoutCheck",
            flags=ui.Gio.ApplicationFlags.NON_UNIQUE,
        )
        app.appearance = "system"
        app.window = None
        app.register(None)
        with (
            patch.object(ui, "configure_logging", return_value=logging.getLogger("pcdiag-layout")),
            patch.object(ui.DiagnosticsWindow, "_check_tutorial"),
            patch.object(ui.DiagnosticsWindow, "refresh_all"),
            patch.object(ui.DiagnosticsWindow, "refresh_page"),
            patch.object(ui.DiagnosticsWindow, "_refresh_storage"),
        ):
            window = ui.DiagnosticsWindow(app)
            app.window = window
            for source_id in window.timeout_ids:
                ui.GLib.source_remove(source_id)
            window.timeout_ids.clear()
            window.present()
            pump(ui, 0.4)

            assert window.nav_list.measure(ui.Gtk.Orientation.VERTICAL, 230)[0] <= 600
            for name in window.page_builders:
                assert window._ensure_page(name)
            for name, maximum_height in (
                ("overview", 769),
                ("performance", 769),
                ("tuning", 769),
                ("settings", 769),
            ):
                page = window.stack.get_child_by_name(name)
                body = page.get_child().get_child()
                assert body.measure(ui.Gtk.Orientation.VERTICAL, 1270)[1] <= maximum_height

            metric_flow = window.metric_cards["cpu"].get_parent().get_parent()
            metric_height = metric_flow.measure(ui.Gtk.Orientation.VERTICAL, 1270)[1]
            assert metric_height <= 240, f"status grid is {metric_height}px tall"

            readings = ui.concurrent.futures.Future()
            readings.set_result(({}, {
                "temperature.CPU Tctl": 96.0,
                "temperature.AMD iGPU edge": 68.0,
                "power.AMD graphics PPT.watts": 41.0,
            }))
            window.metrics_request_id = 7
            window._metrics_ready(readings, 7)
            assert window.metric_cards["temperature"].value.get_text() == "96.0°C"
            assert window.metric_cards["temperature"].get_subtitle() == "CPU Tctl · live sensor"
            assert window.metric_cards["gpu_temperature"].value.get_text() == "68.0°C"
            assert window.metric_cards["power"].value.get_text() == "41 W"
            assert window.metric_cards["gpu"].value.get_text() == "Unavailable"
            window._start_tour("overview")
            pump(ui, 0.3)
            assert window.guide_revealer.get_child().get_height() <= 150

            records = [{"_title": f"Item {index}", "_subtitle": "Detail"} for index in range(500)]
            inventory = ui.detail_list(records)
            view = inventory.get_child()
            assert view.get_model().get_n_items() == 500

            window.close()
            pump(ui)
    print("GTK layout smoke check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
