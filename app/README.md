# PC Diagnostics

PC Diagnostics is a local GTK 4 diagnostic center for systemd-based Linux
workstations. It correlates journal evidence with validated health probes so an
issue is shown as a diagnosis rather than an unfiltered wall of log messages.

The Libadwaita interface follows the system appearance and native Adwaita
typography, spacing, surfaces, and controls. Its adaptive layout is designed
for 1080p desktops at 100% and 125% scaling, with compact resource summaries,
a selectable resource chart, a sortable virtualized issue table, a side
inspector, structured hardware/service/network views, and virtualized feeds
for live events and large inventories.
Selecting an event opens an inspector with an offline confidence-rated probable
cause, a 250-record paginated incident timeline, nearby raw journal context, and
exact technical metadata. Repeated messages are collapsed into 30-second bursts
without deleting or hiding their underlying evidence.

## Coverage

- System/user journals, persistent kernel history, current dmesg, boot and suspend history.
- USB/xHCI/HID, GPU, storage/filesystem/NVMe, network/Bluetooth, ACPI, RAS, OOM, watchdog, service, crash, authentication, and input-sharing failures.
- SMART/NVMe health, validated temperatures, fans, disk capacity, CPU, memory, swap, load, iowait, GPU utilization, GPU board power/cap, explicitly identified component-voltage rails, interfaces, routes, listeners, firmware, and packages.
- Apport and kdump metadata, including incomplete and space-consuming crash dumps.
- Raw paginated access to the original journals and allowlisted protected logs.

Raw logs remain in journald and `/var/log`; the application does not copy the
machine's multi-gigabyte log archive. It stores correlated incidents and
one-minute/15-minute health rollups in:

    ~/.local/share/pc-diagnostics/events.sqlite3

Restart, crash, kernel, and hardware-fault evidence is retained for one year.
Exact ten-second and one-minute telemetry is retained for seven days; compact
15-minute trends are retained for 90 days.

## Refresh cadence and storage behavior

- Journal evidence is followed continuously and replayed from the last stored
  timestamp after a follower restart.
- The visible overview samples CPU, memory, swap, and root-disk use directly
  from `/proc` once per second and reads supported hardware sensors on its
  background executor every 10 seconds. These display-only samples are not
  written to the database. The collector records health metrics every 10 seconds;
  validated power, voltage, temperature, and GPU telemetry keeps exact
  ten-second samples for seven days, one-minute samples are retained for seven
  days, and 15-minute rollups for 90 days. Hardware faults, restart evidence,
  kernel failures, and crash evidence are retained for one year.
- The visible incident page refreshes every five seconds. Performance charts
  refresh from stored telemetry every 10 seconds; service and
  helper status refresh every 30 seconds.
- The Forensic cases view keeps a focused case for every retained restart,
  crash, kernel, or hardware-fault investigation, with its surrounding
  telemetry/evidence time window.

GPU board power is not whole-system, PSU, or wall-outlet power. The voltage view
accepts only rails that lm-sensors explicitly names; anonymous motherboard
`inN` channels are excluded because their mapping and scaling are board-specific.
Explicitly named CPU/SoC, DIMM/DRAM, and M.2/NVMe rails are collected under the
same ten-second/seven-day policy when the platform exposes them. NVMe and SPD
drivers commonly provide temperature but no voltage, which is shown as an
availability limitation rather than a fabricated reading.
- Large hardware, network, SMART, and sysstat results are current-state
  snapshots. A stable health state is updated in place; state transitions retain
  a separate history row. This prevents changing counters from growing the
  database without bound.

## Services

The user collector continuously follows journals and runs scheduled probes:

    systemctl --user status pc-diagnostics-collector.service

Install the packaged user command first, then copy the supplied unit template
into the user unit directory and enable it. A wheel installation places the
template under `/usr/share/pc-diagnostics/systemd/`; use the project-local
`systemd/` path only when running from a source checkout. The template uses the
standard command entry point rather than a development checkout path:

    install -D -m 0644 /usr/share/pc-diagnostics/systemd/pc-diagnostics-collector.service.example \
        ~/.config/systemd/user/pc-diagnostics-collector.service
    systemctl --user daemon-reload
    systemctl --user enable --now pc-diagnostics-collector.service

A root-owned socket helper exposes only six read-only operations: SMART, live
dmesg, DMI, crash metadata, allowlisted captured kernel-crash log previews, and
allowlisted protected log queries. It does not accept commands or arbitrary
paths:

    systemctl status pc-diagnostics-helper.socket

The Safe tuning page is capability-gated and disabled by default. Its isolated
elevated helper, when explicitly installed, accepts only CPU governor/frequency
bounds reported by the kernel and NVIDIA factory power limits reported by the
driver. It never exposes voltage, fan, clock-offset, PBO, firmware, or arbitrary
commands. A root-owned baseline is saved before the first temporary change;
every request is audited locally and a sustained critical temperature signal
restores that baseline automatically.

Install the read-only helper for one desktop user as root. Append
`--with-tuning` only when the owner has deliberately chosen to enable the
separate constrained tuning socket:

    sudo /usr/share/pc-diagnostics/helpers/install-helper.sh "$USER"
    sudo /usr/share/pc-diagnostics/helpers/install-helper.sh "$USER" --with-tuning

From a source checkout, replace `/usr/share/pc-diagnostics/helpers/` with
`./app/` in the two commands above.

## Privacy and repairs

Report export produces a redacted report for safe sharing. System/root repairs,
package upgrades, firmware flashing, mounts, deletes, and arbitrary commands are
never executed. A failed user-session service can be restarted or have its
failed state cleared only after a confirmation dialog shows the exact argv;
those two actions use a strict unit-name and command allowlist.

## Launch

    pc-diagnostics

The GUI is also installed in Plasma's application menu and autostarts after
login. Closing it does not stop the background collector.

## Interface, settings, and local storage

The welcome screen explains what PC Diagnostics does, how its background
collector supplies evidence, and where to begin. Select **Start guided tour**
to explore all 15 tabs in the actual interface. Each step explains the tab in
plain language, suggests a first action, and offers a **Good to know** note
about interpreting the data. The tour itself only navigates; it does not apply
controls or clear data.

Use **Back**, **Next tab**, or the tab picker to explore at your own pace.
**Pause tour** saves the current tab for your next visit. Open **Guide →
Welcome & guided tour** to continue or start again; choose **Help for this tab**
(or press **F1**) for contextual help. Navigating the sidebar while the guide
is open updates the explanation to match. **Explore on my own** dismisses
onboarding without marking the tour complete. The welcome screen is shown
once, including for users upgrading from the earlier text-only tutorial.

The **Settings** section also reopens the guide, lets you choose dark, light,
or system appearance, and shows the location of the private SQLite database
and the report folder. Both tutorial layouts support light and dark themes;
the welcome actions stay visible while its explanation scrolls.

Settings also shows the space used by the database/WAL files, redacted reports,
migration backups, and the bounded local application log. It can delete only
app-owned reports, backups, and logs after confirmation. Selected retained
diagnostic records can also be cleared transactionally; collection checkpoints
and preferences stay in place, so the collector continues normally. It never
deletes system journals, system crash artifacts, or files outside the folders
shown in Settings.

The packaged `io.github.d3v.PCDiagnostics` icon is an original monitor/pulse
mark installed with the desktop entry.
