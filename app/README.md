# PC Diagnostics

PC Diagnostics is a local GTK 4 diagnostic center for systemd-based Linux
workstations. It correlates journal evidence with validated health probes so an
issue is shown as a diagnosis rather than an unfiltered wall of log messages.

The Libadwaita interface uses adaptive navigation, health cards, history charts,
structured hardware/service/network views, and a virtualized live-event feed.
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
  from `/proc` once per second. These display-only samples are not written to
  the database. The collector records health metrics every 10 seconds;
  validated power, voltage, temperature, and GPU telemetry keeps exact
  ten-second samples for seven days, one-minute samples are retained for seven
  days, and 15-minute rollups for 90 days. Hardware faults, restart evidence,
  kernel failures, and crash evidence are retained for one year.
- The visible incident page refreshes every five seconds. Performance cards
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
