#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "This helper installer must run as root." >&2
    exit 1
fi

target_user=${1:-}
install_tuning=${2:-}
case "$target_user" in
    ""|*[!A-Za-z0-9_.-]*) echo "Invalid target user" >&2; exit 1 ;;
esac
case "$install_tuning" in
    ""|--with-tuning) ;;
    *) echo "Usage: $0 USER [--with-tuning]" >&2; exit 1 ;;
esac
target_group=$(id -gn "$target_user")
case "$target_group" in
    ""|*[!A-Za-z0-9_.-]*) echo "Invalid target group" >&2; exit 1 ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -d -m 0755 /usr/libexec /etc/systemd/system
install -o root -g root -m 0755 "$script_dir/pcdiag_helper.py" /usr/libexec/pc-diagnostics-helper
install -o root -g root -m 0644 "$script_dir/pc-diagnostics-helper@.service" /etc/systemd/system/pc-diagnostics-helper@.service
sed -e "s|@USER@|$target_user|g" -e "s|@GROUP@|$target_group|g" \
    "$script_dir/pc-diagnostics-helper.socket.in" > /etc/systemd/system/pc-diagnostics-helper.socket
chown root:root /etc/systemd/system/pc-diagnostics-helper.socket
chmod 0644 /etc/systemd/system/pc-diagnostics-helper.socket
if [ "$install_tuning" = "--with-tuning" ]; then
    install -o root -g root -m 0755 "$script_dir/pcdiag_tuning_helper.py" /usr/libexec/pc-diagnostics-tuning-helper
    install -o root -g root -m 0644 "$script_dir/pc-diagnostics-tuning@.service" /etc/systemd/system/pc-diagnostics-tuning@.service
    sed -e "s|@USER@|$target_user|g" -e "s|@GROUP@|$target_group|g" \
        "$script_dir/pc-diagnostics-tuning.socket.in" > /etc/systemd/system/pc-diagnostics-tuning.socket
    chown root:root /etc/systemd/system/pc-diagnostics-tuning.socket
    chmod 0644 /etc/systemd/system/pc-diagnostics-tuning.socket
fi
systemctl daemon-reload
systemctl enable --now pc-diagnostics-helper.socket
if [ "$install_tuning" = "--with-tuning" ]; then
    systemctl enable --now pc-diagnostics-tuning.socket
fi

echo "PC Diagnostics privileged helper installed for $target_user"
