#!/bin/sh
# PortGuard v0.5: optional event watcher service, independent of audit timer.
# This script does not change SSH, firewall, website, or existing timer.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root' >&2; exit 1; fi
if [ ! -x /usr/local/sbin/portguard ]; then echo 'Missing installed /usr/local/sbin/portguard' >&2; exit 1; fi
if [ -e /etc/systemd/system/portguard-event.service ] || [ -L /etc/systemd/system/portguard-event.service ] ||
    [ -e /etc/systemd/system/multi-user.target.wants/portguard-event.service ] || [ -L /etc/systemd/system/multi-user.target.wants/portguard-event.service ] ||
    systemctl cat portguard-event.service >/dev/null 2>&1; then
    echo 'Refusing to overwrite existing portguard-event.service' >&2
    exit 1
fi
cleanup() {
    status=$?
    trap - 0 HUP INT TERM
    if [ "$status" -ne 0 ]; then
        echo 'Event watcher installation failed; removing partial installation' >&2
        systemctl disable --now portguard-event.service || echo 'WARNING: event watcher stop failed' >&2
        rm -f /etc/systemd/system/portguard-event.service || echo 'WARNING: unit cleanup failed' >&2
        systemctl daemon-reload || echo 'WARNING: daemon-reload failed' >&2
    fi
    exit "$status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
cat > /etc/systemd/system/portguard-event.service <<'SERVICE'
[Unit]
Description=PortGuard Mini file change events (read only)
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/local/sbin/portguard watch-security
User=root
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable --now portguard-event.service
systemctl is-active portguard-event.service
printf '\nEvent watcher installed (READ ONLY).\nLogs: journalctl -u portguard-event.service -f\n'
printf 'Stop: systemctl disable --now portguard-event.service\n'
