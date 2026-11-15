#!/bin/sh
# PortGuard v0.5: optional event watcher service, independent of audit timer.
# This script does not change SSH, firewall, website, or existing timer.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root' >&2; exit 1; fi
if [ ! -x /usr/local/sbin/portguard ]; then echo 'Missing installed /usr/local/sbin/portguard' >&2; exit 1; fi
if [ -e /etc/systemd/system/portguard-event.service ]; then
    echo 'Refusing to overwrite existing portguard-event.service' >&2
    exit 1
fi
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
