#!/bin/sh
# PortGuard Mini v0.2.1: periodic READ-ONLY audit only.
# Does not call apply, change SSH, firewall, Fail2ban, or the Go site.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root: sudo sh install.sh' >&2
    exit 1
fi
cd "$(dirname "$0")"
if [ ! -f ./portguard ]; then
    echo 'Missing binary ./portguard' >&2
    exit 1
fi
if ! ./portguard audit; then
    echo 'Audit failed, refusing install' >&2
    exit 1
fi
install -m 0755 ./portguard /usr/local/sbin/portguard
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/portguard-mini.service <<'SERVICE'
[Unit]
Description=PortGuard Mini read-only audit of services, TCP ports and headers
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/portguard audit
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
SERVICE
cat > /etc/systemd/system/portguard-mini.timer <<'TIMER'
[Unit]
Description=PortGuard Mini read-only audit every 5 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
Unit=portguard-mini.service
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now portguard-mini.timer
printf '\nPortGuard Mini installed (READ-ONLY AUDIT MODE).\n'
printf 'Check: systemctl list-timers portguard-mini.timer\n'
printf 'Logs: journalctl -u portguard-mini.service -n 50 --no-pager\n'
printf 'Stop: systemctl disable --now portguard-mini.timer\n'
printf 'Manual apply is NOT scheduled; only run it after reviewing changes.\n'
