#!/bin/sh
# PortGuard Mini: fresh installation, periodic READ-ONLY audit only.
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
# Upgrades must replace only the binary after a separate review, not rerun the installer.
for path in /usr/local/sbin/portguard /etc/systemd/system/portguard-mini.service /etc/systemd/system/portguard-mini.timer /etc/systemd/system/timers.target.wants/portguard-mini.timer; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        echo "Refusing to overwrite existing installation: $path" >&2
        exit 1
    fi
done
for unit in portguard-mini.service portguard-mini.timer; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
        echo "Refusing to overwrite existing unit: $unit" >&2
        exit 1
    fi
done
if ! ./portguard audit; then
    echo 'Audit failed, refusing install' >&2
    exit 1
fi
# Preflight above ensures these paths were absent. Clean up only this attempt.
binary_created=0
service_created=0
timer_created=0
cleanup() {
    status=$?
    trap - 0 HUP INT TERM
    if [ "$status" -ne 0 ]; then
        echo 'Installation failed; removing partial installation' >&2
        if [ "$timer_created" -eq 1 ]; then
            systemctl disable --now portguard-mini.timer || echo 'WARNING: timer cleanup failed' >&2
        fi
        if [ "$service_created" -eq 1 ]; then
            systemctl stop portguard-mini.service || echo 'WARNING: audit stop failed' >&2
            rm -f /etc/systemd/system/portguard-mini.service || echo 'WARNING: service cleanup failed' >&2
        fi
        if [ "$timer_created" -eq 1 ]; then rm -f /etc/systemd/system/portguard-mini.timer || echo 'WARNING: timer file cleanup failed' >&2; fi
        if [ "$binary_created" -eq 1 ]; then rm -f /usr/local/sbin/portguard || echo 'WARNING: binary cleanup failed' >&2; fi
        systemctl daemon-reload || echo 'WARNING: daemon-reload failed' >&2
    fi
    exit "$status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
binary_created=1
install -m 0755 ./portguard /usr/local/sbin/portguard
mkdir -p /etc/systemd/system
service_created=1
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
timer_created=1
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
systemctl is-active --quiet portguard-mini.timer
printf '\nPortGuard Mini installed (READ-ONLY AUDIT MODE).\n'
printf 'Check: systemctl list-timers portguard-mini.timer\n'
printf 'Logs: journalctl -u portguard-mini.service -n 50 --no-pager\n'
printf 'Stop: systemctl disable --now portguard-mini.timer\n'
printf 'Manual apply is NOT scheduled; only run it after reviewing changes.\n'
