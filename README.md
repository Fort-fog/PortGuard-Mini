# PortGuard Mini

**Lightweight, self-hosted Linux server security monitoring in Go.**

PortGuard Mini checks SSH activity, listening TCP ports, services, running processes, and changes to security-sensitive files. It combines periodic baseline audits with an optional Linux inotify event watcher. No cloud account, database, Docker, or third-party Go modules are required.

> **Status: experimental (v0.8.1).** This is a monitoring and incident-investigation tool, **not** a proven intrusion-prevention system, antivirus, or replacement for operating-system security updates. Test it on a non-production system first.

**Documentation:** [Русская документация / Russian documentation](README-RU.md)

## Features

- **SSH:** inspect accepted SSH logins and compare root public-key fingerprints with a locally configured trusted list. An unknown fingerprint generates an alert; it does **not** prove a compromise.
- **File integrity:** compare metadata and SHA-256 digests of selected SSH, sudoers, cron, and systemd paths against a saved baseline. Detect added, modified, and removed entries.
- **Live filesystem events:** an optional, separate inotify watcher reports security-file changes to the systemd journal.
- **Network and processes:** inventory listening TCP ports, inspect established TCP connections and process associations, and flag selected unusual root executable locations or deleted executables.
- **Service health:** check selected services and PortGuard's own timer/event-watcher status.
- **Incident checks:** `emergency-check` inspects recent root SSH login records; `emergency-simulate` runs a safe classification example.
- **Manual emergency shutdown:** a separate explicit administrator-only command exists. **No automatic shutdown, session killing, or key rotation is enabled.**

## Requirements

- Linux with **systemd** and **journald** for the supplied service setup and SSH log checks.
- Linux inotify for optional event monitoring.
- Root permissions for installation, baseline creation, and full security-file auditing.
- **Go 1.23 or later** on the build machine. Go is not needed on a target server if you deploy a prebuilt binary.
- Standard Linux utilities used by the checks (including `ss`, `ps`, `systemctl`, and `journalctl`).

The current installer targets systemd-based Linux servers. Compatibility across all distributions and future OS versions has **not** been established.

## Build from source

```bash
git clone https://github.com/Fort-fog/PortGuard-Mini.git
cd PortGuard-Mini
go test ./...
go vet ./...
go build -o portguard .
sudo ./portguard audit
```

The above audit is intended to inspect the machine; it does not establish a security baseline or install a service. Review its output before proceeding.

## Install on a test server

Read both scripts **before** running them. `install.sh` installs the binary at `/usr/local/sbin/portguard` and installs/enables a **read-only** audit service with a five-minute systemd timer. It may replace existing PortGuard audit unit files; do not use it as an in-place updater on an already configured server.

```bash
sudo sh install.sh
systemctl list-timers portguard-mini.timer
journalctl -u portguard-mini.service -n 50 --no-pager
```

To add the optional continuous file-event watcher (a **separate** systemd service):

```bash
sudo sh install-event-watch.sh
systemctl is-active portguard-event.service
journalctl -u portguard-event.service -n 50 --no-pager
```

`install-event-watch.sh` refuses to overwrite an existing event-watcher unit. The watcher observes selected files and **does not** automatically block or repair anything.

## Baselines and audits

Create a security baseline **only after inspecting and trusting the current machine state**:

```bash
sudo /usr/local/sbin/portguard baseline-security
sudo /usr/local/sbin/portguard audit
```

- Security baseline: `/var/lib/portguard-mini/security.json`
- Optional TCP-listener baseline: `/var/lib/portguard-mini/ports.json` (created with `portguard baseline`)

The security-baseline command intentionally refuses to overwrite an existing baseline. **Do not erase or regenerate baselines to make an unexplained alert disappear.** Save and investigate differences first. Baselines are stored locally and can be tampered with by an attacker who already controls root.

## Trusted root SSH keys

You can explicitly enroll a **public-key fingerprint**, not a private key, after verifying it from a trusted source:

```bash
sudo /usr/local/sbin/portguard enroll-root-key SHA256:YOUR_VERIFIED_FINGERPRINT
sudo /usr/local/sbin/portguard emergency-check
sudo /usr/local/sbin/portguard emergency-simulate
```

The trusted fingerprint list is `/etc/portguard-mini/trusted-root-key-fingerprints`. Enrollment refuses to replace an existing list and does **not** edit `authorized_keys` or SSH server configuration. Without a trusted list, the check reports that classification is unconfigured.

A successful login with an unknown key is **an investigation signal, not independent proof of intrusion**. A known key may have been stolen, and root access can occur through non-SSH vulnerabilities.

## Commands and safety

| Command | Behavior |
| --- | --- |
| `audit` | Periodic, read-only checks and diagnostics |
| `baseline` | Save TCP-listener baseline |
| `baseline-security` | Save initial security-file baseline (no overwrite) |
| `watch-security` | Run live inotify event watcher (usually via systemd) |
| `enroll-root-key SHA256:...` | Create trusted root fingerprint list (no overwrite) |
| `emergency-check` | Read SSH login history and classify fingerprints |
| `emergency-simulate` | Safe, synthetic classification test |
| `emergency-off POWER_OFF` | **Dangerous**: explicitly request server shutdown |
| `apply`, `rollback`, `watch` | **Legacy configuration-changing paths:** review the source and implications before running; `watch` repeatedly invokes `apply` |

**Never schedule `watch` as a monitoring service.** The supplied `portguard-mini.timer` invokes `audit`, not `watch` or `apply`.

## Limitations

- inotify can miss events while the watcher is stopped and during queue overflow; a file event alone cannot identify an attacker.
- Periodic polling may miss short-lived network/process activity.
- Detection relies in part on Linux utilities and journal formats; unavailable or changed data can reduce visibility.
- Local logs and baselines cannot be trusted after a confirmed root compromise.
- PortGuard does not automatically disconnect sessions, rotate keys, isolate a host, or power it off.
- Long-term compatibility (10–20 years) is an engineering goal, **not a tested guarantee**.
- Continue using OS security updates, proper SSH configuration, firewall policies, backups, and recovery access through your hosting provider.

## Development

```bash
go test ./...
go vet ./...
go build -o portguard .
```

The repository contains Go sources, tests, `install.sh`, `install-event-watch.sh`, and extended [Russian documentation](README-RU.md).

## License

**No license file has been selected yet.** Until a license is added by the repository owner, do not assume permission to redistribute or modify the code beyond applicable law. Contributions and third-party packaging should wait for a clear licensing decision.
