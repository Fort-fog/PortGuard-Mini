package main

// Self-checks and SSH login review. This module never disconnects a session,
// rotates credentials, changes firewall rules or edits systemd units.
import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var acceptedSSH = regexp.MustCompile(`Accepted (?:publickey|password|keyboard-interactive/pam) for (\S+) from (\S+) port \d+`)

const trustedSSHPath = "/etc/portguard-mini/trusted-ssh-ips"

func trustedSSHAddresses(content string) map[string]bool {
	trusted := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if ip := net.ParseIP(line); ip != nil {
			trusted[ip.String()] = true
		}
	}
	return trusted
}

func parseSSHLogins(log string, trusted map[string]bool) []string {
	seen := make(map[string]bool)
	var lines []string
	for _, line := range strings.Split(log, "\n") {
		m := acceptedSSH.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip := net.ParseIP(m[2])
		if ip == nil {
			continue
		}
		key := m[1] + "@" + ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(trusted) == 0 {
			lines = append(lines, "SSH LOGIN OBSERVED user="+m[1]+" ip="+ip.String()+" (no trusted IP list; no classification)")
		} else if !trusted[ip.String()] {
			lines = append(lines, "ALERT SSH LOGIN UNRECOGNIZED user="+m[1]+" ip="+ip.String()+" (review; NOT proof of intrusion)")
		} else {
			lines = append(lines, "SSH LOGIN TRUSTED user="+m[1]+" ip="+ip.String())
		}
	}
	return lines
}

func checkSSHLogins() {
	if !tool("journalctl") {
		fmt.Println("WARN SSH journalctl unavailable")
		return
	}
	trust := make(map[string]bool)
	if b, err := os.ReadFile(trustedSSHPath); err == nil {
		trust = trustedSSHAddresses(string(b))
	} else if !os.IsNotExist(err) {
		fmt.Println("WARN SSH trusted list unreadable:", err)
	}
	out, err := exec.Command("journalctl", "-t", "sshd", "--since", "-6 minutes", "--no-pager", "-o", "cat", "-q").Output()
	if err != nil {
		fmt.Println("WARN SSH login journal:", err)
		return
	}
	findings := parseSSHLogins(string(out), trust)
	if len(findings) == 0 {
		fmt.Println("SSH LOGIN REVIEW: no accepted logins in last 6 minutes")
		return
	}
	for _, line := range findings {
		fmt.Println(line)
	}
}

func checkSelfProtection() {
	if !tool("systemctl") {
		fmt.Println("WARN SELF systemctl unavailable")
		return
	}
	for _, unit := range []string{"portguard-mini.timer", "portguard-event.service"} {
		if !serviceActive(unit) {
			fmt.Println("ALERT SELF INACTIVE", unit)
		} else {
			fmt.Println("SELF ACTIVE", unit)
		}
		out, err := exec.Command("systemctl", "is-enabled", unit).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "enabled" {
			fmt.Printf("ALERT SELF NOT ENABLED %s state=%q\n", unit, strings.TrimSpace(string(out)))
		}
	}
	out, err := exec.Command("systemctl", "show", "portguard-event.service", "-p", "MainPID", "-p", "NRestarts", "-p", "Restart").Output()
	if err != nil {
		fmt.Println("WARN SELF event service metadata:", err)
		return
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			fields[pair[0]] = pair[1]
		}
	}
	if fields["Restart"] != "on-failure" && fields["Restart"] != "always" {
		fmt.Println("ALERT SELF restart policy unsuitable:", fields["Restart"])
	}
	pid, _ := strconv.Atoi(fields["MainPID"])
	if pid <= 1 {
		fmt.Println("ALERT SELF event watcher has no main PID")
	}
	fmt.Printf("SELF WATCHER pid=%d restarts=%s\n", pid, fields["NRestarts"])
}
