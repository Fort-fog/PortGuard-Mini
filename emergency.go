package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const trustedRootKeysPath = "/etc/portguard-mini/trusted-root-key-fingerprints"

// These are observations from sshd's journal, not proof of a compromised root.
// A key is trusted only if the administrator explicitly lists its fingerprint.
var rootLoginRE = regexp.MustCompile(`Accepted (publickey|password|keyboard-interactive/pam) for root from (\S+) port \d+(?: ssh2(?:: (\S+) (SHA256:[A-Za-z0-9+/=]+))?)?`)

type rootLogin struct{ Method, IP, Fingerprint string }

func parseRootLogins(log string) []rootLogin {
	var result []rootLogin
	seen := map[string]bool{}
	for _, line := range strings.Split(log, "\n") {
		match := rootLoginRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		entry := rootLogin{Method: match[1], IP: match[2], Fingerprint: match[4]}
		key := entry.Method + "|" + entry.IP + "|" + entry.Fingerprint
		if !seen[key] {
			result = append(result, entry)
			seen[key] = true
		}
	}
	return result
}

func parseTrustedRootKeys(data string) map[string]bool {
	keys := map[string]bool{}
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if strings.HasPrefix(line, "SHA256:") && len(line) > len("SHA256:") {
			keys[line] = true
		}
	}
	return keys
}

func classifyRootLogin(entry rootLogin, trusted map[string]bool, configured bool) string {
	if !configured {
		return "UNCONFIGURED (trusted fingerprints not configured; no classification)"
	}
	if entry.Method != "publickey" || entry.Fingerprint == "" {
		return "ALERT UNVERIFIED ROOT LOGIN (authentication fingerprint unavailable)"
	}
	if trusted[entry.Fingerprint] {
		return "TRUSTED KEY (not proof that session is safe)"
	}
	return "ALERT UNKNOWN ROOT KEY (investigate; not proof of intrusion)"
}

// Enrollment is an explicit administrative operation. Never modifies sshd or authorized_keys.
func validRootFingerprint(fingerprint string) bool {
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return false
	}
	encoded := strings.TrimPrefix(fingerprint, "SHA256:")
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
	return err == nil && len(raw) == 32
}

func enrollRootKeyAt(path, fingerprint string) error {
	if !validRootFingerprint(fingerprint) {
		return errors.New("expected valid SHA256 SSH public-key fingerprint")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if st, err := os.Lstat(directory); err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("trust directory must be a real directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return errors.New("trusted key file exists; refusing overwrite")
	}
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(file, "# PortGuard trusted root key fingerprint (not a private key)")
	if writeErr == nil {
		_, writeErr = fmt.Fprintln(file, fingerprint)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	return nil
}

func enrollRootKey(fingerprint string) error {
	if os.Geteuid() != 0 {
		return errors.New("enroll-root-key requires root")
	}
	if err := enrollRootKeyAt(trustedRootKeysPath, fingerprint); err != nil {
		return err
	}
	fmt.Println("TRUSTED ROOT KEY FINGERPRINT ENROLLED (SSH keys and access unchanged)")
	return nil
}

// Synthetic evidence only; no SSH access, system files, or poweroff operations.
func emergencySimulate() error {
	content, err := os.ReadFile(trustedRootKeysPath)
	if err != nil {
		return fmt.Errorf("configure trusted key first: %w", err)
	}
	keys := parseTrustedRootKeys(string(content))
	if len(keys) == 0 {
		return errors.New("trusted key list empty")
	}
	var known string
	for key := range keys {
		known = key
		break
	}
	unknown := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fmt.Println("SIMULATION ONLY: no real login, process termination, key rotation or shutdown")
	for _, entry := range []rootLogin{
		{Method: "publickey", IP: "192.0.2.10", Fingerprint: known},
		{Method: "publickey", IP: "192.0.2.11", Fingerprint: unknown},
		{Method: "password", IP: "192.0.2.12"},
	} {
		fmt.Printf("SIMULATED ROOT SSH LOGIN method=%s ip=%s fingerprint=%s status=%s\n", entry.Method, entry.IP, entry.Fingerprint, classifyRootLogin(entry, keys, true))
	}
	fmt.Println("SIMULATION COMPLETE: no shutdown is triggered by classification")
	return nil
}

func emergencyCheck() error {
	if os.Geteuid() != 0 {
		return errors.New("emergency-check requires root")
	}
	if !tool("systemctl") {
		return errors.New("systemctl unavailable")
	}
	if _, err := exec.LookPath("sync"); err != nil {
		return fmt.Errorf("sync unavailable: %w", err)
	}
	fmt.Println("EMERGENCY DRY RUN: no process termination, firewall change, key rotation or shutdown")
	content, err := os.ReadFile(trustedRootKeysPath)
	configured := err == nil
	if err != nil && !os.IsNotExist(err) {
		fmt.Println("WARN: cannot read trusted root key fingerprints:", err)
	}
	trusted := parseTrustedRootKeys(string(content))
	if configured && len(trusted) == 0 {
		fmt.Println("WARN: trusted root key list is empty")
	}
	if !tool("journalctl") {
		fmt.Println("WARN: journalctl unavailable; root logins cannot be reviewed")
		return nil
	}
	// -o cat retains the SSH authentication fingerprint in the sshd message.
	output, err := exec.Command("journalctl", "-t", "sshd", "--since", "-24 hours", "--no-pager", "-o", "cat", "-q").Output()
	if err != nil {
		fmt.Println("WARN: cannot read SSH journal:", err)
		return nil
	}
	logins := parseRootLogins(string(output))
	if len(logins) == 0 {
		fmt.Println("ROOT SSH LOGINS: none in last 24h (journal may be incomplete)")
	}
	for _, login := range logins {
		fmt.Printf("ROOT SSH LOGIN method=%s ip=%s fingerprint=%s status=%s\n", login.Method, login.IP, login.Fingerprint, classifyRootLogin(login, trusted, configured))
	}
	fmt.Println("NO AUTOMATIC SHUTDOWN: SSH logs and heuristics do not establish root compromise")
	return nil
}

// Explicit operator action only, never called by periodic audits or observers.
// poweroff disconnects all sessions, so killing specific SSH PIDs first adds no protection.
func emergencyOff(confirmation string) error {
	if confirmation != "POWER_OFF" {
		return errors.New("refusing shutdown: explicit argument POWER_OFF required")
	}
	if err := emergencyCheck(); err != nil {
		return err
	}
	reason := fmt.Sprintf("PortGuard MANUAL EMERGENCY SHUTDOWN %s; authorized operator request; no credential rotation", time.Now().UTC().Format(time.RFC3339))
	fmt.Println(reason)
	if tool("logger") {
		_ = exec.Command("logger", "-p", "authpriv.crit", "--", reason).Run()
	}
	if err := exec.Command("sync").Run(); err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}
	out, err := exec.Command("systemctl", "poweroff", "--no-wall").CombinedOutput()
	if err != nil {
		return fmt.Errorf("shutdown request failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("SHUTDOWN REQUESTED")
	return nil
}
