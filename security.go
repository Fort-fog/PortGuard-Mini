package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// The inventory contains hashes and metadata only, never private key contents.
const securityStatePath = "/var/lib/portguard-mini/security.json"

type securityEntry struct {
	Kind   string `json:"kind"`
	Mode   string `json:"mode"`
	UID    uint32 `json:"uid"`
	Digest string `json:"sha256,omitempty"`
}
type securitySnapshot struct {
	Version int                      `json:"version"`
	Entries map[string]securityEntry `json:"entries"`
}

var securityTargets = []string{
	"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
	"/etc/sudoers", "/etc/sudoers.d", "/root/.ssh",
	"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
	"/var/spool/cron/crontabs", "/etc/systemd/system", "/usr/local/lib/systemd/system",
}

func inventory(paths []string) (securitySnapshot, error) {
	result := securitySnapshot{Version: 1, Entries: map[string]securityEntry{}}
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if errors.Is(walkErr, fs.ErrNotExist) && path == root {
				return nil
			}
			if walkErr != nil {
				return fmt.Errorf("inventory %s: %w", path, walkErr)
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			entry := securityEntry{Mode: info.Mode().String()}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				entry.UID = st.Uid
			}
			switch {
			case info.Mode().IsRegular():
				entry.Kind = "file"
				if info.Size() > 16*1024*1024 {
					return fmt.Errorf("refusing to hash oversized file %s", path)
				}
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				h := sha256.New()
				_, copyErr := io.Copy(h, f)
				closeErr := f.Close()
				if copyErr != nil {
					return copyErr
				}
				if closeErr != nil {
					return closeErr
				}
				entry.Digest = hex.EncodeToString(h.Sum(nil))
			case info.Mode()&os.ModeSymlink != 0:
				entry.Kind = "symlink"
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				hash := sha256.Sum256([]byte(target))
				entry.Digest = hex.EncodeToString(hash[:])
			case info.IsDir():
				entry.Kind = "directory"
			default:
				entry.Kind = "other"
			}
			result.Entries[path] = entry
			return nil
		})
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func securityDifferences(old, current securitySnapshot) []string {
	var alerts []string
	for path, now := range current.Entries {
		before, found := old.Entries[path]
		if !found {
			alerts = append(alerts, "ALERT SECURITY ADDED "+path)
			continue
		}
		if before != now {
			alerts = append(alerts, "ALERT SECURITY MODIFIED "+path)
		}
	}
	for path := range old.Entries {
		if _, found := current.Entries[path]; !found {
			alerts = append(alerts, "ALERT SECURITY REMOVED "+path)
		}
	}
	sort.Strings(alerts)
	return alerts
}

func securityBaseline() error {
	if os.Geteuid() != 0 {
		return errors.New("baseline-security requires root")
	}
	snapshot, err := inventory(securityTargets)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(securityStatePath), 0700); err != nil {
		return err
	}
	// Never silently overwrite an existing trusted baseline.
	f, err := os.OpenFile(securityStatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("security baseline exists (%s); refuse overwrite; review alerts first", securityStatePath)
	}
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(snapshot, "", "  ")
	if err == nil {
		_, err = f.Write(append(body, '\n'))
	}
	if syncErr := f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(securityStatePath)
		return err
	}
	fmt.Printf("SECURITY BASELINE SAVED %s (%d entries)\n", securityStatePath, len(snapshot.Entries))
	return nil
}
func checkSecurity() {
	if !serviceActive("fail2ban") {
		fmt.Println("ALERT SECURITY fail2ban not active")
	}
	if !serviceActive("portguard-mini.timer") {
		fmt.Println("WARN SECURITY PortGuard timer not active")
	}
	oldBytes, err := os.ReadFile(securityStatePath)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Println("NOTE: security baseline unset; review server then run baseline-security once")
		return
	}
	if err != nil {
		fmt.Println("WARN SECURITY baseline unreadable:", err)
		return
	}
	var old securitySnapshot
	if err := json.Unmarshal(oldBytes, &old); err != nil || old.Version != 1 || old.Entries == nil {
		fmt.Println("WARN SECURITY baseline invalid")
		return
	}
	current, err := inventory(securityTargets)
	if err != nil {
		fmt.Println("WARN SECURITY inventory failed:", err)
		return
	}
	alerts := securityDifferences(old, current)
	fmt.Printf("SECURITY INVENTORY: %d paths; %d changed\n", len(current.Entries), len(alerts))
	for i, alert := range alerts {
		if i >= 40 {
			fmt.Printf("WARN SECURITY %d additional changes omitted\n", len(alerts)-i)
			break
		}
		fmt.Println(strings.TrimSpace(alert))
	}
}

// A sampled root-process check complements the file inventory. It does not
// claim to detect short-lived processes or kernel-level compromise.
func checkRootProcesses() {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Println("WARN SECURITY process enumeration:", err)
		return
	}
	count := 0
	alerts := 0
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		exe, uid := readProcess(pid)
		if uid != "0" || exe == "" {
			continue
		}
		count++
		if !unusualExecutable(exe) && !strings.HasSuffix(exe, " (deleted)") {
			continue
		}
		alerts++
		if alerts <= 20 {
			fmt.Printf("ALERT ROOT PROCESS pid=%d exe=%q\n", pid, exe)
		}
	}
	fmt.Printf("ROOT PROCESSES: %d visible, %d unusual executable paths/deleted binaries\n", count, alerts)
	if alerts > 20 {
		fmt.Printf("WARN ROOT PROCESS %d additional alerts omitted\n", alerts-20)
	}
}
