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
	Kind    string `json:"kind"`
	Mode    string `json:"mode"`
	UID     uint32 `json:"uid"`
	Digest  string `json:"sha256,omitempty"`
	Problem string `json:"problem,omitempty"`
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

const maxHashBytes = 16 * 1024 * 1024

// Check the opened descriptor, not merely the path checked before opening.
// O_NONBLOCK prevents a substituted FIFO from blocking the audit.
func hashRegular(path string, initial fs.FileInfo) (string, error) {
	if initial.Size() > maxHashBytes {
		return "", errors.New("file exceeds hash limit")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || !os.SameFile(initial, before) || before.Size() > maxHashBytes {
		return "", errors.New("file changed before hashing or exceeds hash limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxHashBytes+1))
	if err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil {
		return "", err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if n > maxHashBytes || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(after, current) {
		return "", errors.New("file changed during hashing or exceeds hash limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func inventory(paths []string) (securitySnapshot, error) {
	result := securitySnapshot{Version: 1, Entries: map[string]securityEntry{}}
	var failures []error
	record := func(path string, entry securityEntry, err error) {
		if err != nil {
			entry.Problem = err.Error()
			failures = append(failures, fmt.Errorf("inventory %q: %w", path, err))
		}
		result.Entries[path] = entry
	}
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if errors.Is(walkErr, fs.ErrNotExist) && path == root {
				return nil
			}
			if walkErr != nil {
				record(path, securityEntry{Kind: "unreadable"}, walkErr)
				return nil
			}
			info, err := os.Lstat(path)
			if err != nil {
				record(path, securityEntry{Kind: "unreadable"}, err)
				return nil
			}
			entry := securityEntry{Mode: info.Mode().String()}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				entry.UID = st.Uid
			}
			switch {
			case info.Mode().IsRegular():
				entry.Kind = "file"
				entry.Digest, err = hashRegular(path, info)
			case info.Mode()&os.ModeSymlink != 0:
				entry.Kind = "symlink"
				var target string
				target, err = os.Readlink(path)
				if err == nil {
					hash := sha256.Sum256([]byte(target))
					entry.Digest = hex.EncodeToString(hash[:])
				}
			case info.IsDir():
				entry.Kind = "directory"
			default:
				entry.Kind = "other"
			}
			record(path, entry, err)
			return nil
		})
		if err != nil {
			record(root, securityEntry{Kind: "unreadable"}, err)
		}
	}
	return result, errors.Join(failures...)
}

func securityDifferences(old, current securitySnapshot) []string {
	var alerts []string
	for path, now := range current.Entries {
		if now.Problem != "" {
			alerts = append(alerts, fmt.Sprintf("ALERT SECURITY UNREADABLE %q: %q", path, now.Problem))
			continue
		}
		before, found := old.Entries[path]
		if !found {
			alerts = append(alerts, fmt.Sprintf("ALERT SECURITY ADDED %q", path))
			continue
		}
		if before != now {
			alerts = append(alerts, fmt.Sprintf("ALERT SECURITY MODIFIED %q", path))
		}
	}
	for path := range old.Entries {
		if _, found := current.Entries[path]; !found {
			uncertain := false
			for parent := filepath.Dir(path); parent != path; parent = filepath.Dir(parent) {
				if e, ok := current.Entries[parent]; ok && e.Kind == "unreadable" {
					uncertain = true
					break
				}
				if parent == filepath.Dir(parent) {
					break
				}
			}
			if uncertain {
				continue
			}
			alerts = append(alerts, fmt.Sprintf("ALERT SECURITY REMOVED %q", path))
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
		return fmt.Errorf("security baseline refused: incomplete inventory: %q", err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(securityStatePath), 0700); err != nil {
		return err
	}
	// Publish a complete private snapshot, never replacing an existing baseline.
	body, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(securityStatePath, append(body, '\n'), 0600, false); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("security baseline exists (%s); refuse overwrite; review alerts first", securityStatePath)
		}
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
		fmt.Println("WARN SECURITY inventory incomplete; remaining entries checked; removals under unreadable paths may be unverified")
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
