package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// Fake commands isolate transaction tests from the host's installed services.
func fakeCommand(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestApplyPreservesPHPBodyAndLegacyMarker(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "php", "8.3", "apache2", "conf.d")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "99-portguard-mini.ini")
	old := marker + "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n"
	if err := os.WriteFile(path, []byte(old), 0640); err != nil {
		t.Fatal(err)
	}
	body := iniMarker + "expose_php = Off\ndisplay_errors = Off\n"
	var p plan
	if err := addFile(&p, path, body); err != nil {
		t.Fatal(err)
	}
	if err := applyPlan(p); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != body {
		t.Fatalf("PHP content %q: %v", data, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("original mode lost: %v, %v", info, err)
	}
	if p, err := removalPlan([]string{path}); err != nil || len(p) != 1 {
		t.Fatalf("new marker not recognized: %v, %v", p, err)
	}
}

func TestAffectedServicesOnlyChangedAndInstalled(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	fakeCommand(t, bin, "php-fpm8.3", `test "$1" = -t`)
	fakeCommand(t, bin, "sshd", `test "$1" = -t`)
	changes := []change{{path: sshManagedPath}, {path: "/etc/php/8.3/fpm/conf.d/99-portguard-mini.ini"}}
	if got := affectedServices(changes); !reflect.DeepEqual(got, []string{"ssh", "php8.3-fpm"}) {
		t.Fatalf("services: %v", got)
	}
	if err := validate([]string{"php8.3-fpm"}); err != nil {
		t.Fatal(err)
	}
	if got := affectedServices(nil); len(got) != 0 {
		t.Fatalf("empty plan includes services: %v", got)
	}
	fakeCommand(t, bin, "apache2ctl", `test "$1" = configtest`)
	if got := affectedServices([]change{{path: "/etc/php/8.3/apache2/conf.d/99-portguard-mini.ini"}}); !reflect.DeepEqual(got, []string{"apache2"}) {
		t.Fatalf("PHP Apache reload missing: %v", got)
	}
}

func TestRemovalPreflightDoesNotDeleteManagedFile(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "managed"), filepath.Join(dir, "unmanaged")
	if err := os.WriteFile(first, []byte(marker+"test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("administrator config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := removalPlan([]string{first, second}); err == nil {
		t.Fatal("unmanaged file accepted")
	}
	if b, err := os.ReadFile(first); err != nil || string(b) != marker+"test\n" {
		t.Fatalf("first file changed: %q %v", b, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	if _, err := removalPlan([]string{link}); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestRollbackValidationAndReloadRestore(t *testing.T) {
	for _, fail := range []string{"validation", "reload"} {
		t.Run(fail, func(t *testing.T) {
			dir := t.TempDir()
			bin := t.TempDir()
			t.Setenv("PATH", bin)
			if fail == "validation" {
				fakeCommand(t, bin, "nginx", "exit 1")
			} else {
				fakeCommand(t, bin, "nginx", "exit 0")
			}
			// Fail the first reload, then allow the recovery reload.
			t.Setenv("PG_TEST_RELOAD_MARK", filepath.Join(dir, "reload-seen"))
			fakeCommand(t, bin, "systemctl", `case "$1" in
is-active) exit 0;;
reload) if [ ! -e "$PG_TEST_RELOAD_MARK" ]; then : > "$PG_TEST_RELOAD_MARK"; exit 1; fi; exit 0;;
*) exit 1;; esac`)
			path := filepath.Join(dir, "managed")
			body := marker + "server_tokens off;\n"
			if err := os.WriteFile(path, []byte(body), 0640); err != nil {
				t.Fatal(err)
			}
			changes, err := removalPlan([]string{path})
			if err != nil {
				t.Fatal(err)
			}
			if err := rollbackChanges(changes, []string{"nginx"}); err == nil {
				t.Fatal("expected failure")
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != body {
				t.Fatalf("restore failed: %q %v", b, err)
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0640 {
				t.Fatalf("restore mode: %v %v", info, err)
			}
		})
	}
}

func TestApplyValidationFailureRestoresFiles(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	fakeCommand(t, bin, "nginx", "exit 1")
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	fresh := filepath.Join(dir, "fresh")
	body := marker + "old\n"
	if err := os.WriteFile(old, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	p := plan{reload: []string{"nginx"}}
	if err := addFile(&p, old, marker+"new\n"); err != nil {
		t.Fatal(err)
	}
	if err := addFile(&p, fresh, marker+"new\n"); err != nil {
		t.Fatal(err)
	}
	if err := applyPlan(p); err == nil {
		t.Fatal("validation failure ignored")
	}
	if b, err := os.ReadFile(old); err != nil || string(b) != body {
		t.Fatalf("old config not restored: %q %v", b, err)
	}
	if _, err := os.Lstat(fresh); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("new file not removed: %v", err)
	}
}

func TestPrivateBaselinePublicationDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := atomicWriteFile(path, []byte("original"), 0600, false); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("replacement"), 0600, false); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("replacement not refused: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "original" {
		t.Fatalf("baseline changed: %q %v", b, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
}

func TestInventoryContinuesAfterOversizedFile(t *testing.T) {
	dir := t.TempDir()
	bad, good := filepath.Join(dir, "a-oversized\nALERT forged"), filepath.Join(dir, "z-good")
	f, err := os.Create(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxHashBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	snap, err := inventory([]string{dir})
	if err == nil {
		t.Fatal("incomplete inventory accepted")
	}
	if snap.Entries[bad].Problem == "" || snap.Entries[good].Digest == "" {
		t.Fatalf("missing result: %+v", snap.Entries)
	}
	alerts := securityDifferences(securitySnapshot{}, snap)
	found := false
	for _, alert := range alerts {
		if strings.Contains(alert, "\n") {
			t.Fatalf("log injection: %q", alert)
		}
		if strings.Contains(alert, "ALERT SECURITY UNREADABLE") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing unreadable file alert")
	}
}

func TestHashRejectsFileReplacedBySymlinkOrFIFO(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			other := filepath.Join(dir, "other")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := os.WriteFile(other, []byte("secret"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := hashRegular(path, info); err == nil {
				t.Fatal("accepted replaced path")
			}
		})
	}
}

func TestRollbackWithoutWebServers(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	fakeCommand(t, bin, "sshd", `test "$1" = -t`)
	services := affectedServices([]change{{path: sshManagedPath}})
	path := filepath.Join(t.TempDir(), "managed")
	if err := os.WriteFile(path, []byte(marker+"DebianBanner no\n"), 0644); err != nil {
		t.Fatal(err)
	}
	changes, err := removalPlan([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if err := rollbackChanges(changes, services); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("file not removed: %v", err)
	}
}
