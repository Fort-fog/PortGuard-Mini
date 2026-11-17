package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSecurityInventoryDetectsAddChangeDelete(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "authorized_keys")
	if err := os.WriteFile(a, []byte("key-one\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old, err := inventory([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("key-two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(root, "new.service")
	if err := os.WriteFile(b, []byte("unit"), 0644); err != nil {
		t.Fatal(err)
	}
	now, err := inventory([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	alerts := strings.Join(securityDifferences(old, now), "\n")
	if !strings.Contains(alerts, "MODIFIED "+strconv.Quote(a)) || !strings.Contains(alerts, "ADDED "+strconv.Quote(b)) {
		t.Fatal(alerts)
	}
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	last, err := inventory([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	alerts = strings.Join(securityDifferences(now, last), "\n")
	if !strings.Contains(alerts, "REMOVED "+strconv.Quote(a)) {
		t.Fatal(alerts)
	}
}
func TestSecurityInventoryDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	got, err := inventory([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if got.Entries[filepath.Join(root, "link")].Kind != "symlink" {
		t.Fatal(got)
	}
	if _, ok := got.Entries[secret]; ok {
		t.Fatal("followed symlink")
	}
}
