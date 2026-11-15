package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestEnrollTrustFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "trusted-root-key-fingerprints")
	if err := enrollRootKeyAt(path, testFingerprint); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), testFingerprint) {
		t.Fatal("fingerprint missing")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if err := enrollRootKeyAt(path, testFingerprint); err == nil {
		t.Fatal("must not overwrite existing trust file")
	}
}
func TestRejectInvalidRootFingerprint(t *testing.T) {
	for _, value := range []string{"", "SHA256:fake", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA extra"} {
		if validRootFingerprint(value) {
			t.Fatalf("accepted %q", value)
		}
	}
	if !validRootFingerprint(testFingerprint) {
		t.Fatal("known valid fingerprint rejected")
	}
}
