package main

import (
	"strings"
	"testing"
)

func TestEmergencyRejectsWithoutConfirmation(t *testing.T) {
	for _, arg := range []string{"", "power_off", "POWER-OFF"} {
		if err := emergencyOff(arg); err == nil {
			t.Fatalf("must reject %q", arg)
		}
	}
}

func TestParseRootLoginsAndClassify(t *testing.T) {
	log := `Accepted publickey for root from 198.51.100.10 port 1559 ssh2: ED25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Accepted publickey for root from 203.0.113.8 port 2345 ssh2: ED25519 SHA256:anotherTestFingerprint
Accepted password for root from 203.0.113.10 port 2346 ssh2
Accepted publickey for admin from 203.0.113.11 port 2347 ssh2: ED25519 SHA256:ignored`
	entries := parseRootLogins(log)
	if len(entries) != 3 {
		t.Fatalf("expected 3 root logins, got %#v", entries)
	}
	keys := parseTrustedRootKeys("# accepted key\nSHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
	if got := classifyRootLogin(entries[0], keys, true); !strings.HasPrefix(got, "TRUSTED") {
		t.Fatal(got)
	}
	if got := classifyRootLogin(entries[1], keys, true); !strings.Contains(got, "UNKNOWN ROOT KEY") {
		t.Fatal(got)
	}
	if got := classifyRootLogin(entries[2], keys, true); !strings.Contains(got, "UNVERIFIED") {
		t.Fatal(got)
	}
	if got := classifyRootLogin(entries[1], nil, false); !strings.HasPrefix(got, "UNCONFIGURED") {
		t.Fatal(got)
	}
}
