package main

import (
	"strings"
	"testing"
)

func TestTrustedSSHAddresses(t *testing.T) {
	got := trustedSSHAddresses("# administrator\n198.51.100.10 # trusted\nnot-an-ip\n\n")
	if len(got) != 1 || !got["198.51.100.10"] {
		t.Fatalf("unexpected trusted IPs: %#v", got)
	}
}
func TestParseSSHLogins(t *testing.T) {
	log := "Accepted publickey for root from 198.51.100.10 port 4000 ssh2\nAccepted publickey for root from 203.0.113.8 port 5000 ssh2\nFailed password for invalid user pi from 198.51.100.3 port 20 ssh2\n"
	found := parseSSHLogins(log, map[string]bool{"198.51.100.10": true})
	if len(found) != 2 || !strings.Contains(found[0], "TRUSTED") || !strings.Contains(found[1], "UNRECOGNIZED") {
		t.Fatalf("unexpected: %#v", found)
	}
}
func TestParseSSHLoginsNoTrustedList(t *testing.T) {
	found := parseSSHLogins("Accepted publickey for root from 198.51.100.10 port 20 ssh2\n", nil)
	if len(found) != 1 || !strings.Contains(found[0], "OBSERVED") {
		t.Fatalf("unexpected: %#v", found)
	}
}
