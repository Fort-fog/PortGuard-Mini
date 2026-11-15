package main

import "testing"

func TestParseConnections(t *testing.T) {
	sample := `0 0 192.0.2.10:34001 203.0.113.20:443 users:(("curl",pid=1234,fd=3))
0 0 127.0.0.1:41234 127.0.0.1:8080 users:(("app",pid=222,fd=4))
0 0 192.0.2.10:33001 203.0.113.21:443
`
	result := parseConnections(sample)
	if len(result) != 2 || result[0].pid != 1234 || result[1].pid != 222 {
		t.Fatalf("unexpected connections %+v", result)
	}
}
func TestEndpointClassification(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		external bool
	}{
		{"8.8.8.8:443", true}, {"[2606:4700:4700::1111]:443", true},
		{"127.0.0.1:8080", false}, {"192.168.1.1:22", false}, {"[::1]:443", false},
		{"[fe80::1%eth0]:53", false}, {"*:80", false},
	} {
		if externalEndpoint(tc.endpoint) != tc.external {
			t.Errorf("classification %s", tc.endpoint)
		}
	}
}
func TestUnusualExecutable(t *testing.T) {
	if !unusualExecutable("/tmp/.hidden/worker") || !unusualExecutable("/dev/shm/run (deleted)") || unusualExecutable("/usr/local/bin/mini-site") {
		t.Fatal("unusual executable classification")
	}
}
