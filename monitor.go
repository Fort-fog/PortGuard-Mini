package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A short read-only snapshot. An established TCP socket alone cannot reliably
// identify an outgoing connection, an attacker, or a compromised process.
var socketPID = regexp.MustCompile(`pid=(\d+)`)

type connection struct {
	pid    int
	local  string
	remote string
}

func parseConnections(output string) []connection {
	var result []connection
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		match := socketPID.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		pid, err := strconv.Atoi(match[1])
		if err != nil || pid <= 0 {
			continue
		}
		result = append(result, connection{pid: pid, local: fields[2], remote: fields[3]})
	}
	return result
}

func externalEndpoint(endpoint string) bool {
	host := endpoint
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]:"); i >= 0 {
			host = host[1:i]
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.SplitN(host, "%", 2)[0]
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func unusualExecutable(path string) bool {
	clean := strings.TrimSuffix(path, " (deleted)")
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if clean == dir || strings.HasPrefix(clean, dir+"/") {
			return true
		}
	}
	return false
}

func readProcess(pid int) (exe, uid string) {
	exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return exe, "?"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return exe, fields[1]
			}
		}
	}
	return exe, "?"
}

func checkProcessesAndConnections() {
	// ps %CPU is a moving average, not instantaneous CPU utilization.
	ps, err := exec.Command("ps", "-eo", "pid=,pcpu=,comm=", "--sort=-pcpu").Output()
	if err != nil {
		fmt.Println("WARN process snapshot:", err)
		return
	}
	fmt.Println("TOP CPU (ps %CPU moving average; not proof of malware):")
	lines := strings.Split(strings.TrimSpace(string(ps)), "\n")
	if len(lines) > 5 {
		lines = lines[:5]
	}
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			fmt.Println(" ", strings.TrimSpace(line))
		}
	}

	if !tool("ss") {
		fmt.Println("WARN network snapshot: ss unavailable")
		return
	}
	raw, err := exec.Command("ss", "-Htnp", "state", "established").CombinedOutput()
	if err != nil {
		fmt.Println("WARN network snapshot:", strings.TrimSpace(string(raw)))
		return
	}
	found := parseConnections(string(raw))
	remoteCount := 0
	flagged := 0
	seen := map[string]bool{}
	var alerts []string
	for _, c := range found {
		if !externalEndpoint(c.remote) {
			continue
		}
		remoteCount++
		exe, uid := readProcess(c.pid)
		reason := ""
		if unusualExecutable(exe) {
			reason = "executable in temporary directory"
		}
		if strings.HasSuffix(exe, " (deleted)") {
			if reason != "" {
				reason += "; "
			}
			reason += "running deleted executable"
		}
		if reason == "" {
			continue
		}
		key := strconv.Itoa(c.pid) + "|" + c.remote
		if seen[key] {
			continue
		}
		seen[key] = true
		flagged++
		alerts = append(alerts, fmt.Sprintf("ALERT SUSPICIOUS PROCESS pid=%d uid=%s exe=%q peer=%q (%s)", c.pid, uid, filepath.Clean(exe), c.remote, reason))
	}
	sort.Strings(alerts)
	fmt.Printf("TCP ESTABLISHED: %d sockets with process attribution; %d public remote endpoints; %d suspicious process/peer combinations\n", len(found), remoteCount, flagged)
	for i, line := range alerts {
		if i >= 20 {
			fmt.Printf("WARN %d additional alerts omitted\n", len(alerts)-i)
			break
		}
		fmt.Println(line)
	}
	fmt.Println("NOTE: socket polling misses short-lived traffic; no packet/byte accounting, auto-blocking or verified intrusion detection")
}
