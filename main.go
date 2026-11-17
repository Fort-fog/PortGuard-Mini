// PortGuard Mini: conservative, dependency-free banner hardening for Debian/Ubuntu VPS.
// It never changes firewall, listening ports, SSH authentication, or application code.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const sshManagedPath = "/etc/ssh/sshd_config.d/00-portguard-mini.conf"
const statePath = "/var/lib/portguard-mini/ports.json"
const marker = "# Managed by PortGuard Mini - do not edit; remove via portguard rollback\n"

const iniMarker = "; Managed by PortGuard Mini - do not edit; remove via portguard rollback\n"

type change struct {
	path      string
	old, body []byte
	existed   bool
	mode      fs.FileMode
}

func managed(body []byte) bool {
	return strings.HasPrefix(string(body), marker) || strings.HasPrefix(string(body), iniMarker)
}

type plan struct {
	files  []change
	reload []string
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
func tool(n string) bool   { _, err := exec.LookPath(n); return err == nil }
func run(name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
func serviceActive(s string) bool {
	return tool("systemctl") && run("systemctl", "is-active", "--quiet", s) == nil
}
func addFile(p *plan, path, body string) error {
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", path)
		}
		old, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(old) == body {
			return nil
		}
		if !managed(old) {
			return fmt.Errorf("%s: existing unmanaged file, refusing overwrite", path)
		}
		p.files = append(p.files, change{path: path, old: old, body: []byte(body), existed: true, mode: st.Mode().Perm()})
	} else if errors.Is(err, fs.ErrNotExist) {
		p.files = append(p.files, change{path: path, body: []byte(body)})
	} else {
		return err
	}
	return nil
}
func atomicWrite(path string, data []byte) error {
	return atomicWriteMode(path, data, 0644)
}
func atomicWriteMode(path string, data []byte, mode fs.FileMode) error {
	return atomicWriteFile(path, data, mode, true)
}

// Baselines are published atomically without replacing an existing reference.
func atomicWriteFile(path string, data []byte, mode fs.FileMode, replace bool) error {
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s not directory", dir)
	}
	temp, err := os.CreateTemp(dir, ".portguard-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err = temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if !replace {
		return os.Link(name, path)
	}
	return os.Rename(name, path)
}
func restore(changes []change) error {
	var failures []string
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i]
		var err error
		if c.existed {
			err = atomicWriteMode(c.path, c.old, c.mode)
		} else {
			err = os.Remove(c.path)
			if errors.Is(err, fs.ErrNotExist) {
				err = nil
			}
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", c.path, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}
func nginxHasStandardConfDInclude(conf []byte) bool {
	const target = "/etc/nginx/conf.d/*.conf"
	for _, raw := range strings.Split(string(conf), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasSuffix(line, ";") {
			continue
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, ";"))
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "include" && fields[1] == target {
			return true
		}
	}
	return false
}

func collect() (plan, error) {
	var p plan
	if exists("/etc/apache2/conf-enabled") && tool("apache2ctl") {
		path := "/etc/apache2/conf-enabled/zz-portguard-mini.conf"
		data := marker + "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n"
		if err := addFile(&p, path, data); err != nil {
			return p, err
		}
	}
	if exists("/etc/nginx/conf.d") && tool("nginx") {
		// Only use the standard conf.d include; do not alter the main nginx.conf.
		conf, err := os.ReadFile("/etc/nginx/nginx.conf")
		if err != nil {
			return p, err
		}
		if nginxHasStandardConfDInclude(conf) {
			path := "/etc/nginx/conf.d/zz-portguard-mini.conf"
			if err := addFile(&p, path, marker+"server_tokens off;\n"); err != nil {
				return p, err
			}
		} else {
			fmt.Println("WARN nginx: standard conf.d include missing; manual review needed")
		}
	}
	// Only Debian/Ubuntu standard PHP SAPI layout. Never modify CLI PHP.
	dirs, _ := filepath.Glob("/etc/php/*/*/conf.d")
	sort.Strings(dirs)
	for _, dir := range dirs {
		sapi := filepath.Base(filepath.Dir(dir))
		if sapi != "fpm" && sapi != "apache2" && sapi != "cgi" {
			continue
		}
		file := filepath.Join(dir, "99-portguard-mini.ini")
		if err := addFile(&p, file, iniMarker+"expose_php = Off\ndisplay_errors = Off\n"); err != nil {
			return p, err
		}

	}
	// Ubuntu OpenSSH supports DebianBanner. The existing admin-managed
	// 00-portguard.conf is left untouched when already effective.
	if tool("sshd") && exists("/etc/ssh/sshd_config.d") {
		value, err := sshBannerSetting()
		if err != nil {
			fmt.Printf("WARN SSH: %v; SSH configuration skipped\n", err)
		} else if value != "no" {
			if err := addFile(&p, sshManagedPath, marker+"DebianBanner no\n"); err != nil {
				return p, err
			}
		}
	}
	p.reload = affectedServices(p.files)
	return p, nil
}
func sshBannerSetting() (string, error) {
	out, err := exec.Command("sshd", "-T").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sshd -T: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "debianbanner" {
			return fields[1], nil
		}
	}
	return "", errors.New("sshd does not expose DebianBanner; SSH changes unsupported")
}
func validate(services []string) error {
	for _, s := range unique(services) {
		switch s {
		case "apache2":
			if err := run("apache2ctl", "configtest"); err != nil {
				return err
			}
		case "nginx":
			if err := run("nginx", "-t"); err != nil {
				return err
			}
		case "ssh":
			if err := run("sshd", "-t"); err != nil {
				return err
			}
			v, err := sshBannerSetting()
			if err != nil {
				return err
			}
			if v != "no" {
				return errors.New("SSH DebianBanner no not effective; refusing reload")
			}
		default:
			if strings.HasPrefix(s, "php") && strings.HasSuffix(s, "-fpm") {
				bin := phpFPMBinary(s)
				if tool(bin) || serviceActive(s) {
					if err := run(bin, "-t"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func unique(a []string) []string {
	m := map[string]bool{}
	var r []string
	for _, s := range a {
		if !m[s] {
			m[s] = true
			r = append(r, s)
		}
	}
	return r
}
func apply() error {
	if os.Geteuid() != 0 {
		return errors.New("apply requires root")
	}
	p, err := collect()
	if err != nil {
		return err
	}
	return applyPlan(p)
}

func applyPlan(p plan) error {
	if len(p.files) == 0 {
		fmt.Println("OK: managed configurations already up to date")
		return nil
	}
	fmt.Printf("Applying %d managed configuration files\n", len(p.files))
	written := []change{}
	for _, c := range p.files {
		mode := fs.FileMode(0644)
		if c.existed {
			mode = c.mode
		}
		if err := atomicWriteMode(c.path, c.body, mode); err != nil {
			return fmt.Errorf("write %s failed; rollback=%v: %w", c.path, restore(written), err)
		}
		written = append(written, c)
		fmt.Println("UPDATED", c.path)
	}
	if err := validate(p.reload); err != nil {
		restoreErr := restore(written)
		return fmt.Errorf("validation failed; rollback=%v: %w", restoreErr, err)
	}
	for _, s := range unique(p.reload) {
		if !serviceActive(s) {
			continue
		}
		if err := run("systemctl", "reload", s); err != nil {
			restoreErr := restoreAndReload(written, p.reload)
			return fmt.Errorf("reload %s failed; rollback=%v: %w", s, restoreErr, err)
		}
		fmt.Println("RELOADED", s)
	}
	fmt.Println("OK: hardening applied and services validated")
	return nil
}

// Preflight every file before making any change; never remove an unmanaged file.
func removalPlan(paths []string) ([]change, error) {
	var changes []change
	for _, path := range paths {
		st, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing to remove non-regular file: %s", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !managed(b) {
			return nil, fmt.Errorf("refusing to remove unmanaged file: %s", path)
		}
		changes = append(changes, change{path: path, old: b, existed: true, mode: st.Mode().Perm()})
	}
	return changes, nil
}

// Debian/Ubuntu ships php-fpm8.x, while its systemd unit is php8.x-fpm.
func phpFPMBinary(service string) string {
	return "php-fpm" + strings.TrimSuffix(strings.TrimPrefix(service, "php"), "-fpm")
}

func affectedServices(changes []change) []string {
	var services []string
	for _, c := range changes {
		switch c.path {
		case sshManagedPath:
			if tool("sshd") || serviceActive("ssh") {
				services = append(services, "ssh")
			}
		case "/etc/apache2/conf-enabled/zz-portguard-mini.conf":
			if tool("apache2ctl") || serviceActive("apache2") {
				services = append(services, "apache2")
			}
		case "/etc/nginx/conf.d/zz-portguard-mini.conf":
			if tool("nginx") || serviceActive("nginx") {
				services = append(services, "nginx")
			}
		default:
			dir := filepath.Dir(filepath.Dir(c.path))
			switch filepath.Base(dir) {
			case "apache2":
				if tool("apache2ctl") || serviceActive("apache2") {
					services = append(services, "apache2")
				}
			case "fpm":
				service := "php" + filepath.Base(filepath.Dir(dir)) + "-fpm"
				if tool(phpFPMBinary(service)) || serviceActive(service) {
					services = append(services, service)
				}
			}
		}
	}
	return unique(services)
}
func restoreAndReload(changes []change, services []string) error {
	err := restore(changes)
	if err != nil {
		return err
	}
	var errs []error
	for _, service := range unique(services) {
		if serviceActive(service) {
			if e := run("systemctl", "reload", service); e != nil {
				errs = append(errs, e)
			}
		}
	}
	return errors.Join(errs...)
}
func rollback() error {
	if os.Geteuid() != 0 {
		return errors.New("rollback requires root")
	}
	paths := []string{"/etc/apache2/conf-enabled/zz-portguard-mini.conf", "/etc/nginx/conf.d/zz-portguard-mini.conf", sshManagedPath}
	dirs, _ := filepath.Glob("/etc/php/*/*/conf.d/99-portguard-mini.ini")
	for _, path := range dirs {
		switch filepath.Base(filepath.Dir(filepath.Dir(path))) {
		case "fpm", "apache2", "cgi":
			paths = append(paths, path)
		}
	}
	changes, err := removalPlan(paths)
	if err != nil {
		return err
	}
	return rollbackChanges(changes, affectedServices(changes))
}

func rollbackChanges(changes []change, services []string) error {
	var removed []change
	for _, c := range changes {
		if err := os.Remove(c.path); err != nil {
			return fmt.Errorf("remove %s failed; restoration=%v: %w", c.path, restore(removed), err)
		}
		removed = append(removed, c)
		fmt.Println("REMOVED", c.path)
	}
	for _, service := range services {
		var err error
		if service == "ssh" {
			err = run("sshd", "-t")
		} else {
			err = validate([]string{service})
		}
		if err != nil {
			return fmt.Errorf("rollback validation failed; restoration=%v: %w", restore(removed), err)
		}
	}
	for _, service := range services {
		if serviceActive(service) {
			if err := run("systemctl", "reload", service); err != nil {
				return fmt.Errorf("rollback reload failed; restoration=%v: %w", restoreAndReload(removed, services), err)
			}
		}
	}
	fmt.Println("OK: managed files removed; note that prior unmanaged configurations were never edited")
	return nil
}

// A stored TCP listener baseline is informational, never a firewall allowlist.
type listenerSnapshot struct {
	Addresses []string `json:"addresses"`
}

func listeners() ([]string, error) {
	out, err := exec.Command("ss", "-lntH").Output()
	if err != nil {
		return nil, err
	}
	var a []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			a = append(a, f[3])
		}
	}
	sort.Strings(a)
	return a, nil
}
func baseline() error {
	if os.Geteuid() != 0 {
		return errors.New("baseline requires root")
	}
	ports, err := listeners()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(listenerSnapshot{ports}, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(statePath, append(b, '\n'), 0600, false); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("port baseline exists (%s); refuse overwrite; review alerts first", statePath)
		}
		return err
	}
	fmt.Println("BASELINE SAVED", statePath)
	return nil
}
func checkPorts() {
	current, err := listeners()
	if err != nil {
		fmt.Println("WARN port check:", err)
		return
	}
	fmt.Println("LISTENING TCP (local view; not proof of external reachability):")
	for _, a := range current {
		fmt.Println(" ", a)
	}
	b, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("NOTE: port baseline not set; run baseline once")
		return
	}
	if err != nil {
		fmt.Println("WARN baseline:", err)
		return
	}
	var prior listenerSnapshot
	if json.Unmarshal(b, &prior) != nil {
		fmt.Println("WARN baseline invalid")
		return
	}
	seen := map[string]bool{}
	for _, a := range prior.Addresses {
		seen[a] = true
	}
	for _, a := range current {
		if !seen[a] {
			fmt.Println("ALERT NEW LISTENING TCP", a)
		}
	}
}
func checkHTTP(rawURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		fmt.Println("WARN HTTP URL", err)
		return
	}
	client := &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, DisableKeepAlives: true}, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("WARN HTTP", rawURL, err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("HTTP", rawURL, resp.Status)
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if value := resp.Header.Get(h); value != "" {
			fmt.Printf("WARN HEADER %s: %s\n", h, value)
		}
	}
}
func audit() {
	fmt.Println("PortGuard Mini - read-only audit", time.Now().Format(time.RFC3339))
	for _, s := range []string{"apache2", "nginx", "ssh", "sshd", "fail2ban", "mini-site"} {
		if serviceActive(s) {
			fmt.Println("ACTIVE", s)
		}
	}
	if tool("sshd") {
		if v, err := sshBannerSetting(); err == nil {
			fmt.Println("SSH DebianBanner:", v)
		} else {
			fmt.Println("WARN SSH:", err)
		}
	}
	for _, p := range []string{"/etc/apache2/conf-enabled/zz-portguard-mini.conf", "/etc/nginx/conf.d/zz-portguard-mini.conf", sshManagedPath} {
		if exists(p) {
			fmt.Println("MANAGED", p)
		}
	}
	dirs, _ := filepath.Glob("/etc/php/*/*/conf.d/99-portguard-mini.ini")
	for _, p := range dirs {
		fmt.Println("MANAGED", p)
	}
	if tool("ss") {
		checkPorts()
	}
	checkHTTP("http://127.0.0.1:80/")
	checkProcessesAndConnections()
	checkSecurity()
	checkRootProcesses()
	checkSelfProtection()
	checkSSHLogins()
	fmt.Println("NOTE: SSH and firewall access rules unchanged; app responses other than local HTTP root require separate checks")
}

func main() {
	interval := flag.Duration("interval", 5*time.Minute, "watch polling interval")
	flag.Parse()
	mode := "audit"
	if flag.NArg() > 0 {
		mode = flag.Arg(0)
	}
	var err error
	switch mode {
	case "audit":
		audit()
	case "baseline":
		err = baseline()
	case "baseline-security":
		err = securityBaseline()
	case "apply":
		err = apply()
	case "rollback":
		err = rollback()
	case "watch-security":
		err = watchSecurity()
	case "emergency-check":
		err = emergencyCheck()
	case "enroll-root-key":
		if flag.NArg() != 2 {
			err = errors.New("usage: portguard enroll-root-key SHA256:... ")
		} else {
			err = enrollRootKey(flag.Arg(1))
		}
	case "emergency-simulate":
		err = emergencySimulate()
	case "emergency-off":
		if flag.NArg() != 2 {
			err = errors.New("usage: portguard emergency-off POWER_OFF")
		} else {
			err = emergencyOff(flag.Arg(1))
		}
	case "watch":
		if *interval < time.Minute {
			err = errors.New("interval must be at least 1 minute")
			break
		}
		for {
			if e := apply(); e != nil {
				fmt.Fprintln(os.Stderr, "ERROR", e)
			}
			audit()
			time.Sleep(*interval)
		}
	default:
		err = fmt.Errorf("unknown command %q; use audit|baseline|baseline-security|watch-security|emergency-check|enroll-root-key|emergency-simulate|emergency-off POWER_OFF|apply|watch|rollback", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}
