package main

// Linux inotify provides fast notifications; the existing security inventory
// remains the authority for periodic checks. This watcher never modifies files.
import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const eventMask = syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_CLOSE_WRITE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

// A watchdog needs to monitor directories (and parents of individual files),
// not individual files: atomic rename replaces inodes.
type eventWatcher struct {
	fd     int
	byWD   map[int]string
	byPath map[string]int
}

func newEventWatcher() (*eventWatcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &eventWatcher{fd: fd, byWD: make(map[int]string), byPath: make(map[string]int)}, nil
}

func (w *eventWatcher) close() { _ = syscall.Close(w.fd) }

func (w *eventWatcher) addDir(dir string) error {
	if _, ok := w.byPath[dir]; ok {
		return nil
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	wd, err := syscall.InotifyAddWatch(w.fd, dir, eventMask|syscall.IN_ONLYDIR|syscall.IN_DONT_FOLLOW)
	if err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	w.byWD[wd] = dir
	w.byPath[dir] = wd
	return nil
}

func (w *eventWatcher) addTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == dir {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return w.addDir(path)
		}
		return nil
	})
}

func (w *eventWatcher) addTargets(targets []string) error {
	for _, path := range targets {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			// If a file or directory doesn't exist, the nearest existing parent
			// can still warn us when the missing target appears.
			parent := filepath.Dir(path)
			for parent != "/" {
				st, e := os.Lstat(parent)
				if e == nil && st.IsDir() {
					if err := w.addDir(parent); err != nil {
						return err
					}
					break
				}
				parent = filepath.Dir(parent)
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := w.addTree(path); err != nil {
				return err
			}
		} else {
			if err := w.addDir(filepath.Dir(path)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *eventWatcher) event(path string, mask uint32) {
	// Kernel may merge events and may overflow the queue. Notifications are
	// evidence of activity, never proof of compromise or completeness.
	if mask&syscall.IN_Q_OVERFLOW != 0 {
		fmt.Println("ALERT EVENT WATCH QUEUE OVERFLOW; run portguard audit immediately")
		return
	}
	if mask&syscall.IN_IGNORED != 0 {
		fmt.Printf("WARN EVENT WATCH REMOVED %q; audit recommended\n", path)
		return
	}
	actions := []struct {
		bit  uint32
		name string
	}{
		{syscall.IN_CREATE, "CREATED"}, {syscall.IN_DELETE, "DELETED"},
		{syscall.IN_MOVED_FROM, "MOVED_FROM"}, {syscall.IN_MOVED_TO, "MOVED_TO"},
		{syscall.IN_CLOSE_WRITE, "WRITTEN"}, {syscall.IN_ATTRIB, "ATTRIBUTES"},
		{syscall.IN_DELETE_SELF, "DIR_DELETED"}, {syscall.IN_MOVE_SELF, "DIR_MOVED"},
	}
	names := make([]string, 0, 3)
	for _, action := range actions {
		if mask&action.bit != 0 {
			names = append(names, action.name)
		}
	}
	// MODIFY fires on every write and can be extremely noisy. CLOSE_WRITE is
	// more useful for humans, while periodic hash audits detect final changes.
	if len(names) == 0 {
		return
	}
	fmt.Printf("EVENT SECURITY %s %q\n", strings.Join(names, ","), path)
}

func (w *eventWatcher) process(buf []byte) {
	for len(buf) >= 16 {
		wd := int(int32(binary.LittleEndian.Uint32(buf[0:4])))
		mask := binary.LittleEndian.Uint32(buf[4:8])
		length := int(binary.LittleEndian.Uint32(buf[12:16]))
		if length < 0 || length > len(buf)-16 {
			fmt.Println("WARN EVENT malformed kernel notification")
			return
		}
		name := strings.TrimRight(string(buf[16:16+length]), "\x00")
		base := w.byWD[wd]
		full := base
		if name != "" {
			full = filepath.Join(base, name)
		}
		if mask&syscall.IN_Q_OVERFLOW != 0 {
			w.event("", mask)
		}
		if base != "" {
			w.event(full, mask)
			if mask&syscall.IN_IGNORED != 0 {
				delete(w.byWD, wd)
				delete(w.byPath, base)
			}
			if mask&syscall.IN_ISDIR != 0 && mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
				if err := w.addTree(full); err != nil && !errors.Is(err, fs.ErrNotExist) {
					fmt.Printf("WARN EVENT new directory watch %q: %v\n", full, err)
				}
			}
		}
		buf = buf[16+length:]
	}
}

func watchSecurity() error {
	if os.Geteuid() != 0 {
		return errors.New("watch-security requires root (to monitor protected directories)")
	}
	watcher, err := newEventWatcher()
	if err != nil {
		return err
	}
	defer watcher.close()
	if err = watcher.addTargets(securityTargets); err != nil {
		return err
	}
	// Force immediate journald delivery even when the service has no terminal.
	fmt.Printf("PortGuard EVENT WATCH started %s; %d directories; READ ONLY\n", time.Now().Format(time.RFC3339), len(watcher.byPath))
	if len(watcher.byPath) == 0 {
		return errors.New("no watchable directories")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() { <-sig; _ = syscall.Close(watcher.fd) }()
	buf := make([]byte, 256*1024)
	for {
		n, readErr := syscall.Read(watcher.fd, buf)
		if n > 0 {
			watcher.process(buf[:n])
		}
		if readErr != nil {
			if errors.Is(readErr, syscall.EINTR) {
				continue
			}
			if errors.Is(readErr, syscall.EBADF) {
				fmt.Println("PortGuard EVENT WATCH stopped")
				return nil
			}
			return readErr
		}
	}
}

func watchedDirectoriesPreview(targets []string) []string {
	dirs := map[string]bool{}
	for _, t := range targets {
		if st, e := os.Lstat(t); e == nil {
			if st.IsDir() {
				dirs[t] = true
			} else {
				dirs[filepath.Dir(t)] = true
			}
		}
	}
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
