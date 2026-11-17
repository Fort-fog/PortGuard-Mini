package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestEventWatcherTracksDirectories(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "sub")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	w, err := newEventWatcher()
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.close()
	if err = w.addTargets([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.byPath[dir]; !ok {
		t.Fatal("root not watched")
	}
	if _, ok := w.byPath[child]; !ok {
		t.Fatal("child not watched")
	}
	// Nonblocking read proves the kernel delivered a create notification.
	if err = syscall.SetNonblock(w.fd, true); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(child, "canary"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096)
	n, err := syscall.Read(w.fd, b)
	if err != nil {
		t.Fatal(err)
	}
	if n <= 16 {
		t.Fatalf("short inotify event: %d", n)
	}
}

func TestEventWatcherGracefulStopWithoutEvents(t *testing.T) {
	w, err := newEventWatcher()
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.close()
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- runEventLoop(w, stop) }()
	stop <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop after SIGTERM notification")
	}
}

// The watcher must also shut down while idle after the nonblocking read
// has already returned EAGAIN (the normal long-lived service case).
func TestEventWatcherGracefulStopAfterIdle(t *testing.T) {
	w, err := newEventWatcher()
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.close()
	stop := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- runEventLoop(w, stop) }()
	time.Sleep(50 * time.Millisecond)
	stop <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful stop while idle: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle watcher did not stop")
	}
}

func TestEventWatcherInvalidatedCoverageRequiresRestart(t *testing.T) {
	for _, mask := range []uint32{syscall.IN_Q_OVERFLOW, syscall.IN_MOVE_SELF, syscall.IN_DELETE_SELF, syscall.IN_IGNORED, syscall.IN_ISDIR | syscall.IN_MOVED_FROM} {
		w := &eventWatcher{byWD: map[int]string{1: "/fake-directory"}, byPath: map[string]int{"/fake-directory": 1}}
		event := make([]byte, 16)
		binary.LittleEndian.PutUint32(event[0:4], 1)
		binary.LittleEndian.PutUint32(event[4:8], mask)
		if err := w.process(event); err == nil {
			t.Fatalf("watch invalidation not propagated for mask %x", mask)
		}
	}
}
