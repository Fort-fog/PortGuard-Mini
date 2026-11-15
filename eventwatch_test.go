package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
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
