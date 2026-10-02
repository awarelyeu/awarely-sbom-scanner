package safeio

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInputBoundary(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("PRIVATE_CANARY"), 0600)
	os.WriteFile(filepath.Join(dir, "ok"), []byte("safe"), 0600)
	os.Symlink(secret, filepath.Join(dir, "link"))
	if err := os.Link(secret, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	os.Symlink(outside, filepath.Join(dir, "escape"))
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, path := range []string{"link", "hardlink", "escape/secret", "../" + filepath.Base(outside) + "/secret", secret, "fifo", "."} {
		t.Run(path, func(t *testing.T) {
			b, err := ReadRegular(context.Background(), r, path, 100)
			if err == nil || strings.Contains(string(b), "PRIVATE_CANARY") {
				t.Fatal("escaped boundary", err)
			}
		})
	}
	b, err := ReadRegular(context.Background(), r, "ok", 4)
	if err != nil || string(b) != "safe" {
		t.Fatal(string(b), err)
	}
	if _, err := ReadRegular(context.Background(), r, "ok", 3); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadRegular(ctx, r, "ok", 100); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestOutputNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "report.json")
	if err := WriteNew(dest, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(dest, []byte("second")); err == nil {
		t.Fatal("overwrote existing output")
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "first" {
		t.Fatal(string(b))
	}
	st, _ := os.Stat(dest)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	link := filepath.Join(dir, "link")
	os.Symlink(dest, link)
	if err := WriteNew(link, []byte("third")); err == nil {
		t.Fatal("overwrote symlink")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".awarely-scan-") {
			t.Fatal("temporary file leaked")
		}
	}
}
