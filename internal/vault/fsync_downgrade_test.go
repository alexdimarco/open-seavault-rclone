// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F5 (integrity/F5-atomicwrite-reports-failure-after-successful-rename): a
// directory fsync that fails AFTER the publishing rename must NOT turn an
// already-durable write into a reported failure. On filesystems where directory
// fsync is unsupported (some FUSE/network mounts) fsyncDir returns
// EINVAL/ENOTSUP; the file is already renamed into place, so atomicWriteFile
// reports success and the bytes are on disk. Before the fix atomicWriteFile
// returned the fsync error even though the rename had published the file.
func TestAtomicWriteFileSucceedsWhenDirFsyncUnsupported(t *testing.T) {
	orig := fsyncDir
	var called bool
	fsyncDir = func(dir string) error { called = true; return syscall.EINVAL }
	t.Cleanup(func() { fsyncDir = orig })

	p := filepath.Join(t.TempDir(), "sub", "durable.bin")
	want := []byte("payload-that-is-already-durable")
	if err := atomicWriteFile(p, want, 0o600); err != nil {
		t.Fatalf("atomicWriteFile must succeed after a durable rename even when the post-rename dir fsync is unsupported; got %v", err)
	}
	if !called {
		t.Fatal("fsyncDir was never exercised; the durable path did not run")
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("published file not readable: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("published file content = %q, want %q", got, want)
	}
}

// F5 end-to-end: a put whose only failure is an unsupported post-rename
// directory fsync must succeed AND stay visible. The finding's symptom was that
// PutReader propagated the fsync error while the chunk+manifest were durably on
// disk, leaving the write invisible on the open handle (cache not updated) until
// a later reload. After the fix the put succeeds and the file is listed both on
// the same handle and after a fresh Open.
func TestPutReaderSucceedsWhenDirFsyncUnsupported(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	// Model an FS whose directory fsync is unsupported, but only after the vault
	// is open so setup writes still succeed.
	orig := fsyncDir
	var called bool
	fsyncDir = func(dir string) error { called = true; return syscall.EINVAL }
	t.Cleanup(func() { fsyncDir = orig })

	content := strings.Repeat("durable-", 64)
	if _, err := v.PutReader(strings.NewReader(content), "only-fsync-fails.txt", int64(len(content)), 0o600, time.Now()); err != nil {
		t.Fatalf("PutReader must succeed when the post-rename dir fsync is unsupported; got %v", err)
	}
	if !called {
		t.Fatal("fsyncDir was never exercised; the durable path did not run")
	}

	assertListed := func(label string, list func() ([]string, error)) {
		t.Helper()
		files, err := list()
		if err != nil {
			t.Fatalf("%s: List failed: %v", label, err)
		}
		for _, f := range files {
			if strings.Contains(f, "only-fsync-fails.txt") {
				return
			}
		}
		t.Fatalf("%s: put file not visible; List=%v", label, files)
	}

	// Visible on the same handle (cache was updated, not left stale).
	assertListed("same handle", v.List)

	// Durable across a fresh Open with the failing fsync still in force.
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatalf("fresh Open must succeed when the post-rename dir fsync is unsupported; got %v", err)
	}
	assertListed("fresh open", v2.List)
}
