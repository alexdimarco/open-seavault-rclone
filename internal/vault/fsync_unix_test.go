// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !windows

package vault

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R10: on unix, atomicWriteFile fsyncs the containing directory after the
// rename, so the durable path is exercised for both a chunk write and a manifest
// write (design D5.2, P3 atomicwrite-no-dir-fsync).
func TestFsyncDirCalledForChunkAndManifestWrites(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	orig := fsyncDir
	var dirs []string
	fsyncDir = func(dir string) error { dirs = append(dirs, dir); return orig(dir) }
	t.Cleanup(func() { fsyncDir = orig })

	content := strings.Repeat("durable-", 40)
	if _, err := v.PutReader(strings.NewReader(content), "doc.txt", int64(len(content)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	var chunkSynced, manifestSynced bool
	for _, d := range dirs {
		slash := filepath.ToSlash(d)
		if strings.Contains(slash, "objects/chunks") {
			chunkSynced = true
		}
		if strings.Contains(slash, "/"+ManifestDirName) {
			manifestSynced = true
		}
	}
	if !chunkSynced {
		t.Fatalf("expected a chunk-directory fsync; dirs=%v", dirs)
	}
	if !manifestSynced {
		t.Fatalf("expected a manifest-directory fsync; dirs=%v", dirs)
	}
}
