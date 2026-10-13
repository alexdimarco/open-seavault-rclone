// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"os"
	"strings"
	"testing"
	"time"
)

// GC's phase-2 deletion gate protects a chunk whose file mtime is younger than
// the fence ("a re-uploaded chunk is young", gc.go). But the native dedup path
// reused an existing chunk WITHOUT touching its mtime, so a chunk another device
// had already aged and queued for deletion stayed old-mtimed after reuse: that
// device could reap it before this device's referencing manifest propagated —
// online data loss to ordinary sync lag. Reuse must refresh the chunk's mtime so
// the fresh mtime syncs out and the other device's mtime gate protects it.
func TestDedupReuseRefreshesChunkMtime(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	body := strings.Repeat("dedup-mtime-", 40)
	if _, err := v.PutReader(strings.NewReader(body), "a.txt", int64(len(body)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	chunks := files["content/a.txt"].Chunks
	if len(chunks) == 0 {
		t.Fatal("precondition: a.txt must have chunks")
	}

	// Age every chunk far past any fence, as another device would have left them.
	old := time.Now().Add(-200 * time.Hour)
	for _, c := range chunks {
		if err := os.Chtimes(v.chunkPath(c.ID), old, old); err != nil {
			t.Fatal(err)
		}
	}

	// Re-add identical content elsewhere: a pure dedup reuse (no new chunks).
	res, err := v.PutReader(strings.NewReader(body), "b.txt", int64(len(body)), 0o600, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.NewChunkCount != 0 {
		t.Fatalf("precondition: the re-add must be a pure dedup reuse, got %d new chunks", res.NewChunkCount)
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	for _, c := range chunks {
		fi, err := os.Stat(v.chunkPath(c.ID))
		if err != nil {
			t.Fatal(err)
		}
		if fi.ModTime().Before(cutoff) {
			t.Fatalf("dedup reuse left chunk %s mtime stale (%s); GC on another device could reap a chunk this file now references", c.ID, fi.ModTime())
		}
	}
}
