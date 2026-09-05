// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// TestReAddBeatsHighGenerationSyncedDelete reproduces the cross-device lost-update
// hazard: device A (e.g. a fast clock) deletes a file with a very high
// generation; that tombstone syncs to device B as a conflict variant; B then
// re-adds the file. The re-add must win — i.e. a local write is ordered strictly
// after every generation the device has observed. With the old wall-clock
// generation scheme B's re-add (gen = now) lost to the far-future tombstone.
func TestReAddBeatsHighGenerationSyncedDelete(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.PutReader(strings.NewReader("v1"), "a.txt", 2, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Simulate a delete from another device with a generation far in the future
	// (clock skew), and keep it around as a synced conflict variant.
	hugeGen := time.Now().Add(10 * 365 * 24 * time.Hour).UnixNano()
	// deletedGeneration is irrelevant here: the only other on-disk copy is an
	// identical tombstone variant, not a live loser, so nothing is suppressed by
	// the field. Pass 0 (the 0.15-compatible default).
	if err := v.saveTombstone("content/a.txt", hugeGen, 0); err != nil {
		t.Fatal(err)
	}
	id := v.manifestID("content/a.txt")
	canonical := v.manifestPath(id)
	variant := strings.TrimSuffix(canonical, ".manifest") + ".sync-conflict.manifest"
	copyFile(t, canonical, variant)

	// Device observes the synced delete.
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.FileInfo("a.txt"); ok {
		t.Fatal("precondition: a.txt should be deleted after the high-gen tombstone")
	}

	// Re-add the file locally; it must supersede the high-gen tombstone.
	if _, err := v.PutReader(strings.NewReader("v2-readded"), "a.txt", 10, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := v.FileInfo("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("re-add was silently lost to the far-future synced delete (lost update)")
	}
	if rec.Generation <= hugeGen {
		t.Fatalf("re-add generation %d must exceed the observed tombstone generation %d", rec.Generation, hugeGen)
	}
	var buf bytes.Buffer
	if err := v.WriteFileTo("a.txt", &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "v2-readded" {
		t.Fatalf("unexpected restored content %q", buf.String())
	}
}

// TestChunkRecoveredFromSyncConflictCopy verifies that if a cloud sync renames
// the canonical chunk object to a *.sync-conflict-* copy, the file still
// restores and verifies by recovering from the renamed copy.
func TestChunkRecoveredFromSyncConflictCopy(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("chunk-recovery-", 50)
	if _, err := v.PutReader(strings.NewReader(content), "doc.txt", int64(len(content)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	rec := files["content/doc.txt"]
	if len(rec.Chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	// Rename every canonical chunk object to a sync-conflict copy.
	for _, ref := range rec.Chunks {
		cp := v.chunkPath(ref.ID)
		renamed := strings.TrimSuffix(cp, ".chunk") + ".sync-conflict-20260101-000000.chunk"
		if err := os.Rename(cp, renamed); err != nil {
			t.Fatal(err)
		}
	}
	// Restore must still succeed via the renamed copy.
	var buf bytes.Buffer
	if err := v.WriteFileTo("doc.txt", &buf); err != nil {
		t.Fatalf("restore should recover from the sync-conflict chunk copy: %v", err)
	}
	if buf.String() != content {
		t.Fatal("recovered content does not match original")
	}
	if err := v.Verify(); err != nil {
		t.Fatalf("verify should pass after recovering renamed chunks: %v", err)
	}
}

// TestGCKeepsLiveChunkConflictCopy ensures GarbageCollect does not delete a
// sync-conflict copy of a chunk whose object id is still live — that copy is
// what loadChunk uses to recover a chunk the cloud sync renamed; deleting it
// would cause permanent data loss.
func TestGCKeepsLiveChunkConflictCopy(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("gc-keep-", 60)
	if _, err := v.PutReader(strings.NewReader(content), "doc.txt", int64(len(content)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, _ := v.Files()
	rec := files["content/doc.txt"]
	if len(rec.Chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	// Back-date the conflict copies: the chunk-mtime fence must be
	// CLEARED at the final run so a GC that forgot the object is still live would
	// actually delete it there, rather than being spared by a young mtime.
	old := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Add(-500 * time.Hour)
	for _, ref := range rec.Chunks {
		cp := v.chunkPath(ref.ID)
		renamed := strings.TrimSuffix(cp, ".chunk") + ".sync-conflict-20260101-000000.chunk"
		if err := os.Rename(cp, renamed); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(renamed, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// A single --confirm run structurally removes NOTHING (phase 1 only writes
	// intents), so asserting RemovedChunks==0 after one run is vacuous — it holds
	// even if GC misclassified the live conflict copy as garbage.
	// Drive the whole two-phase fenced protocol PAST the fence with a controlled
	// clock so the recorded time, this device's first-seen record, and the chunk
	// mtime all age beyond it: only then could GC delete the copy. If GC failed to
	// treat the conflict copy's object id as live, run 3 would collect it here and
	// destroy the only surviving copy of a referenced chunk.
	seenDir := t.TempDir() + "/gc-seen"
	t0 := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	var clockNow time.Time
	clock := func() time.Time { return clockNow }
	const fence = 72 * time.Hour
	for run, at := range []time.Duration{0, 100 * time.Hour, 300 * time.Hour} {
		clockNow = t0.Add(at)
		report, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: fence, Now: clock, SeenStore: seenDir})
		if err != nil {
			t.Fatalf("run %d: %v", run+1, err)
		}
		if len(report.RemovedChunks) != 0 {
			t.Fatalf("run %d: GC must not delete sync-conflict copies of live chunks; removed %v", run+1, report.RemovedChunks)
		}
	}
	var buf bytes.Buffer
	if err := v.WriteFileTo("doc.txt", &buf); err != nil {
		t.Fatalf("restore after GC should still succeed: %v", err)
	}
	if buf.String() != content {
		t.Fatal("content mismatch after GC")
	}
}

// TestReloadIfChangedPicksUpExternalWrites verifies the auto-reload fingerprint:
// a long-lived vault picks up manifests written by another process (e.g. the
// Nextcloud sync client), while its own writes do not trigger a needless reload.
func TestReloadIfChangedPicksUpExternalWrites(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v1, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.PutReader(strings.NewReader("a"), "a.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	// First call only establishes the baseline (no reload).
	if reloaded, err := v1.ReloadIfChanged(); err != nil || reloaded {
		t.Fatalf("first ReloadIfChanged should establish baseline, reloaded=%v err=%v", reloaded, err)
	}

	// Simulate another device's edit arriving via sync: a second handle writes a
	// new file's manifest to disk, which v1 knows nothing about.
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.PutReader(strings.NewReader("b"), "b.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := v1.ReloadIfChanged()
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("ReloadIfChanged should detect and reload an external write")
	}
	if _, ok, _ := v1.FileInfo("b.txt"); !ok {
		t.Fatal("v1 should see the externally-synced b.txt after reload")
	}
	if _, ok, _ := v1.FileInfo("a.txt"); !ok {
		t.Fatal("v1 should still see its own a.txt after reload")
	}

	// v1's own subsequent write changes the on-disk fingerprint; the next check
	// reloads from disk (correct — disk already has it) and it stays visible.
	if _, err := v1.PutReader(strings.NewReader("c"), "c.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v1.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v1.FileInfo("c.txt"); !ok {
		t.Fatal("v1 should see its own c.txt")
	}
	// Steady state: nothing changed -> no reload.
	if reloaded, err := v1.ReloadIfChanged(); err != nil || reloaded {
		t.Fatalf("no change should not reload, reloaded=%v err=%v", reloaded, err)
	}
}

// TestReloadIfChangedDetectsExternalChangeAlongsideLocalWrite guards against a
// regression where an own-write heuristic absorbs (and permanently hides) an
// external change that arrives in the same check window as a local write.
func TestReloadIfChangedDetectsExternalChangeAlongsideLocalWrite(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v1, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.PutReader(strings.NewReader("a"), "a.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v1.ReloadIfChanged(); err != nil { // establish baseline
		t.Fatal(err)
	}

	// Same window: v1 writes locally AND another handle writes externally.
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.PutReader(strings.NewReader("local"), "local.txt", 5, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.PutReader(strings.NewReader("ext"), "ext.txt", 3, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, err := v1.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v1.FileInfo("ext.txt"); !ok {
		t.Fatal("external change must not be hidden when it lands alongside a local write")
	}
	if _, ok, _ := v1.FileInfo("local.txt"); !ok {
		t.Fatal("local write should remain visible")
	}
}

// TestMissingChunkReportsPendingAwareError checks that a genuinely absent chunk
// (no canonical and no conflict copy) yields an os.ErrNotExist-wrapped error
// whose message distinguishes "missing or not-yet-synced" from corruption, so a
// partially-synced vault is not misreported as corrupt.
func TestMissingChunkReportsPendingAwareError(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("pending"), "p.txt", 7, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, _ := v.Files()
	ref := files["content/p.txt"].Chunks[0]
	if err := os.Remove(v.chunkPath(ref.ID)); err != nil {
		t.Fatal(err)
	}
	report, err := v.VerifyReport()
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || report.MissingChunks != 1 {
		t.Fatalf("expected one missing chunk, got %#v", report)
	}
	if !strings.Contains(report.Issues[0].Error, "not yet synced") {
		t.Fatalf("missing-chunk error should mention the pending-sync possibility, got %q", report.Issues[0].Error)
	}
}
