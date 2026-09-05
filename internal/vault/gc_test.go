// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R6 — two-phase, fenced garbage collection (design §3, P0-5). Each row below is
// one line of the R6 matrix; the GC mechanics are exercised against fabricated
// orphan chunks and hand-written intents so a single test controls the exact
// (reference, recorded-time, first-seen, mtime) state a row needs, independent of
// the chunker.

func gcHexID(b byte) string { return strings.Repeat(fmt.Sprintf("%02x", b), 32) }

func gcContains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func gcFileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writeOrphanChunk fabricates an unreferenced chunk file with the given id and
// mtime. GC never decrypts chunks, so arbitrary content is fine — only the
// filename-derived id, the reference set, and the mtime matter.
func writeOrphanChunk(t *testing.T, v *Vault, id, content string, mtime time.Time) string {
	t.Helper()
	p := v.chunkPath(id)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func writeIntentFile(t *testing.T, v *Vault, name, rfc3339 string) string {
	t.Helper()
	dir := filepath.Join(v.MetaRoot, GCIntentDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(rfc3339+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func intentFilesFor(t *testing.T, v *Vault, id string) []string {
	t.Helper()
	dir := filepath.Join(v.MetaRoot, GCIntentDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if chunkIDFromFileName(e.Name()) == id {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func writeSeenStore(t *testing.T, dir string, v *Vault, m map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, v.ID()+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readSeenStore(t *testing.T, dir string, v *Vault) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, v.ID()+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatal(err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func openGCVault(t *testing.T) (*Vault, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	return v, filepath.Join(t.TempDir(), "gc-seen")
}

// R6: dry-run computes candidates and writes nothing anywhere.
func TestGCDryRunWritesNothing(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x11)
	writeOrphanChunk(t, v, id, "orphan-data", time.Time{})

	report, err := v.GarbageCollect(GCOptions{Confirm: false, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if report.Confirm {
		t.Fatal("dry-run report must not be marked confirm")
	}
	if !gcContains(report.Candidates, id) {
		t.Fatalf("dry-run must list the orphan chunk as a candidate; got %v", report.Candidates)
	}
	if len(report.RemovedChunks) != 0 || len(report.IntentsWritten) != 0 {
		t.Fatalf("dry-run must write and remove nothing; removed=%v intents=%v", report.RemovedChunks, report.IntentsWritten)
	}
	if entries, _ := os.ReadDir(filepath.Join(v.MetaRoot, GCIntentDirName)); len(entries) != 0 {
		t.Fatalf("dry-run wrote intent files: %v", entries)
	}
	if gcFileExists(filepath.Join(seenDir, v.ID()+".json")) {
		t.Fatal("dry-run wrote the first-seen store")
	}
	if !gcFileExists(v.chunkPath(id)) {
		t.Fatal("dry-run removed a chunk")
	}
}

// R6: --confirm writes intents only on the first pass (removes nothing).
func TestGCConfirmWritesIntentsOnly(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x22)
	writeOrphanChunk(t, v, id, "data", time.Time{})

	report, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(report.IntentsWritten, id) {
		t.Fatalf("confirm must write an intent for the orphan; got %v", report.IntentsWritten)
	}
	if len(intentFilesFor(t, v, id)) != 1 {
		t.Fatalf("expected exactly one intent file on disk, got %d", len(intentFilesFor(t, v, id)))
	}
	if len(report.RemovedChunks) != 0 {
		t.Fatalf("the intent-writing pass must remove nothing; removed %v", report.RemovedChunks)
	}
	if !gcFileExists(v.chunkPath(id)) {
		t.Fatal("the intent-writing pass removed the chunk")
	}
}

// R6: a second confirm run before the fence removes nothing.
func TestGCSecondRunBeforeFenceRemovesNothing(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x33)
	writeOrphanChunk(t, v, id, "data", time.Time{})

	if _, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir}); err != nil {
		t.Fatal(err)
	}
	if len(intentFilesFor(t, v, id)) != 1 {
		t.Fatal("first run should have written an intent")
	}
	report, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.RemovedChunks) != 0 {
		t.Fatalf("second run before the fence must remove nothing; removed %v", report.RemovedChunks)
	}
	if !gcFileExists(v.chunkPath(id)) {
		t.Fatal("chunk removed before the fence")
	}
	if len(intentFilesFor(t, v, id)) != 1 {
		t.Fatal("the intent should persist before the fence")
	}
}

// R6: past both fences (recorded time AND first-seen) with an old chunk mtime,
// the chunk is removed and then its intent.
func TestGCPastBothFencesRemovesChunkThenIntent(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x44)
	old := time.Now().Add(-100 * time.Hour)
	writeOrphanChunk(t, v, id, "data", old)
	writeIntentFile(t, v, id+".intent", old.UTC().Format(time.RFC3339))
	writeSeenStore(t, seenDir, v, map[string]string{id: old.UTC().Format(time.RFC3339)})

	report, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: 72 * time.Hour, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(report.RemovedChunks, id) {
		t.Fatalf("past both fences the chunk must be removed; got %v", report.RemovedChunks)
	}
	if gcFileExists(v.chunkPath(id)) {
		t.Fatal("chunk file still present after collection")
	}
	if len(intentFilesFor(t, v, id)) != 0 {
		t.Fatal("the intent files must be removed after the chunk")
	}
	if report.Phase2Reloads > 1 {
		t.Fatalf("phase 2 must reload at most once; reloads=%d", report.Phase2Reloads)
	}
}

// R6: an intent with an old recorded time but a young first-seen time does NOT
// collect — the first-seen record is what stops a skewed or just-synced intent
// tripping the fence early (design D3.4).
func TestGCOldRecordedYoungFirstSeenDoesNotCollect(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x55)
	old := time.Now().Add(-100 * time.Hour)
	writeOrphanChunk(t, v, id, "data", old)
	writeIntentFile(t, v, id+".intent", old.UTC().Format(time.RFC3339))
	// No pre-seeded first-seen: phase 1 records it now (young).

	report, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: 72 * time.Hour, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.RemovedChunks) != 0 {
		t.Fatalf("a young first-seen must block collection; removed %v", report.RemovedChunks)
	}
	if !gcFileExists(v.chunkPath(id)) {
		t.Fatal("chunk removed despite a young first-seen record")
	}
	if len(intentFilesFor(t, v, id)) != 1 {
		t.Fatal("the intent should persist")
	}
	if _, ok := readSeenStore(t, seenDir, v)[id]; !ok {
		t.Fatal("phase 1 must record first-seen for a present, unreferenced, intented chunk")
	}
}

// R6: a reference appearing between runs cancels the intent (design D3.3(a)).
func TestGCReferenceBetweenRunsCancels(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x66)
	writeOrphanChunk(t, v, id, "data", time.Time{})

	if _, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir}); err != nil {
		t.Fatal(err)
	}
	if len(intentFilesFor(t, v, id)) != 1 {
		t.Fatal("first run should have written an intent")
	}
	// A manifest now references the chunk (a peer re-added identical content).
	if err := v.saveFileManifest("content/ref.txt", FileRecord{Size: 4, Chunks: []ChunkRef{{ID: id, Size: 4}}}); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	report, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(report.Cancelled, id) {
		t.Fatalf("a reference appearing between runs must cancel the intent; got %v", report.Cancelled)
	}
	if len(intentFilesFor(t, v, id)) != 0 {
		t.Fatal("a cancelled intent's files must be removed")
	}
	if !gcFileExists(v.chunkPath(id)) {
		t.Fatal("cancel must not remove the now-live chunk")
	}
}

// R6: a conflict-renamed duplicate intent folds to ONE logical intent with the
// OLDEST recorded time, and is removed together with its twin (design D3.2). The
// canonical file carries a YOUNG time that would not clear the fence on its own,
// so collection proves the fold used the older twin's time.
func TestGCConflictRenamedDuplicateFoldsAndRemovesTwin(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x77)
	old := time.Now().Add(-100 * time.Hour)
	young := time.Now().Add(-10 * time.Hour)
	writeOrphanChunk(t, v, id, "data", old)
	writeIntentFile(t, v, id+".intent", young.UTC().Format(time.RFC3339))
	writeIntentFile(t, v, id+".sync-conflict-20260101-000000.intent", old.UTC().Format(time.RFC3339))
	writeSeenStore(t, seenDir, v, map[string]string{id: old.UTC().Format(time.RFC3339)})

	report, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: 72 * time.Hour, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(report.RemovedChunks, id) {
		t.Fatalf("folding to the oldest recorded time must let the chunk collect; got %v", report.RemovedChunks)
	}
	if len(intentFilesFor(t, v, id)) != 0 {
		t.Fatal("the intent and its conflict-renamed twin must be removed together")
	}
	if gcFileExists(v.chunkPath(id)) {
		t.Fatal("the folded chunk should be removed")
	}
}

// R6: an intent whose chunk file is gone is reaped by phase 1, including any
// conflict-renamed twin (design D3.3(b)).
func TestGCMissingChunkIntentReapedByPhase1(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x88)
	stamp := time.Now().Add(-100 * time.Hour).UTC().Format(time.RFC3339)
	// No chunk file exists for id.
	writeIntentFile(t, v, id+".intent", stamp)
	writeIntentFile(t, v, id+".deviceB (conflicted copy).intent", stamp)

	report, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(report.Reaped, id) {
		t.Fatalf("an intent whose chunk is gone must be reaped; got %v", report.Reaped)
	}
	if len(intentFilesFor(t, v, id)) != 0 {
		t.Fatal("reaped intent files (including conflict twins) must be removed")
	}
	if len(report.RemovedChunks) != 0 {
		t.Fatalf("a reap removes no chunk (there is none); removed %v", report.RemovedChunks)
	}
}

// R6: a crash between the chunk removal and the intent removal is cleaned up on
// the next run — the orphaned intent is reaped (design D3.4).
func TestGCCrashBetweenChunkAndIntentCleanedNextRun(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x99)
	old := time.Now().Add(-100 * time.Hour)
	writeOrphanChunk(t, v, id, "data", old)
	writeIntentFile(t, v, id+".intent", old.UTC().Format(time.RFC3339))
	writeSeenStore(t, seenDir, v, map[string]string{id: old.UTC().Format(time.RFC3339)})

	r1, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: 72 * time.Hour, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(r1.RemovedChunks, id) {
		t.Fatalf("expected the chunk to collect on the first run; got %v", r1.RemovedChunks)
	}
	// Simulate a crash AFTER chunk removal but BEFORE intent removal: the chunk is
	// gone, an intent for it lingers.
	writeIntentFile(t, v, id+".intent", old.UTC().Format(time.RFC3339))

	r2, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: 72 * time.Hour, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(r2.Reaped, id) {
		t.Fatalf("the next run must reap the orphaned intent; got %v", r2.Reaped)
	}
	if len(intentFilesFor(t, v, id)) != 0 {
		t.Fatal("the orphaned intent must be removed")
	}
}

// R6: the manifest and chunk walkers ignore gc-intents.
func TestGCLoadersIgnoreIntentDir(t *testing.T) {
	v, _ := openGCVault(t)
	if _, err := v.PutReader(strings.NewReader("hello world content here"), "doc.txt", 24, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	before, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	fpBefore, err := v.indexFingerprint()
	if err != nil {
		t.Fatal(err)
	}

	// Drop files under gc-intents whose names mimic a manifest and a chunk.
	dir := filepath.Join(v.MetaRoot, GCIntentDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{gcHexID(0xaa) + ".intent", gcHexID(0xbb) + ".manifest", gcHexID(0xcc) + ".chunk"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	after, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the manifest walker must ignore gc-intents; files %d -> %d", len(before), len(after))
	}
	if fpAfter, err := v.indexFingerprint(); err != nil || fpAfter != fpBefore {
		t.Fatalf("indexFingerprint must ignore gc-intents (before=%d after=%d err=%v)", fpBefore, fpAfter, err)
	}

	// A real orphan is a candidate; the .chunk-named file under gc-intents is not.
	orphan := gcHexID(0xdd)
	writeOrphanChunk(t, v, orphan, "x", time.Time{})
	report, err := v.GarbageCollect(GCOptions{Confirm: false})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(report.Candidates, orphan) {
		t.Fatalf("the chunk walker should find the real orphan; got %v", report.Candidates)
	}
	if gcContains(report.Candidates, gcHexID(0xcc)) {
		t.Fatal("the chunk walker must ignore a .chunk-named file under gc-intents")
	}
}

// R6: phase 2 reloads the index at most once per pass, and skips the reload
// entirely when phase 1 wrote only (loader-ignored) intents.
func TestGCPhase2ReloadsAtMostOnce(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0xee)
	writeOrphanChunk(t, v, id, "data", time.Time{})

	report, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.IntentsWritten) != 1 {
		t.Fatalf("phase 1 should have written one intent; got %v", report.IntentsWritten)
	}
	if report.Phase2Reloads != 0 {
		t.Fatalf("phase 2 must skip its reload when only intents changed; reloads=%d", report.Phase2Reloads)
	}
}

// R6/D3.6: verify lists pending deletion intents (count and age) without writing.
func TestVerifyListsPendingIntents(t *testing.T) {
	v, _ := openGCVault(t)
	if _, err := v.PutReader(strings.NewReader("payload content xyz"), "doc.txt", 19, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	id := gcHexID(0x5a)
	writeIntentFile(t, v, id+".intent", time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339))

	fpBefore, err := v.indexFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	report, err := v.VerifyReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PendingIntents) != 1 || report.PendingIntents[0].ChunkID != id {
		t.Fatalf("verify must list the pending intent; got %+v", report.PendingIntents)
	}
	if report.PendingIntents[0].AgeSeconds < 3600 {
		t.Fatalf("verify must report the intent age; got %ds", report.PendingIntents[0].AgeSeconds)
	}
	// Verify is a read: it must not touch the metadata fingerprint (invariant I2).
	if fpAfter, err := v.indexFingerprint(); err != nil || fpAfter != fpBefore {
		t.Fatalf("verify must not write metadata (before=%d after=%d err=%v)", fpBefore, fpAfter, err)
	}
}

// R6 tombstone (server/F2-firstseen-store-leak-defeats-fence): collecting a
// chunk in phase 2 must PRUNE this device's first-seen record for it. Chunk ids
// are content-addressed (dedup id = HMAC(indexKey, plaintext)), so a surviving
// entry would let a re-created chunk inherit an ancient first-seen time. This
// drives the leak with NO hand-seeding of the final state: a legitimate
// multi-run collection (the first-seen recorded naturally by phase 1) must leave
// the store holding NO entry for the collected id (design D3.4, D3.2b).
func TestGCCollectionPrunesFirstSeenRecord(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x5f)
	t0 := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	var now time.Time
	clock := func() time.Time { return now }
	fence := 72 * time.Hour
	writeOrphanChunk(t, v, id, "data", t0.Add(-500*time.Hour)) // server-old mtime

	// Run 1 (T0): phase 1 writes the intent (no first-seen yet); nothing collects.
	now = t0
	if _, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: fence, Now: clock, SeenStore: seenDir}); err != nil {
		t.Fatal(err)
	}
	// Run 2 (T0+100h): phase 1 records the first-seen; still inside the fence.
	now = t0.Add(100 * time.Hour)
	if _, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: fence, Now: clock, SeenStore: seenDir}); err != nil {
		t.Fatal(err)
	}
	if _, ok := readSeenStore(t, seenDir, v)[id]; !ok {
		t.Fatal("setup: run 2 must have recorded a first-seen entry")
	}
	// Run 3 (T0+300h): all fences cleared -> the chunk collects.
	now = t0.Add(300 * time.Hour)
	r3, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: fence, Now: clock, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if !gcContains(r3.RemovedChunks, id) {
		t.Fatalf("run 3 must collect the chunk; got %v", r3.RemovedChunks)
	}
	if gcFileExists(v.chunkPath(id)) {
		t.Fatal("run 3 must remove the chunk file")
	}
	// The tombstone: the first-seen record must NOT survive the collection.
	if ts, ok := readSeenStore(t, seenDir, v)[id]; ok {
		t.Fatalf("collecting a chunk must prune its first-seen record; store still holds %q=%q", id, ts)
	}
}

// R6 tombstone (server/F2-firstseen-store-leak-defeats-fence), end-to-end: after
// a chunk is legitimately collected and later re-created with the SAME content-
// addressed id, a hostile sync server that forges ONE ancient-recorded intent
// must NOT collect the re-created chunk in a single confirm run. This is R6's
// "old recorded time but young first-seen does NOT collect" invariant applied to
// the re-created-chunk case (design line 344, D3.4) — with no hand-seeding.
func TestGCRecreatedChunkResistsForgedAncientIntent(t *testing.T) {
	v, seenDir := openGCVault(t)
	id := gcHexID(0x6f)
	t0 := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	var now time.Time
	clock := func() time.Time { return now }
	fence := 72 * time.Hour
	gc := func() GCReport {
		t.Helper()
		r, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: fence, Now: clock, SeenStore: seenDir})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Legit collection over three runs (the natural leak path, no hand-seeding).
	writeOrphanChunk(t, v, id, "data", t0.Add(-500*time.Hour))
	now = t0
	gc()
	now = t0.Add(100 * time.Hour)
	gc()
	now = t0.Add(300 * time.Hour)
	if r := gc(); !gcContains(r.RemovedChunks, id) {
		t.Fatalf("setup: run 3 must collect the chunk; got %v", r.RemovedChunks)
	}

	// The hostile sync server re-materialises identical content (same id) with a
	// back-dated mtime and forges ONE ancient-recorded intent.
	writeOrphanChunk(t, v, id, "data", t0.Add(200*time.Hour))
	writeIntentFile(t, v, id+".intent", "2000-01-01T00:00:00Z")

	// A single confirm run well past the fence must NOT collect the re-created
	// chunk: phase 1 records a fresh (young) first-seen, which phase 2 respects.
	now = t0.Add(400 * time.Hour)
	r := gc()
	if gcContains(r.RemovedChunks, id) {
		t.Fatalf("a forged ancient intent must not collect a re-created chunk in one run; removed %v", r.RemovedChunks)
	}
	if !gcFileExists(v.chunkPath(id)) {
		t.Fatal("the re-created chunk must survive a single confirm run")
	}
}

// Tombstone (conditions/F4): the temp-orphan sweep must honour the RUN's GC
// fence (design D5.3: Compact "sweeps .tmp-* files older than the GC fence" and
// "gc dry-run lists them"), not the hardcoded 72h GCFenceDefault. A .tmp-*
// orphan older than a custom --fence but younger than the 72h default must be
// LISTED by `gc` dry-run and SWEPT by `gc --confirm`; one younger than that
// fence must be kept. Before the fix sweepTmpOrphans compared against
// GCFenceDefault regardless of the run's fence, so a 3h orphan under a 2h fence
// was neither listed nor swept.
func TestGCTempOrphanSweepHonoursCustomFence(t *testing.T) {
	v, seenDir := openGCVault(t)
	base := time.Now()
	fence := 2 * time.Hour
	now := func() time.Time { return base }

	chunkDir := filepath.Join(v.MetaRoot, "objects", "chunks", "aa")
	if err := os.MkdirAll(chunkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldOrphan := filepath.Join(chunkDir, ".tmp-old-orphan")     // 3h: older than the 2h fence, younger than the 72h default
	youngOrphan := filepath.Join(chunkDir, ".tmp-young-orphan") // 1h: younger than the fence
	for _, p := range []struct {
		path string
		mt   time.Time
	}{
		{oldOrphan, base.Add(-3 * time.Hour)},
		{youngOrphan, base.Add(-1 * time.Hour)},
	} {
		if err := os.WriteFile(p.path, []byte("partial write"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p.path, p.mt, p.mt); err != nil {
			t.Fatal(err)
		}
	}

	// Dry run: the plan must LIST the 3h orphan (older than the 2h fence), must
	// NOT list the 1h orphan, and must touch nothing on disk.
	dry, err := v.GarbageCollect(GCOptions{Confirm: false, Fence: fence, Now: now, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Compact == nil {
		t.Fatal("dry-run report is missing its compact plan")
	}
	if !gcContains(dry.Compact.TmpOrphans, oldOrphan) {
		t.Fatalf("dry-run must list the 3h orphan under a 2h fence; TmpOrphans=%#v", dry.Compact.TmpOrphans)
	}
	if gcContains(dry.Compact.TmpOrphans, youngOrphan) {
		t.Fatalf("dry-run must not list the 1h orphan under a 2h fence; TmpOrphans=%#v", dry.Compact.TmpOrphans)
	}
	if _, statErr := os.Stat(oldOrphan); statErr != nil {
		t.Fatalf("dry-run must not remove the orphan; stat err: %v", statErr)
	}

	// Confirm: the 3h orphan is swept, the 1h orphan is kept.
	got, err := v.GarbageCollect(GCOptions{Confirm: true, Fence: fence, Now: now, SeenStore: seenDir})
	if err != nil {
		t.Fatal(err)
	}
	if got.Compact == nil || !gcContains(got.Compact.TmpOrphans, oldOrphan) {
		t.Fatalf("confirm must sweep the 3h orphan under a 2h fence; compact=%#v", got.Compact)
	}
	if _, statErr := os.Stat(oldOrphan); !os.IsNotExist(statErr) {
		t.Fatalf("confirm must remove the 3h orphan; stat err: %v", statErr)
	}
	if _, statErr := os.Stat(youngOrphan); statErr != nil {
		t.Fatalf("confirm must keep the 1h orphan; stat err: %v", statErr)
	}
}
