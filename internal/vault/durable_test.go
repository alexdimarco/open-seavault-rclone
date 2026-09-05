// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withRenameSeam saves the rename injection points and restores them at test
// end, and installs a classifier that treats retryable (and anything wrapping
// it) as a transient sharing violation. It lets a portable test drive the
// Windows retry loop on any OS.
func withRenameSeam(t *testing.T, retryable error) {
	t.Helper()
	origFn, origSleep, origRetry := renameFn, renameSleep, renameRetryable
	t.Cleanup(func() { renameFn, renameSleep, renameRetryable = origFn, origSleep, origRetry })
	renameRetryable = func(err error) bool { return retryable != nil && errors.Is(err, retryable) }
}

// a sharing violation on the first renameAttempts-1 tries, then success, is
// retried to completion with the documented exponential backoff.
func TestRenameWithRetrySucceedsAfterTransientViolations(t *testing.T) {
	fake := errors.New("fake ERROR_SHARING_VIOLATION")
	withRenameSeam(t, fake)
	var calls int
	var sleeps []time.Duration
	renameFn = func(_, _ string) error {
		calls++
		if calls < renameAttempts {
			return fake
		}
		return nil
	}
	renameSleep = func(d time.Duration) { sleeps = append(sleeps, d) }

	if err := renameWithRetry("old", "new"); err != nil {
		t.Fatalf("expected success after transient violations, got %v", err)
	}
	if calls != renameAttempts {
		t.Fatalf("expected %d rename attempts, got %d", renameAttempts, calls)
	}
	if len(sleeps) != renameAttempts-1 {
		t.Fatalf("expected %d backoff sleeps, got %d (%v)", renameAttempts-1, len(sleeps), sleeps)
	}
	want := []time.Duration{25, 50, 100, 200, 400, 400, 400, 400, 400}
	for i, w := range want {
		if sleeps[i] != w*time.Millisecond {
			t.Fatalf("backoff[%d]=%v want %v (full: %v)", i, sleeps[i], w*time.Millisecond, sleeps)
		}
	}
}

// a permanent sharing violation surfaces after exactly renameAttempts tries.
func TestRenameWithRetrySurfacesPermanentViolation(t *testing.T) {
	fake := errors.New("permanent ERROR_LOCK_VIOLATION")
	withRenameSeam(t, fake)
	var calls int
	renameFn = func(_, _ string) error { calls++; return fake }
	renameSleep = func(time.Duration) {}

	err := renameWithRetry("old", "new")
	if !errors.Is(err, fake) {
		t.Fatalf("expected the permanent violation to surface, got %v", err)
	}
	if calls != renameAttempts {
		t.Fatalf("expected %d attempts before giving up, got %d", renameAttempts, calls)
	}
}

// an error that is NOT a sharing violation is returned on the first try with
// no retry and no sleep (POSIX rename semantics; rename_other.go).
func TestRenameWithRetryReturnsNonRetryableImmediately(t *testing.T) {
	retryable := errors.New("would-retry")
	withRenameSeam(t, retryable)
	other := errors.New("cross-device link, not retryable")
	var calls int
	renameFn = func(_, _ string) error { calls++; return other }
	renameSleep = func(time.Duration) { t.Fatal("must not sleep for a non-retryable error") }

	err := renameWithRetry("old", "new")
	if !errors.Is(err, other) {
		t.Fatalf("expected the non-retryable error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one attempt for a non-retryable error, got %d", calls)
	}
}

// A generic (non-errno) error is never a retryable rename on any OS; the
// Windows errno mapping that DOES retry is covered by rename_windows_test.go.
func TestGenericErrorIsNeverRetryableRename(t *testing.T) {
	if isRetryableRenameError(errors.New("anything")) {
		t.Fatal("a generic error must not be classified as a retryable rename")
	}
	if isRetryableRenameError(nil) {
		t.Fatal("nil must not be classified as a retryable rename")
	}
}

// an upper- or mixed-case chunk/manifest filename parses to the same
// lower-case id as its canonical name.
func TestIDsFromFileNamesAreLowerCased(t *testing.T) {
	loHex := strings.Repeat("ab", 32) // 64 hex chars, lower
	hiHex := strings.ToUpper(loHex)
	if got, want := chunkIDFromFileName(hiHex+".chunk"), loHex; got != want {
		t.Fatalf("chunkIDFromFileName(upper) = %q, want %q", got, want)
	}
	if chunkIDFromFileName(hiHex+".chunk") != chunkIDFromFileName(loHex+".chunk") {
		t.Fatal("upper and lower chunk names must map to the same id")
	}
	mixHex := strings.Repeat("aB", 32)
	if got := manifestIDFromFileName(mixHex + ".manifest"); got != strings.ToLower(mixHex) {
		t.Fatalf("manifestIDFromFileName(mixed) = %q, want %q", got, strings.ToLower(mixHex))
	}
	if manifestIDFromFileName(hiHex+".sync-conflict.manifest") != loHex {
		t.Fatal("manifest id must be lower-cased and tolerate a conflict suffix")
	}
}

// GC keeps a live chunk whose on-disk name has been case-folded to
// upper-case; without the lower-casing it would be deleted as unreferenced.
func TestGCKeepsLiveChunkUnderUpperCaseName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("hex-case-", 60)
	if _, err := v.PutReader(strings.NewReader(content), "doc.txt", int64(len(content)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, _ := v.Files()
	rec := files["content/doc.txt"]
	if len(rec.Chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	// Back-date the chunk objects: the chunk-mtime fence must be
	// CLEARED at the final run so the ONLY thing that can keep the object alive
	// past every fence is the case-folding liveness match — not a young mtime.
	old := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Add(-500 * time.Hour)
	for _, ref := range rec.Chunks {
		cp := v.chunkPath(ref.ID)
		on := cp
		if upper := filepath.Join(filepath.Dir(cp), strings.ToUpper(ref.ID)+".chunk"); upper != cp {
			if err := os.Rename(cp, upper); err != nil {
				t.Fatal(err)
			}
			on = upper
		}
		if err := os.Chtimes(on, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// A single --confirm run structurally removes NOTHING (phase 1 only writes
	// intents), so asserting RemovedChunks==0 after one run is vacuous — it holds
	// even when the object is misclassified as garbage. Drive the
	// whole two-phase fenced protocol PAST the fence with a controlled clock so
	// the recorded time, this device's first-seen record, and the chunk mtime all
	// age beyond it: only then can GC delete a chunk it deems unreferenced. If the
	// upper-case name defeated the liveness match, run 3 would collect these
	// LIVE chunks here.
	seenDir := filepath.Join(t.TempDir(), "gc-seen")
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
			t.Fatalf("run %d: GC must keep a live chunk under an upper-case name; removed %v", run+1, report.RemovedChunks)
		}
	}
	if n := countChunkFiles(t, root); n == 0 {
		t.Fatal("expected the upper-cased chunk to survive GC past the fence")
	}
}

// two on-disk copies of the same losing manifest converge to ONE conflict
// path, because conflictPath is now seeded from the record's content, not the
// device-local on-disk filename.
func TestConflictPathConvergesAcrossOnDiskFilenames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("version one"), "doc.txt", int64(len("version one")), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	orig := firstManifestFile(t, root, v)
	// Two sync clients each left a differently-named copy of the SAME losing
	// record on disk. They are one peer device's concurrent edit duplicated under
	// two names, so both copies carry the SAME disjoint peer vector clock (design
	// ): concurrent with this device's edit (kept as a conflict), and
	// identical to each other (must converge to ONE conflict path, not two).
	copyA := strings.TrimSuffix(orig, ".manifest") + ".deviceA-sync-conflict.manifest"
	copyB := strings.TrimSuffix(orig, ".manifest") + ".deviceB (conflicted copy).manifest"
	copyFile(t, orig, copyA)
	copyFile(t, orig, copyB)
	if _, err := v.PutReader(strings.NewReader("version two"), "doc.txt", int64(len("version two")), 0o600, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	peerClock := map[string]int64{"peer-device-00000000000000000000": 1}
	rewriteManifestClock(t, v, copyA, peerClock)
	rewriteManifestClock(t, v, copyB, peerClock)
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	conflicts := map[string]struct{}{}
	for p, rec := range files {
		if strings.HasPrefix(p, "content/doc.txt.conflict-") && rec.ConflictOf == "content/doc.txt" {
			conflicts[p] = struct{}{}
		}
	}
	if len(conflicts) != 1 {
		t.Fatalf("expected the two identical losing copies to converge to one conflict path, got %d: %v", len(conflicts), conflicts)
	}
}

// conflictPath is a pure function of the original path and the record's
// content — deterministic, and sensitive to the content it seeds from.
func TestConflictPathIsContentSeededAndDeterministic(t *testing.T) {
	rec := FileRecord{
		Generation: 42,
		UpdatedAt:  "2026-09-01T12:00:00Z",
		Chunks:     []ChunkRef{{ID: strings.Repeat("aa", 32), Size: 10}, {ID: strings.Repeat("bb", 32), Size: 20}},
	}
	a := conflictPath("content/doc.txt", rec)
	if a == "" || !strings.HasPrefix(a, "content/doc.txt.conflict-") {
		t.Fatalf("unexpected conflict path %q", a)
	}
	if a != conflictPath("content/doc.txt", rec) {
		t.Fatal("conflictPath must be deterministic for the same input")
	}
	recGen := rec
	recGen.Generation = 43
	if conflictPath("content/doc.txt", recGen) == a {
		t.Fatal("a different generation must change the conflict suffix")
	}
	recChunk := rec
	recChunk.Chunks = []ChunkRef{{ID: strings.Repeat("cc", 32), Size: 10}}
	if conflictPath("content/doc.txt", recChunk) == a {
		t.Fatal("different chunk content must change the conflict suffix")
	}
}

func countChunkFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(filepath.Join(metaRootOf(t, root), "objects", "chunks"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".chunk") {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
