// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a delete tombstone that wins over a live
// loser leaves the deleted path absent and the loser present as a *.conflict-*
// entry carrying the loser's chunks — all IN MEMORY, with zero writes to the
// metadata dir on load or read. Compact materialises the conflict and a second
// Compact is an empty no-op.
func TestTombstoneWinnerKeepsLoserAsConflictWithoutWriting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const password = "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	// A second live file so the "Get leaves the fingerprint unchanged" assertion
	// exercises a real chunk read.
	const keepBody = "keep me around"
	if _, err := v.PutReader(strings.NewReader(keepBody), "keep.txt", int64(len(keepBody)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The losing edit: put it, snapshot its record, and keep a sync-conflict copy
	// of its manifest as the live loser before deleting it.
	const editBody = "the losing concurrent edit"
	if _, err := v.PutReader(strings.NewReader(editBody), "doc.txt", int64(len(editBody)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	editRec := files["content/doc.txt"]
	if len(editRec.Chunks) == 0 {
		t.Fatal("precondition: the edit must have chunks")
	}
	docManifest := v.manifestPath(v.manifestID("content/doc.txt"))
	copyFile(t, docManifest, strings.TrimSuffix(docManifest, ".manifest")+".sync-conflict.manifest")
	// Overwrite the canonical manifest with a tombstone that wins on generation
	// and whose deletedGeneration is below the edit, so the edit survives (I4).
	if err := v.saveTombstone("content/doc.txt", editRec.Generation+1_000_000, editRec.Generation-1000); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}

	files, err = v.Files()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["content/doc.txt"]; ok {
		t.Fatalf("the deleted path must be absent after the tombstone wins, files: %#v", files)
	}
	var conflict string
	var conflictRec FileRecord
	for p, rec := range files {
		if strings.HasPrefix(p, "content/doc.txt.conflict-") && rec.ConflictOf == "content/doc.txt" {
			conflict, conflictRec = p, rec
		}
	}
	if conflict == "" {
		t.Fatalf("the live loser must be present as a conflict entry, files: %#v", files)
	}
	if !sameChunks(conflictRec.Chunks, editRec.Chunks) {
		t.Fatalf("conflict entry must carry the loser's chunks; got %#v want %#v", conflictRec.Chunks, editRec.Chunks)
	}

	// List / Get / AllEntries must not write anything: the metadata-dir
	// fingerprint is identical before and after.
	fpBefore, err := v.indexFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.List(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := v.WriteFileTo("keep.txt", &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != keepBody {
		t.Fatalf("Get returned %q, want %q", buf.String(), keepBody)
	}
	if _, err := v.AllEntries(); err != nil {
		t.Fatal(err)
	}
	fpAfter, err := v.indexFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fpAfter != fpBefore {
		t.Fatalf("List/Get/AllEntries must not change the metadata-dir fingerprint (before %d, after %d)", fpBefore, fpAfter)
	}

	// Compact materialises the conflict on disk and reports it.
	report, err := v.Compact()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Conflicts) != 1 || report.Conflicts[0] != conflict {
		t.Fatalf("Compact should materialise exactly %q, report: %#v", conflict, report)
	}
	if report.RemovedManifests == 0 {
		t.Fatalf("Compact should remove the loser source it replaced, report: %#v", report)
	}
	fpCompacted, err := v.indexFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fpCompacted == fpBefore {
		t.Fatal("Compact must change the on-disk fingerprint by materialising the conflict")
	}
	// The materialised conflict survives a fresh reload and its chunks are intact.
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err = v.Files()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := files[conflict]
	if !ok {
		t.Fatalf("materialised conflict %q missing after reload, files: %#v", conflict, files)
	}
	if !sameChunks(rec.Chunks, editRec.Chunks) {
		t.Fatalf("materialised conflict lost its chunks; got %#v want %#v", rec.Chunks, editRec.Chunks)
	}

	// A second Compact recomputes the plan from settled disk and finds nothing.
	second, err := v.Compact()
	if err != nil {
		t.Fatal(err)
	}
	if second.Materialised() {
		t.Fatalf("a second Compact must be an empty no-op, report: %#v", second)
	}
}

// R6b: Compact sweeps atomic-write.tmp-* orphans older than the GC
// fence from both objects/chunks and manifests, and keeps young ones (a rename
// may still be in flight). The clock is injected so both branches are exercised
// deterministically.
func TestCompactSweepsOldTmpOrphans(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const password = "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	old := base.Add(-100 * time.Hour) // older than the 72h fence
	young := base.Add(-1 * time.Hour) // younger than the fence

	type tmp struct {
		path string
		mt   time.Time
		old  bool
	}
	tmps := []tmp{
		{filepath.Join(v.MetaRoot, "objects", "chunks", "aa", ".tmp-old-chunk"), old, true},
		{filepath.Join(v.MetaRoot, "objects", "chunks", "aa", ".tmp-young-chunk"), young, false},
		{filepath.Join(v.MetaRoot, ManifestDirName, "bb", ".tmp-old-manifest"), old, true},
		{filepath.Join(v.MetaRoot, ManifestDirName, "bb", ".tmp-young-manifest"), young, false},
	}
	for _, f := range tmps {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.path, []byte("partial write"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(f.path, f.mt, f.mt); err != nil {
			t.Fatal(err)
		}
	}

	report, err := v.compact(base, true, GCFenceDefault)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.TmpOrphans) != 2 {
		t.Fatalf("expected exactly the two old orphans swept, got %#v", report.TmpOrphans)
	}
	for _, f := range tmps {
		_, statErr := os.Stat(f.path)
		if f.old && !os.IsNotExist(statErr) {
			t.Fatalf("old orphan %s should have been swept, stat err: %v", f.path, statErr)
		}
		if !f.old && statErr != nil {
			t.Fatalf("young orphan %s must be kept, stat err: %v", f.path, statErr)
		}
	}

	// Idempotent: with the old orphans gone and the young ones still inside the
	// fence, a second sweep at the same instant does nothing.
	second, err := v.compact(base, true, GCFenceDefault)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.TmpOrphans) != 0 {
		t.Fatalf("second sweep should find no old orphans, got %#v", second.TmpOrphans)
	}
}

// Regression: writeIntent
// (gc.go) writes each intent through atomicWriteFile, so a crash between
// CreateTemp and rename leaves a.tmp-* orphan in the SYNCED gc-intents/ tree —
// the same window /R6b concede for chunks and manifests. sweepTmpOrphans must
// cover gc-intents/ too, or that orphan is never reclaimed and syncs to the
// provider forever. A real <id>.intent file (no.tmp- prefix) must survive.
func TestCompactSweepsOldTmpOrphansInGCIntents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const password = "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	old := base.Add(-100 * time.Hour) // older than the 72h fence
	young := base.Add(-1 * time.Hour) // younger than the fence

	intentDir := filepath.Join(v.MetaRoot, GCIntentDirName)
	if err := os.MkdirAll(intentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realID := strings.Repeat("a", 64) // a valid 64-hex chunk id
	oldTmp := filepath.Join(intentDir, ".tmp-crashed-intent-old")
	youngTmp := filepath.Join(intentDir, ".tmp-crashed-intent-young")
	realIntent := filepath.Join(intentDir, realID+gcIntentSuffix)

	type plant struct {
		path string
		mt   time.Time
	}
	for _, p := range []plant{
		{oldTmp, old},
		{youngTmp, young},
		{realIntent, old}, // an aged, legitimate intent — must NOT be swept
	} {
		if err := os.WriteFile(p.path, []byte("partial write"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p.path, p.mt, p.mt); err != nil {
			t.Fatal(err)
		}
	}

	report, err := v.compact(base, true, GCFenceDefault)
	if err != nil {
		t.Fatal(err)
	}

	var sweptOld bool
	for _, o := range report.TmpOrphans {
		if o == oldTmp {
			sweptOld = true
		}
		if o == realIntent {
			t.Fatalf("real intent %s was reported as a temp orphan", realIntent)
		}
	}
	if !sweptOld {
		t.Fatalf("old gc-intents.tmp-* orphan %s must be reported swept, got TmpOrphans=%#v", oldTmp, report.TmpOrphans)
	}
	if _, statErr := os.Stat(oldTmp); !os.IsNotExist(statErr) {
		t.Fatalf("old gc-intents orphan %s should have been removed, stat err: %v", oldTmp, statErr)
	}
	if _, statErr := os.Stat(youngTmp); statErr != nil {
		t.Fatalf("young gc-intents orphan %s must be kept (rename may still be in flight), stat err: %v", youngTmp, statErr)
	}
	if _, statErr := os.Stat(realIntent); statErr != nil {
		t.Fatalf("real intent %s must never be swept, stat err: %v", realIntent, statErr)
	}
}
