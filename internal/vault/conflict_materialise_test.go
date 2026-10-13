// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// When a user edits a sync-conflict copy (doc.txt.conflict-…) and then compacts,
// the materialiser used to overwrite that edit with the OLD losing record: the
// planned conflict for the conflict path was emitted even though a real manifest
// already lived there. loadManifestIndex must defer to the real record at a
// conflict path, and compact must not clobber it.
func TestEditedConflictCopySurvivesCompaction(t *testing.T) {
	v, cp := vaultWithConflictCopy(t)

	// The user edits that conflict copy (a real PUT at the conflict path).
	const editedBody = "the user's EDIT of the conflict copy"
	if _, err := v.PutReader(strings.NewReader(editedBody), cp, int64(len(editedBody)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	editedChunks := files[cp].Chunks
	if len(editedChunks) == 0 {
		t.Fatalf("precondition: the edited copy must have chunks; files: %#v", files)
	}

	// Reclaim space. The edit must survive, byte-for-byte, not be reverted to the
	// old loser.
	if _, err := v.Compact(); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err = v.Files()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := files[cp]
	if !ok {
		t.Fatalf("the edited conflict copy vanished after compaction; files: %#v", files)
	}
	if !sameChunks(rec.Chunks, editedChunks) {
		t.Fatalf("compaction reverted the edited conflict copy to the old loser:\n got  %#v\n want %#v", rec.Chunks, editedChunks)
	}

	dst := filepath.Join(t.TempDir(), "out.txt")
	if err := v.GetPath(cp, dst); err != nil {
		t.Fatalf("reading back the edited conflict copy: %v", err)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != editedBody {
		t.Fatalf("the edited conflict copy reads back as %q, want %q", out, editedBody)
	}
}

// vaultWithConflictCopy builds a vault whose doc.txt has two concurrent live
// manifests (disjoint device clocks), so reconciliation surfaces the loser as a
// sync-conflict copy, and returns the open vault and that conflict path.
func vaultWithConflictCopy(t *testing.T) (*Vault, string) {
	t.Helper()
	root := t.TempDir() + "/vault"
	const password = "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	winnerRec := recordFromScratchPut(t, v, "scratch-w.txt", "the winning concurrent edit")
	loserRec := recordFromScratchPut(t, v, "scratch-l.txt", "the OLD losing concurrent edit")
	winnerRec.Clock = map[string]int64{"DEV-A": 2}
	loserRec.Clock = map[string]int64{"DEV-B": 2}

	writeRecordAt(t, v, "content/doc.txt", loserRec)
	docManifest := v.manifestPath(v.manifestID("content/doc.txt"))
	copyFile(t, docManifest, strings.TrimSuffix(docManifest, ".manifest")+".sync-conflict.manifest")
	writeRecordAt(t, v, "content/doc.txt", winnerRec)
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	var cp string
	for p, rec := range files {
		if strings.HasPrefix(p, "content/doc.txt.conflict-") && rec.ConflictOf == "content/doc.txt" {
			cp = p
		}
	}
	if cp == "" {
		t.Fatalf("precondition: the loser must appear as a conflict copy; files: %#v", files)
	}
	return v, cp
}

// Deleting a conflict copy must stick: reconciliation must not resurrect it from
// the losing manifest, and compact must not rewrite it.
func TestDeletedConflictCopyStaysDeleted(t *testing.T) {
	v, cp := vaultWithConflictCopy(t)

	if _, err := v.RemovePath(cp); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	if files, _ := v.Files(); files[cp].ConflictOf != "" || len(files[cp].Chunks) != 0 {
		t.Fatalf("the deleted conflict copy must be gone after reload, got %#v", files[cp])
	}
	if _, err := v.Compact(); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	if files, _ := v.Files(); files[cp].ConflictOf != "" || len(files[cp].Chunks) != 0 {
		t.Fatalf("compaction resurrected the deleted conflict copy: %#v", files[cp])
	}
}

// recordFromScratchPut puts body at a scratch path, snapshots the resulting
// FileRecord (real chunks), then tombstones the scratch path so only the record
// we re-home carries those chunks.
func recordFromScratchPut(t *testing.T, v *Vault, scratch, body string) FileRecord {
	t.Helper()
	if _, err := v.PutReader(strings.NewReader(body), scratch, int64(len(body)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := files["content/"+scratch]
	if !ok || len(rec.Chunks) == 0 {
		t.Fatalf("scratch put %q produced no record with chunks", scratch)
	}
	if _, err := v.RemovePath("content/" + scratch); err != nil {
		t.Fatal(err)
	}
	rec.ConflictOf = ""
	return rec
}

// writeRecordAt writes rec as the canonical manifest for virtualPath, preserving
// rec's clock (a concurrent-edit fixture).
func writeRecordAt(t *testing.T, v *Vault, virtualPath string, rec FileRecord) {
	t.Helper()
	mr := ManifestRecord{Version: 1, Path: virtualPath, UpdatedAt: rec.UpdatedAt, Clock: rec.Clock, File: rec}
	if err := v.saveManifestRecord(mr); err != nil {
		t.Fatal(err)
	}
}
