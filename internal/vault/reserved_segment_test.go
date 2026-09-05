// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestF3LegacyReservedSegmentFileStaysReachable is the tombstone for finding
// peer/F3. A 0.15 peer (or any legacy/other-OS client) has no reserved-segment
// rule, so it can create a normal, visible, retrievable content file whose
// virtual path contains a segment equal to a metadata dir name (SeaVaultData or
// .seavault, case-insensitively). Design D7.1 promises such an EXISTING file
// stays reachable "everywhere, so no existing file ever becomes unreachable or
// uneditable": it must still list, read, get, export, overwrite and delete after
// this version opens the vault. Regression: A1 routed those metadata-name
// segments through the same always-on rejection/hiding as the directory marker,
// so the file silently vanished from `list`, every read/mutate returned
// "reserved virtual path ... is not allowed", and its chunk stayed pinned live
// yet unreachable — recoverable only by returning to a 0.15 client.
//
// The peer's write is simulated with injectRawFile (the low-level putReader, the
// same helper the D7.1 portable-name tests use), which stores real chunks under
// the exact index key a 0.15 client would land after a sync, bypassing this
// version's create gate.
func TestF3LegacyReservedSegmentFileStaysReachable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "correct horse battery staple"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	const reserved = "content/SeaVaultData/notes.txt"
	payload := []byte("secret notes payload")
	injectRawFile(t, v, reserved, payload)

	// A normal sibling, so export/list have a known-good comparison.
	if _, err := v.PutReader(strings.NewReader("normal payload"), "content/normal.txt", 14, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	// D7.1: the existing reserved-segment file is LISTED (not silently hidden).
	list, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if !sliceContains(list, reserved) {
		t.Fatalf("D7.1: existing reserved-segment file must be listed; List() = %v", list)
	}

	// D7.1: it READS back byte-for-byte through WriteFileTo.
	var buf bytes.Buffer
	if err := v.WriteFileTo(reserved, &buf); err != nil {
		t.Fatalf("D7.1: reading an existing reserved-segment file must work: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), payload) {
		t.Fatalf("read content = %q, want %q", buf.Bytes(), payload)
	}

	// D7.1: it GETS to disk.
	getOut := filepath.Join(t.TempDir(), "got.txt")
	if err := v.GetPath(reserved, getOut); err != nil {
		t.Fatalf("D7.1: getting an existing reserved-segment file must work: %v", err)
	}
	if got, _ := os.ReadFile(getOut); !bytes.Equal(got, payload) {
		t.Fatalf("got content = %q, want %q", got, payload)
	}

	// D7.1: it EXPORTS (not silently dropped from the export set).
	expDir := t.TempDir()
	res, err := v.ExportPath(context.Background(), "content/", expDir, ExportOptions{})
	if err != nil {
		t.Fatalf("D7.1: export must not fail: %v", err)
	}
	if !exportWroteFileWithContent(t, expDir, payload) {
		t.Fatalf("D7.1: the reserved-segment file must be exported; result = %#v", res.Entries)
	}

	// D7.1: it OVERWRITES in place through PutReader on the existing key.
	newPayload := []byte("rewritten by this version")
	if _, err := v.PutReader(bytes.NewReader(newPayload), reserved, int64(len(newPayload)), 0o600, time.Now()); err != nil {
		t.Fatalf("D7.1: overwriting an existing reserved-segment file must work: %v", err)
	}
	buf.Reset()
	if err := v.WriteFileTo(reserved, &buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), newPayload) {
		t.Fatalf("overwrite did not take; read %q, want %q", buf.Bytes(), newPayload)
	}

	// D7.1: it DELETES.
	if err := v.Remove(reserved); err != nil {
		t.Fatalf("D7.1: deleting an existing reserved-segment file must work: %v", err)
	}
	list, err = v.List()
	if err != nil {
		t.Fatal(err)
	}
	if sliceContains(list, reserved) {
		t.Fatalf("after delete the reserved-segment file must be gone; List() = %v", list)
	}

	// D1.2 STILL holds: directly CREATING a NEW reserved-segment virtual path is
	// refused (the create gate is not weakened by the D7.1 fix).
	for _, p := range []string{"content/SeaVaultData/other.txt", "SeaVaultData/x.txt", ".seavault/x.txt", "sub/SeaVaultData/x.txt"} {
		if _, err := v.PutReader(strings.NewReader("x"), p, 1, 0o600, time.Now()); err == nil {
			t.Fatalf("D1.2: creating a NEW reserved-segment path %q must still be refused", p)
		}
	}
}

func sliceContains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func exportWroteFileWithContent(t *testing.T, dir string, want []byte) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		got, rErr := os.ReadFile(p)
		if rErr != nil {
			return rErr
		}
		if bytes.Equal(got, want) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestConditionsF1DirectoryPutReservedSegmentReachableAndReclaimable is the
// tombstone for finding conditions/F1 (Condition 6 / design D1.2). It exercises
// the exact mechanism the finding faults: THIS version's directory `put` of a
// source tree that contains a subdirectory named like a SeaVault metadata dir
// (the "legacy .seavault inside a backup tree" case Condition 6 names) walks the
// tree and writes the foreign file to a reserved-segment virtual path
// (content/backup/SeaVaultData/data.txt). Design D1.2 requires that file be
// "imported like any other directory ... never a silent skip" AND that "no
// existing file ever becomes unreachable" — so after the put it must LIST, READ,
// GET, EXPORT and REMOVE, its chunk must be counted LIVE while reachable, and
// become RECLAIMABLE by gc once removed. A D1.2 advisory warning must also reach
// the PutReport (never a silent import).
//
// Regression (conditions/F1): A1 routed reserved-name segments through the same
// always-on hide/reject as the directory marker, so the directory-put import
// landed at a path that `list` omitted and get/export/remove rejected with
// "reserved virtual path ... is not allowed", while liveChunkSet kept its chunk
// pinned live — permanently unreachable AND unreclaimable, a silent leak, behind
// a put line that reported "1 new" success. This differs from the peer/F3
// tombstone (which injects a peer-created file via the low-level writer): here
// the unreachable path is produced by this version's own PutPathReport walk.
func TestConditionsF1DirectoryPutReservedSegmentReachableAndReclaimable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "correct horse battery staple"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	// Source tree: a foreign metadata-named subdir plus an ordinary sibling.
	src := filepath.Join(t.TempDir(), "backup")
	foreignDir := filepath.Join(src, "SeaVaultData")
	if err := os.MkdirAll(foreignDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignPayload := []byte("foreign metadata-named file payload")
	if err := os.WriteFile(filepath.Join(foreignDir, "data.txt"), foreignPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "normal.txt"), []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}

	const reserved = "content/backup/SeaVaultData/data.txt"

	rep, err := v.PutPathReport(src, "content/backup")
	if err != nil {
		t.Fatalf("conditions/F1: directory put must succeed (import as plain content, never refuse): %v", err)
	}

	// D1.2: the import is NOT silent — a warning reaches the operator-facing report.
	warned := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "imported as plain content") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("conditions/F1: the D1.2 metadata-dir warning must reach the PutReport; Warnings=%#v", rep.Warnings)
	}

	// Capture the imported file's chunk so gc reclaimability can be asserted by id.
	idx, err := v.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := idx.Files[reserved]
	if !ok {
		t.Fatalf("conditions/F1: the foreign file must be indexed at %q; index keys=%v", reserved, indexKeys(idx))
	}
	if len(rec.Chunks) == 0 {
		t.Fatalf("conditions/F1: the imported file must reference at least one chunk; rec=%#v", rec)
	}
	chunkID := rec.Chunks[0].ID

	// D1.2 reachability: the reserved-segment file is LISTED (never silently hidden).
	list, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if !sliceContains(list, reserved) {
		t.Fatalf("conditions/F1: the directory-put reserved-segment file must be listed; List()=%v", list)
	}

	// D1.2 reachability: it READS back byte-for-byte.
	var buf bytes.Buffer
	if err := v.WriteFileTo(reserved, &buf); err != nil {
		t.Fatalf("conditions/F1: reading the imported reserved-segment file must work: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), foreignPayload) {
		t.Fatalf("read content = %q, want %q", buf.Bytes(), foreignPayload)
	}

	// D1.2 reachability: it GETS to disk.
	getOut := filepath.Join(t.TempDir(), "got.txt")
	if err := v.GetPath(reserved, getOut); err != nil {
		t.Fatalf("conditions/F1: getting the imported reserved-segment file must work: %v", err)
	}
	if got, _ := os.ReadFile(getOut); !bytes.Equal(got, foreignPayload) {
		t.Fatalf("got content = %q, want %q", got, foreignPayload)
	}

	// D1.2 reachability: the whole subtree EXPORTS, including the foreign file.
	expDir := t.TempDir()
	if _, err := v.ExportPath(context.Background(), "content/backup", expDir, ExportOptions{}); err != nil {
		t.Fatalf("conditions/F1: export must not fail: %v", err)
	}
	if !exportWroteFileWithContent(t, expDir, foreignPayload) {
		t.Fatalf("conditions/F1: the imported reserved-segment file must be exported, not silently dropped")
	}

	// Space accounting: while reachable the chunk is LIVE — a dry-run gc must NOT
	// list it as a candidate (the finding's "0 unreferenced" is CORRECT here only
	// because the file is genuinely reachable, not because it is a hidden leak).
	planBefore, err := v.GarbageCollect(GCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sliceContains(planBefore.Candidates, chunkID) {
		t.Fatalf("conditions/F1: a reachable file's chunk must not be a gc candidate; Candidates=%v", planBefore.Candidates)
	}

	// D1.2 reachability: it DELETES.
	if err := v.Remove(reserved); err != nil {
		t.Fatalf("conditions/F1: deleting the imported reserved-segment file must work: %v", err)
	}
	list, err = v.List()
	if err != nil {
		t.Fatal(err)
	}
	if sliceContains(list, reserved) {
		t.Fatalf("after delete the reserved-segment file must be gone; List()=%v", list)
	}

	// Space accounting: once removed the chunk is RECLAIMABLE — a dry-run gc now
	// lists it as a candidate. The finding's leak was a chunk pinned live yet
	// unreachable, reclaimable by no one; here removal frees it.
	planAfter, err := v.GarbageCollect(GCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !sliceContains(planAfter.Candidates, chunkID) {
		t.Fatalf("conditions/F1: after removal the freed chunk must be reclaimable by gc; Candidates=%v", planAfter.Candidates)
	}
}

func indexKeys(idx Index) []string {
	keys := make([]string, 0, len(idx.Files))
	for k := range idx.Files {
		keys = append(keys, k)
	}
	return keys
}
