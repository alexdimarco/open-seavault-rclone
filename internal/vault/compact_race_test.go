// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regression for.
//
// Compact holds v.mu across plan+mutate and removes each conflict loser by its
// plan-time Source (compact.go). commitFileManifest must therefore perform its
// manifest DISK write UNDER v.mu, not before taking it: otherwise a concurrent
// commit that rewrites the canonical manifest — after Compact computed a plan in
// which the canonical file is the loser it will remove, but before the remove —
// lands the new edit on disk exactly where Compact then deletes it. The edit is
// silently lost (: "a concurrent edit is never silently lost").
//
// This models the interleaving deterministically: a synced sync-conflict sibling
// outranks the local canonical (making the canonical the loser Compact removes),
// and at the instant Compact removes that canonical loser a concurrent
// commitFileManifest writes a NEW higher-generation edit to the same canonical
// path. With commitFileManifest's disk write serialized under v.mu against
// Compact, the concurrent edit survives (as canonical, since it outranks the
// sibling). Without it, Compact's os.Remove deletes the just-written edit.
func TestCompactSerializesConcurrentCommitAgainstLoserRemoval(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const password = "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}

	const vp = "content/doc.txt"
	loserChunk := strings.Repeat("a", 64)
	winnerChunk := strings.Repeat("b", 64)
	newChunk := strings.Repeat("c", 64)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	mkRec := func(gen int64, chunk string) FileRecord {
		return FileRecord{
			Size:       3,
			Mode:       0o600,
			ModTime:    ts,
			UpdatedAt:  ts,
			Generation: gen,
			Chunks:     []ChunkRef{{ID: chunk, Size: 3}},
		}
	}
	loserRec := mkRec(1000, loserChunk)   // the local canonical, lower generation
	winnerRec := mkRec(2000, winnerChunk) // the synced sync-conflict sibling
	newRec := mkRec(5000, newChunk)       // the concurrent edit, outranks both

	canonicalPath := v.manifestPath(v.manifestID(vp))
	siblingPath := strings.TrimSuffix(canonicalPath, ".manifest") + ".sync-conflict.manifest"

	// Build state: canonical = loser (gen 1000, chunk a), sibling = winner
	// (gen 2000, chunk b). Writing the winner first, copying it to the sibling,
	// then overwriting the canonical with the loser leaves exactly that on disk.
	if err := v.saveFileManifest(vp, winnerRec); err != nil {
		t.Fatal(err)
	}
	copyFile(t, canonicalPath, siblingPath)
	if err := v.saveFileManifest(vp, loserRec); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}

	// Precondition: the pure load must plan to remove the canonical file as the
	// losing edit's Source, and the winner (sibling, chunk b) must be live at vp.
	// If this precondition ever changes, the interleaving below no longer targets
	// the canonical path and the test would silently stop guarding the race.
	idx, plan, err := v.loadManifestIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.conflicts) != 1 {
		t.Fatalf("precondition: expected exactly one planned conflict, got %#v", plan.conflicts)
	}
	if plan.conflicts[0].Source != canonicalPath {
		t.Fatalf("precondition: planned conflict Source = %q, want the canonical path %q", plan.conflicts[0].Source, canonicalPath)
	}
	if live, ok := idx.Files[vp]; !ok || len(live.Chunks) != 1 || live.Chunks[0].ID != winnerChunk {
		t.Fatalf("precondition: %q must be the winner (chunk b) before Compact, got %#v (ok=%v)", vp, live, ok)
	}

	origBytes, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}

	// Hook the package removeFn so that the instant Compact removes the canonical
	// loser, a concurrent commitFileManifest writes newRec (gen 5000, chunk c) to
	// the same canonical path — modelling a browser upload / `seavault put`
	// racing `seavault compact` inside one open *Vault, coupled only by v.mu.
	origRemove := removeFn
	defer func() { removeFn = origRemove }()
	commitErr := make(chan error, 1)
	var once sync.Once
	removeFn = func(path string) error {
		if path == canonicalPath {
			once.Do(func() {
				go func() { commitErr <- v.commitFileManifest(vp, newRec) }()
				// Wait until the concurrent commit's disk write actually lands
				// (the canonical bytes change) or a deadline passes. When
				// commitFileManifest is NOT serialized under v.mu, its lock-free
				// disk write lands here (Compact holds v.mu) and this returns
				// early — os.Remove then deletes the new edit. When it IS
				// serialized, the commit blocks on v.mu until Compact finishes,
				// so the bytes never change during this window (deadline hit) and
				// os.Remove deletes only the old loser; the edit lands afterward.
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					cur, rerr := os.ReadFile(canonicalPath)
					if rerr == nil && !bytes.Equal(cur, origBytes) {
						break
					}
					time.Sleep(2 * time.Millisecond)
				}
			})
		}
		return origRemove(path)
	}

	if _, err := v.Compact(); err != nil {
		t.Fatalf("Compact returned error: %v", err)
	}
	if err := <-commitErr; err != nil {
		t.Fatalf("concurrent commit returned error: %v", err)
	}

	// Reload from settled disk and confirm the concurrent edit survives somewhere
	// (as the live path or a materialised *.conflict-* entry). Its distinctive
	// chunk id must be present in the index.
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range files {
		for _, ch := range rec.Chunks {
			if ch.ID == newChunk {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("DATA LOSS: the concurrently-committed edit (chunk %s) is absent from every record after Compact; files=%#v", newChunk, files)
	}
}
