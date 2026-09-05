// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- test helpers for hand-built manifest copies ------------------------------

// writeManifestCopy encrypts rec and writes it as an on-disk manifest copy of
// rec.Path under a distinct filename suffix, exactly as saveManifestRecord would
// (same id and AAD), so a reload sees it as another copy of the path. suffix ""
// writes the canonical <id>.manifest; ".wa" writes <id>.wa.manifest. It is how a
// reconciliation test stages several concurrent versions of one path.
func writeManifestCopy(t *testing.T, v *Vault, suffix string, rec ManifestRecord) string {
	t.Helper()
	cleaned, err := CleanVirtualPath(rec.Path)
	if err != nil || cleaned == "" {
		t.Fatalf("invalid manifest path %q: %v", rec.Path, err)
	}
	rec.Path = cleaned
	if rec.Version == 0 {
		rec.Version = 1
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = now
	}
	if rec.File.UpdatedAt == "" {
		rec.File.UpdatedAt = rec.UpdatedAt
	}
	if len(rec.Clock) == 0 && len(rec.File.Clock) > 0 {
		rec.Clock = rec.File.Clock
	}
	if len(rec.File.Clock) == 0 && len(rec.Clock) > 0 {
		rec.File.Clock = rec.Clock
	}
	id := v.manifestID(cleaned)
	canonical := v.manifestPath(id)
	dst := strings.TrimSuffix(canonical, ".manifest") + suffix + ".manifest"
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		t.Fatal(err)
	}
	ct := v.indexAEAD.Seal(nil, nonce, data, []byte(manifestAADPrefix+id))
	if err := os.WriteFile(dst, encodeEncrypted(manifestMagic, nonce, ct), 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

// rewriteManifestClock replaces the vector clock of an existing on-disk manifest
// file with clock and re-encrypts it in place (same id/AAD). It lets a test turn
// a copied same-device manifest into a genuinely CONCURRENT peer edit (a disjoint
// device clock), which is what a cloud sync client's "conflicted copy" really is.
func rewriteManifestClock(t *testing.T, v *Vault, manifestFilePath string, clock map[string]int64) {
	t.Helper()
	data, err := os.ReadFile(manifestFilePath)
	if err != nil {
		t.Fatal(err)
	}
	id := manifestIDFromFileName(filepath.Base(manifestFilePath))
	rec, err := v.decryptManifest(data, id)
	if err != nil {
		t.Fatalf("decrypt %s: %v", manifestFilePath, err)
	}
	rec.File.Clock = clock
	rec.Clock = clock
	// A rewritten clock stands in for a DIFFERENT device's record, which carries
	// its own aging bookkeeping — never this device's accumulated counters — so
	// reset ClockAge to model a genuine foreign record (whose ClockAge never holds
	// a counter for its own writer, the source of the aging refresh-by-inheritance).
	rec.File.ClockAge = nil
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		t.Fatal(err)
	}
	ct := v.indexAEAD.Seal(nil, nonce, out, []byte(manifestAADPrefix+id))
	if err := os.WriteFile(manifestFilePath, encodeEncrypted(manifestMagic, nonce, ct), 0o600); err != nil {
		t.Fatal(err)
	}
}

// liveEditCandidate builds a live (non-deleted) manifestCandidate for a path with
// a given chunk id, generation, and vector clock, sourced from a distinct file
// name so isCausallyDominated's self-skip and the sort behave as on disk.
func liveEditCandidate(path, source, chunkID string, gen int64, clock map[string]int64) manifestCandidate {
	return manifestCandidate{
		Record: ManifestRecord{
			Version:   1,
			Path:      path,
			UpdatedAt: "2026-09-04T00:00:00Z",
			Clock:     clock,
			File: FileRecord{
				Size:       int64(len(chunkID)),
				UpdatedAt:  "2026-09-04T00:00:00Z",
				Generation: gen,
				Chunks:     []ChunkRef{{ID: chunkID, Size: 3}},
				Clock:      clock,
			},
		},
		ID:     "id-" + path,
		Source: source,
	}
}

func conflictPathsOf(files map[string]FileRecord, base string) []string {
	var out []string
	for p, rec := range files {
		if strings.HasPrefix(p, base+".conflict-") && rec.ConflictOf == base {
			out = append(out, p)
		}
	}
	return out
}

// ---: 3+ concurrent writers, dominance, content-key winner, fallback -------

// TestConcurrentAntichainConvergesToOneWinner is 's core: three concurrent
// writers with disjoint vector clocks form a 3-record antichain. Reconciliation
// keeps ALL three (none dominates), elects exactly ONE canonical winner by the
// device-independent content key, and materialises the rest as conflicts — and
// the choice is invariant under the load/WalkDir order. The shuffle
// is the proof the winner is content-chosen, never filename- or sort-order-chosen.
func TestConcurrentAntichainConvergesToOneWinner(t *testing.T) {
	const p = "content/doc.txt"
	cands := []manifestCandidate{
		liveEditCandidate(p, "/disk/aaa.manifest", strings.Repeat("a", 64), 100, map[string]int64{"deviceA00000000000000000000000000": 1}),
		liveEditCandidate(p, "/disk/bbb.manifest", strings.Repeat("b", 64), 200, map[string]int64{"deviceB00000000000000000000000000": 1}),
		liveEditCandidate(p, "/disk/ccc.manifest", strings.Repeat("c", 64), 300, map[string]int64{"deviceC00000000000000000000000000": 1}),
	}

	// The expected winner is the largest content key (device-independent), and the
	// other two are the conflict set. Compute it once so we can assert invariance.
	winnerChunk := ""
	bestKey := ""
	for _, c := range cands {
		k := contentKey(c.Record)
		if k > bestKey {
			bestKey, winnerChunk = k, c.Record.File.Chunks[0].ID
		}
	}
	if winnerChunk == "" {
		t.Fatal("precondition: could not determine a content-key winner")
	}

	rng := rand.New(rand.NewSource(1))
	var firstConflicts []string
	for iter := 0; iter < 40; iter++ {
		shuffled := append([]manifestCandidate(nil), cands...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

		live, conflicts, removes := reconcilePathCandidates(p, shuffled)
		if live == nil {
			t.Fatalf("iter %d: the antichain must elect a live winner", iter)
		}
		if len(live.Chunks) != 1 || live.Chunks[0].ID != winnerChunk {
			t.Fatalf("iter %d: winner must be the content-key holder %s regardless of order, got %s", iter, winnerChunk[:6], live.Chunks[0].ID[:6])
		}
		if len(removes) != 0 {
			t.Fatalf("iter %d: no concurrent record may be cleanly superseded, removes=%v", iter, removes)
		}
		if len(conflicts) != 2 {
			t.Fatalf("iter %d: the two non-winners must survive as conflicts, got %d", iter, len(conflicts))
		}
		paths := []string{conflicts[0].Path, conflicts[1].Path}
		if paths[0] > paths[1] {
			paths[0], paths[1] = paths[1], paths[0]
		}
		if firstConflicts == nil {
			firstConflicts = paths
			continue
		}
		if paths[0] != firstConflicts[0] || paths[1] != firstConflicts[1] {
			t.Fatalf("iter %d: conflict paths must converge regardless of load order: got %v want %v", iter, paths, firstConflicts)
		}
	}
}

// TestDominatingClockSupersedesCleanly is 's dominance leg: a record whose
// clock DOMINATES another (the same lineage re-edited) supersedes it cleanly —
// planned removal, no conflict copy. This is the A2 improvement over A1, which
// kept every live loser as a spurious conflict.
func TestDominatingClockSupersedesCleanly(t *testing.T) {
	const p = "content/doc.txt"
	older := liveEditCandidate(p, "/disk/old.manifest", strings.Repeat("a", 64), 100, map[string]int64{"deviceA00000000000000000000000000": 1})
	newer := liveEditCandidate(p, "/disk/new.manifest", strings.Repeat("b", 64), 200, map[string]int64{"deviceA00000000000000000000000000": 2})

	live, conflicts, removes := reconcilePathCandidates(p, []manifestCandidate{older, newer})
	if live == nil || len(live.Chunks) != 1 || live.Chunks[0].ID != newer.Record.File.Chunks[0].ID {
		t.Fatalf("the dominating record must win the live slot, got %#v", live)
	}
	if len(conflicts) != 0 {
		t.Fatalf("a dominated record must NOT become a conflict, got %v", conflicts)
	}
	if len(removes) != 1 || removes[0] != older.Source {
		t.Fatalf("the dominated record must be planned for clean removal, removes=%v", removes)
	}
}

// TestNoClockRecordsUseGenerationFallback is 's fallback leg: two records with
// NO vector clock (a 0.16-written pair) reconcile by the A1 Generation order —
// the higher generation wins the slot, the other survives as a conflict — never
// by dominance (there is no clock to dominate with).
func TestNoClockRecordsUseGenerationFallback(t *testing.T) {
	const p = "content/doc.txt"
	older := liveEditCandidate(p, "/disk/old.manifest", strings.Repeat("a", 64), 100, nil)
	newer := liveEditCandidate(p, "/disk/new.manifest", strings.Repeat("b", 64), 200, nil)

	live, conflicts, removes := reconcilePathCandidates(p, []manifestCandidate{older, newer})
	if live == nil || live.Chunks[0].ID != newer.Record.File.Chunks[0].ID {
		t.Fatalf("Generation fallback must pick the higher-generation record, got %#v", live)
	}
	if len(removes) != 0 {
		t.Fatalf("no-clock records are never cleanly superseded by dominance, removes=%v", removes)
	}
	if len(conflicts) != 1 || conflicts[0].Rec.Chunks[0].ID != older.Record.File.Chunks[0].ID {
		t.Fatalf("the lower-generation no-clock record must survive as a conflict, got %v", conflicts)
	}
}

// TestConcurrentAntichainConvergesEndToEnd stages the scenario as real on-disk
// manifests and reloads the vault, proving the pure-function convergence holds
// through the actual load/reconcile path (winner live at the path, two conflicts).
func TestConcurrentAntichainConvergesEndToEnd(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	const p = "content/doc.txt"
	mk := func(chunk string, gen int64, dev string) ManifestRecord {
		return ManifestRecord{Version: 1, Path: p, UpdatedAt: "2026-09-04T00:00:00Z",
			File: FileRecord{Size: 3, UpdatedAt: "2026-09-04T00:00:00Z", Generation: gen, Chunks: []ChunkRef{{ID: strings.Repeat(chunk, 64), Size: 3}}, Clock: map[string]int64{dev: 1}}}
	}
	writeManifestCopy(t, v, ".wa", mk("a", 100, "deviceA00000000000000000000000000"))
	writeManifestCopy(t, v, ".wb", mk("b", 200, "deviceB00000000000000000000000000"))
	writeManifestCopy(t, v, ".wc", mk("c", 300, "deviceC00000000000000000000000000"))
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[p]; !ok {
		t.Fatalf("a concurrent antichain must leave one live winner at %s, files: %#v", p, files)
	}
	if got := conflictPathsOf(files, p); len(got) != 2 {
		t.Fatalf("the two non-winners must be conflicts, got %d: %v", len(got), got)
	}
}

// ---: delete-vs-edit under vector clocks ----------------------------------

// TestDeleteVsEditUnderClocks is. Concurrent delete and edit (disjoint
// clocks): the path is deleted AND the edit is preserved as a conflict. A delete
// whose clock DOMINATES the edit (the deleter saw it): a clean delete, no
// conflict. The generation/deletedGeneration fallback must NOT override the
// causal decision when both records are clocked.
func TestDeleteVsEditUnderClocks(t *testing.T) {
	const p = "content/doc.txt"
	editChunk := strings.Repeat("e", 64)

	t.Run("concurrent delete and edit both survive", func(t *testing.T) {
		// Tombstone from device D (clock {D:1}); a concurrent edit from device E
		// (clock {E:1}); disjoint, so neither dominates. deletedGeneration is set
		// ABOVE the edit's generation to prove the causal path — not the A1
		// suppression — decides: under A1 alone the edit would be suppressed.
		tomb := manifestCandidate{Record: ManifestRecord{Version: 1, Path: p, Deleted: true, DeletedGeneration: 9999, UpdatedAt: "2026-09-04T00:00:00Z", Clock: map[string]int64{"deviceD00000000000000000000000000": 1}, File: FileRecord{UpdatedAt: "2026-09-04T00:00:00Z", Generation: 5000, Clock: map[string]int64{"deviceD00000000000000000000000000": 1}}}, ID: "id", Source: "/disk/tomb.manifest"}
		edit := liveEditCandidate(p, "/disk/edit.manifest", editChunk, 100, map[string]int64{"deviceE00000000000000000000000000": 1})

		live, conflicts, _ := reconcilePathCandidates(p, []manifestCandidate{tomb, edit})
		if live != nil {
			t.Fatalf("a concurrent tombstone must take the live slot (path deleted), got live %#v", live)
		}
		if len(conflicts) != 1 || conflicts[0].Rec.Chunks[0].ID != editChunk {
			t.Fatalf("the concurrent edit must survive as a conflict despite deletedGeneration, got %v", conflicts)
		}
	})

	t.Run("delete dominating the edit is a clean delete", func(t *testing.T) {
		// Device D edited ({D:1}) then deleted ({D:2}); the tombstone dominates the
		// edit copy, so it is a clean delete with no conflict.
		edit := liveEditCandidate(p, "/disk/edit.manifest", editChunk, 100, map[string]int64{"deviceD00000000000000000000000000": 1})
		tomb := manifestCandidate{Record: ManifestRecord{Version: 1, Path: p, Deleted: true, DeletedGeneration: 100, UpdatedAt: "2026-09-04T00:00:01Z", Clock: map[string]int64{"deviceD00000000000000000000000000": 2}, File: FileRecord{UpdatedAt: "2026-09-04T00:00:01Z", Generation: 5000, Clock: map[string]int64{"deviceD00000000000000000000000000": 2}}}, ID: "id", Source: "/disk/tomb.manifest"}

		live, conflicts, removes := reconcilePathCandidates(p, []manifestCandidate{edit, tomb})
		if live != nil {
			t.Fatalf("the dominating delete must leave the path deleted, got live %#v", live)
		}
		if len(conflicts) != 0 {
			t.Fatalf("a dominated edit must be cleanly deleted, not kept as a conflict, got %v", conflicts)
		}
		if len(removes) != 1 || removes[0] != edit.Source {
			t.Fatalf("the dominated edit must be planned for clean removal, removes=%v", removes)
		}
	})
}

// TestDeleteVsEditConcurrentEndToEnd stages 's concurrent case as real on-disk
// manifests through a full reload: the path is absent (deleted) and the peer's
// concurrent edit survives as a conflict entry with its chunk.
func TestDeleteVsEditConcurrentEndToEnd(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	const p = "content/doc.txt"
	editChunk := strings.Repeat("e", 64)
	writeManifestCopy(t, v, ".tomb", ManifestRecord{Version: 1, Path: p, Deleted: true, DeletedGeneration: 9999, UpdatedAt: "2026-09-04T00:00:00Z", File: FileRecord{UpdatedAt: "2026-09-04T00:00:00Z", Generation: 5000, Clock: map[string]int64{"deviceD00000000000000000000000000": 1}}})
	writeManifestCopy(t, v, ".edit", ManifestRecord{Version: 1, Path: p, UpdatedAt: "2026-09-04T00:00:00Z", File: FileRecord{Size: 3, UpdatedAt: "2026-09-04T00:00:00Z", Generation: 100, Chunks: []ChunkRef{{ID: editChunk, Size: 3}}, Clock: map[string]int64{"deviceE00000000000000000000000000": 1}}})
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[p]; ok {
		t.Fatalf("the concurrent delete must leave %s absent, files: %#v", p, files)
	}
	got := conflictPathsOf(files, p)
	if len(got) != 1 {
		t.Fatalf("the concurrent edit must survive as one conflict, got %d: %v", len(got), got)
	}
	if files[got[0]].Chunks[0].ID != editChunk {
		t.Fatalf("the surviving conflict must carry the edit's chunk, got %#v", files[got[0]])
	}
}

// --- Clock aging -------------------------------------------------------

// TestClockAgesOutStaleEntry proves the aging horizon: a foreign clock entry that
// does not advance across clockAgeCompactions local writes of a record is dropped
// on the next write, while this device's own entry (and any still-advancing peer)
// is kept. Without aging the clock would grow one entry per decommissioned device
// forever.
func TestClockAgesOutStaleEntry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	dev := v.DeviceID()
	if dev == "" {
		t.Fatal("precondition: this device must have a stable id to age clocks")
	}
	const stale = "stale-writer-00000000000000000000"

	if _, err := v.PutReader(strings.NewReader("v0"), "doc.txt", 2, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Inject a foreign entry that will never advance again (a decommissioned
	// device) alongside this device's own entry.
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	clk := files["content/doc.txt"].Clock
	if clk == nil || clk[dev] == 0 {
		t.Fatalf("precondition: the first write must carry this device's clock entry, got %v", clk)
	}
	clk[stale] = 5
	canonical := v.manifestPath(v.manifestID("content/doc.txt"))
	rewriteManifestClock(t, v, canonical, clk)
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}

	// One write short of the horizon: the stale entry is still carried (it has not
	// yet aged out, so a briefly-quiet device is not dropped prematurely).
	for i := 0; i < clockAgeCompactions-1; i++ {
		if _, err := v.PutReader(strings.NewReader("vn"), "doc.txt", 2, 0o600, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	files, _ = v.Files()
	if _, ok := files["content/doc.txt"].Clock[stale]; !ok {
		t.Fatalf("the stale entry must survive until the aging horizon, clock=%v", files["content/doc.txt"].Clock)
	}

	// The write that reaches the horizon drops it.
	if _, err := v.PutReader(strings.NewReader("vn"), "doc.txt", 2, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, _ = v.Files()
	final := files["content/doc.txt"].Clock
	if _, ok := final[stale]; ok {
		t.Fatalf("the stale entry must age out at the horizon, clock=%v", final)
	}
	if final[dev] == 0 {
		t.Fatalf("aging must never drop this device's own entry, clock=%v", final)
	}
}

// TestActivePeerSurvivesAging proves aging does not drop an ACTIVE peer: when a
// peer keeps syncing dominating edits, its clock entry is refreshed by
// inheritance (a real peer record carries no aging counter for its own id) and
// survives well past the aging horizon — only a decommissioned device ages out.
func TestActivePeerSurvivesAging(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	dev := v.DeviceID()
	const peer = "active-peer-000000000000000000000"

	if _, err := v.PutReader(strings.NewReader("v0"), "doc.txt", 2, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	canonical := v.manifestPath(v.manifestID("content/doc.txt"))
	// Well past the horizon: each round the peer syncs a dominating advance (its
	// record carries this device's entry plus a higher peer entry, and — like any
	// real peer record — no self aging counter), then this device re-edits.
	for i := 0; i < clockAgeCompactions*2; i++ {
		files, err := v.Files()
		if err != nil {
			t.Fatal(err)
		}
		clk := files["content/doc.txt"].Clock
		if clk == nil {
			t.Fatalf("round %d: this device's clock vanished, files=%v", i, files)
		}
		clk[peer] = int64(3 + i) // the peer keeps advancing
		rewriteManifestClock(t, v, canonical, clk)
		if err := v.ReloadIndex(); err != nil {
			t.Fatal(err)
		}
		if _, err := v.PutReader(strings.NewReader("vn"), "doc.txt", 2, 0o600, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := v.Files()
	final := files["content/doc.txt"].Clock
	if _, ok := final[peer]; !ok {
		t.Fatalf("an actively-syncing peer must NOT age out, clock=%v", final)
	}
	if final[dev] == 0 {
		t.Fatalf("this device's own entry must persist, clock=%v", final)
	}
}

// TestDeviceIDStableAcrossOpens proves a vault reads the same stable writer key
// across reopens: the vector clock's identity must not churn.
func TestDeviceIDStableAcrossOpens(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v1, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	id1 := v1.DeviceID()
	if id1 == "" {
		t.Fatal("a vault opened with a writable app home must expose a device id")
	}
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if id2 := v2.DeviceID(); id2 != id1 {
		t.Fatalf("device id must be stable across opens: %q vs %q", id1, id2)
	}
}
