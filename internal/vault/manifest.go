// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ManifestDirName = "manifests"

type ManifestRecord struct {
	Version   int    `json:"version"`
	Path      string `json:"path"`
	UpdatedAt string `json:"updatedAt"`
	Deleted   bool   `json:"deleted,omitempty"`
	// DeletedGeneration is the generation of the live record this delete
	// superseded (design D4.2, P0-6). It is additive: 0.15.0 readers ignore an
	// unknown JSON field (invariant I1), and a tombstone written by 0.15.0 (or by
	// any path that does not know the superseded generation) carries 0. The pure
	// load uses it to tell a stale copy the deleter had already seen (loser
	// generation <= DeletedGeneration -> suppressed) from a newer edit the deleter
	// never saw (loser generation > DeletedGeneration, or DeletedGeneration == 0 ->
	// survives as a conflict).
	DeletedGeneration int64 `json:"deletedGeneration,omitempty"`
	// Clock is the additive per-record vector clock at the manifest level (design
	// D4.1, P1-8), mirroring FileRecord.Clock so a tombstone (whose File may be
	// empty) can still carry causal ordering. Additive/omitempty: a 0.16-written
	// manifest has no clock and reconciliation falls back to Generation. The
	// causal-compare and join paths land in slice 5.
	Clock map[string]int64 `json:"clock,omitempty"`
	File  FileRecord       `json:"file,omitempty"`
}

type manifestCandidate struct {
	Record ManifestRecord
	ID     string
	Name   string
	Source string
}

// plannedConflict is a losing LIVE manifest that a load decided to materialise
// as a deterministic *.conflict-* entry (design D4.3). Compact writes Rec at
// Path and then removes the loser file at Source; the entry is also placed in
// the in-memory index (Rec.ConflictOf set) on every load so it is visible and
// its chunks count as live for GC without any write (I2).
type plannedConflict struct {
	Path   string
	Rec    FileRecord
	Source string
}

// reconcilePlan is the set of on-disk mutations a pure load COMPUTED but did not
// perform (design D4.1, invariant I2). loadManifestIndex never removes or writes
// a manifest; every mutation it would once have made on load is recorded here for
// Compact (D4.4) to apply under an explicit command.
type reconcilePlan struct {
	// conflicts are losing live records to materialise (write Path, remove Source).
	conflicts []plannedConflict
	// removeManifests are manifest files to delete outright: exact duplicates of
	// the winner, generation-suppressed stale copies under a delete tombstone, and
	// superseded (older) tombstones. No manifest is written for these.
	removeManifests []string
	// sawManifest records whether any decodable *.manifest with a path was found,
	// so loadIndexFromDisk can tell an empty manifest store from a legacy vault
	// without a second directory walk. Not part of the applied plan.
	sawManifest bool
}

// loadManifestIndex is a PURE function of the manifest files on disk (design
// D4.1, invariant I2): it decrypts and reconciles them into an in-memory index
// but performs NO writes — no os.Remove, no saveFileManifest. Every mutation it
// would once have made on load (removing redundant/stale copies, materialising a
// losing edit as a *.conflict-* copy) is returned in the reconcilePlan for
// Compact (D4.4) to apply under an explicit command. Conflict entries are still
// placed in the returned in-memory index with ConflictOf set, so a losing edit
// is visible and its chunks count as live for GC without any write. The caller
// (cachedIndexLocked via loadIndexFromDisk) holds v.mu.
func (v *Vault) loadManifestIndex() (Index, reconcilePlan, error) {
	var plan reconcilePlan
	root := filepath.Join(v.MetaRoot, ManifestDirName)
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return NewIndex(), plan, nil
	} else if err != nil {
		return Index{}, plan, err
	}

	var candidates []manifestCandidate
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.Contains(strings.ToLower(name), ".manifest") {
			return nil
		}
		id := manifestIDFromFileName(name)
		if id == "" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rec, err := v.decryptManifest(data, id)
		if err != nil {
			return fmt.Errorf("manifest %s: %w", p, err)
		}
		if rec.Path == "" {
			return nil
		}
		// Fold every observed generation — including tombstones and conflict
		// variants that never enter the live index — into the high-water mark so
		// a subsequent local write is ordered strictly after all of them.
		if rec.File.Generation > v.maxGen {
			v.maxGen = rec.File.Generation
		}
		candidates = append(candidates, manifestCandidate{Record: rec, ID: id, Name: name, Source: p})
		return nil
	})
	if err != nil {
		return Index{}, reconcilePlan{}, err
	}
	plan.sawManifest = len(candidates) > 0
	if len(candidates) == 0 {
		return NewIndex(), plan, nil
	}

	byPath := map[string][]manifestCandidate{}
	for _, c := range candidates {
		cleaned, err := CleanVirtualPath(c.Record.Path)
		if err != nil || cleaned == "" {
			continue
		}
		if expected := v.manifestID(cleaned); expected != c.ID {
			continue
		}
		c.Record.Path = cleaned
		byPath[cleaned] = append(byPath[cleaned], c)
	}

	idx := NewIndex()
	for p, list := range byPath {
		live, conflicts, removes := reconcilePathCandidates(p, list)
		if live != nil {
			idx.Files[p] = *live
		}
		for _, c := range conflicts {
			idx.Files[c.Path] = c.Rec
			plan.conflicts = append(plan.conflicts, c)
		}
		plan.removeManifests = append(plan.removeManifests, removes...)
	}
	idx.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return idx, plan, nil
}

// manifestFilesPresent reports whether the manifests directory holds at least
// one file whose name parses as a manifest (a 64-hex id followed by .manifest).
// It never decrypts, so it is cheap enough to run on every first index load
// (design D2.1): the downgrade-detection check needs only file presence, not
// content. A missing manifests directory yields (false, nil).
func (v *Vault) manifestFilesPresent() (bool, error) {
	root := filepath.Join(v.MetaRoot, ManifestDirName)
	found := false
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if manifestIDFromFileName(d.Name()) != "" {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

// manifestStoreState summarises the manifests directory for the GC refusal gate
// (design D2.2): whether any manifest file exists at all, and whether any of them
// decrypts to a NON-tombstone record. An undecryptable manifest counts toward
// hasAny (a file is present) but not toward hasNonTombstone (it is not a
// classifiable live record).
type manifestStoreState struct {
	hasAny          bool
	hasNonTombstone bool
}

func (v *Vault) inspectManifestStore() (manifestStoreState, error) {
	var st manifestStoreState
	root := filepath.Join(v.MetaRoot, ManifestDirName)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		id := manifestIDFromFileName(d.Name())
		if id == "" {
			return nil
		}
		st.hasAny = true
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rec, err := v.decryptManifest(data, id)
		if err != nil {
			// Present but not classifiable; leave hasNonTombstone alone.
			return nil
		}
		if !rec.Deleted && strings.TrimSpace(rec.Path) != "" {
			st.hasNonTombstone = true
		}
		return nil
	})
	if err != nil {
		return manifestStoreState{}, err
	}
	return st, nil
}

func manifestIDFromFileName(name string) string {
	lower := strings.ToLower(name)
	idx := strings.Index(lower, ".manifest")
	if idx <= 0 {
		return ""
	}
	prefix := name[:idx]
	// Lower-case the parsed id so a case-folded manifest name maps to the same
	// derived id as its canonical lower-case object (design D6.1,
	// P3 hex-case-mismatch-gc).
	if len(prefix) >= 64 && isHex(prefix[:64]) {
		return strings.ToLower(prefix[:64])
	}
	if isHex(prefix) {
		return strings.ToLower(prefix)
	}
	return ""
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func normalizeRecordMetadata(rec FileRecord, updatedAt string) FileRecord {
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = updatedAt
	}
	if rec.Generation == 0 {
		rec.Generation = unixNanoOrNow(rec.UpdatedAt)
	}
	return rec
}

// reconcilePathCandidates reconciles every on-disk manifest copy of ONE virtual
// path into the causal winner and the losing conflicts/removals (design D4.2,
// P1-8). It is a PURE function of the candidate SET and independent of the order
// in which they were loaded (Condition 2): a caller may pass them in any order —
// including a shuffled WalkDir order — and always gets the identical winner,
// conflict paths, and removals. That order-independence is what makes every
// device in a fleet converge on the same canonical file (R9).
//
// Two decisions, kept separate (design D4.2) — and they MUST stay separate:
//  1. Dominance prunes causally-superseded copies. A record whose vector clock
//     is strictly dominated by SOME other record's is causally superseded and is
//     dropped CLEANLY (planned removal, no conflict copy). What survives is the
//     maximal antichain: the causally-concurrent set. A record with no clock
//     (0.16-written) neither dominates nor is dominated, so it always survives
//     into the antichain and is ordered by the A1 Generation fallback in step 2.
//  2. Among the surviving antichain the single live winner (the canonical-name
//     holder) is the CONTENT-key holder — a deterministic, device-independent
//     hash over chunk ids+sizes+generation+updatedAt — never the on-disk
//     filename or the input order. Every other antichain member materialises as
//     a deterministic *.conflict-* entry.
//
// The pruning MUST happen BEFORE the winner sort, not inside candidateCompare
// (config-server/F2-candidatecompare-intransitive). Dominance is a PARTIAL order
// and the content key is a TOTAL order; folding both into one per-pair comparator
// makes it intransitive — with A dominating B and C concurrent with both, ordered
// by content key ka<kc<kb, the comparator reports A>B (dominance), B>C and C>A
// (content), a 3-cycle. sort.SliceStable then has no canonical result: the winner
// depends on the on-disk (WalkDir) order, which sync clients shuffle differently
// per device, so honest fleet members would reconcile the same path to different
// canonical files (a Condition 2 / R9 break), and a dominated record could even
// land in the live slot while its dominator is demoted to a conflict (a T-A2-3
// causal inversion). Pruning first guarantees the records that reach the sort are
// mutually concurrent, so candidateCompare never exercises its dominance branch
// there and is a genuine total order.
//
// The A1 tombstone-takes-the-live-slot and deletedGeneration-suppression rules
// are preserved as the fallback for field-less/no-clock peers.
func reconcilePathCandidates(p string, list []manifestCandidate) (live *FileRecord, conflicts []plannedConflict, removeSources []string) {
	if len(list) == 0 {
		return nil, nil, nil
	}

	// Decision 1: dominance pruning over the WHOLE set. Every record strictly
	// dominated by some other record is causally superseded — the fleet has
	// provably moved past it (a re-edit of the same lineage, a delete that saw the
	// edit) — so it is dropped cleanly rather than resurrected as a spurious
	// conflict, and it can never be elected live. dominance is a transitive
	// partial order, so testing each record against the full input set yields
	// exactly the maximal antichain; a no-clock record is never dominated and so
	// always survives. The set is non-empty because a finite strict partial order
	// always has a maximal (undominated) element.
	antichain := make([]manifestCandidate, 0, len(list))
	for _, cand := range list {
		if isCausallyDominated(cand, list) {
			removeSources = append(removeSources, cand.Source)
			continue
		}
		antichain = append(antichain, cand)
	}

	// Decision 2: among the surviving antichain choose the single live winner by
	// candidateCompare. It is a TOTAL order here precisely because no antichain
	// member dominates another (its dominance branch is dead on this input), so it
	// reduces to the concurrent content-key tiebreak — or, for a no-clock pair,
	// the A1 Generation fallback — and sort.SliceStable is deterministic
	// regardless of the load order (Condition 2).
	sorted := append([]manifestCandidate(nil), antichain...)
	sort.SliceStable(sorted, func(i, j int) bool { return candidateCompare(sorted[i], sorted[j]) > 0 })
	winner := sorted[0]
	if !winner.Record.Deleted {
		rec := normalizeRecordMetadata(winner.Record.File, winner.Record.UpdatedAt)
		live = &rec
	}
	for i := 1; i < len(sorted); i++ {
		loser := sorted[i]

		// An exact duplicate of the winner (same deleted-ness, same file record) is
		// a redundant sync copy: plan its removal, no conflict.
		if loser.Record.Deleted == winner.Record.Deleted && sameFileRecord(loser.Record.File, winner.Record.File) {
			removeSources = append(removeSources, loser.Source)
			continue
		}

		// A superseded (older) tombstone under a newer winner: plan removal.
		// (Dominance was already handled in decision 1; every loser here is
		// causally concurrent with the winner.)
		if loser.Record.Deleted {
			removeSources = append(removeSources, loser.Source)
			continue
		}

		// A live loser under a delete-tombstone winner (design D4.2/D4.3, P0-6):
		// the A1 deletedGeneration suppression, kept as the FALLBACK for the
		// field-less / no-clock case only. When both records carry clocks the
		// causal decision above is authoritative — a concurrent edit (not
		// dominated by the tombstone) must survive as a conflict even if its
		// generation sits at or below the tombstone's deletedGeneration (R10), so
		// the generation shortcut is skipped whenever both sides are clocked.
		if winner.Record.Deleted && winner.Record.DeletedGeneration > 0 && !bothClocked(winner.Record, loser.Record) {
			loserGen := loser.Record.File.Generation
			if loserGen == 0 {
				loserGen = unixNanoOrNow(loser.Record.UpdatedAt)
			}
			if loserGen <= winner.Record.DeletedGeneration {
				removeSources = append(removeSources, loser.Source)
				continue
			}
		}

		rec := normalizeRecordMetadata(loser.Record.File, loser.Record.UpdatedAt)
		cp := conflictPath(p, rec)
		rec.ConflictOf = p
		conflicts = append(conflicts, plannedConflict{Path: cp, Rec: rec, Source: loser.Source})
	}
	return live, conflicts, removeSources
}

// candidateCompare orders the manifest copies of one path for the winner sort in
// reconcilePathCandidates (design D4.2, Condition 2). It is a genuine TOTAL order
// ONLY over a set with no dominance relations — a causally-concurrent antichain —
// which is exactly the input reconcilePathCandidates hands it, having pruned every
// dominated record FIRST (config-server/F2-candidatecompare-intransitive). Over
// such a set the dominance branch below is never taken, so the effective order is
// the concurrent content-key tiebreak (or the A1 Generation fallback for a
// no-clock pair), both transitive, and the stable sort is deterministic regardless
// of load order. It layers three rules:
//
//   - When BOTH records carry a vector clock, dominance decides: a clock that
//     strictly dominates the other sorts first. Concurrent (neither dominates)
//     or equal clocks fall through to the content tiebreak. NOTE: this branch is
//     the reason candidateCompare is NOT transitive on a set that still contains
//     dominance relations, so it must not be sorted with until that pruning has
//     run — see reconcilePathCandidates' header.
//   - When at least one record has NO clock, the A1 Generation comparison
//     decides (the documented 0.16 fallback) — unchanged from A1.
//   - The content tiebreak (tombstone-takes-the-slot, then the device-independent
//     content-key hash, then a canonical clock serialisation) breaks a
//     concurrent pair deterministically and device-independently.
func candidateCompare(a, b manifestCandidate) int {
	ac, bc := clockOf(a.Record), clockOf(b.Record)
	if len(ac) > 0 && len(bc) > 0 {
		if clockDominates(ac, bc) {
			return 1
		}
		if clockDominates(bc, ac) {
			return -1
		}
		return concurrentTiebreak(a, b)
	}
	return generationCompare(a, b)
}

// generationCompare is the A1 wall-clock/Generation total order, retained
// verbatim as the fallback for any pair where at least one record predates the
// vector clock (a 0.16 writer). It orders by generation, then parsed UpdatedAt,
// then the raw UpdatedAt string, then deleted-ness, then the manifest id.
func generationCompare(a, b manifestCandidate) int {
	ag, bg := a.Record.File.Generation, b.Record.File.Generation
	if a.Record.Deleted && ag == 0 {
		ag = unixNanoOrNow(a.Record.UpdatedAt)
	}
	if b.Record.Deleted && bg == 0 {
		bg = unixNanoOrNow(b.Record.UpdatedAt)
	}
	if ag != bg {
		if ag > bg {
			return 1
		}
		return -1
	}
	at, aerr := time.Parse(time.RFC3339Nano, a.Record.UpdatedAt)
	bt, berr := time.Parse(time.RFC3339Nano, b.Record.UpdatedAt)
	if aerr == nil && berr == nil && !at.Equal(bt) {
		if at.After(bt) {
			return 1
		}
		return -1
	}
	if a.Record.UpdatedAt != b.Record.UpdatedAt {
		if a.Record.UpdatedAt > b.Record.UpdatedAt {
			return 1
		}
		return -1
	}
	if a.Record.Deleted != b.Record.Deleted {
		if a.Record.Deleted {
			return 1
		}
		return -1
	}
	if a.ID > b.ID {
		return 1
	}
	if a.ID < b.ID {
		return -1
	}
	return 0
}

// concurrentTiebreak breaks a causally-concurrent (or clock-equal) pair
// deterministically and device-independently (design D4.2). A tombstone takes
// the live slot over a concurrent edit (the A1 rule, preserved), so a delete and
// a concurrent edit converge to "path deleted, edit kept as a conflict" (R10).
// Among records of the same deleted-ness the canonical winner is the larger
// content key — the hash over chunk ids+sizes+generation+updatedAt — never the
// on-disk filename. A final canonical clock serialisation keeps the order total
// even for the pathological same-content/different-clock pair, so the result is
// 0 only for genuinely identical records (which the duplicate rule removes).
func concurrentTiebreak(a, b manifestCandidate) int {
	if a.Record.Deleted != b.Record.Deleted {
		if a.Record.Deleted {
			return 1
		}
		return -1
	}
	ak, bk := contentKey(a.Record), contentKey(b.Record)
	if ak != bk {
		if ak > bk {
			return 1
		}
		return -1
	}
	as, bs := clockString(clockOf(a.Record)), clockString(clockOf(b.Record))
	if as != bs {
		if as > bs {
			return 1
		}
		return -1
	}
	return 0
}

// clockOf returns a record's vector clock, preferring the FileRecord clock (the
// live-record home) and falling back to the manifest-level clock (a tombstone,
// whose File is minimal, carries its clock there — design D4.1). An empty result
// means the record predates the clock (a 0.16 writer) and reconciliation uses
// the Generation fallback for it.
func clockOf(rec ManifestRecord) map[string]int64 {
	if len(rec.File.Clock) > 0 {
		return rec.File.Clock
	}
	return rec.Clock
}

// bothClocked reports whether both records carry a vector clock, i.e. the causal
// comparison is authoritative and the A1 Generation/deletedGeneration fallbacks
// should stand aside (design D4.2).
func bothClocked(a, b ManifestRecord) bool {
	return len(clockOf(a)) > 0 && len(clockOf(b)) > 0
}

// clockDominates reports whether clock a STRICTLY dominates clock b (design
// D4.2, the happens-after relation): a[k] >= b[k] for every k, and a[k] > b[k]
// for at least one k. Two empty or identical clocks never dominate; concurrent
// clocks (each ahead on some key) never dominate. Callers compare only clocked
// records — an absent entry reads as 0, which is the correct vector-clock
// identity for a device a record has never seen.
func clockDominates(a, b map[string]int64) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	strictly := false
	for k, bv := range b {
		av := a[k]
		if av < bv {
			return false
		}
		if av > bv {
			strictly = true
		}
	}
	if !strictly {
		for k, av := range a {
			if av <= 0 {
				continue
			}
			if _, ok := b[k]; !ok {
				strictly = true
				break
			}
		}
	}
	return strictly
}

// isCausallyDominated reports whether some OTHER candidate in the set strictly
// dominates target's vector clock (design D4.2). A dominated record is causally
// superseded and is dropped cleanly rather than kept as a conflict. A record
// with no clock never counts as dominated (Generation decides it instead), and a
// no-clock candidate can never dominate anything.
func isCausallyDominated(target manifestCandidate, all []manifestCandidate) bool {
	tc := clockOf(target.Record)
	if len(tc) == 0 {
		return false
	}
	for i := range all {
		if all[i].Source == target.Source {
			continue
		}
		oc := clockOf(all[i].Record)
		if len(oc) == 0 {
			continue
		}
		if clockDominates(oc, tc) {
			return true
		}
	}
	return false
}

// contentKey is the device-independent content hash used to pick the canonical
// winner of a concurrent antichain (design D4.2): the full SHA-256 over the
// record's chunk ids+sizes, generation, updatedAt, and deleted-ness — the same
// inputs conflictSuffix seeds a conflict name from, so winner selection and
// conflict naming stay consistent and neither depends on the on-disk filename.
func contentKey(rec ManifestRecord) string {
	f := rec.File
	h := sha256.New()
	for _, c := range f.Chunks {
		fmt.Fprintf(h, "%s:%d\n", c.ID, c.Size)
	}
	fmt.Fprintf(h, "gen=%d\nupdated=%s\ndeleted=%v\n", f.Generation, f.UpdatedAt, rec.Deleted)
	return hex.EncodeToString(h.Sum(nil))
}

// clockString is a canonical, order-independent serialisation of a vector clock
// (keys sorted) used only as the final total-order tiebreak in concurrentTiebreak
// so two records with identical content but different clocks still order
// deterministically (Condition 2).
func clockString(clock map[string]int64) string {
	if len(clock) == 0 {
		return ""
	}
	keys := make([]string, 0, len(clock))
	for k := range clock {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d;", k, clock[k])
	}
	return b.String()
}

// joinClock merges src into dst by element-wise maximum (the vector-clock join,
// design D4.1): dst[k] becomes max(dst[k], src[k]) for every k in src. It is how
// a local write carries forward every device entry it has seen for a path.
func joinClock(dst, src map[string]int64) {
	for k, v := range src {
		if v > dst[k] {
			dst[k] = v
		}
	}
}

// conflictPath is the deterministic virtual path a losing manifest is
// materialised under. Per design D4.3 the disambiguating suffix is seeded from
// device-stable CONTENT — the loser's chunk ids and sizes, generation and
// updatedAt — and never from the on-disk manifest filename, which sync clients
// rename differently on every device. Two on-disk copies of the same losing
// record therefore converge to one conflict path (R8), instead of accumulating a
// distinct copy per device-local rename. It is a pure function: given the same
// original path and record it always returns the same result, and stage 3's
// Compact relies on that. Convergence across a fleet is conditional on every
// device running >= A1 (a 0.15 peer still seeds from the on-disk name; §12).
func conflictPath(original string, rec FileRecord) string {
	dir, file := path.Split(original)
	if file == "" {
		file = "conflict"
	}
	return path.Join(strings.TrimSuffix(dir, "/"), file+"."+conflictSuffix(rec))
}

// conflictSuffix is the device-stable, deterministic disambiguator appended to a
// name when two records would otherwise collide: "conflict-<stamp>-<hash>",
// where the stamp is the record's UpdatedAt and the hash is over the loser's
// chunk ids and sizes, generation and UpdatedAt (design D4.3). It is seeded only
// from record content — never from an on-disk filename that sync clients rename
// per device — so the same record yields the same suffix on every device.
// conflictPath uses it for reconciled losers; export (D7.2) uses it to keep two
// files that sanitise to the same portable name from clobbering each other.
func conflictSuffix(rec FileRecord) string {
	updatedAt := rec.UpdatedAt
	stamp := updatedAt
	if t, err := time.Parse(time.RFC3339Nano, updatedAt); err == nil {
		stamp = t.UTC().Format("20060102T150405Z")
	}
	stamp = strings.NewReplacer(":", "", "/", "-", "\\", "-", ".", "-").Replace(stamp)
	h := sha256.New()
	for _, c := range rec.Chunks {
		fmt.Fprintf(h, "%s:%d\n", c.ID, c.Size)
	}
	fmt.Fprintf(h, "gen=%d\nupdated=%s\n", rec.Generation, updatedAt)
	return "conflict-" + stamp + "-" + hex.EncodeToString(h.Sum(nil))[:12]
}

func (v *Vault) saveIndexAsManifests(idx Index) error {
	for p, rec := range idx.Files {
		if rec.ConflictOf != "" {
			continue
		}
		if err := v.saveFileManifest(p, rec); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) saveFileManifest(virtualPath string, rec FileRecord) error {
	cleaned, err := CleanVirtualPath(virtualPath)
	if err != nil || cleaned == "" {
		return fmt.Errorf("invalid manifest path %q", virtualPath)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = now
	}
	if rec.Generation == 0 {
		rec.Generation = unixNanoOrNow(rec.UpdatedAt)
	}
	rec.ConflictOf = ""
	mr := ManifestRecord{Version: 1, Path: cleaned, UpdatedAt: rec.UpdatedAt, File: rec}
	return v.saveManifestRecord(mr)
}

// saveTombstone writes a delete tombstone. generation is the tombstone's own
// ordering generation (a fresh nextGeneration value); deletedGeneration is the
// generation of the LIVE record this delete superseded (design D4.2), written so
// a later pure load can suppress a stale copy the deleter had already seen while
// letting a newer edit survive as a conflict. A caller that does not know the
// superseded generation (a migration, a legacy path) passes 0, which reproduces
// the 0.15-compatible "keep every live loser" behaviour.
func (v *Vault) saveTombstone(virtualPath string, generation, deletedGeneration int64) error {
	return v.saveTombstoneWithClock(virtualPath, generation, deletedGeneration, nil)
}

// saveTombstoneWithClock is saveTombstone carrying an additive vector clock
// (design D4.1/D4.3): the tombstone's clock lets a later load decide delete-vs-
// edit causally — a delete that DOMINATES an edit is a clean delete, a concurrent
// edit survives as a conflict (R10) — instead of relying on the deletedGeneration
// fallback alone. A nil clock reproduces the field-less (0.16) tombstone, which
// reconciliation still handles by the Generation/deletedGeneration path.
func (v *Vault) saveTombstoneWithClock(virtualPath string, generation, deletedGeneration int64, clock map[string]int64) error {
	cleaned, err := CleanVirtualPath(virtualPath)
	if err != nil || cleaned == "" {
		return fmt.Errorf("invalid manifest path %q", virtualPath)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if generation <= 0 {
		generation = unixNanoOrNow(now)
	}
	if deletedGeneration < 0 {
		deletedGeneration = 0
	}
	rec := ManifestRecord{Version: 1, Path: cleaned, UpdatedAt: now, Deleted: true, DeletedGeneration: deletedGeneration, Clock: clock, File: FileRecord{UpdatedAt: now, Generation: generation, Clock: clock}}
	return v.saveManifestRecord(rec)
}

func (v *Vault) saveManifestRecord(rec ManifestRecord) error {
	cleaned, err := CleanVirtualPath(rec.Path)
	if err != nil || cleaned == "" {
		return fmt.Errorf("invalid manifest path %q", rec.Path)
	}
	rec.Path = cleaned
	if rec.Version == 0 {
		rec.Version = 1
	}
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.File.UpdatedAt == "" {
		rec.File.UpdatedAt = rec.UpdatedAt
	}
	if rec.File.Generation == 0 {
		rec.File.Generation = unixNanoOrNow(rec.UpdatedAt)
	}
	// Mirror the vector clock to the manifest level (design D4.1): the FileRecord
	// clock is the source of truth for a live record, but a tombstone's File is
	// minimal, so reconciliation reads the clock via clockOf (File first, then
	// here). Keeping both in step means a future field-less read path still finds
	// the clock, and clockOf is unambiguous.
	if len(rec.Clock) == 0 && len(rec.File.Clock) > 0 {
		rec.Clock = rec.File.Clock
	}
	id := v.manifestID(cleaned)
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		return err
	}
	ct := v.indexAEAD.Seal(nil, nonce, data, []byte(manifestAADPrefix+id))
	return atomicWriteFile(v.manifestPath(id), encodeEncrypted(manifestMagic, nonce, ct), 0o600)
}

func (v *Vault) decryptManifest(data []byte, id string) (ManifestRecord, error) {
	nonce, ct, err := decodeEncrypted(manifestMagic, v.indexAEAD.NonceSize(), data)
	if err != nil {
		return ManifestRecord{}, err
	}
	pt, err := v.indexAEAD.Open(nil, nonce, ct, []byte(manifestAADPrefix+id))
	if err != nil {
		return ManifestRecord{}, errors.New("manifest decrypt/authenticate failed")
	}
	var rec ManifestRecord
	if err := json.Unmarshal(pt, &rec); err != nil {
		return ManifestRecord{}, err
	}
	return rec, nil
}

func (v *Vault) manifestID(virtualPath string) string {
	return hmacHex(v.keys.IndexKey, []byte("manifest:"+virtualPath))
}

func (v *Vault) manifestPath(id string) string {
	prefix := id
	if len(prefix) > 2 {
		prefix = id[:2]
	}
	return filepath.Join(v.MetaRoot, ManifestDirName, prefix, id+".manifest")
}

func sameFileRecord(a, b FileRecord) bool {
	if a.Size != b.Size || len(a.Chunks) != len(b.Chunks) {
		return false
	}
	for i := range a.Chunks {
		if a.Chunks[i] != b.Chunks[i] {
			return false
		}
	}
	return true
}

func unixNanoOrNow(ts string) int64 {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UnixNano()
	}
	return time.Now().UTC().UnixNano()
}
