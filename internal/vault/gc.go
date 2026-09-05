// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// GCIntentDirName is the synced directory under the metadata root holding one
// <chunkID>.intent file per unreferenced chunk queued for deletion (design
// ). It sits beside manifests/ and objects/ so the manifest walker
// (manifests/ only) and the chunk walker (objects/chunks/ only) never see it,
// and an old 0.15 reader ignores it too. The intent content is a
// single RFC3339-UTC line and no device identifier.
const GCIntentDirName = "gc-intents"

const gcIntentSuffix = ".intent"

// GCFenceMin is the smallest fence a confirm run accepts: a
// shorter window would collect a chunk another device may still be
// deduplicating against.
const GCFenceMin = time.Hour

// ErrGCRefused is returned by GarbageCollect when the vault's on-disk state has
// the signature of a wiped or replaced index under an intact vault.json (design
// ): a manifest-store vault whose loaded index is empty while a
// non-tombstone manifest still exists, or one with no manifests at all but chunk
// objects present. Collecting in either state could mass-delete live data, so it
// refuses without writing or removing anything. An all-tombstone vault (every
// file legitimately deleted) is not refused and stays collectable.
var ErrGCRefused = errors.New("refusing to garbage-collect: the vault index looks wiped or replaced under an intact vault.json")

// GCOptions parameterises GarbageCollect. The zero value is a safe
// dry run: Confirm false computes candidates and writes nothing anywhere.
type GCOptions struct {
	// Confirm switches from a dry run to the two-phase, fenced collection that
	// writes intents and (past the fence) removes chunks.
	Confirm bool
	// Fence is the age an intent's recorded time, this device's first-seen time,
	// and the chunk's mtime must all exceed before the chunk is removed. Zero
	// uses GCFenceDefault (72h); anything below GCFenceMin (1h) is raised to it.
	Fence time.Duration
	// Now injects the clock for deterministic tests; nil uses time.Now.
	Now func() time.Time
	// SeenStore overrides the directory holding this device's first-seen record
	// <vaultID>.json (.2b). Empty uses <appdir data>/gc-seen.
	SeenStore string
}

// PendingIntent describes one deletion intent still in flight, for verify
// and the gc report.
type PendingIntent struct {
	ChunkID    string `json:"chunkId"`
	Recorded   string `json:"recorded,omitempty"`
	AgeSeconds int64  `json:"ageSeconds"`
}

// GCReport is the outcome (or, in dry-run, the plan) of a GarbageCollect run.
type GCReport struct {
	Confirm        bool            `json:"confirm"`
	Fence          string          `json:"fence"`
	Candidates     []string        `json:"candidates"`
	CandidateBytes int64           `json:"candidateBytes"`
	IntentsWritten []string        `json:"intentsWritten,omitempty"`
	Cancelled      []string        `json:"cancelled,omitempty"`
	Reaped         []string        `json:"reaped,omitempty"`
	RemovedChunks  []string        `json:"removedChunks,omitempty"`
	RemovedBytes   int64           `json:"removedBytes,omitempty"`
	Pending        []PendingIntent `json:"pending,omitempty"`
	Phase2Reloads  int             `json:"phase2Reloads"`
	Compact        *CompactReport  `json:"compact,omitempty"`
}

// GarbageCollect reclaims unreferenced chunks under the two-phase, fenced,
// synced-intent protocol of. It is a DRY RUN by default: with
// Confirm false it computes the candidate set and writes nothing anywhere. With
// Confirm true it first Compacts (materialise conflicts, sweep temp orphans),
// then runs phase 1 (write/cancel/reap intents, record first-seen) and phase 2
// (remove a chunk only when its intent's recorded time, this device's first-seen
// record, and the chunk file's mtime are ALL older than the fence, and the chunk
// is still unreferenced). No device identifier is ever written.
func (v *Vault) GarbageCollect(opts GCOptions) (GCReport, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	fence := opts.Fence
	if fence <= 0 {
		fence = GCFenceDefault
	}
	if fence < GCFenceMin {
		fence = GCFenceMin
	}
	report := GCReport{Confirm: opts.Confirm, Fence: fence.String()}
	// Downgrade/wipe safety gate: reload so the check reasons
	// about the current on-disk state, then refuse — writing and removing nothing —
	// when the index looks wiped or replaced under an intact vault.json. The gate
	// runs before Compact so a refused confirm mutates nothing.
	if err := v.ReloadIndex(); err != nil {
		return GCReport{}, err
	}
	if err := v.gcRefusalGate(); err != nil {
		return GCReport{}, err
	}
	if !opts.Confirm {
		return v.gcDryRun(report, now(), fence)
	}
	return v.gcConfirm(report, now, fence, opts.SeenStore)
}

// gcRefusalGate implements the narrowed refusal. It returns ErrGCRefused
// (wrapped with a specific reason) when either: the vault uses the manifest store
// and its loaded index is empty while at least one non-tombstone manifest exists
// on disk (a wiped or replaced index); or the vault uses the manifest store, no
// manifest files exist at all, and chunk objects are present (a wiped manifest
// store). A legacy single-index vault (usesManifestStore false) is never refused
// here. An all-tombstone vault keeps at least the protected content
// marker in its index, so its loaded index is non-empty and it stays collectable.
func (v *Vault) gcRefusalGate() error {
	if !v.usesManifestStore() {
		return nil
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	// A non-empty loaded index (which always includes the protected content marker
	// for a settled vault) is the normal case and needs no manifest decrypt walk.
	// Both refusal signatures imply an EMPTY loaded index: a wiped or replaced
	// index leaves no live records, and wiped manifests leave nothing to load.
	if len(idx.Files) != 0 {
		return nil
	}
	st, err := v.inspectManifestStore()
	if err != nil {
		return err
	}
	if st.hasNonTombstone {
		return fmt.Errorf("%w: the loaded index is empty but a non-tombstone manifest still exists on disk; restore the index from a backup or another device", ErrGCRefused)
	}
	if !st.hasAny {
		chunks, err := v.walkChunkFiles()
		if err != nil {
			return err
		}
		if len(chunks) > 0 {
			return fmt.Errorf("%w: no manifests exist but %d chunk object(s) are present; restore the manifests from a backup or another device", ErrGCRefused, len(chunks))
		}
	}
	return nil
}

// gcDryRun computes the candidate set (unreferenced present chunks) and the
// pending-intent and compaction plans without writing anything (
// ). A pure ReloadIndex reflects current disk state but performs no writes
// . fence is the run's --fence: the compaction plan lists.tmp-*
// orphans older than it, so the dry run reports what a confirm
// with the same fence would sweep.
func (v *Vault) gcDryRun(report GCReport, now time.Time, fence time.Duration) (GCReport, error) {
	if err := v.ReloadIndex(); err != nil {
		return GCReport{}, err
	}
	live, err := v.liveChunkSet()
	if err != nil {
		return GCReport{}, err
	}
	chunks, err := v.walkChunkFiles()
	if err != nil {
		return GCReport{}, err
	}
	for id, files := range chunks {
		if live[id] {
			continue
		}
		report.Candidates = append(report.Candidates, id)
		report.CandidateBytes += totalSize(files)
	}
	sort.Strings(report.Candidates)

	intents, err := v.walkIntents()
	if err != nil {
		return GCReport{}, err
	}
	report.Pending = pendingList(intents, now)

	plan, err := v.compact(now, false, fence)
	if err != nil {
		return GCReport{}, err
	}
	report.Compact = &plan
	return report, nil
}

// gcConfirm runs the full two-phase collection.
func (v *Vault) gcConfirm(report GCReport, now func() time.Time, fence time.Duration, seenStore string) (GCReport, error) {
	// --confirm first runs Compact: materialise conflicts, remove
	// superseded manifests, sweep temp orphans older than the run's fence
	// — so phase 1 reasons about a settled index. Compact returns an error only
	// after reporting every failure.
	cr, err := v.compact(now(), true, fence)
	report.Compact = &cr
	if err != nil {
		return report, err
	}

	seenPath, err := v.seenStorePath(seenStore)
	if err != nil {
		return report, err
	}

	// ---- Phase 1 ----
	if err := v.ReloadIndex(); err != nil {
		return report, err
	}
	fpPhase1, err := v.indexFingerprint()
	if err != nil {
		return report, err
	}
	live, err := v.liveChunkSet()
	if err != nil {
		return report, err
	}
	chunks, err := v.walkChunkFiles()
	if err != nil {
		return report, err
	}
	intents, err := v.walkIntents()
	if err != nil {
		return report, err
	}
	seen, err := loadSeenStore(seenPath)
	if err != nil {
		return report, err
	}
	seenDirty := false

	for id, li := range intents {
		switch {
		case live[id]:
			// (a) referenced again -> cancel: delete all its intent files.
			if err := removeIntentFiles(li); err != nil {
				return report, err
			}
			report.Cancelled = append(report.Cancelled, id)
			if _, ok := seen[id]; ok {
				delete(seen, id)
				seenDirty = true
			}
		case !chunkPresent(chunks, id):
			// (b) chunk file gone -> reap: delete all its intent files.
			if err := removeIntentFiles(li); err != nil {
				return report, err
			}
			report.Reaped = append(report.Reaped, id)
			if _, ok := seen[id]; ok {
				delete(seen, id)
				seenDirty = true
			}
		default:
			// (c) present + unreferenced: record first-seen if absent.
			if _, ok := seen[id]; !ok {
				seen[id] = now().UTC().Format(time.RFC3339)
				seenDirty = true
			}
		}
	}

	// Compute candidates and write an intent for every unreferenced present chunk
	// that lacks one. Newly written intents get no first-seen record this pass;
	// the next run observes them as existing intents and records it (case c).
	for id, files := range chunks {
		if live[id] {
			continue
		}
		report.Candidates = append(report.Candidates, id)
		report.CandidateBytes += totalSize(files)
		if _, has := intents[id]; has {
			continue
		}
		if err := v.writeIntent(id, now()); err != nil {
			return report, err
		}
		report.IntentsWritten = append(report.IntentsWritten, id)
	}
	sort.Strings(report.Candidates)
	sort.Strings(report.IntentsWritten)
	sort.Strings(report.Cancelled)
	sort.Strings(report.Reaped)

	if seenDirty {
		if err := saveSeenStore(seenPath, seen); err != nil {
			return report, err
		}
	}

	// ---- Phase 2 ----
	// Reload the index at most ONCE for the pass, and skip even that when the
	// manifest fingerprint is unchanged since phase 1 — phase 1 wrote only
	// loader-ignored intent files, so the live set is normally still valid
	// (C14). Count reloads for.
	fpNow, err := v.indexFingerprint()
	if err != nil {
		return report, err
	}
	if fpNow != fpPhase1 {
		if err := v.ReloadIndex(); err != nil {
			return report, err
		}
		report.Phase2Reloads++
		if live, err = v.liveChunkSet(); err != nil {
			return report, err
		}
	}
	// Re-read intents (phase 1 may have written new ones) and chunks; phase 1
	// never removes chunks, but re-reading keeps mtimes current and cheap.
	intents, err = v.walkIntents()
	if err != nil {
		return report, err
	}
	chunks, err = v.walkChunkFiles()
	if err != nil {
		return report, err
	}
	seen, err = loadSeenStore(seenPath)
	if err != nil {
		return report, err
	}
	seenDirty2 := false
	t := now()
	for id, li := range intents {
		files, present := chunks[id]
		if !present {
			continue // reaped by the next run's phase 1
		}
		if live[id] {
			// Referenced at this moment: delete its intents instead of the chunk.
			if err := removeIntentFiles(li); err != nil {
				return report, err
			}
			report.Cancelled = append(report.Cancelled, id)
			// A re-referenced chunk starts a fresh fence window if it is later
			// unreferenced again: drop any first-seen record, as phase 1(a) does.
			if _, ok := seen[id]; ok {
				delete(seen, id)
				seenDirty2 = true
			}
			continue
		}
		if !li.hasTime || t.Sub(li.recorded) < fence {
			continue // recorded time not yet older than the fence
		}
		firstSeen, ok := parseSeenTime(seen[id])
		if !ok || t.Sub(firstSeen) < fence {
			continue // this device has not held the intent long enough
		}
		if t.Sub(newestMtime(files)) < fence {
			continue // a re-uploaded chunk is young
		}
		// All fences cleared: remove the chunk file(s) FIRST, then the intents, so
		// a crash in between leaves an intent for a missing chunk that phase 1(b)
		// of the next run reaps.
		if err := removeChunkFiles(files); err != nil {
			return report, err
		}
		report.RemovedChunks = append(report.RemovedChunks, id)
		report.RemovedBytes += totalSize(files)
		if err := removeIntentFiles(li); err != nil {
			return report, err
		}
		// Prune this device's first-seen record for the collected chunk. Ids are
		// content-addressed, so re-adding identical content re-creates this id; a
		// surviving entry would pre-satisfy the first-seen fence and let a forged
		// ancient intent collect the re-created chunk in a single run
		// .
		if _, ok := seen[id]; ok {
			delete(seen, id)
			seenDirty2 = true
		}
	}
	sort.Strings(report.RemovedChunks)
	if seenDirty2 {
		if err := saveSeenStore(seenPath, seen); err != nil {
			return report, err
		}
	}

	pending, err := v.walkIntents()
	if err != nil {
		return report, err
	}
	report.Pending = pendingList(pending, t)
	return report, nil
}

// logicalIntent folds every intent file that shares a leading 64-hex chunk id —
// two devices marking the same chunk, or a sync-conflict copy — into ONE logical
// intent whose recorded time is the OLDEST of the set. cancel/reap/
// collect act on all of its files together.
type logicalIntent struct {
	chunkID  string
	files    []string
	recorded time.Time
	hasTime  bool
}

// walkIntents reads <meta>/gc-intents and folds its files into one logical
// intent per chunk id. Files whose name does not begin with a 64-hex id (a
// .tmp-* from an interrupted write, foreign clutter) are ignored.
func (v *Vault) walkIntents() (map[string]*logicalIntent, error) {
	dir := filepath.Join(v.MetaRoot, GCIntentDirName)
	out := map[string]*logicalIntent{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id := chunkIDFromFileName(e.Name())
		if id == "" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		li := out[id]
		if li == nil {
			li = &logicalIntent{chunkID: id}
			out[id] = li
		}
		li.files = append(li.files, p)
		if ts, ok := readIntentTime(p); ok && (!li.hasTime || ts.Before(li.recorded)) {
			li.recorded, li.hasTime = ts, true
		}
	}
	return out, nil
}

func (v *Vault) writeIntent(id string, t time.Time) error {
	dir := filepath.Join(v.MetaRoot, GCIntentDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	line := t.UTC().Format(time.RFC3339) + "\n"
	return atomicWriteFile(filepath.Join(dir, id+gcIntentSuffix), []byte(line), 0o600)
}

func readIntentTime(path string) (time.Time, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	return parseSeenTime(strings.TrimSpace(string(data)))
}

func removeIntentFiles(li *logicalIntent) error {
	for _, f := range li.files {
		if err := removeWithRetry(f); err != nil {
			return err
		}
	}
	return nil
}

// chunkFile is a present chunk file on disk: its path, size and mtime.
type chunkFile struct {
	path  string
	size  int64
	mtime time.Time
}

func totalSize(files []chunkFile) int64 {
	var n int64
	for _, f := range files {
		n += f.size
	}
	return n
}

// newestMtime is the most recent mtime among an id's on-disk copies. Phase 2
// requires it older than the fence so a re-uploaded chunk (a young copy) blocks
// collection.
func newestMtime(files []chunkFile) time.Time {
	var newest time.Time
	for _, f := range files {
		if f.mtime.After(newest) {
			newest = f.mtime
		}
	}
	return newest
}

func chunkPresent(chunks map[string][]chunkFile, id string) bool {
	return len(chunks[id]) > 0
}

func removeChunkFiles(files []chunkFile) error {
	for _, f := range files {
		if err := removeWithRetry(f.path); err != nil {
			return err
		}
	}
	return nil
}

// walkChunkFiles maps every present chunk id (leading 64-hex of the filename,
// tolerating sync-conflict suffixes) to its on-disk copies. A missing tree is an
// empty map.
func (v *Vault) walkChunkFiles() (map[string][]chunkFile, error) {
	root := filepath.Join(v.MetaRoot, "objects", "chunks")
	out := map[string][]chunkFile{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".chunk") {
			return nil
		}
		id := chunkIDFromFileName(d.Name())
		if id == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil // raced with a concurrent removal; ignore
			}
			return err
		}
		out[id] = append(out[id], chunkFile{path: p, size: info.Size(), mtime: info.ModTime()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// liveChunkSet is the set of chunk ids referenced by any record in the index,
// including conflict entries (whose chunks count as live for GC).
func (v *Vault) liveChunkSet() (map[string]bool, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	for _, rec := range idx.Files {
		for _, ref := range rec.Chunks {
			live[strings.ToLower(ref.ID)] = true
		}
	}
	return live, nil
}

func pendingList(intents map[string]*logicalIntent, now time.Time) []PendingIntent {
	out := make([]PendingIntent, 0, len(intents))
	for id, li := range intents {
		p := PendingIntent{ChunkID: id}
		if li.hasTime {
			p.Recorded = li.recorded.UTC().Format(time.RFC3339)
			p.AgeSeconds = int64(now.Sub(li.recorded).Seconds())
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChunkID < out[j].ChunkID })
	return out
}

// seenStorePath is the device-local first-seen record for this vault (design
// b): <seenStore or appdir-data/gc-seen>/<vaultID>.json.
func (v *Vault) seenStorePath(override string) (string, error) {
	dir := strings.TrimSpace(override)
	if dir == "" {
		base, err := appdir.DataDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "gc-seen")
	}
	return filepath.Join(dir, v.ID()+".json"), nil
}

func loadSeenStore(path string) (map[string]string, error) {
	m := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

func saveSeenStore(path string, m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func parseSeenTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}
