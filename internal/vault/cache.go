// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// In-memory index cache.
//
// The encrypted sharded manifests on disk are the source of truth. Rebuilding
// the index from them (loadManifestIndex) walks the whole manifests/ tree and
// AEAD-decrypts every file, so doing it on every operation made each call O(N)
// in the number of files and bulk ingest O(N^2). A long-lived *Vault (the GUI
// and WebDAV server hold one open vault across all requests, and a future mount
// would too) instead keeps a decrypted snapshot here and mutates it in step
// with the per-file manifest writes, turning steady-state operations into O(1)
// index access plus a single manifest write.
//
// Cache invariant: every code path that persists a manifest or tombstone for a
// LIVE record also updates the cache (commitFileManifest / commitTombstone /
// cacheReplace). loadManifestIndex is a pure read (design D4.1): it never writes,
// so there is nothing to reflect from a load. Compact, the one command that
// materialises a load's deferred reconciliation, invalidates the cache instead
// (v.cached = nil) so the next read rebuilds from the settled manifests.

// cloneIndex returns a deep copy so callers can mutate their snapshot without
// touching the cache (and vice versa). Only Chunks needs a deep copy; the rest
// of FileRecord is value-typed.
func cloneIndex(idx Index) Index {
	out := Index{Version: idx.Version, UpdatedAt: idx.UpdatedAt, Files: make(map[string]FileRecord, len(idx.Files))}
	for k, rec := range idx.Files {
		out.Files[k] = cloneFileRecord(rec)
	}
	return out
}

// cloneFileRecord deep-copies the reference-typed members of a FileRecord — the
// chunk slice and the two vector-clock maps — so a caller mutating its snapshot
// (or the cache) can never alias the other's Clock/ClockAge. Missing this on the
// maps would let a returned index's clock mutation corrupt the cache in place.
func cloneFileRecord(rec FileRecord) FileRecord {
	rec.Chunks = append([]ChunkRef(nil), rec.Chunks...)
	rec.Clock = cloneClock(rec.Clock)
	rec.ClockAge = cloneClockAge(rec.ClockAge)
	return rec
}

func cloneClock(c map[string]int64) map[string]int64 {
	if len(c) == 0 {
		return nil
	}
	out := make(map[string]int64, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

func cloneClockAge(c map[string]int) map[string]int {
	if len(c) == 0 {
		return nil
	}
	out := make(map[string]int, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

// cachedIndexLocked returns the authoritative in-memory index, loading and
// reconciling it from disk on first use. Callers must hold v.mu.
func (v *Vault) cachedIndexLocked() (*Index, error) {
	if v.cached != nil {
		return v.cached, nil
	}
	idx, err := v.loadIndexFromDisk()
	if err != nil {
		return nil, err
	}
	if idx.Files == nil {
		idx.Files = map[string]FileRecord{}
	}
	// Seed the generation high-water mark from the live index. loadManifestIndex
	// additionally folds in tombstone and conflict-variant generations (which are
	// not present in idx.Files) so maxGen reflects everything on disk.
	for _, rec := range idx.Files {
		if rec.Generation > v.maxGen {
			v.maxGen = rec.Generation
		}
	}
	v.cached = &idx
	return v.cached, nil
}

// nextGeneration returns a generation strictly greater than every generation
// this vault has observed (loaded from disk or written this session), using the
// wall clock only as a floor. This makes ordering monotonic per device so a
// newer local write cannot be silently lost to an older edit from a device with
// a faster clock, nor to an already-synced delete tombstone. It must be called
// without v.mu held.
func (v *Vault) nextGeneration(wallNano int64) int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	g := wallNano
	if v.maxGen+1 > g {
		g = v.maxGen + 1
	}
	v.maxGen = g
	return g
}

// clockAgeCompactions is the aging horizon N (design D4.4): a foreign vector-clock
// entry that has not advanced across this many consecutive local writes of a
// record is dropped from that record's clock on the next write. A returning
// device with the same id is a genuine new causal writer, so aging out a stale
// entry cannot lose data — it only prunes a decommissioned/reset device that has
// stopped writing, bounding the clock at the number of ACTIVE writers.
const clockAgeCompactions = 8

// nextRecordClock computes the vector clock (and its aging bookkeeping) for a
// local write of virtualPath (design D4.1/D4.4). It carries forward (joins) the
// clock of the record this write SUPERSEDES — the current live record for the
// path, which already accumulated every device entry earlier writes merged —
// then advances this device's own entry to max(seen, wallNano)+1, then ages the
// aging counter of every FOREIGN entry, dropping any that reaches
// clockAgeCompactions.
//
// It deliberately does NOT join the clocks of concurrent conflict COPIES the
// device holds for the path (records at *.conflict-* paths, ConflictOf set): a
// plain edit has not merged those unresolved forks, so joining them would falsely
// claim to dominate a peer's concurrent edit and silently drop it on the next
// reconcile. That also keeps this O(1) in the index size, not O(N) — a bulk
// ingest stays linear. Resolving a conflict is a separate, explicit act.
//
// Aging is by consecutive-local-write count, refreshed by INHERITANCE: a device
// never records an age entry for its OWN id (the k == dev skip below), so when a
// peer's record later dominates and becomes the base of a local write, its
// ClockAge carries no counter for that peer — the peer's entry resets to 1 in
// this device's lineage. A peer that keeps syncing dominating edits therefore
// stays fresh, while a decommissioned/reset device (whose edits never return)
// ages out after clockAgeCompactions local re-writes. Dropping an entry cannot
// lose data — a returning id is a genuine new causal writer (D4.4) — so an
// over-eager drop costs at worst one spurious conflict copy, never a lost edit.
//
// It reads only from the supplied snapshot and returns fresh maps, so callers
// replace (never mutate) a record's clock. A blank device id (id unavailable)
// yields a clockless write that reconciles by the Generation fallback, exactly
// like a 0.16 peer.
func (v *Vault) nextRecordClock(idx *Index, virtualPath string, wallNano int64) (map[string]int64, map[string]int) {
	dev := v.deviceID
	if dev == "" {
		return nil, nil
	}
	seen := map[string]int64{}
	var prevAge map[string]int
	if cur, ok := idx.Files[virtualPath]; ok {
		joinClock(seen, cur.Clock)
		prevAge = cur.ClockAge
	}
	self := seen[dev]
	if wallNano > self {
		self = wallNano
	}
	self++
	seen[dev] = self

	age := map[string]int{}
	for k := range seen {
		if k == dev {
			continue
		}
		a := prevAge[k] + 1
		if a >= clockAgeCompactions {
			// Aged out: a foreign entry carried unchanged for the whole horizon.
			delete(seen, k)
			continue
		}
		age[k] = a
	}
	if len(age) == 0 {
		age = nil
	}
	return seen, age
}

// advanceClock returns a fresh vector clock that strictly dominates prev by
// joining prev and bumping this device's own entry to max(prev[dev], wallNano)+1
// (design D4.1). It is the join-and-bump without the seen-conflict gather or the
// aging bookkeeping — used where the caller already holds the exact prior clock
// to supersede (a layout-migration tombstone). A blank device id yields a nil
// (clockless) result, so the write reconciles by the Generation fallback.
func (v *Vault) advanceClock(prev map[string]int64, wallNano int64) map[string]int64 {
	if v.deviceID == "" {
		return nil
	}
	next := map[string]int64{}
	joinClock(next, prev)
	self := next[v.deviceID]
	if wallNano > self {
		self = wallNano
	}
	self++
	next[v.deviceID] = self
	return next
}

// cacheKey normalizes a virtual path the same way loadManifestIndex keys the
// rebuilt index, so cached entries match what a fresh load would produce.
func cacheKey(virtualPath string) string {
	if cleaned, err := CleanVirtualPath(virtualPath); err == nil && cleaned != "" {
		return cleaned
	}
	return virtualPath
}

// commitFileManifest persists a single file manifest and reflects it in the
// cache. The disk write and the cache update BOTH happen under v.mu: the write
// still precedes the cache update, so a failed write never leaves the cache
// ahead of disk, but holding v.mu across the write also serializes it against
// Compact (integrity/F3). Compact holds v.mu across plan+mutate and removes each
// conflict loser by its plan-time Source (compact.go); if the manifest write ran
// outside v.mu, a commit landing after Compact planned the canonical file as a
// loser but before Compact's os.Remove would be deleted without being
// materialised — a silently lost concurrent edit (invariant I4). Under the lock
// the two are mutually exclusive: the commit either lands wholly before Compact
// plans (so Compact sees and reconciles it) or wholly after Compact's removes
// (so the manifest survives).
func (v *Vault) commitFileManifest(virtualPath string, rec FileRecord) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.saveFileManifest(virtualPath, rec); err != nil {
		return err
	}
	if v.cached != nil {
		stored := cloneFileRecord(rec)
		stored.ConflictOf = ""
		v.cached.Files[cacheKey(virtualPath)] = stored
	}
	return nil
}

// commitTombstone persists a delete tombstone and removes the path from the
// cache. Like commitFileManifest, the disk write and the cache update both run
// under v.mu (the write first): this serializes the tombstone write against
// Compact's out-of-band removes for the same reason (integrity/F3), so a delete
// landing concurrently with a Compact is not dropped by a loser removal.
// deletedGeneration is the generation of the live record being deleted (design
// D4.2); it is threaded to saveTombstone so a later pure load can distinguish a
// stale copy the deleter superseded from a newer edit it never saw.
func (v *Vault) commitTombstone(virtualPath string, generation, deletedGeneration int64, clock map[string]int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.saveTombstoneWithClock(virtualPath, generation, deletedGeneration, clock); err != nil {
		return err
	}
	if v.cached != nil {
		delete(v.cached.Files, cacheKey(virtualPath))
	}
	return nil
}

// cacheReplace overwrites the cached index after a whole-index save.
func (v *Vault) cacheReplace(idx Index) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c := cloneIndex(idx)
	if c.Files == nil {
		c.Files = map[string]FileRecord{}
	}
	v.cached = &c
}

// ReloadIndex discards the cached snapshot so the next operation rebuilds and
// reconciles it from the on-disk manifests. Call this after another process
// (for example a remote pull) changes the encrypted manifests underneath an
// already-open vault, so a long-lived server picks up the new state.
func (v *Vault) ReloadIndex() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cached = nil
	_, err := v.cachedIndexLocked()
	return err
}

// indexFingerprint is a cheap, dependency-free signature of the on-disk vault
// metadata: a hash over (relative path, size, mtime) of every manifest plus
// vault.json. It uses stat only (no decryption), so it is far cheaper than a
// full ReloadIndex and changes whenever a manifest is added, removed, or
// rewritten — which is exactly when an external process (e.g. the Nextcloud
// sync client) has changed .seavault underneath us. Walk order is deterministic
// (lexical) so the same on-disk state always yields the same fingerprint.
func (v *Vault) indexFingerprint() (uint64, error) {
	h := fnv.New64a()
	if fi, err := os.Stat(filepath.Join(v.MetaRoot, ConfigFileName)); err == nil {
		fmt.Fprintf(h, "cfg\x00%d\x00%d\n", fi.Size(), fi.ModTime().UnixNano())
	}
	root := filepath.Join(v.MetaRoot, ManifestDirName)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() || !strings.Contains(strings.ToLower(d.Name()), ".manifest") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil // raced with a concurrent sync delete; ignore
			}
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			rel = p
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", rel, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return h.Sum64(), nil
}

// ReloadIfChanged rebuilds the cached index whenever the on-disk manifests
// changed since the last check, so a long-lived process (GUI/WebDAV server)
// picks up edits another process delivered — e.g. the Nextcloud sync client
// syncing another device's changes. The first call only establishes the
// baseline. Returns true if it reloaded.
//
// It deliberately does NOT try to skip reloads caused by this vault's own
// writes: a local write and an external delivery can land in the same check
// window, and any "that change was mine" heuristic would then absorb the
// external change into the baseline and hide it permanently. A redundant reload
// after a local write is merely an O(N) rebuild of data the cache already holds
// (correct, just wasted), and the caller throttles how often this runs.
func (v *Vault) ReloadIfChanged() (bool, error) {
	fp, err := v.indexFingerprint()
	if err != nil {
		return false, err
	}
	v.mu.Lock()
	if !v.fpKnown {
		v.lastFP, v.fpKnown = fp, true
		v.mu.Unlock()
		return false, nil
	}
	if fp == v.lastFP {
		v.mu.Unlock()
		return false, nil
	}
	v.mu.Unlock()

	if err := v.ReloadIndex(); err != nil {
		return false, err
	}
	// Re-fingerprint AFTER the reload to baseline on the state actually loaded.
	// The load itself writes nothing now (design D4.1: reconciliation is pure and
	// its mutations are deferred to Compact), so this normally equals fp; it still
	// absorbs any further external change that landed in the reload window, so a
	// single delivery does not provoke a second reload on the next check.
	if fp2, ferr := v.indexFingerprint(); ferr == nil {
		fp = fp2
	}
	v.mu.Lock()
	v.lastFP, v.fpKnown = fp, true
	v.mu.Unlock()
	return true, nil
}
