// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GCFenceDefault is the default age below which a garbage-collection intent
// cannot fire and an atomic-write temp orphan is left alone (design D3.1, D5.3).
// The standalone Compact/CompactPlan entry points (which take no fence) sweep
// .tmp-* orphans older than it; the fenced `gc [--confirm] --fence N` path
// threads N instead, and the two-phase chunk collection (§3) reuses it as its
// own default. A young temp file may be a rename still in flight, so it is kept.
const GCFenceDefault = 72 * time.Hour

// CompactReport summarises a Compact run, or — from CompactPlan — what one would
// do (design D4.4). Conflicts and TmpOrphans list the affected virtual/temp
// paths so `seavault gc` can print the plan; RemovedManifests counts the
// duplicate, generation-suppressed, and superseded-tombstone manifest files that
// Compact deletes (their on-disk names are not user-meaningful). Errors collects
// every failure encountered while applying the plan — never swallowed (D4.4);
// Compact returns a non-nil error when it is non-empty.
type CompactReport struct {
	Conflicts        []string `json:"conflicts"`
	RemovedManifests int      `json:"removedManifests"`
	TmpOrphans       []string `json:"tmpOrphans"`
	Errors           []string `json:"errors,omitempty"`
}

// Materialised reports whether the run changed anything on disk, so callers can
// tell an effective compaction from an empty (idempotent) one.
func (r CompactReport) Materialised() bool {
	return len(r.Conflicts) > 0 || r.RemovedManifests > 0 || len(r.TmpOrphans) > 0
}

// Compact applies the reconcilePlan a pure load computed (design D4.4, P0-6/P2):
// it materialises each losing edit as a deterministic *.conflict-* manifest,
// removes redundant/superseded manifest files, and sweeps atomic-write temp
// orphans older than the GC fence from the chunk, manifest, and gc-intents trees — all under
// v.mu, with Windows retry semantics, collecting every error instead of swallowing
// it. It is idempotent: a second run recomputes the plan from the now-settled disk
// state and finds nothing to do. Reads never call it (invariant I2); the passive
// sync watcher never calls it (R18) — only `seavault compact`, `seavault gc
// --confirm`, and POST /api/compact do.
func (v *Vault) Compact() (CompactReport, error) {
	return v.compact(time.Now(), true, GCFenceDefault)
}

// CompactPlan computes what Compact would do without touching disk (design D4.4,
// D5.3): `seavault gc` prints it as the dry-run plan and orphan list.
func (v *Vault) CompactPlan() (CompactReport, error) {
	return v.compact(time.Now(), false, GCFenceDefault)
}

// compact is the shared engine for Compact (apply=true) and CompactPlan
// (apply=false). now is injectable so a test can age .tmp-* orphans across the
// fence deterministically. fence is the age below which a .tmp-* orphan is kept
// (a rename may still be in flight): the standalone Compact/CompactPlan entry
// points, which take no fence, pass GCFenceDefault, while GarbageCollect threads
// the run's --fence so `gc [--confirm] --fence N` sweeps orphans older than N
// (design D5.3).
func (v *Vault) compact(now time.Time, apply bool, fence time.Duration) (CompactReport, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Recompute the plan from the current on-disk state under the lock so we act
	// on exactly what is there now (another process may have synced changes).
	_, plan, err := v.loadManifestIndex()
	if err != nil {
		return CompactReport{}, err
	}

	var report CompactReport

	// Materialise losing edits: write the deterministic conflict manifest, then
	// remove the loser file it replaces. On a write failure the loser is kept, so
	// no edit is lost; the error is recorded and the run continues. A loser-removal
	// failure after a successful write still counts the conflict as materialised —
	// the manifest exists — and the next Compact retries the (idempotent) removal.
	for _, c := range plan.conflicts {
		if !apply {
			report.Conflicts = append(report.Conflicts, c.Path)
			report.RemovedManifests++ // the loser source would be removed
			continue
		}
		if err := v.saveFileManifest(c.Path, c.Rec); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("materialise conflict %s: %v", c.Path, err))
			continue
		}
		report.Conflicts = append(report.Conflicts, c.Path)
		if err := removeWithRetry(c.Source); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("remove superseded %s: %v", c.Source, err))
			continue
		}
		report.RemovedManifests++
	}

	// Remove redundant duplicates, generation-suppressed stale copies, and
	// superseded tombstones.
	for _, p := range plan.removeManifests {
		if !apply {
			report.RemovedManifests++
			continue
		}
		if err := removeWithRetry(p); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("remove %s: %v", p, err))
			continue
		}
		report.RemovedManifests++
	}

	// Sweep atomic-write temp orphans older than the fence from both synced trees.
	orphans, sweepErrs := v.sweepTmpOrphans(now, apply, fence)
	report.TmpOrphans = orphans
	report.Errors = append(report.Errors, sweepErrs...)

	if apply && report.Materialised() {
		// The on-disk state changed underneath the cache; force the next read to
		// rebuild from the settled manifests.
		v.cached = nil
	}

	if len(report.Errors) > 0 {
		return report, fmt.Errorf("compact completed with %d error(s)", len(report.Errors))
	}
	return report, nil
}

// sweepTmpOrphans finds (and, when apply is set, removes) atomic-write temp files
// left by a crash between CreateTemp and rename (design D5.3, R6b) in any of the
// three synced trees atomicWriteFile targets: objects/chunks, manifests, and
// gc-intents (writeIntent, gc.go, writes each intent through atomicWriteFile too).
// Only orphans older than fence — the run's GC fence — are touched: a young
// .tmp-* may be a write still in flight. Real <id>.intent files lack the .tmp-
// prefix and are never touched. Returns the orphan paths and any errors.
func (v *Vault) sweepTmpOrphans(now time.Time, apply bool, fence time.Duration) ([]string, []string) {
	var orphans, errs []string
	roots := []string{
		filepath.Join(v.MetaRoot, "objects", "chunks"),
		filepath.Join(v.MetaRoot, ManifestDirName),
		filepath.Join(v.MetaRoot, GCIntentDirName),
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsNotExist(walkErr) {
					return nil
				}
				errs = append(errs, fmt.Sprintf("walk %s: %v", p, walkErr))
				return nil
			}
			if d.IsDir() || !strings.HasPrefix(d.Name(), ".tmp-") {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				if os.IsNotExist(err) {
					return nil // raced with a concurrent sweep/rename; ignore
				}
				errs = append(errs, fmt.Sprintf("stat %s: %v", p, err))
				return nil
			}
			if now.Sub(info.ModTime()) < fence {
				return nil // young: a rename may still be completing
			}
			orphans = append(orphans, p)
			if apply {
				if err := removeWithRetry(p); err != nil {
					errs = append(errs, fmt.Sprintf("sweep %s: %v", p, err))
				}
			}
			return nil
		})
	}
	return orphans, errs
}
