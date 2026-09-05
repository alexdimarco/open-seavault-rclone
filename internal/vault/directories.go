// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// EnsureContentLayout creates the protected content/ workspace and migrates
// older vaults whose user files lived at the virtual root into content/.
// It is intentionally called by Open so older vaults are upgraded before any
// WebDAV, GUI, CLI, or sync operation can mutate them further.
func (v *Vault) EnsureContentLayout() error {
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	if idx.Files == nil {
		idx = NewIndex()
	}
	rootMarker := path.Join(ContentRootName, DirectoryMarkerName)
	hasRootMarker := false
	if _, ok := idx.Files[rootMarker]; ok {
		hasRootMarker = true
	}
	changed := false

	if !hasRootMarker {
		// Do NOT re-create the content marker when doing so would MASK a wiped or
		// replaced index (design D2.2, P0-3): if the loaded index is otherwise empty
		// but the on-disk store shows a populated vault we failed to load — manifest
		// files present (a replaced index) or chunk objects present with no manifests
		// (a wiped store) — recreating the marker here makes the loaded index
		// non-empty and silently defeats GarbageCollect's refusal gate
		// (gc.go: len(idx.Files) != 0). Leave the index empty so the gate can detect
		// the wipe and refuse. A genuinely fresh/empty vault (no manifests, no chunks)
		// still gets its marker, and a legacy migration (non-empty index) is unaffected.
		mask, err := v.markerWouldMaskWipe(idx)
		if err != nil {
			return err
		}
		if !mask {
			idx.Files[rootMarker] = markerFileRecord()
			changed = true
		}
	}

	// Move pre-content user records into content/. Paths already under content/
	// are treated as new-layout records and are not double-prefixed. A legacy
	// file named exactly "content" is moved to content/content to free the
	// protected workspace directory name.
	paths := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	movedGen := make(map[string]int64)
	movedClock := make(map[string]map[string]int64)
	for _, oldPath := range paths {
		if oldPath == rootMarker || IsInternalVirtualPath(oldPath) {
			continue
		}
		if strings.HasPrefix(oldPath, ContentRootName+"/") {
			continue
		}
		newPath := path.Join(ContentRootName, oldPath)
		if oldPath == ContentRootName {
			newPath = path.Join(ContentRootName, ContentRootName)
		}
		rec := idx.Files[oldPath]
		movedGen[oldPath] = rec.Generation
		movedClock[oldPath] = rec.Clock
		if _, exists := idx.Files[newPath]; exists {
			newPath = conflictPath(newPath, rec)
		}
		idx.Files[newPath] = rec
		delete(idx.Files, oldPath)
		changed = true
	}

	if !changed {
		return nil
	}
	if v.usesManifestStore() {
		for p, rec := range idx.Files {
			if err := v.commitFileManifest(p, rec); err != nil {
				return err
			}
		}
		for _, oldPath := range paths {
			if oldPath == rootMarker || IsInternalVirtualPath(oldPath) || strings.HasPrefix(oldPath, ContentRootName+"/") {
				continue
			}
			// The old-layout record moved to content/; tombstone its old path with
			// a clock that dominates it (design D4.3), so a stale synced copy at the
			// old path is a clean supersede rather than a resurrected conflict.
			tombClock := v.advanceClock(movedClock[oldPath], time.Now().UTC().UnixNano())
			if err := v.commitTombstone(oldPath, 0, movedGen[oldPath], tombClock); err != nil {
				return err
			}
		}
		return nil
	}
	return v.SaveIndex(idx)
}

// markerWouldMaskWipe reports whether re-creating the content marker on the
// given (already loaded) index would mask a wiped or replaced index under an
// intact vault.json (design D2.2, P0-3). It is true only for a manifest-store
// vault whose loaded index is EMPTY while the on-disk store still shows a
// previously populated vault we could not load: manifest files are present (the
// index was replaced — e.g. id/path-mismatched or undecryptable manifests), or
// no manifests remain but chunk objects are present (the manifest store was
// wiped). A fresh/empty vault (empty index, no manifests, no chunks) returns
// false so its marker is created; a legacy single-index vault returns false too.
func (v *Vault) markerWouldMaskWipe(idx Index) (bool, error) {
	if len(idx.Files) != 0 || !v.usesManifestStore() {
		return false, nil
	}
	present, err := v.manifestFilesPresent()
	if err != nil {
		return false, err
	}
	if present {
		return true, nil
	}
	chunks, err := v.walkChunkFiles()
	if err != nil {
		return false, err
	}
	return len(chunks) > 0, nil
}

func (v *Vault) EnsureDirectory(virtualPath string) error {
	marker, err := directoryMarkerPath(virtualPath)
	if err != nil {
		return err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	if _, ok := idx.Files[marker]; ok {
		return nil
	}
	// Create-time gates for a NEW directory only (design D7.1/D1.2, B6): no
	// metadata-name segment may be CREATED as a virtual path, and the new leaf
	// (marker is <dir>/.seavault-dir) must be portable. An existing reserved dir
	// short-circuits at the marker check above, so this never blocks reaching one
	// a peer/legacy client created (finding peer/F3).
	if err := reservedNewPathError(path.Dir(marker)); err != nil {
		return err
	}
	if err := ValidatePortableName(path.Base(path.Dir(marker))); err != nil {
		return err
	}
	idx.Files[marker] = markerFileRecord()
	if v.usesManifestStore() {
		return v.commitFileManifest(marker, idx.Files[marker])
	}
	return v.SaveIndex(idx)
}

func (v *Vault) DirectoryExists(virtualPath string) (bool, error) {
	vp, err := normalizeContentDirPath(virtualPath)
	if err != nil {
		return false, err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return false, err
	}
	return directoryExistsInIndex(idx.Files, vp), nil
}

func directoryExistsInIndex(files map[string]FileRecord, vp string) bool {
	vp = strings.Trim(vp, "/")
	if vp == "" {
		return true
	}
	if _, ok := files[path.Join(vp, DirectoryMarkerName)]; ok {
		return true
	}
	prefix := strings.TrimSuffix(vp, "/") + "/"
	for p := range files {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func normalizeMigratedPathForMessage(input string) string {
	vp, err := NormalizeContentPath(input)
	if err != nil {
		return fmt.Sprintf("%q", input)
	}
	return vp
}
