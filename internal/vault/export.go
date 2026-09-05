// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	OverwriteFail    = "fail"
	OverwriteSkip    = "skip"
	OverwriteReplace = "replace"
)

type ExportOptions struct {
	Overwrite string
	Zip       bool
	DryRun    bool
}

type ExportEntry struct {
	Path     string `json:"path"`
	DestPath string `json:"destPath,omitempty"`
	Size     int64  `json:"size"`
	Skipped  bool   `json:"skipped,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Error carries a per-entry failure so a single unreadable file does not
	// abort the whole batch. Empty on success.
	Error string `json:"error,omitempty"`
}

type ExportResult struct {
	VirtualPath string        `json:"virtualPath"`
	DestPath    string        `json:"destPath"`
	Zip         bool          `json:"zip"`
	Overwrite   string        `json:"overwrite"`
	DryRun      bool          `json:"dryRun"`
	Files       int           `json:"files"`
	Exported    int           `json:"exported"`
	Skipped     int           `json:"skipped"`
	Failed      int           `json:"failed,omitempty"`
	Bytes       int64         `json:"bytes"`
	Entries     []ExportEntry `json:"entries,omitempty"`
}

func normalizeOverwrite(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", OverwriteFail:
		return OverwriteFail, nil
	case OverwriteSkip:
		return OverwriteSkip, nil
	case OverwriteReplace, "overwrite":
		return OverwriteReplace, nil
	default:
		return "", fmt.Errorf("unsupported overwrite policy %q; use fail, skip, or replace", policy)
	}
}

func (v *Vault) ExportPath(ctx context.Context, virtualPath string, destPath string, opts ExportOptions) (ExportResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	overwrite, err := normalizeOverwrite(opts.Overwrite)
	if err != nil {
		return ExportResult{}, err
	}
	if strings.TrimSpace(destPath) == "" {
		return ExportResult{}, errors.New("destination path is required")
	}
	if err := v.ensureDestinationOutsideVault(destPath); err != nil {
		return ExportResult{}, err
	}
	matches, idx, vp, err := v.exportMatches(virtualPath)
	if err != nil {
		return ExportResult{}, err
	}
	result := ExportResult{VirtualPath: vp, DestPath: destPath, Zip: opts.Zip, Overwrite: overwrite, DryRun: opts.DryRun, Files: len(matches)}
	exactFile := false
	if _, ok := idx.Files[vp]; ok && vp != "" {
		exactFile = true
	}
	// rels maps each match to the portable, batch-disambiguated relative path it
	// is written under: illegal segments are sanitised so no colon
	// reaches a Windows path, and a name that would collide with another target
	// already chosen in this batch gains the deterministic conflict suffix so
	// both files are written and neither clobbers the other.
	rels := exportTargets(matches, idx, vp, exactFile)
	if opts.Zip {
		zipPath := exportZipPath(destPath, vp)
		result.DestPath = zipPath
		for _, p := range matches {
			rec := idx.Files[p]
			result.Bytes += rec.Size
			result.Entries = append(result.Entries, ExportEntry{Path: p, DestPath: zipPath, Size: rec.Size})
		}
		if opts.DryRun {
			return result, nil
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := checkOverwrite(zipPath, overwrite); err != nil {
			if overwrite == OverwriteSkip && errors.Is(err, errSkipExisting) {
				result.Skipped = len(matches)
				for i := range result.Entries {
					result.Entries[i].Skipped = true
					result.Entries[i].Reason = "destination ZIP already exists"
				}
				return result, nil
			}
			return result, err
		}
		if err := os.MkdirAll(filepath.Dir(zipPath), 0o700); err != nil {
			return result, err
		}
		if overwrite == OverwriteReplace {
			_ = os.Remove(zipPath)
		}
		if err := v.writeZip(ctx, zipPath, matches, idx, rels); err != nil {
			return result, err
		}
		result.Exported = len(matches)
		return result, nil
	}

	for _, p := range matches {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		rec := idx.Files[p]
		target := filepath.Join(destPath, filepath.FromSlash(rels[p]))
		entry := ExportEntry{Path: p, DestPath: target, Size: rec.Size}
		result.Bytes += rec.Size
		if opts.DryRun {
			result.Entries = append(result.Entries, entry)
			continue
		}
		if err := checkOverwrite(target, overwrite); err != nil {
			if overwrite == OverwriteSkip && errors.Is(err, errSkipExisting) {
				entry.Skipped = true
				entry.Reason = "destination exists"
				result.Skipped++
				result.Entries = append(result.Entries, entry)
				continue
			}
			// A checkOverwrite failure other than skip (a stat error or a
			// fail-policy collision) is per-entry: record it and continue so one
			// bad destination does not abort the batch.
			entry.Error = err.Error()
			result.Failed++
			result.Entries = append(result.Entries, entry)
			continue
		}
		if err := v.restoreFileWithOverwrite(rec, target, overwrite); err != nil {
			entry.Error = err.Error()
			result.Failed++
			result.Entries = append(result.Entries, entry)
			continue
		}
		result.Exported++
		result.Entries = append(result.Entries, entry)
	}
	if result.Failed > 0 {
		return result, fmt.Errorf("export completed with %d error(s); see per-entry detail", result.Failed)
	}
	return result, nil
}

// exportTargets computes, for the matched virtual paths in order, the relative
// on-disk path each is written under. Every segment that fails
// ValidatePortableName is sanitised (so no illegal character — a colon most
// dangerously — reaches the OS path); when the resulting slash path collides
// case-insensitively with one already chosen in this batch, the leaf gains the
// deterministic conflict suffix so both files land and neither clobbers
// the other. A name that is already portable but folds onto an earlier target
// gets the bare suffix. The returned paths are slash-separated.
func exportTargets(matches []string, idx Index, vp string, exactFile bool) map[string]string {
	rels := make(map[string]string, len(matches))
	used := make(map[string]bool, len(matches))
	for _, p := range matches {
		segs := strings.Split(exportRelativePath(p, vp, exactFile), "/")
		for i, s := range segs {
			if ValidatePortableName(s) != nil {
				segs[i] = sanitizePortableSegment(s)
			}
		}
		key := strings.ToLower(strings.Join(segs, "/"))
		if used[key] {
			suffix := conflictSuffix(idx.Files[p])
			base := segs[len(segs)-1] + "." + suffix
			segs[len(segs)-1] = base
			key = strings.ToLower(strings.Join(segs, "/"))
			// Two truly-distinct records almost never share content-seeded
			// suffixes, but guard termination with a numeric fallback.
			for n := 2; used[key]; n++ {
				segs[len(segs)-1] = fmt.Sprintf("%s.%d", base, n)
				key = strings.ToLower(strings.Join(segs, "/"))
			}
		}
		used[key] = true
		rels[p] = strings.Join(segs, "/")
	}
	return rels
}

func (v *Vault) exportMatches(virtualPath string) ([]string, Index, string, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, Index{}, "", err
	}
	vp, err := normalizeContentDirPath(virtualPath)
	if err != nil {
		return nil, Index{}, "", err
	}
	if _, ok := idx.Files[vp]; ok && vp != "" && !IsInternalVirtualPath(vp) {
		return []string{vp}, visibleIndex(idx), vp, nil
	}
	prefix := vp
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var matches []string
	for p := range idx.Files {
		if IsInternalVirtualPath(p) {
			continue
		}
		if prefix == "" || strings.HasPrefix(p, prefix) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil, Index{}, "", fmt.Errorf("virtual path %q not found", virtualPath)
	}
	sort.Strings(matches)
	return matches, visibleIndex(idx), vp, nil
}

func exportRelativePath(p, vp string, exactFile bool) string {
	if exactFile {
		return path.Base(p)
	}
	if vp == "" {
		return p
	}
	prefix := strings.TrimSuffix(vp, "/") + "/"
	rel := strings.TrimPrefix(p, prefix)
	if rel == "" || rel == p {
		rel = path.Base(p)
	}
	return rel
}

func exportZipPath(destPath, vp string) string {
	if strings.EqualFold(filepath.Ext(destPath), ".zip") {
		return destPath
	}
	name := "seavault-export"
	if strings.TrimSpace(vp) != "" {
		name = strings.Trim(path.Base(vp), ".")
		if name == "" || name == "/" {
			name = "seavault-export"
		}
	}
	return filepath.Join(destPath, name+".zip")
}

var errSkipExisting = errors.New("skip existing destination")

func checkOverwrite(target string, overwrite string) error {
	if _, err := os.Stat(target); err == nil {
		switch overwrite {
		case OverwriteSkip:
			return errSkipExisting
		case OverwriteReplace:
			return nil
		default:
			return fmt.Errorf("destination already exists: %s", target)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (v *Vault) restoreFileWithOverwrite(rec FileRecord, destPath string, overwrite string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".seavault-export-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	var writeErr error
	defer func() {
		_ = tmp.Close()
		if writeErr != nil {
			_ = os.Remove(tmpName)
		}
	}()
	for _, ref := range rec.Chunks {
		chunk, err := v.loadChunk(ref)
		if err != nil {
			writeErr = err
			return err
		}
		if _, err := tmp.Write(chunk); err != nil {
			writeErr = err
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	mode := os.FileMode(rec.Mode)
	if mode == 0 {
		mode = 0o600
	}
	_ = os.Chmod(tmpName, mode)
	if rec.ModTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
			_ = os.Chtimes(tmpName, t, t)
		}
	}
	if overwrite == OverwriteReplace {
		_ = os.Remove(destPath)
	}
	return os.Rename(tmpName, destPath)
}

func (v *Vault) writeZip(ctx context.Context, zipPath string, matches []string, idx Index, rels map[string]string) error {
	tmp, err := os.CreateTemp(filepath.Dir(zipPath), ".seavault-zip-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	var writeErr error
	defer func() {
		_ = tmp.Close()
		if writeErr != nil {
			_ = os.Remove(tmpName)
		}
	}()
	zw := zip.NewWriter(tmp)
	for _, p := range matches {
		if err := ctx.Err(); err != nil {
			writeErr = err
			_ = zw.Close()
			return err
		}
		rec := idx.Files[p]
		hdr := &zip.FileHeader{Name: rels[p], Method: zip.Deflate}
		hdr.SetMode(os.FileMode(rec.Mode))
		if rec.ModTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
				hdr.SetModTime(t)
			}
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			writeErr = err
			_ = zw.Close()
			return err
		}
		for _, ref := range rec.Chunks {
			chunk, err := v.loadChunk(ref)
			if err != nil {
				writeErr = err
				_ = zw.Close()
				return err
			}
			if _, err := w.Write(chunk); err != nil {
				writeErr = err
				_ = zw.Close()
				return err
			}
		}
	}
	if err := zw.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, zipPath); err != nil {
		return err
	}
	return nil
}
