// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PutDirectoryContents stores the contents of sourceDir under virtualBase.
// Unlike PutPath on a directory, this method never includes the source
// directory's own basename in the virtual path. It is kept as a compatibility
// API for rsync-backed staging code that prepares a temporary directory whose
// children should be imported directly into the target prefix.
func (v *Vault) PutDirectoryContents(sourceDir string, virtualBase string) ([]PutResult, error) {
	info, err := os.Stat(sourceDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source %s is not a directory", sourceDir)
	}

	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}

	base := strings.TrimSpace(virtualBase)
	if base == "" {
		base = ContentRootName
	} else {
		base, err = normalizeContentDirPath(base)
		if err != nil {
			return nil, err
		}
	}

	metaRootAbs, _ := filepath.Abs(v.MetaRoot)
	var results []PutResult
	var written []string
	err = filepath.WalkDir(sourceDir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" {
				return filepath.SkipDir
			}
			// Exclude exactly this vault's own metadata directory (design D1.2); a
			// foreign directory that merely shares the name is imported as content.
			if abs, aerr := filepath.Abs(p); aerr == nil && abs == metaRootAbs {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(sourceDir, p)
		if err != nil {
			return err
		}
		vp, err := virtualJoin(base, rel)
		if err != nil {
			return err
		}
		if vp == "" {
			return fmt.Errorf("empty virtual path for %s", p)
		}
		res, err := v.putFile(p, vp, &idx)
		if err != nil {
			return err
		}
		results = append(results, res)
		written = append(written, vp)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if v.usesManifestStore() {
		for _, p := range written {
			if err := v.commitFileManifest(p, idx.Files[p]); err != nil {
				return nil, err
			}
		}
		return results, nil
	}
	return results, v.SaveIndex(idx)
}
