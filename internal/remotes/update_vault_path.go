// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package remotes

import (
	"path/filepath"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

// UpdateVaultPathMatching rewrites remote profiles that point at oldPath.
func UpdateVaultPathMatching(oldPath, newPath string) (int, error) {
	oldAbs, err := userpath.Abs(oldPath)
	if err != nil {
		return 0, err
	}
	newAbs, err := userpath.Abs(newPath)
	if err != nil {
		return 0, err
	}
	s, err := Load()
	if err != nil {
		return 0, err
	}
	count := 0
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range s.Profiles {
		p, err := userpath.Abs(s.Profiles[i].Vault)
		if err != nil {
			continue
		}
		if filepath.Clean(p) == filepath.Clean(oldAbs) {
			s.Profiles[i].Vault = newAbs
			s.Profiles[i].UpdatedAt = now
			count++
		}
	}
	if count == 0 {
		return 0, nil
	}
	return count, SaveStore(s)
}
