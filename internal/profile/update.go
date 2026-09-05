// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package profile

import (
	"path/filepath"

	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

// UpdatePath changes one saved vault location without touching any keychain entry.
func UpdatePath(name, vaultPath string) (Entry, error) {
	return Add(name, vaultPath)
}

// UpdatePathsMatching rewrites every saved vault location that points at oldPath.
func UpdatePathsMatching(oldPath, newPath string) (int, error) {
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
	for i := range s.Profiles {
		p, err := userpath.Abs(s.Profiles[i].VaultPath)
		if err != nil {
			continue
		}
		if samePath(p, oldAbs) {
			s.Profiles[i].VaultPath = newAbs
			count++
		}
	}
	if count == 0 {
		return 0, nil
	}
	return count, Save(s)
}

func samePath(a, b string) bool {
	ca := filepath.Clean(a)
	cb := filepath.Clean(b)
	return ca == cb
}
