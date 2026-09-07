// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"path/filepath"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

// SyncFolder is one detected consumer-sync-client folder the wizard can place a
// vault inside: the provider that owns it, the absolute folder path, and the
// provider's caveat (design §3.1). Note always carries the catalog caveat for a
// known provider, so a hit is never advisory-without-warning.
type SyncFolder struct {
	Provider Provider
	Path     string
	Note     string
}

// DetectSyncFolders reports the consumer-sync-client folders present under home
// for the given goos (design §3.1/§4). It is the wizard-facing detector: a thin,
// catalog-attaching wrapper over the single OS-path detector
// userpath.DetectSyncRoots (C10), so the two never diverge (T10). home and goos
// are injected for tests; detection is pure existence checks and never writes.
// A folder is reported only when it exists as a directory. Detection is
// advisory: it changes the wizard's default, it never selects a folder on its
// own.
func DetectSyncFolders(home string, goos string) []SyncFolder {
	roots := userpath.DetectSyncRoots(home, goos)
	if len(roots) == 0 {
		return nil
	}
	out := make([]SyncFolder, 0, len(roots))
	for _, r := range roots {
		p := Provider(r.Provider)
		out = append(out, SyncFolder{
			Provider: p,
			Path:     r.Path,
			Note:     Caveat(p),
		})
	}
	return out
}

// ProviderRootFor reports the detected provider whose folder contains vaultDir
// (or whose folder IS vaultDir), and true, when vaultDir sits under one of the
// detected sync roots for the given home/goos (design §3.3 step 4 / C5). It lets
// a custom vault path reach the "already synced" outcome even when the user
// typed the path rather than picking the provider. The empty Provider and false
// are returned when vaultDir is under no detected root.
func ProviderRootFor(vaultDir, home, goos string) (Provider, bool) {
	target := filepath.Clean(vaultDir)
	for _, f := range DetectSyncFolders(home, goos) {
		if pathWithin(target, filepath.Clean(f.Path)) {
			return f.Provider, true
		}
	}
	return "", false
}

// pathWithin reports whether target is root itself or a descendant of root,
// compared segment-wise so a sibling with a shared prefix ("/a/bc" vs "/a/b")
// is not a false positive.
func pathWithin(target, root string) bool {
	if target == root {
		return true
	}
	rootSlash := root
	if !strings.HasSuffix(rootSlash, string(filepath.Separator)) {
		rootSlash += string(filepath.Separator)
	}
	return strings.HasPrefix(target, rootSlash)
}
