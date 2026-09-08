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
	fold := caseInsensitiveFS(goos)
	for _, f := range DetectSyncFolders(home, goos) {
		if pathWithin(target, filepath.Clean(f.Path), fold) {
			return f.Provider, true
		}
	}
	return "", false
}

// caseInsensitiveFS reports whether the given OS has a case-insensitive
// filesystem by default (Windows NTFS, macOS APFS/HFS+). On those, a custom
// vault path typed with different case than the detected root still sits under
// it, so the "already synced" pre-answer must not be skipped just because the
// case differs (detection-preflight-5). Linux is case-sensitive.
func caseInsensitiveFS(goos string) bool {
	return goos == "windows" || goos == "darwin"
}

// pathWithin reports whether target is root itself or a descendant of root,
// compared segment-wise so a sibling with a shared prefix ("/a/bc" vs "/a/b")
// is not a false positive. When fold is true the comparison is case-insensitive,
// matching a case-insensitive host filesystem; it mirrors the EqualFold matching
// the vault preflight segment matcher already uses.
func pathWithin(target, root string, fold bool) bool {
	if fold {
		if strings.EqualFold(target, root) {
			return true
		}
	} else if target == root {
		return true
	}
	rootSlash := root
	if !strings.HasSuffix(rootSlash, string(filepath.Separator)) {
		rootSlash += string(filepath.Separator)
	}
	if fold {
		return len(target) >= len(rootSlash) && strings.EqualFold(target[:len(rootSlash)], rootSlash)
	}
	return strings.HasPrefix(target, rootSlash)
}

// PathInsideVault reports whether target is the vault directory itself or a path
// within it, honoring the host filesystem's case sensitivity (goos). The
// standalone CLI `recovery generate --save` reuses it to REFUSE writing the
// plaintext recovery card inside the vault folder — the same guard
// runRecoveryCeremony's allowRecoverySavePath applies (design U2 §2.5 /
// recovery-integration-1): a plaintext master secret inside the synced vault
// would be uploaded to the untrusted remote and defeat the encryption.
func PathInsideVault(target, vaultDir, goos string) bool {
	return pathWithin(filepath.Clean(target), filepath.Clean(vaultDir), caseInsensitiveFS(goos))
}
