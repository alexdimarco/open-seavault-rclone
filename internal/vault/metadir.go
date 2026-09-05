// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// MetadataDirNames are the directory names, preferred first, under which a vault
// keeps its encrypted metadata. New vaults use the visible
// "SeaVaultData"; ".seavault" is the legacy hidden name a 0.15.0 client created
// and still opens. The legacy MetadataDirName constant is retained for callers
// that have not moved to the list; new code resolves through MetadataDirNames.
var MetadataDirNames = []string{"SeaVaultData", ".seavault"}

// ErrAmbiguousMetadataDir is returned when a vault root holds BOTH a
// SeaVaultData/vault.json and a.seavault/vault.json: the tool refuses to guess
// which is authoritative rather than silently picking one.
var ErrAmbiguousMetadataDir = errors.New("vault root holds both a SeaVaultData and a .seavault metadata directory; refusing to guess which is authoritative — keep one and remove or rename the other")

// ResolveMetaDir reports which metadata directory a vault root uses. It returns
// the first name in MetadataDirNames whose <root>/<name>/vault.json exists
// (exists=true); if none exists it returns the preferred name with exists=false;
// if BOTH names hold a vault.json it returns ErrAmbiguousMetadataDir (design
// ). It never silently picks between the two.
func ResolveMetaDir(root string) (name string, exists bool, err error) {
	var found []string
	for _, n := range MetadataDirNames {
		if _, statErr := os.Stat(filepath.Join(root, n, ConfigFileName)); statErr == nil {
			found = append(found, n)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", false, statErr
		}
	}
	if len(found) > 1 {
		return "", false, ErrAmbiguousMetadataDir
	}
	if len(found) == 1 {
		return found[0], true, nil
	}
	return MetadataDirNames[0], false, nil
}

// isMetadataDirName reports whether a bare directory segment matches a known
// metadata directory name (case-insensitively). It is used by the source-walk
// exclusions to tell a foreign metadata-named directory (imported as plain
// content, with a warning) from ordinary content.
func isMetadataDirName(segment string) bool {
	for _, n := range MetadataDirNames {
		if strings.EqualFold(segment, n) {
			return true
		}
	}
	return false
}

// syncClientFolderNames are the local sync-client folder names whose presence in
// a vault root's path triggers the preflight note. There is deliberately no
// bare "Sync" token (too generic).
var syncClientFolderNames = []string{"Nextcloud", "ownCloud", "OneDrive", "Dropbox", "Google Drive", "iCloud Drive", "Syncthing"}

// hasSyncClientSegment reports whether any path SEGMENT of root equals a known
// sync-client folder name, case-insensitively (matcher shape reused
// from userpath's segment-wise comparison).
func hasSyncClientSegment(root string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(root), "/") {
		if seg == "" {
			continue
		}
		for _, name := range syncClientFolderNames {
			if strings.EqualFold(seg, name) {
				return true
			}
		}
	}
	return false
}

// SyncClientPreflightNote returns the one-line CREATE-time informational note of
// the design when the vault root sits under a known sync-client folder, and ""
// otherwise. It is used by `init` and the GUI create path. The note states that
// new vaults use the visible SeaVaultData directory, how to sync a legacy hidden
// .seavault vault, and the one-way I1 boundary: a vault this version creates is
// not located by SeaVault 0.15.0 or older on another device. The quoted 0.15
// failure is its real errno wording (verified against the ab64d05 fixture), not
// a paraphrase, so an operator recognises the message they will actually see.
func SyncClientPreflightNote(root string) string {
	if !hasSyncClientSegment(root) {
		return ""
	}
	return "note: new vaults keep their encrypted data in the visible SeaVaultData directory. " +
		"If you open an older vault stored as .seavault, enable hidden-file sync in your client. " +
		"A vault created by this version is not found by SeaVault 0.15.0 or older on another device " +
		"(it reports a \"no such file\" error on .seavault/vault.json); upgrade every device before creating new vaults in a shared folder."
}

// LegacyOpenPreflightNote returns the one-line note shown when OPENING a legacy
// hidden.seavault vault under a known sync-client folder (C2). It
// is deliberately shorter than SyncClientPreflightNote: opening an existing
// .seavault vault, the only advice that applies is to enable hidden-file sync so
// the vault reaches the other devices, so the create-oriented SeaVaultData /
// 0.15-boundary text (which would only confuse someone opening an old vault) is
// omitted. Returns "" when the root is not under a sync-client folder.
func LegacyOpenPreflightNote(root string) string {
	if !hasSyncClientSegment(root) {
		return ""
	}
	return "note: this vault keeps its encrypted data in the hidden .seavault directory; " +
		"enable hidden-file synchronization in your sync client so it reaches your other devices."
}
