// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	ContentRootName     = "content"
	DirectoryMarkerName = ".seavault-dir"
)

// NormalizeContentPath maps user-visible paths into the protected content root.
// The empty path and "." select the content root. Paths already under content/
// are kept as-is; every other valid user path is prefixed with content/.
func NormalizeContentPath(input string) (string, error) {
	vp, err := CleanVirtualPath(input)
	if err != nil {
		return "", err
	}
	if vp == "" || vp == "." {
		return ContentRootName, nil
	}
	// NormalizeContentPath is a PURE path mapper shared by every read and mutate
	// entrypoint (get, read, delete, export, overwrite). It must NOT reject a
	// metadata-name segment here: an existing peer/legacy path that contains one
	// (content/SeaVaultData/notes.txt) has to stay fully reachable — no existing
	// file ever becomes unreachable or uneditable.
	// The "neither name can be CREATED as a virtual path" rule of is a
	// new-path-only gate (reservedNewPathError), applied by the create
	// entrypoints beside the portable-name gate, never on this shared path.
	if vp == ContentRootName || strings.HasPrefix(vp, ContentRootName+"/") {
		return vp, nil
	}
	return path.Join(ContentRootName, vp), nil
}

// reservedNewPathError reports an error when a NEW virtual path names a segment
// this version will not create — either metadata dir name (SeaVaultData,
// .seavault) or the directory marker. It is a create-time POLICY
// gate applied ONLY when the target does not yet exist in the index: an existing
// peer/legacy path that already carries such a segment stays reachable —
// readable, gettable, exportable, overwritable and deletable (
// ). Firing this on an existing path is exactly the F3
// regression, so callers guard it with an idx.Files existence check, the same
// shape the ValidatePortableName gate uses.
func reservedNewPathError(vp string) error {
	if ReservedContentSegment(vp) {
		return fmt.Errorf("reserved virtual path %q is not allowed", vp)
	}
	return nil
}

// ReservedContentSegment reports whether a normalized content path names a
// segment the design forbids CREATING — a metadata dir name (SeaVaultData or
// .seavault) or the directory marker. Boundary layers that create paths (the
// WebDAV PUT/MKCOL/MOVE/COPY destinations, the webui upload/rename) call it to
// refuse a NEW reserved destination with a clean client error, while an EXISTING
// reserved path a peer or legacy client created stays reachable for read, get,
// export and delete. It expects an
// already-normalized content path (see NormalizeContentPath).
func ReservedContentSegment(vp string) bool {
	return containsReservedSegment(vp)
}

func normalizeContentFilePath(input string) (string, error) {
	vp, err := NormalizeContentPath(input)
	if err != nil {
		return "", err
	}
	if vp == "" || vp == ContentRootName || strings.HasSuffix(vp, "/") {
		return "", fmt.Errorf("virtual file path must be inside %s/", ContentRootName)
	}
	if IsDirectoryMarkerPath(vp) {
		return "", fmt.Errorf("reserved virtual path %q is not allowed", input)
	}
	return vp, nil
}

func normalizeContentDirPath(input string) (string, error) {
	vp, err := NormalizeContentPath(input)
	if err != nil {
		return "", err
	}
	if IsDirectoryMarkerPath(vp) {
		return "", fmt.Errorf("reserved virtual path %q is not allowed", input)
	}
	return vp, nil
}

// containsReservedSegment reports whether any segment of a virtual path is a
// name this version will not CREATE: the directory marker or either metadata dir
// name. It backs the create-time gate (reservedNewPathError) only.
// It is deliberately NOT used to classify an EXISTING path as internal or to
// reject reads/mutates — an existing metadata-name content path is ordinary,
// reachable content, and the genuinely internal
// artifact is the directory marker, recognised on its own by IsInternalVirtualPath.
func containsReservedSegment(vp string) bool {
	for _, seg := range strings.Split(vp, "/") {
		if strings.EqualFold(seg, DirectoryMarkerName) {
			return true
		}
		// Reject EITHER metadata directory name: neither SeaVaultData
		// nor.seavault may be created as a virtual path segment.
		if isMetadataDirName(seg) {
			return true
		}
	}
	return false
}

func IsDirectoryMarkerPath(vp string) bool {
	vp = strings.Trim(vp, "/")
	return strings.EqualFold(vp, DirectoryMarkerName) || strings.HasSuffix(strings.ToLower(vp), "/"+strings.ToLower(DirectoryMarkerName))
}

// IsInternalVirtualPath reports whether a virtual path names an internal vault
// artifact that must be hidden from listings and content operations. The only
// such artifact is the empty-directory marker (<dir>/.seavault-dir). A path
// whose segment merely equals a metadata dir name (content/SeaVaultData/…) is
// NOT internal — it is ordinary content a peer or another-OS client created and
// stays fully visible and reachable. Treating it
// as internal is what silently vanished the file from `list` and export.
func IsInternalVirtualPath(vp string) bool {
	if vp == "" {
		return false
	}
	return IsDirectoryMarkerPath(vp)
}

func directoryMarkerPath(dir string) (string, error) {
	vp, err := normalizeContentDirPath(dir)
	if err != nil {
		return "", err
	}
	return path.Join(vp, DirectoryMarkerName), nil
}

func markerFileRecord() FileRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return FileRecord{Size: 0, Mode: 0o700, ModTime: now, UpdatedAt: now, Generation: unixNanoOrNow(now), Chunks: nil}
}

func visibleIndex(idx Index) Index {
	out := NewIndex()
	out.UpdatedAt = idx.UpdatedAt
	for p, rec := range idx.Files {
		if IsInternalVirtualPath(p) {
			continue
		}
		out.Files[p] = rec
	}
	return out
}
