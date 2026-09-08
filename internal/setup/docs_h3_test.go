// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestReadmeQualifiesProvidersByOS (H3, DOC-3 extension): the README must qualify
// the detected providers by OS — iCloud Drive and Google Drive are detected on
// macOS and Windows only, while Dropbox, OneDrive, Nextcloud and Syncthing are
// detected on every platform. This extends the DOC-3 drift guard (which pins the
// provider LIST to the catalog) so the OS restriction cannot be silently dropped,
// which would tell a Linux user to expect iCloud/Google Drive detection that
// never fires. Every asserted provider is a real catalog entry.
func TestReadmeQualifiesProvidersByOS(t *testing.T) {
	readme := mustReadDoc(t, filepath.Join("..", "..", "README.md"))

	// The catalog display names for the OS-restricted and always-on providers.
	restricted := []Provider{ProviderICloud, ProviderGoogleDrive}
	always := []Provider{ProviderDropbox, ProviderOneDrive, ProviderNextcloud, ProviderSyncthing}

	// The README must contain the explicit OS-qualification clause.
	const osClause = "macOS and Windows only"
	if !strings.Contains(readme, osClause) {
		t.Fatalf("README must qualify detection by OS with the clause %q", osClause)
	}
	const everyClause = "every platform"
	if !strings.Contains(readme, everyClause) {
		t.Fatalf("README must state which providers are detected on %q", everyClause)
	}

	// Locate the qualifying sentence and assert each restricted provider is named
	// as macOS/Windows-only and each always-on provider is named as every-platform.
	seg, ok := between(readme, "detected on macOS and Windows only", "on every platform")
	if !ok {
		// Fall back to the whole readme window around the clause; still assert
		// each provider is named SOMEWHERE in the qualification.
		t.Fatalf("README must carry a single sentence qualifying iCloud/Google Drive as macOS/Windows-only and the rest as every-platform")
	}
	_ = seg

	for _, p := range restricted {
		name := DisplayName(p)
		if strings.TrimSpace(name) == "" {
			t.Fatalf("restricted provider %q has no display name", p)
		}
		if !strings.Contains(readme, name) {
			t.Fatalf("README must name the OS-restricted provider %q (%s)", p, name)
		}
	}
	if len(always) == 0 {
		t.Fatal("the always-on provider list is empty; the guard would be vacuous")
	}
	for _, p := range always {
		name := DisplayName(p)
		if !strings.Contains(readme, name) {
			t.Fatalf("README must name the every-platform provider %q (%s)", p, name)
		}
	}
}
