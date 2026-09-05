// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// makeLegacyVault creates a vault and relocates its metadata to the hidden
// .seavault name, standing in for a vault a 0.15.0 client created.
func makeLegacyVault(t *testing.T, root, pw string) {
	t.Helper()
	createTestVault(t, root, pw)
	if err := os.Rename(filepath.Join(root, "SeaVaultData"), filepath.Join(root, ".seavault")); err != nil {
		t.Fatal(err)
	}
}

// R4 (P0-4, D1.1): a new vault creates the visible SeaVaultData directory (never
// the hidden .seavault), and ResolveMetaDir reports it.
func TestCreateWritesVisibleSeaVaultData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "password")
	if !fileExists(filepath.Join(root, "SeaVaultData", "vault.json")) {
		t.Fatal("a new vault must create SeaVaultData/vault.json")
	}
	if fileExists(filepath.Join(root, ".seavault", "vault.json")) {
		t.Fatal("a new vault must not create the hidden .seavault directory")
	}
	name, exists, err := ResolveMetaDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if name != "SeaVaultData" || !exists {
		t.Fatalf("ResolveMetaDir = (%q, %v); want (SeaVaultData, true)", name, exists)
	}
}

// R4 (D1.1): a legacy .seavault vault opens unchanged and resolves to the legacy
// name.
func TestOpenResolvesLegacySeavault(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	makeLegacyVault(t, root, pw)
	name, exists, err := ResolveMetaDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if name != ".seavault" || !exists {
		t.Fatalf("ResolveMetaDir = (%q, %v); want (.seavault, true)", name, exists)
	}
	v, err := Open(root, pw)
	if err != nil {
		t.Fatalf("a legacy .seavault vault must open: %v", err)
	}
	if filepath.Base(v.MetaRoot) != ".seavault" {
		t.Fatalf("MetaRoot must point at the legacy dir, got %q", v.MetaRoot)
	}
	if _, err := v.PutReader(strings.NewReader("x"), "a.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatalf("writing to a legacy vault must work: %v", err)
	}
}

// R4 (D1.1): a root holding BOTH metadata names is ambiguous and refused, from
// ResolveMetaDir and from Open, rather than silently picking one.
func TestBothMetadataNamesAreAmbiguous(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	// Add a second, legacy-named metadata dir alongside the SeaVaultData one.
	legacy := filepath.Join(root, ".seavault")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, "SeaVaultData", "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "vault.json"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveMetaDir(root); !errors.Is(err, ErrAmbiguousMetadataDir) {
		t.Fatalf("ResolveMetaDir on both names must return ErrAmbiguousMetadataDir, got %v", err)
	}
	if _, err := Open(root, pw); !errors.Is(err, ErrAmbiguousMetadataDir) {
		t.Fatalf("Open on both names must return ErrAmbiguousMetadataDir, got %v", err)
	}
}

// R4 (D1.1): Create on a root that already holds a legacy .seavault vault returns
// "vault already exists" and writes no SeaVaultData directory.
func TestCreateOnLegacyRefusesAndWritesNoSeaVaultData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	makeLegacyVault(t, root, pw)
	err := CreateWithOptions(root, pw, CreateOptions{Chunk: testParams(), KDF: FastKDFConfigForTests()})
	if err == nil || !strings.Contains(err.Error(), "vault already exists") {
		t.Fatalf("Create over a legacy vault must report 'vault already exists', got %v", err)
	}
	if fileExists(filepath.Join(root, "SeaVaultData", "vault.json")) {
		t.Fatal("Create must not write SeaVaultData when a legacy vault already exists")
	}
}

// R4 (D1.2): neither metadata name may be created as a virtual path segment, at
// the top of a path or nested within one.
func TestBothMetadataNamesRejectedAsVirtualSegments(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"SeaVaultData/x.txt", ".seavault/x.txt", "sub/SeaVaultData/x.txt", "sub/.seavault/x.txt"} {
		if _, err := v.PutReader(strings.NewReader("x"), p, 1, 0o600, time.Now()); err == nil {
			t.Fatalf("PutReader(%q) must be refused as a reserved segment", p)
		}
	}
}

// R4 (D1.2): a put whose source is the vault root excludes exactly v.MetaRoot —
// the vault's own encrypted metadata is never re-imported, while ordinary
// sibling content is.
func TestPutSourceRootSkipsExactlyMetaRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := v.PutPathReport(root, "backup")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Warnings) != 0 {
		t.Fatalf("the vault's own metadata is skipped, not warned about; got %v", rep.Warnings)
	}
	entries, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	sawHello := false
	for p := range entries {
		if strings.Contains(p, "SeaVaultData") || strings.Contains(p, "vault.json") || strings.Contains(p, ".chunk") {
			t.Fatalf("the vault's own metadata must not be imported; leaked %q", p)
		}
		if strings.HasSuffix(p, "backup/hello.txt") {
			sawHello = true
		}
	}
	if !sawHello {
		t.Fatal("the sibling content file must be imported")
	}
}

// R4 (D1.2): a source tree containing a directory merely NAMED like a metadata
// dir (not this vault's own) is imported as plain content, with a warning.
func TestForeignMetadataDirImportedWithWarning(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "backup-tree")
	foreign := filepath.Join(src, "SeaVaultData")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "inner.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := v.PutPathReport(src, "restored")
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "imported as plain content") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("a foreign metadata-named dir must produce a warning; got %v", rep.Warnings)
	}
	entries, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	imported := false
	for p := range entries {
		if strings.HasSuffix(p, "SeaVaultData/inner.txt") {
			imported = true
		}
	}
	if !imported {
		t.Fatal("the foreign metadata dir's file must be imported as plain content")
	}
}

// R4 / D1.3: SyncClientPreflightNote fires only for a root under a known
// sync-client folder, and states the SeaVaultData default and the 0.15 boundary.
func TestSyncClientPreflightNote(t *testing.T) {
	note := SyncClientPreflightNote(filepath.Join("/home", "alex", "Nextcloud", "seavault"))
	if note == "" {
		t.Fatal("a root under Nextcloud must produce a preflight note")
	}
	if !strings.Contains(note, "SeaVaultData") || !strings.Contains(note, "0.15") {
		t.Fatalf("the note must mention SeaVaultData and the 0.15 boundary: %q", note)
	}
	if SyncClientPreflightNote(filepath.Join("/home", "alex", "projects", "seavault")) != "" {
		t.Fatal("a root not under a sync folder must produce no note")
	}
}

// D1.3: opening a legacy .seavault vault under a sync-client folder surfaces the
// preflight note; a new SeaVaultData vault or a vault outside a sync folder does
// not.
func TestOpenLegacyVaultUnderSyncFolderSetsNote(t *testing.T) {
	const pw = "password"

	legacyRoot := filepath.Join(t.TempDir(), "Nextcloud", "vault")
	makeLegacyVault(t, legacyRoot, pw)
	v, err := Open(legacyRoot, pw)
	if err != nil {
		t.Fatal(err)
	}
	note := v.PreflightNote()
	if note == "" {
		t.Fatal("opening a legacy vault under Nextcloud must set the preflight note")
	}
	// Owner C2: the Open note is the SHORT hidden-file-sync guidance, distinct
	// from the create-time note. It must match LegacyOpenPreflightNote and must
	// NOT carry the create-oriented SeaVaultData / 0.15-boundary text.
	if note != LegacyOpenPreflightNote(legacyRoot) {
		t.Fatalf("the Open note must be the short LegacyOpenPreflightNote, got %q", note)
	}
	if !strings.Contains(note, "hidden") {
		t.Fatalf("the Open note must give hidden-file-sync guidance, got %q", note)
	}
	if strings.Contains(note, "SeaVaultData") || strings.Contains(note, "0.15") {
		t.Fatalf("the Open note must not carry the create-time SeaVaultData/0.15 text, got %q", note)
	}

	newRoot := filepath.Join(t.TempDir(), "Nextcloud", "vault2")
	createTestVault(t, newRoot, pw)
	nv, err := Open(newRoot, pw)
	if err != nil {
		t.Fatal(err)
	}
	if nv.PreflightNote() != "" {
		t.Fatal("a new SeaVaultData vault must not carry the legacy preflight note")
	}

	plainRoot := filepath.Join(t.TempDir(), "projects", "vault3")
	makeLegacyVault(t, plainRoot, pw)
	pv, err := Open(plainRoot, pw)
	if err != nil {
		t.Fatal(err)
	}
	if pv.PreflightNote() != "" {
		t.Fatal("a legacy vault outside a sync folder must carry no note")
	}
}
