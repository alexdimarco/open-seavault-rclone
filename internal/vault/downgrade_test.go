// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// editConfig rewrites vault.json in place, applying mutate to the decoded config.
func editConfig(t *testing.T, root string, mutate func(*VaultConfig)) {
	t.Helper()
	cfgPath := filepath.Join(metaRootOf(t, root), ConfigFileName)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg VaultConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	mutate(&cfg)
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// R5 (P0-3, D2.1): a vault.json downgraded to a legacy single-index / version-1
// layout while encrypted manifests still exist is refused with
// ErrConfigInconsistent rather than silently opened as an empty legacy vault.
func TestOpenRefusesDowngradedConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*VaultConfig)
	}{
		{
			name: "version 1 and blank manifestMode",
			mutate: func(c *VaultConfig) {
				c.Version = 1
				c.Crypto.ManifestMode = ""
			},
		},
		{
			name: "version 1 with manifestMode intact",
			mutate: func(c *VaultConfig) {
				c.Version = 1
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			const pw = "password"
			createTestVault(t, root, pw)
			v, err := Open(root, pw)
			if err != nil {
				t.Fatal(err)
			}
			// A put materialises at least one encrypted manifest on disk.
			if _, err := v.PutReader(strings.NewReader("payload"), "doc.txt", 7, 0o600, time.Now()); err != nil {
				t.Fatal(err)
			}
			present, err := v.manifestFilesPresent()
			if err != nil || !present {
				t.Fatalf("precondition: manifests must exist (present=%v err=%v)", present, err)
			}

			editConfig(t, root, tc.mutate)

			if _, err := Open(root, pw); !errors.Is(err, ErrConfigInconsistent) {
				t.Fatalf("downgraded vault.json must be refused with ErrConfigInconsistent, got %v", err)
			}
		})
	}
}

// R5: an intact, un-downgraded manifest vault still opens cleanly (control: the
// downgrade check does not fire on a legitimate v2 vault).
func TestOpenIntactManifestVaultSucceeds(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("payload"), "doc.txt", 7, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, pw); err != nil {
		t.Fatalf("an intact manifest vault must still open: %v", err)
	}
}

// R5 (P0-3, D2.2): GarbageCollect refuses on a wiped manifest store — no
// manifests at all but chunk objects present — removing and writing nothing.
func TestGCRefusesWipedManifestStore(t *testing.T) {
	v, seenDir := openGCVault(t)
	if _, err := v.PutReader(strings.NewReader("payload data for chunking here"), "doc.txt", 30, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Wipe every manifest (including the content marker) while chunks remain.
	if err := os.RemoveAll(filepath.Join(v.MetaRoot, ManifestDirName)); err != nil {
		t.Fatal(err)
	}
	chunksBefore := countChunkFiles(t, v.Root)
	if chunksBefore == 0 {
		t.Fatal("precondition: chunks must remain on disk")
	}

	_, err := v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if !errors.Is(err, ErrGCRefused) {
		t.Fatalf("GC on a wiped manifest store must return ErrGCRefused, got %v", err)
	}
	if n := countChunkFiles(t, v.Root); n != chunksBefore {
		t.Fatalf("a refused GC must remove nothing; chunks %d -> %d", chunksBefore, n)
	}
	if entries, _ := os.ReadDir(filepath.Join(v.MetaRoot, GCIntentDirName)); len(entries) != 0 {
		t.Fatalf("a refused GC must write no intents; got %v", entries)
	}
}

// R5 (P0-3, D2.2), regression for server/F1-gc-refusal-dead-in-production: the
// wiped-manifest-store refusal must fire through the REAL open path. Every
// CLI/GUI entry to GarbageCollect first runs vault.Open, which runs
// EnsureContentLayout; if that re-creates the content-marker manifest on a wiped
// store, the loaded index becomes non-empty and the refusal gate's early return
// (gc.go: len(idx.Files) != 0) silently defeats both refusal branches — so a
// hostile server that deletes every manifest under an intact vault.json can drive
// gc into queueing and deleting live-file chunks. Unlike
// TestGCRefusesWipedManifestStore, which calls GarbageCollect on an already-open
// *Vault (never re-invoking Open, a false green), this test re-Opens the wiped
// vault so it exercises the exact production sequence.
func TestGCRefusesWipedManifestStoreAfterReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "password"
	createTestVault(t, root, pw)
	seenDir := filepath.Join(t.TempDir(), "gc-seen")

	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("payload data for chunking here"), "doc.txt", 30, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Hostile server: delete every manifest (content marker included) under an
	// intact vault.json, leaving the live-file chunks orphaned on disk.
	if err := os.RemoveAll(filepath.Join(v.MetaRoot, ManifestDirName)); err != nil {
		t.Fatal(err)
	}
	chunksBefore := countChunkFiles(t, root)
	if chunksBefore == 0 {
		t.Fatal("precondition: live-file chunks must remain on disk")
	}

	// Re-open through the production path (Open -> EnsureContentLayout).
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	_, err = v2.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if !errors.Is(err, ErrGCRefused) {
		t.Fatalf("GC on a wiped manifest store re-opened through Open must return ErrGCRefused, got %v", err)
	}
	if n := countChunkFiles(t, root); n != chunksBefore {
		t.Fatalf("a refused GC must remove nothing; chunks %d -> %d", chunksBefore, n)
	}
	if entries, _ := os.ReadDir(filepath.Join(v2.MetaRoot, GCIntentDirName)); len(entries) != 0 {
		t.Fatalf("a refused GC must write no intents; got %v", entries)
	}
	// Open of a wiped store must NOT re-create the content-marker manifest:
	// re-creating it is exactly what masks the wipe from the refusal gate.
	if present, err := v2.manifestFilesPresent(); err != nil || present {
		t.Fatalf("Open of a wiped store must not re-create any manifest (present=%v err=%v); that masks the wipe from the GC gate", present, err)
	}
}

// writeMismatchedManifest seals a NON-tombstone manifest for recordPath but
// stores it under a filename id that does not match manifestID(recordPath), so a
// pure load decrypts it yet drops it on the id/path check — the "replaced index"
// signature the D2.2 gate refuses. It is written directly with the vault's keys
// because such a state is unreachable through the normal write path.
func writeMismatchedManifest(t *testing.T, v *Vault, recordPath, filenamePath string) {
	t.Helper()
	fnID := v.manifestID(filenamePath)
	if fnID == v.manifestID(recordPath) {
		t.Fatal("test setup: filename path must differ from record path")
	}
	rec := ManifestRecord{Version: 1, Path: recordPath, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), File: FileRecord{Size: 3, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Generation: 1}}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		t.Fatal(err)
	}
	ct := v.indexAEAD.Seal(nil, nonce, data, []byte(manifestAADPrefix+fnID))
	if err := atomicWriteFile(v.manifestPath(fnID), encodeEncrypted(manifestMagic, nonce, ct), 0o600); err != nil {
		t.Fatal(err)
	}
}

// R5 (D2.2): GarbageCollect refuses when the loaded index is empty while a
// non-tombstone manifest still exists on disk (a wiped or replaced index).
func TestGCRefusesEmptyIndexWithNonTombstoneManifest(t *testing.T) {
	v, seenDir := openGCVault(t)
	// Remove the content marker manifest so the loaded index is genuinely empty.
	if err := os.RemoveAll(filepath.Join(v.MetaRoot, ManifestDirName)); err != nil {
		t.Fatal(err)
	}
	// A non-tombstone manifest exists on disk but is dropped by the load's id/path
	// check, leaving an empty index alongside a live-looking manifest.
	writeMismatchedManifest(t, v, "content/ghost.txt", "content/other.txt")

	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	idx, err := v.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Files) != 0 {
		t.Fatalf("precondition: loaded index must be empty, got %d entries", len(idx.Files))
	}

	_, err = v.GarbageCollect(GCOptions{Confirm: true, SeenStore: seenDir})
	if !errors.Is(err, ErrGCRefused) {
		t.Fatalf("GC on an empty index with a non-tombstone manifest must return ErrGCRefused, got %v", err)
	}
}

// R5 (D2.2): a vault whose files were all deleted (tombstones present, chunks
// orphaned) is NOT refused — it stays collectable so the orphaned chunks can be
// reclaimed. The protected content marker keeps the loaded index non-empty.
func TestGCAllowsVaultWithDeletions(t *testing.T) {
	v, seenDir := openGCVault(t)
	if _, err := v.PutReader(strings.NewReader("payload data for chunking here"), "doc.txt", 30, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("doc.txt"); err != nil {
		t.Fatal(err)
	}
	report, err := v.GarbageCollect(GCOptions{Confirm: false, SeenStore: seenDir})
	if errors.Is(err, ErrGCRefused) {
		t.Fatal("a vault with deletions must stay GC-able, not refused")
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) == 0 {
		t.Fatal("expected the orphaned chunk(s) from the delete to be GC candidates")
	}
}
