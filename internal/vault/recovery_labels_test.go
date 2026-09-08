// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
)

// readVaultConfigBytes reads the raw on-disk vault.json for a vault root, resolving
// its metadata directory exactly as production does.
func readVaultConfigBytes(t *testing.T, root string) []byte {
	t.Helper()
	name, _, err := ResolveMetaDir(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, name, ConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// W5 (I-U3): labeling a recovery key is DEVICE-LOCAL and never touches the
// MAC-covered config. vault.json bytes are byte-identical before and after
// labeling; the label store is keyed by the full entry ID; and the listing shows
// the label with its stable handle.
func TestW5_LabelsNeverEnterConfig(t *testing.T) {
	isolateAppHome(t)
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, rotOldPassword)
	v, err := Open(root, rotOldPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, commit, err := v.PrepareRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	// The full entry ID for the recovery key the caller would label at generate time.
	var entryID string
	for _, ref := range v.WrapEntryRefs() {
		if ref.Type == WrapTypeRecovery {
			entryID = ref.ID
		}
	}
	if entryID == "" {
		t.Fatal("expected a recovery entry after commit")
	}

	before := readVaultConfigBytes(t, root)

	label := profile.RecoveryKeyLabel{Label: "laptop key", Created: "2026-09-07", Device: "alex-laptop"}
	if err := profile.SetRecoveryLabel(entryID, label); err != nil {
		t.Fatalf("SetRecoveryLabel: %v", err)
	}

	after := readVaultConfigBytes(t, root)
	if !bytes.Equal(before, after) {
		t.Fatalf("labeling must not change vault.json bytes (mixed-fleet MAC guarantee)\nbefore=%q\nafter =%q", before, after)
	}

	// Store keyed by the full entry ID.
	got, ok, err := profile.GetRecoveryLabel(entryID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("label store must have a record keyed by entry ID %q", entryID)
	}
	if got != label {
		t.Fatalf("stored label mismatch: got %+v want %+v", got, label)
	}

	// Listing shows the label and the stable handle (first four hex of the ID).
	views, err := profile.LabelledRecoveryKeys([]string{entryID})
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 listing row, got %d", len(views))
	}
	view := views[0]
	if view.Handle != entryID[:4] {
		t.Fatalf("handle must be the first four hex of the entry ID: got %q want %q", view.Handle, entryID[:4])
	}
	if !view.HasRecord || view.Label != "laptop key" {
		t.Fatalf("listing must surface the stored label, got %+v", view)
	}
	disp := view.Display()
	for _, want := range []string{"#" + entryID[:4], "laptop key", "alex-laptop"} {
		if !bytesContains(disp, want) {
			t.Fatalf("listing display %q must contain %q", disp, want)
		}
	}
}

func bytesContains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
