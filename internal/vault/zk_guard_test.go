// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExportAndGetRejectDestinationInsideVault verifies the zero-knowledge
// enforcement: decrypted output may never be written inside .seavault (which
// would sync the plaintext to the server), but writing outside the vault works.
func TestExportAndGetRejectDestinationInsideVault(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("secret"), "a.txt", 6, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	insideDir := filepath.Join(v.MetaRoot, "leak")
	insideFile := filepath.Join(v.MetaRoot, "leak.txt")

	if err := v.GetPath("a.txt", insideFile); err == nil {
		t.Fatal("GetPath into .seavault must be rejected")
	}
	if _, err := v.ExportPath(context.Background(), ".", insideDir, ExportOptions{}); err == nil {
		t.Fatal("ExportPath into .seavault must be rejected")
	}
	if _, err := v.ExportPath(context.Background(), ".", insideDir, ExportOptions{Zip: true}); err == nil {
		t.Fatal("zip ExportPath into .seavault must be rejected")
	}

	// Destinations outside the vault metadata directory must still work.
	if err := v.GetPath("a.txt", filepath.Join(t.TempDir(), "get", "a.txt")); err != nil {
		t.Fatalf("GetPath outside the vault should succeed: %v", err)
	}
	if _, err := v.ExportPath(context.Background(), ".", filepath.Join(t.TempDir(), "exp"), ExportOptions{}); err != nil {
		t.Fatalf("ExportPath outside the vault should succeed: %v", err)
	}
}
