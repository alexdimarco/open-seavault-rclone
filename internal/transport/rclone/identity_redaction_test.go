// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// The identity guard reads the remote vault.json through CommandRunner.Run,
// which ALWAYS applies Redact (RedactText) to the output — and RedactText cuts
// everything after the first ':' on any line mentioning "key". This proves the
// non-secret vaultId still survives that redaction on a REAL, MarshalIndent'd
// vault.json (the scriptedRunner fixtures in identity_test.go bypass Redact and
// use single-line JSON, so they would not catch a regression here).
func TestParseVaultIDSurvivesProductionRedaction(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := vault.CreateWithOptions(root, "password", vault.CreateOptions{KDF: vault.FastKDFConfigForTests()}); err != nil {
		t.Fatal(err)
	}
	cfg, err := vault.ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(cfg.VaultID) == "" {
		t.Fatal("precondition: the created vault must have a vaultId")
	}

	name, _, err := vault.ResolveMetaDir(root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, name, vault.ConfigFileName))
	if err != nil {
		t.Fatal(err)
	}

	redacted := Redact(string(raw))

	// Precondition: redaction must actually be biting the wrapped-key material,
	// otherwise this test would prove nothing.
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Fatalf("precondition: redaction did not fire on the real vault.json:\n%s", redacted)
	}

	id, ok := parseVaultID(redacted)
	if !ok {
		t.Fatalf("vaultId must survive redaction of a real vault.json:\n%s", redacted)
	}
	if id != cfg.VaultID {
		t.Fatalf("parsed vaultId %q != actual %q", id, cfg.VaultID)
	}
}
