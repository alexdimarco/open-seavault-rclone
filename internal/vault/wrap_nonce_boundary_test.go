// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
)

// A crafted vault.json with a wrong-length wrap nonce must be rejected as a
// generic unlock failure, never crash the process: cipher.GCM.Open PANICS on a
// wrong-length nonce, so the unwrap decode boundary guards it (crypto invariant:
// decode boundaries return typed errors, never crash). Covers both the legacy
// top-level wrap and a WrapEntry nonce.
func TestWrapNonceLengthBoundary(t *testing.T) {
	isolateAppHome(t)

	t.Run("legacy top-level wrap nonce truncated", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r3Password)
		// A 5-byte nonce is not a valid GCM nonce length (12); before the guard this
		// panicked inside Open.
		editConfig(t, root, func(c *VaultConfig) {
			c.WrapNonce = base64.StdEncoding.EncodeToString([]byte("short"))
		})
		if _, err := Open(root, r3Password); !errors.Is(err, errWrongSecret) {
			t.Fatalf("a wrong-length legacy wrap nonce must yield the generic unlock failure, got %v", err)
		}
	})

	t.Run("wrap-entry nonce oversized", func(t *testing.T) {
		root, keys := createEntryFixture(t)
		editConfig(t, root, func(c *VaultConfig) {
			// Give the password entry a 20-byte (wrong) nonce.
			c.WrapEntries[0].Nonce = base64.StdEncoding.EncodeToString(make([]byte, 20))
		})
		cfg, err := ReadConfig(root)
		if err != nil {
			t.Fatal(err)
		}
		_ = keys
		if _, err := cfg.unlockWith(r3Password, WrapTypePassword); !errors.Is(err, errWrongSecret) {
			t.Fatalf("a wrong-length wrap-entry nonce must yield the generic unlock failure, got %v", err)
		}
	})
}
