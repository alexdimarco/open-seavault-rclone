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
)

// TestOpenMinReaderForwardFence is. The forward
// fence must refuse a vault whose MinReader exceeds SupportedFormat BEFORE any
// unwrap, with the typed hedged ErrFormatTooNew; a MinReader at or below
// SupportedFormat opens; a Version this build newly tolerates (3) opens; and an
// unparseable vault.json is a HARD error, never silently treated as version 0.
func TestOpenMinReaderForwardFence(t *testing.T) {
	const pw = "correct horse battery staple"

	t.Run("minReader above SupportedFormat is fenced", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, pw)
		// Version stays 2 (grace release); only MinReader is raised past the
		// ceiling — exactly the forged/forward case the fence must catch.
		editConfig(t, root, func(c *VaultConfig) { c.MinReader = SupportedFormat + 1 })
		v, err := Open(root, pw)
		if v != nil {
			t.Fatalf("Open must not return a vault when the format is too new; got %#v", v)
		}
		if !errors.Is(err, ErrFormatTooNew) {
			t.Fatalf("Open with minReader=%d must return ErrFormatTooNew, got %v", SupportedFormat+1, err)
		}
		// The message is HEDGED: it must name the tamper possibility, not
		// merely tell the operator to upgrade.
		if !strings.Contains(err.Error(), "may have been modified") {
			t.Fatalf("ErrFormatTooNew message must be hedged about tampering, got %q", err.Error())
		}
	})

	t.Run("minReader at or below SupportedFormat opens", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, pw)
		editConfig(t, root, func(c *VaultConfig) { c.MinReader = SupportedFormat })
		v, err := Open(root, pw)
		if err != nil {
			t.Fatalf("Open with minReader=%d (== SupportedFormat) must succeed, got %v", SupportedFormat, err)
		}
		if v == nil {
			t.Fatal("Open returned a nil vault with no error")
		}
	})

	t.Run("version 3 is tolerated on read", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, pw)
		// ReadConfig/Open accept versions 1, 2 AND 3. A hand-set
		// Version=3 with no MinReader must open, not hit "unsupported vault version".
		editConfig(t, root, func(c *VaultConfig) { c.Version = 3 })
		v, err := Open(root, pw)
		if err != nil {
			t.Fatalf("Open of a version-3 config must succeed (forward tolerance), got %v", err)
		}
		if v == nil {
			t.Fatal("Open returned a nil vault with no error")
		}
	})

	t.Run("unparseable vault.json is a hard error, never version 0", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, pw)
		cfgPath := filepath.Join(metaRootOf(t, root), ConfigFileName)
		if err := os.WriteFile(cfgPath, []byte("{ this is not valid json"), 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := Open(root, pw)
		if err == nil {
			t.Fatal("Open of an unparseable vault.json must return a hard error, not succeed")
		}
		if v != nil {
			t.Fatalf("Open of an unparseable vault.json must not return a vault; got %#v", v)
		}
		// It must never be laundered into "unsupported vault version 0": that would
		// mean the parse silently produced a zero-valued config.
		if strings.Contains(err.Error(), "version 0") {
			t.Fatalf("unparseable vault.json must not be treated as version 0, got %q", err.Error())
		}
	})
}

// legacyVaultConfig mirrors the 0.16 VaultConfig shape — the KNOWN fields only,
// with none of the format-v3 additions — so that unmarshalling an A2 config into
// it reproduces exactly what a 0.16 json.Unmarshal does: drop the unknown
// (additive) fields and keep the rest. It reuses the unchanged KDF/Crypto/Chunk
// types.
type legacyVaultConfig struct {
	Version     int          `json:"version"`
	VaultID     string       `json:"vaultId,omitempty"`
	CreatedAt   string       `json:"createdAt"`
	KDF         KDFConfig    `json:"kdf"`
	Crypto      CryptoConfig `json:"crypto"`
	Chunk       ChunkParams  `json:"chunk"`
	WrappedKeys string       `json:"wrappedKeys"`
	WrapNonce   string       `json:"wrapNonce"`
}

// TestConfigAdditiveFieldsRoundTrip proves the format-v3 additions are additive:
// on a legacy-shaped config they omit entirely (byte-identical vault.json for a
// 0.16 peer), and an A2 config that DOES set them survives a 0.16-style
// Unmarshal with the known fields intact and no error.
func TestConfigAdditiveFieldsRoundTrip(t *testing.T) {
	// 1. A config with the new fields left zero must marshal WITHOUT their keys,
	//  so a grace-release vault.json is byte-for-byte what 0.16 would write.
	legacyShaped := VaultConfig{
		Version:     2,
		VaultID:     "abc123",
		CreatedAt:   "2026-09-04T00:00:00Z",
		WrappedKeys: "d3adb33f",
		WrapNonce:   "n0nc3",
	}
	legacyJSON, err := json.Marshal(legacyShaped)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"minReader", "formatEpoch", "configTag", "wrapEntries"} {
		if strings.Contains(string(legacyJSON), key) {
			t.Fatalf("a config with zero-valued format-v3 fields must omit %q (omitempty); got %s", key, legacyJSON)
		}
	}

	// 2. An A2 config that SETS the new fields must still unmarshal into a
	//  0.16-shaped struct with no error and the known fields intact.
	a2 := VaultConfig{
		Version:     2,
		MinReader:   3,
		FormatEpoch: 7,
		VaultID:     "vault-42",
		CreatedAt:   "2026-09-04T01:02:03Z",
		KDF:         FastKDFConfigForTests(),
		Crypto:      CryptoConfig{KeyWrap: "AES-256-GCM"},
		Chunk:       testParams(),
		WrappedKeys: "cafef00d",
		WrapNonce:   "nonce-legacy",
		WrapEntries: []WrapEntry{{ID: "0011aabb", Type: "password", KDF: FastKDFConfigForTests(), Nonce: "wn", CT: "wct"}},
		ConfigTag:   "dGFn",
	}
	a2JSON, err := json.Marshal(a2)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the A2 marshal DID include the new fields (otherwise the drop below
	// would be vacuous).
	if !strings.Contains(string(a2JSON), "wrapEntries") || !strings.Contains(string(a2JSON), "minReader") {
		t.Fatalf("an A2 config with fields set must serialize them; got %s", a2JSON)
	}
	var legacy legacyVaultConfig
	if err := json.Unmarshal(a2JSON, &legacy); err != nil {
		t.Fatalf("a 0.16-style Unmarshal of an A2 config must not error, got %v", err)
	}
	if legacy.Version != a2.Version {
		t.Fatalf("Version not preserved: got %d want %d", legacy.Version, a2.Version)
	}
	if legacy.VaultID != a2.VaultID {
		t.Fatalf("VaultID not preserved: got %q want %q", legacy.VaultID, a2.VaultID)
	}
	if legacy.WrappedKeys != a2.WrappedKeys {
		t.Fatalf("WrappedKeys not preserved: got %q want %q", legacy.WrappedKeys, a2.WrappedKeys)
	}
	if legacy.WrapNonce != a2.WrapNonce {
		t.Fatalf("WrapNonce not preserved: got %q want %q", legacy.WrapNonce, a2.WrapNonce)
	}
	if legacy.CreatedAt != a2.CreatedAt {
		t.Fatalf("CreatedAt not preserved: got %q want %q", legacy.CreatedAt, a2.CreatedAt)
	}
}
