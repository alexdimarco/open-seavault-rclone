// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
)

// the wrap-entry read leg. Open (and the
// underlying unlockWith) must try each WrapEntries entry filtered by type, and
// fall back to the legacy top-level WrappedKeys/WrapNonce only when WrapEntries
// is empty. A password opens via its entry, a recovery secret via its entry, a
// wrong secret matches neither (one generic error, no per-entry oracle), and
// every legacy single-wrap vault still opens.

const (
	r3Password = "correct horse battery staple"
	r3Recovery = "recovery alpha bravo charlie delta echo foxtrot"
)

func keysEqual(a, b Keys) bool {
	return bytes.Equal(a.MasterKey, b.MasterKey) && bytes.Equal(a.IndexKey, b.IndexKey)
}

func copyKeys(k Keys) Keys {
	return Keys{
		MasterKey: append([]byte(nil), k.MasterKey...),
		IndexKey:  append([]byte(nil), k.IndexKey...),
	}
}

// fastKDFWithSalt is FastKDFConfigForTests with a fresh random salt, so each
// hand-built wrap entry has its own salt like a real one.
func fastKDFWithSalt(t *testing.T) KDFConfig {
	t.Helper()
	salt, err := randomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	k := FastKDFConfigForTests()
	k.Salt = base64.StdEncoding.EncodeToString(salt)
	return k
}

// bareEntry wraps keys under secret with the legacy bare AAD, exactly as the
// existing wrapKeys primitive does (the construction the slice-2 task calls for).
func bareEntry(t *testing.T, secret string, keys Keys, id, typ string) WrapEntry {
	t.Helper()
	kdf := fastKDFWithSalt(t)
	nonce, ct, err := wrapKeys(secret, kdf, keys)
	if err != nil {
		t.Fatal(err)
	}
	return WrapEntry{ID: id, Type: typ, KDF: kdf, Nonce: nonce, CT: ct}
}

// versionedEntry wraps keys under secret with a versioned AAD: the AAD
// scheme tag plus the bound config Version, computed through the SAME
// wrapEntryAAD the reader uses (so the test cannot drift from the implementation).
func versionedEntry(t *testing.T, secret string, keys Keys, id, typ, aadTag string, version int) WrapEntry {
	t.Helper()
	kdf := fastKDFWithSalt(t)
	wrapKey, err := deriveWrapKey(secret, kdf)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newAESGCM(wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		t.Fatal(err)
	}
	e := WrapEntry{ID: id, Type: typ, KDF: kdf, Nonce: base64.StdEncoding.EncodeToString(nonce), AAD: aadTag}
	bundle := append(append([]byte{}, keys.MasterKey...), keys.IndexKey...)
	ct := aead.Seal(nil, nonce, bundle, wrapEntryAAD(e, version))
	e.CT = base64.StdEncoding.EncodeToString(ct)
	return e
}

// corruptLegacyWrap replaces the top-level wrap with valid-base64 garbage, so a
// read that (wrongly) fell back to it while WrapEntries is populated would fail —
// making the entries provably the thing that opened the vault.
func corruptLegacyWrap(c *VaultConfig) {
	c.WrappedKeys = base64.StdEncoding.EncodeToString([]byte("garbage-not-the-real-wrapped-key-bundle"))
	c.WrapNonce = base64.StdEncoding.EncodeToString([]byte("bogus-nonce!"))
}

// createEntryFixture builds a v2 vault, captures its real master||index bundle,
// then rewrites vault.json to carry a password AND a recovery WrapEntry over that
// same bundle, with the legacy top-level wrap corrupted.
func createEntryFixture(t *testing.T) (root string, keys Keys) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, r3Password)
	v0, err := Open(root, r3Password)
	if err != nil {
		t.Fatal(err)
	}
	keys = copyKeys(v0.keys)
	pwEntry := bareEntry(t, r3Password, keys, "aaaa0001", WrapTypePassword)
	recEntry := bareEntry(t, r3Recovery, keys, "bbbb0002", WrapTypeRecovery)
	editConfig(t, root, func(c *VaultConfig) {
		c.WrapEntries = []WrapEntry{pwEntry, recEntry}
		corruptLegacyWrap(c)
	})
	return root, keys
}

func TestWrapEntryReadLeg(t *testing.T) {
	t.Run("password opens via its entry", func(t *testing.T) {
		root, keys := createEntryFixture(t)
		v, err := Open(root, r3Password)
		if err != nil {
			t.Fatalf("password must open via its WrapEntry (legacy wrap is corrupt): %v", err)
		}
		if v == nil {
			t.Fatal("Open returned a nil vault with no error")
		}
		if !keysEqual(v.keys, keys) {
			t.Fatal("Open unwrapped a different master||index than the entry was built over")
		}
	})

	t.Run("recovery opens via its entry", func(t *testing.T) {
		root, keys := createEntryFixture(t)
		cfg, err := ReadConfig(root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := cfg.unlockWith(r3Recovery, WrapTypeRecovery)
		if err != nil {
			t.Fatalf("recovery secret must open its WrapEntry: %v", err)
		}
		if !keysEqual(got, keys) {
			t.Fatal("recovery unwrap returned a different master||index than the entry was built over")
		}
		// The type filter holds: the recovery secret does NOT unlock a
		// password-typed entry, and the password does NOT unlock a recovery-typed
		// entry — each returns the one generic error, no cross-type oracle.
		if _, err := cfg.unlockWith(r3Recovery, WrapTypePassword); !errors.Is(err, errWrongSecret) {
			t.Fatalf("recovery secret must not unlock a password-typed entry, got %v", err)
		}
		if _, err := cfg.unlockWith(r3Password, WrapTypeRecovery); !errors.Is(err, errWrongSecret) {
			t.Fatalf("password must not unlock a recovery-typed entry, got %v", err)
		}
	})

	t.Run("wrong secret matches neither entry", func(t *testing.T) {
		root, _ := createEntryFixture(t)
		cfg, err := ReadConfig(root)
		if err != nil {
			t.Fatal(err)
		}
		const wrong = "definitely not the secret"
		if _, err := cfg.unlockWith(wrong, WrapTypePassword); !errors.Is(err, errWrongSecret) {
			t.Fatalf("a wrong password must return the generic errWrongSecret, got %v", err)
		}
		if _, err := cfg.unlockWith(wrong, WrapTypeRecovery); !errors.Is(err, errWrongSecret) {
			t.Fatalf("a wrong recovery secret must return the generic errWrongSecret, got %v", err)
		}
		if _, err := Open(root, wrong); !errors.Is(err, errWrongSecret) {
			t.Fatalf("Open with a wrong secret must return the generic errWrongSecret, got %v", err)
		}
	})

	t.Run("legacy single-wrap vault still opens", func(t *testing.T) {
		// No WrapEntries: the legacy top-level wrap IS the implicit password entry
		// (I1). This is a fresh createTestVault, untouched.
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r3Password)
		v, err := Open(root, r3Password)
		if err != nil {
			t.Fatalf("a legacy single-wrap v2 vault must open unchanged: %v", err)
		}
		if v == nil {
			t.Fatal("Open returned a nil vault with no error")
		}
		if _, err := Open(root, "nope"); !errors.Is(err, errWrongSecret) {
			t.Fatalf("a wrong password on a legacy vault must still return the generic error, got %v", err)
		}
	})

	t.Run("versioned-AAD entry opens at its bound version and breaks on downgrade", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r3Password)
		v0, err := Open(root, r3Password)
		if err != nil {
			t.Fatal(err)
		}
		keys := copyKeys(v0.keys)
		// A password entry whose AAD binds Version 2.
		ve := versionedEntry(t, r3Password, keys, "cccc0003", WrapTypePassword, "seavault-wrap-v3", 2)
		editConfig(t, root, func(c *VaultConfig) {
			c.Version = 2
			c.WrapEntries = []WrapEntry{ve}
			corruptLegacyWrap(c)
		})
		cfg, err := ReadConfig(root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := cfg.unlockWith(r3Password, WrapTypePassword)
		if err != nil {
			t.Fatalf("a versioned-AAD entry must open at its bound Version: %v", err)
		}
		if !keysEqual(got, keys) {
			t.Fatal("versioned-AAD unwrap returned the wrong master||index")
		}
		// A Version downgrade (or forward-forge) recomputes a different AAD and the
		// unwrap fails independent of any config MAC — with the same generic
		// error, no oracle.
		cfg.Version = 3
		if _, err := cfg.unlockWith(r3Password, WrapTypePassword); !errors.Is(err, errWrongSecret) {
			t.Fatalf("a Version mismatch must break the versioned-AAD unwrap, got %v", err)
		}
	})
}
