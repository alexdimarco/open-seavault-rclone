// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
)

// vault.json is read BEFORE its integrity tag can be checked (the tag is keyed by
// the master key, which needs the KDF), so every KDF parameter in it is attacker
// controlled at unlock time. Two consequences are pinned here.
//
// 1. An out-of-range cost must return a typed error, never crash the process
//    (argon2 narrows time to uint32: 1<<32 becomes 0 and panics) or exhaust memory.
// 2. A rewrap (password change, recovery redeem) must not INHERIT a weak stored
//    cost: a server that edits the KDF to PBKDF2 x1 would otherwise get the user's
//    next password wrapped at that cost and crack it offline.

func TestDeriveWrapKeyRejectsOutOfRangeParams(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	rows := []struct {
		name string
		cfg  KDFConfig
	}{
		{"argon2 time wraps to 0 when narrowed to uint32", KDFConfig{Algorithm: "ARGON2ID", Time: 1 << 32, MemoryKiB: 65536, Parallelism: 1, Salt: salt}},
		{"argon2 time absurdly large", KDFConfig{Algorithm: "ARGON2ID", Time: 1 << 30, MemoryKiB: 65536, Parallelism: 1, Salt: salt}},
		{"argon2 memory in the TiB", KDFConfig{Algorithm: "ARGON2ID", Time: 3, MemoryKiB: 1 << 32, Parallelism: 1, Salt: salt}},
		{"scrypt N in the billions", KDFConfig{Algorithm: "SCRYPT", ScryptN: 1 << 30, ScryptR: 8, ScryptP: 1, Salt: salt}},
		{"scrypt r large", KDFConfig{Algorithm: "SCRYPT", ScryptN: 32768, ScryptR: 1 << 20, ScryptP: 1, Salt: salt}},
		{"pbkdf2 iterations in the trillions", KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: 1 << 40, Salt: salt}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("deriveWrapKey panicked on attacker-controlled parameters: %v", p)
				}
			}()
			_, err := deriveWrapKey("password", r.cfg)
			if !errors.Is(err, ErrKDFParamsOutOfRange) {
				t.Fatalf("want ErrKDFParamsOutOfRange, got %v", err)
			}
		})
	}

	// Control: a legitimate (test-fast) config must still derive a key.
	fast := FastKDFConfigForTests()
	fast.Salt = salt
	if k, err := deriveWrapKey("password", fast); err != nil || len(k) != keySize {
		t.Fatalf("a sane config must still work: key=%d err=%v", len(k), err)
	}
}

func TestRewrapDoesNotInheritWeakKDF(t *testing.T) {
	isolateAppHome(t)
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, rotOldPassword) // FastKDFConfigForTests: scrypt N=16, far below the floor
	weak, err := NormalizeKDFConfig(FastKDFConfigForTests(), true)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateKDFStrength(weak) == nil {
		t.Fatal("test premise broken: the fast test config is supposed to be below the floor")
	}

	v, err := Open(root, rotOldPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ChangePassword(rotNewPassword); err != nil {
		t.Fatal(err)
	}

	cfg, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string, k KDFConfig) {
		t.Helper()
		n, nerr := NormalizeKDFConfig(k, false)
		if nerr != nil {
			t.Fatalf("%s: %v", label, nerr)
		}
		if serr := ValidateKDFStrength(n); serr != nil {
			t.Errorf("%s inherited a weak KDF after a password change: %v", label, serr)
		}
	}
	check("legacy top-level wrap", cfg.KDF)
	sawPassword := false
	for _, e := range cfg.WrapEntries {
		if e.Type == WrapTypePassword {
			sawPassword = true
			check("password wrap entry", e.KDF)
		}
	}
	if !sawPassword {
		t.Fatal("no password wrap entry found; the check would be vacuous")
	}

	// The strengthened wrap must actually unlock with the new password.
	if _, err := Open(root, rotNewPassword); err != nil {
		t.Fatalf("new password does not open the vault: %v", err)
	}

	// A recovery entry is built from the same base and gets the same floor.
	entry, err := makeRecoveryEntry("recovery-secret", weak, v.keys)
	if err != nil {
		t.Fatal(err)
	}
	check("recovery wrap entry", entry.KDF)
}
