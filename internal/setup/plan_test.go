// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// T4 (I-S2): --expert KDF choices are validated through the SAME floor cmdInit
// enforces. A config below the floor is rejected with the exact error init
// would raise (wrapped in ErrKDFBelowFloor); a config at the floor is accepted.
func TestExpertKDFFloor(t *testing.T) {
	rows := []struct {
		name    string
		kdf     vault.KDFConfig
		wantErr bool
	}{
		{"argon2id below floor", vault.KDFConfig{Algorithm: "ARGON2ID", Time: 1, MemoryKiB: 8192, Parallelism: 1}, true},
		{"argon2id at floor", vault.KDFConfig{Algorithm: "ARGON2ID", Time: 2, MemoryKiB: 19456, Parallelism: 1}, false},
		{"argon2id high-memory floor", vault.KDFConfig{Algorithm: "ARGON2ID", Time: 1, MemoryKiB: 65536, Parallelism: 1}, false},
		{"argon2id defaults", vault.DefaultKDFConfig(), false},
		{"scrypt below floor", vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: 16384, ScryptR: 8, ScryptP: 1}, true},
		{"scrypt at floor", vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: 32768, ScryptR: 8, ScryptP: 1}, false},
		{"pbkdf2 below floor", vault.KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: 100000}, true},
		{"pbkdf2 at floor", vault.KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: 600000}, false},
	}
	if len(rows) == 0 {
		t.Fatal("KDF table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			p := Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), Expert: &ExpertOptions{KDF: row.kdf}}
			err := p.Validate()
			if row.wantErr {
				if !errors.Is(err, ErrKDFBelowFloor) {
					t.Fatalf("below-floor KDF must return ErrKDFBelowFloor; got %v", err)
				}
				// Prove it is the SAME check init runs, not a copy: the wrapped
				// message is exactly vault.ValidateKDFStrength's on the normalized
				// config.
				norm, nerr := vault.NormalizeKDFConfig(row.kdf, true)
				if nerr != nil {
					t.Fatalf("normalize: %v", nerr)
				}
				want := vault.ValidateKDFStrength(norm)
				if want == nil {
					t.Fatal("test row marked below-floor but ValidateKDFStrength accepts it")
				}
				if !strings.Contains(err.Error(), want.Error()) {
					t.Fatalf("Validate error must carry init's floor message %q; got %q", want.Error(), err.Error())
				}
			} else if err != nil {
				t.Fatalf("at-floor KDF must be accepted; got %v", err)
			}
		})
	}
}

// Validate rejects an invalid rclone remote name so a name can never smuggle a
// path or flag onward, and accepts a conservative one.
func TestValidateRemoteName(t *testing.T) {
	rows := []struct {
		name    string
		remote  string
		wantErr bool
	}{
		{"plain", "myremote", false},
		{"dotted", "my.remote-1_v2", false},
		{"empty", "", true},
		{"space", "my remote", true},
		{"path separator", "my/remote", true},
		{"colon", "remote:path", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			p := Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), Cloud: RcloneRemote{Name: row.remote, RemotePath: "bucket:/x"}}
			err := p.Validate()
			if row.wantErr {
				if !errors.Is(err, ErrRemoteNameInvalid) {
					t.Fatalf("remote name %q must be rejected with ErrRemoteNameInvalid; got %v", row.remote, err)
				}
			} else if err != nil {
				t.Fatalf("remote name %q must be accepted; got %v", row.remote, err)
			}
		})
	}
}
