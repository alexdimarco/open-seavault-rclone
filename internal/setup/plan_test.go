// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// profile-collision-orphan: Plan.Validate catches a same-name-different-path
// profile collision with ZERO side effects, so /api/setup/validate refuses a
// plan that Execute would otherwise commit-then-fail on. A same-name profile at
// the SAME path is not a collision, and a syntactically invalid profile name is
// rejected up front.
func TestPlanValidateProfileCollision(t *testing.T) {
	orig := profileLookup
	defer func() { profileLookup = orig }()

	vaultDir := filepath.Join(t.TempDir(), "MyVault")

	// A profile of the resolved name (basename "MyVault") points at a DIFFERENT
	// vault: a collision, caught side-effect-free.
	profileLookup = func(string) (string, bool, error) { return "/somewhere/else", true, nil }
	if err := (Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}).Validate(); !errors.Is(err, ErrProfileNameInUse) {
		t.Fatalf("Validate must catch the collision with ErrProfileNameInUse; got %v", err)
	}
	if _, statErr := os.Stat(vaultDir); !os.IsNotExist(statErr) {
		t.Fatalf("Validate must create nothing; stat err=%v", statErr)
	}

	// A same-name profile at the SAME path is idempotent, not a collision.
	profileLookup = func(string) (string, bool, error) { return vaultDir, true, nil }
	if err := (Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}).Validate(); err != nil {
		t.Fatalf("a same-name profile at the same path must not be a collision; got %v", err)
	}

	// A syntactically invalid profile name is rejected before any lookup.
	profileLookup = func(string) (string, bool, error) {
		t.Fatal("profileLookup must not run for a name that fails syntactic validation")
		return "", false, nil
	}
	if err := (Plan{VaultDir: vaultDir, ProfileName: "a/b", Cloud: LocalOnly{}}).Validate(); err == nil {
		t.Fatal("a profile name containing a path separator must be rejected")
	}
}

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
