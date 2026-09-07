// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// Typed plan/execute errors (design §3.1). Callers branch on these with
// errors.Is to render the right remedy; the wrapped message names the specifics.
var (
	// ErrVaultDirNotEmpty means the target directory already holds a vault
	// (a vault.json is present). The remedy is "open it instead", never a
	// second create over the existing one (design §3.1/§6, C8).
	ErrVaultDirNotEmpty = errors.New("a vault already exists in that directory")
	// ErrVaultDirLeftovers means the target directory is non-empty but holds no
	// vault.json: leftovers from an interrupted setup. The remedy is to remove
	// them and retry (design §3.1, C8, T11). It is distinct from
	// ErrVaultDirNotEmpty so the wizard offers remove-and-retry, not "open it".
	ErrVaultDirLeftovers = errors.New("the target directory has leftover files from an interrupted setup")
	// ErrKDFBelowFloor means an --expert KDF choice is weaker than the floor
	// cmdInit enforces. Validate runs the SAME check (vault.ValidateKDFStrength)
	// so the wizard can never create a vault the init command would reject
	// (design I-S2, T4).
	ErrKDFBelowFloor = errors.New("KDF parameters are below the strength floor")
	// ErrRemoteNameInvalid means the chosen rclone remote name is empty or holds
	// characters an rclone remote name may not (design §3.1 Validate).
	ErrRemoteNameInvalid = errors.New("rclone remote name is invalid")
	// ErrProfileNameInUse means a local profile of the chosen name already points
	// at a DIFFERENT vault path; the wizard offers a suffixed name and never
	// silently repoints the existing profile (design §3.1, C3, T12).
	ErrProfileNameInUse = errors.New("a profile with that name already points at a different vault")
)

// CloudChoice is the sealed sum of how a vault reaches its cloud (design §3.1):
// SyncedFolder (no transport — a consumer sync client moves the ciphertext),
// RcloneRemote (an existing rclone remote), or LocalOnly.
type CloudChoice interface{ isCloudChoice() }

// SyncedFolder is the no-transport outcome: the vault lives inside a folder a
// sync client already watches. Provider may be "" when the user chose the manual
// "my own sync client already watches this folder" option (C5).
type SyncedFolder struct{ Provider Provider }

// RcloneRemote is an existing rclone remote (configured in rclone or imported
// with `seavault remote config import`). U1 does not drive `rclone config`
// (C1); the remote must already exist.
type RcloneRemote struct {
	Name       string
	RemotePath string
}

// LocalOnly is the local / external-drive-only outcome: no cloud sync.
type LocalOnly struct{}

func (SyncedFolder) isCloudChoice() {}
func (RcloneRemote) isCloudChoice() {}
func (LocalOnly) isCloudChoice()    {}

// ExpertOptions carries the --expert knobs (design §3.1). A nil *ExpertOptions
// on a Plan means "use the defaults" (current argon2id defaults + default chunk
// params); a non-nil one is validated through the SAME floor cmdInit enforces.
type ExpertOptions struct {
	KDF   vault.KDFConfig
	Chunk vault.ChunkParams
}

// Plan is the UI-agnostic description of the vault to build (design §3.1). The
// CLI wizard and the GUI stepper both assemble a Plan and hand it to Execute.
type Plan struct {
	VaultDir     string
	ProfileName  string // default: basename of VaultDir (resolved by ResolvedProfileName)
	SaveKeychain bool
	Cloud        CloudChoice
	Expert       *ExpertOptions
}

// ResolvedProfileName returns the profile name Execute will use: the explicit
// ProfileName, or the basename of VaultDir when it is empty (design §3.1).
func (p Plan) ResolvedProfileName() string {
	name := strings.TrimSpace(p.ProfileName)
	if name != "" {
		return name
	}
	return filepath.Base(filepath.Clean(p.VaultDir))
}

// createOptions resolves the vault.CreateOptions this plan builds with: the
// expert KDF+chunk when set, otherwise the defaults. The KDF is normalized (so
// an algorithm-only expert choice gets its defaults filled) exactly as cmdInit
// does before validating the floor.
func (p Plan) createOptions() (vault.CreateOptions, error) {
	kdf := vault.DefaultKDFConfig()
	chunk := vault.DefaultChunkParams()
	if p.Expert != nil {
		kdf = p.Expert.KDF
		if p.Expert.Chunk != (vault.ChunkParams{}) {
			chunk = p.Expert.Chunk
		}
	}
	normalized, err := vault.NormalizeKDFConfig(kdf, true)
	if err != nil {
		return vault.CreateOptions{}, err
	}
	return vault.CreateOptions{Chunk: chunk, KDF: normalized}, nil
}

// Validate checks the plan for side-effect-free problems before Execute runs
// (design §3.1). It returns the typed errors above so the GUI /api/setup/validate
// endpoint and the CLI can pre-warn without touching disk beyond existence
// checks on the target directory. It never mutates anything.
func (p Plan) Validate() error {
	if strings.TrimSpace(p.VaultDir) == "" {
		return errors.New("vault directory is required")
	}
	if err := vaultDirState(filepath.Clean(p.VaultDir)); err != nil {
		return err
	}

	// Expert KDF is validated through the SAME floor cmdInit uses: normalize
	// first (so an algorithm-only choice gets its defaults), then run
	// vault.ValidateKDFStrength. The check is CALLED, never copied, so the
	// wizard's floor can never drift from init's (I-S2, T4).
	if p.Expert != nil {
		normalized, err := vault.NormalizeKDFConfig(p.Expert.KDF, true)
		if err != nil {
			return err
		}
		if err := vault.ValidateKDFStrength(normalized); err != nil {
			return fmt.Errorf("%w: %v", ErrKDFBelowFloor, err)
		}
		if p.Expert.Chunk != (vault.ChunkParams{}) {
			if err := p.Expert.Chunk.Validate(); err != nil {
				return err
			}
		}
	}

	if r, ok := p.Cloud.(RcloneRemote); ok {
		if err := validateRemoteName(r.Name); err != nil {
			return err
		}
	}
	return nil
}

// vaultDirState classifies the target directory: nil when it is absent or empty
// (safe to create), ErrVaultDirNotEmpty when a vault.json is present (an
// existing vault), ErrVaultDirLeftovers when it is non-empty without a
// vault.json (interrupted-setup leftovers). Shared by Validate and Execute so
// both agree (C8).
func vaultDirState(vaultDir string) error {
	if _, exists, err := vault.ResolveMetaDir(vaultDir); err == nil && exists {
		return fmt.Errorf("%w: %s", ErrVaultDirNotEmpty, vaultDir)
	} else if err != nil && !errors.Is(err, vault.ErrAmbiguousMetadataDir) {
		// A stat error other than the ambiguous-layout sentinel is a real
		// problem (e.g. a parent component that is a file); surface it.
		return err
	} else if errors.Is(err, vault.ErrAmbiguousMetadataDir) {
		// Both metadata names hold a vault.json: an existing (ambiguous) vault.
		return fmt.Errorf("%w: %s", ErrVaultDirNotEmpty, vaultDir)
	}
	nonEmpty, err := dirNonEmpty(vaultDir)
	if err != nil {
		return err
	}
	if nonEmpty {
		return fmt.Errorf("%w: %s", ErrVaultDirLeftovers, vaultDir)
	}
	return nil
}

func validateRemoteName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrRemoteNameInvalid)
	}
	// rclone remote names are conservative: letters, digits, underscore,
	// hyphen, dot. Reject anything else (path separators, spaces, colons) so a
	// name can never smuggle a path or flag onward.
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return fmt.Errorf("%w: %q contains an unsupported character", ErrRemoteNameInvalid, name)
		}
	}
	return nil
}
