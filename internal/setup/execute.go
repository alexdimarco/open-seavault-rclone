// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	localtransport "github.com/alexdimarco/open-seavault-rclone/internal/transport/local"
	rclonetransport "github.com/alexdimarco/open-seavault-rclone/internal/transport/rclone"

	"github.com/alexdimarco/open-seavault-rclone/internal/keychain"
	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/transport"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// Step names Execute records in Result.FailedStep so the caller can render the
// step-appropriate remedy (design §3.1, C9).
const (
	StepCreate       = "create"
	StepKeychain     = "keychain"
	StepProfile      = "profile"
	StepRcloneEnsure = "rclone-ensure"
	StepRemoteAdd    = "remote-add"
	StepRemoteTest   = "remote-test"
)

// Deps is the seam for the privilege boundaries and side effects Execute drives
// (design §3.1). It is the ONLY thing mocked in tests: the real defaults wrap
// the existing vault-create path, keychain.Set, profile.Add/Resolve, the new
// RcloneEnsure, and the existing remote add/test. A test builds it from
// DefaultDeps and overrides just the seam it is exercising (a failing keychain,
// a failing RcloneEnsure, a colliding profile) or injects a fault at
// CreateVault.
type Deps struct {
	// CreateVault builds a vault at dir with the given options. The real default
	// is vault.CreateWithOptions (the same path cmdInit uses). Execute always
	// calls it on a sibling temp directory, never the final path.
	CreateVault func(dir, password string, opts vault.CreateOptions) error
	// KeychainSet stores the vault password under vaultID. The real default is
	// keychain.Set. A failure is a warning, never a hard failure (I-S4).
	KeychainSet func(vaultID, password string) error
	// ProfileLookup reports the vault path an existing profile of this name
	// points at. The real default wraps profile.Resolve. Execute uses it to
	// detect a same-name collision BEFORE ProfileAdd (C3).
	ProfileLookup func(name string) (path string, found bool, err error)
	// ProfileAdd registers name -> vaultDir. The real default wraps profile.Add.
	ProfileAdd func(name, vaultDir string) error
	// RcloneEnsure installs-if-missing and verifies the rclone runtime, with
	// consent already bound by the caller (interactive prompt, or --allow-download
	// for a preset). The real default denies the network download; the CLI/GUI
	// override it with a consent-carrying wrapper over the package RcloneEnsure.
	RcloneEnsure func() error
	// RemoteAdd binds vaultDir to an existing rclone remote at remotePath under a
	// seavault remote profile named name. The real default wraps remotes.Add.
	RemoteAdd func(name, vaultDir, remotePath string) error
	// RemoteTest verifies the named remote reaches its backend. The real default
	// runs the transport's Test. The wizard never reports a remote working unless
	// this passes (C1).
	RemoteTest func(name string) error
}

// Result is what Execute produces: what was created and any notes the caller
// surfaces (design §3.1). It carries NO secret — never the password, never a
// recovery phrase (I-S1). RecoveryNote is set by the caller's interactive
// recovery step, not by Execute (§3.1).
type Result struct {
	VaultID       string
	VaultDir      string
	ProfileName   string
	KeychainSaved bool
	KeychainNote  string
	// KeychainErrDetail carries the RAW underlying keychain error (e.g. the
	// secret-tool exec message) when a keychain store failed. It is NEVER shown
	// in the default summary — KeychainNote is the plain, user-facing one-liner
	// (CLI-1). A CLI caller prints this detail only under --debug; it carries no
	// secret (a keychain backend error names the service/keyring, not the
	// password).
	KeychainErrDetail string
	RecoveryNote      string
	CloudNote         string
	PreflightNote     string
	// CaveatNote carries the placement caveat for the sync provider the vault
	// landed inside (on-demand/online-only eviction guidance), when the vault
	// is a SyncedFolder with a known provider — including a custom path or a
	// --preset synced-folder run that resolved to a detected root (CLI-3/DOC-4).
	// It is empty for local/rclone/manual outcomes. Callers surface it in the
	// summary; it carries no secret.
	CaveatNote string
	FailedStep string
}

// DefaultDeps returns the real, side-effecting Deps. The CLI and GUI start from
// this and override RcloneEnsure with a consent-carrying wrapper (the default
// here denies the network download, the safe choice when no UI has bound a
// consent decision).
func DefaultDeps() Deps {
	return Deps{
		CreateVault: func(dir, password string, opts vault.CreateOptions) error {
			return vault.CreateWithOptions(dir, password, opts)
		},
		KeychainSet: keychain.Set,
		ProfileLookup: func(name string) (string, bool, error) {
			e, ok, err := profile.Resolve(name)
			if err != nil {
				return "", false, err
			}
			return e.VaultPath, ok, nil
		},
		ProfileAdd: func(name, vaultDir string) error {
			_, err := profile.Add(name, vaultDir)
			return err
		},
		RcloneEnsure: func() error { return RcloneEnsure(func() bool { return false }) },
		RemoteAdd: func(name, vaultDir, remotePath string) error {
			_, err := remotes.Add(remotes.DefaultProfile(name, vaultDir, remotePath, "rclone"))
			return err
		},
		RemoteTest: defaultRemoteTest,
	}
}

// defaultRemoteTest runs the existing transport Test for a named remote profile.
// It is exercised by fake seams in unit tests; a real end-to-end drive needs a
// real remote and is a pending lab drill (no lab tier in this repo).
func defaultRemoteTest(name string) error {
	p, ok, err := remotes.Get(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("remote profile %q not found", name)
	}
	ctx := context.Background()
	var b interface {
		Test(context.Context) (transport.Result, error)
	}
	if p.Type == "local" {
		b = localtransport.New(p)
	} else {
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		b = rclonetransport.New(bin, p)
	}
	_, err = b.Test(ctx)
	return err
}

// Execute builds the vault and wires it up per the plan (design §3.1). It is
// sequential and, on any failure, reports what exists in the returned Result
// (§6). The vault is built in a sibling temp directory and os.Rename'd into
// place only on success, so an interrupted create leaves either a complete
// vault or nothing (C8). Recovery generation is NOT here: it stays in the
// caller's interactive step (§3.1, I-S3). The password is used only to create
// the vault and (optionally) store in the keychain; it never lands in the
// Result, a log, or a note (I-S1).
func Execute(p Plan, password string, deps Deps) (Result, error) {
	if err := p.Validate(); err != nil {
		return Result{}, err
	}
	if password == "" {
		return Result{}, errors.New("password must not be empty")
	}
	vaultDir := filepath.Clean(p.VaultDir)
	res := Result{VaultDir: vaultDir, ProfileName: p.ResolvedProfileName()}

	// Profile-name collision is checked FIRST, before ANY side effect — no
	// vault, no temp sibling, no keychain entry (profile-collision-orphan). A
	// name that already points at a different vault must never leave an
	// orphaned, unreferenced vault (and, formerly, an orphaned keychain
	// password) on disk. Validate ran the same check against the real store;
	// this repeats it through the Deps seam so the refusal holds even when the
	// caller injected a store, and closes the gap before the create. Because it
	// is pre-create, res.VaultID stays empty here: the caller sees that nothing
	// was built.
	name := res.ProfileName
	if existingPath, found, err := deps.ProfileLookup(name); err != nil {
		res.FailedStep = StepProfile
		return res, err
	} else if found && filepath.Clean(existingPath) != vaultDir {
		res.FailedStep = StepProfile
		return res, fmt.Errorf("%w: profile %q points at %s", ErrProfileNameInUse, name, existingPath)
	}

	// Authoritative pre-build check (Validate ran earlier but this closes the
	// TOCTOU window): refuse an existing vault or interrupted-setup leftovers.
	if err := vaultDirState(vaultDir); err != nil {
		return res, err
	}

	opts, err := p.createOptions()
	if err != nil {
		return res, err
	}

	// Build in a sibling temp directory, rename on success (C8). Create the
	// parent chain first so the temp sibling has a home.
	parent := filepath.Dir(vaultDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		res.FailedStep = StepCreate
		return res, err
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(vaultDir)+".setup-")
	if err != nil {
		res.FailedStep = StepCreate
		return res, err
	}
	if err := deps.CreateVault(tmp, password, opts); err != nil {
		os.RemoveAll(tmp)
		res.FailedStep = StepCreate
		return res, err
	}
	// Place the built tree atomically. If the target is an existing empty
	// directory, remove it first so os.Rename is portable (Windows refuses a
	// rename onto an existing directory).
	if info, statErr := os.Stat(vaultDir); statErr == nil && info.IsDir() {
		if err := os.Remove(vaultDir); err != nil {
			os.RemoveAll(tmp)
			res.FailedStep = StepCreate
			return res, err
		}
	}
	if err := os.Rename(tmp, vaultDir); err != nil {
		os.RemoveAll(tmp)
		res.FailedStep = StepCreate
		return res, err
	}

	cfg, err := vault.ReadConfig(vaultDir)
	if err != nil {
		res.FailedStep = StepCreate
		return res, err
	}
	res.VaultID = cfg.VaultID

	// Profile: re-check the collision now that the vault exists, to catch a
	// racing Add that appeared between the pre-create check and here (TOCTOU).
	// If it did, the vault is already built — so report what exists (VaultID and
	// dir are set) and name the created vault in the error, rather than silently
	// orphaning it (profile-collision-orphan, I-S5/§6). Never silently repoint
	// an existing same-name profile (C3).
	if existingPath, found, err := deps.ProfileLookup(name); err != nil {
		res.FailedStep = StepProfile
		return res, err
	} else if found && filepath.Clean(existingPath) != vaultDir {
		res.FailedStep = StepProfile
		res.CloudNote = fmt.Sprintf("a vault was created at %s but its profile name %q is now taken by %s; open it with a different --profile name (nothing was removed).", vaultDir, name, existingPath)
		return res, fmt.Errorf("%w: profile %q points at %s (a vault was already created at %s)", ErrProfileNameInUse, name, existingPath, vaultDir)
	}
	if err := deps.ProfileAdd(name, vaultDir); err != nil {
		res.FailedStep = StepProfile
		return res, err
	}

	// Keychain: an explicit, visible choice (I-S4), written only AFTER a
	// successful ProfileAdd (profile-collision-orphan) so a password entry is
	// never orphaned by a profile step that later fails. A keychain failure is a
	// warning naming the remedy, never a hard failure — the vault still exists.
	if p.SaveKeychain {
		if err := deps.KeychainSet(cfg.VaultID, password); err != nil {
			res.KeychainSaved = false
			// Plain, user-facing one-liner (CLI-1): the raw exec error is kept in
			// KeychainErrDetail for --debug, not spilled into the summary.
			res.KeychainNote = fmt.Sprintf("could not save the password to the OS keychain (it may be locked, unavailable, or not configured). The vault still opens with the password you typed or via SEAVAULT_PASSWORD; store it later with `seavault keychain store %s`.", shellQuote(name))
			res.KeychainErrDetail = err.Error()
		} else {
			res.KeychainSaved = true
		}
	}

	// Preflight/compatibility note when the vault sits under a sync-client folder
	// (C4). SyncClientPreflightNote self-gates (returns "" otherwise), and its
	// matcher now covers the org-suffixed CloudStorage forms.
	res.PreflightNote = vault.SyncClientPreflightNote(vaultDir)

	// Cloud step.
	switch c := p.Cloud.(type) {
	case SyncedFolder:
		// No transport. Never assert "synced" (C2): report placement and ask the
		// user to confirm the sync client shows it uploaded.
		res.CloudNote = fmt.Sprintf("placed inside %s — check that your sync client shows it as uploaded. Nothing else is needed; any sync client that watches this folder moves the encrypted vault.", vaultDir)
		// Surface the provider placement caveat (on-demand/online-only eviction)
		// whenever the synced folder has a known provider — a custom path under a
		// detected root or a --preset synced-folder run resolves it here too
		// (CLI-3/DOC-4), not only the "picked from the list" path.
		if cav := Caveat(c.Provider); cav != "" {
			res.CaveatNote = cav
		}
	case LocalOnly, nil:
		res.CloudNote = "local / external-drive only — no cloud sync was configured."
	case RcloneRemote:
		if err := deps.RcloneEnsure(); err != nil {
			res.FailedStep = StepRcloneEnsure
			res.CloudNote = fmt.Sprintf("the vault and profile were created, but the rclone runtime is not ready: %v. Run `seavault rclone install` to install it (offline: `seavault rclone install --offline-archive <zip>` or `--from-binary <path>`), then `seavault remote test %s`.", err, c.Name)
			return res, err
		}
		if err := deps.RemoteAdd(c.Name, vaultDir, c.RemotePath); err != nil {
			res.FailedStep = StepRemoteAdd
			res.CloudNote = fmt.Sprintf("the vault and profile were created, but the remote %q could not be registered: %v.", c.Name, err)
			return res, err
		}
		if err := deps.RemoteTest(c.Name); err != nil {
			res.FailedStep = StepRemoteTest
			res.CloudNote = fmt.Sprintf("the vault, profile and remote were created, but the remote did not verify: %v. Fix it and run `seavault remote test %s`.", err, c.Name)
			return res, err
		}
		res.CloudNote = fmt.Sprintf("remote %q verified — the vault will sync through it.", c.Name)
	}

	return res, nil
}

// dirNonEmpty reports whether path is an existing directory with at least one
// entry. A missing path is not an error (reports false).
func dirNonEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil {
		// A non-directory (ENOTDIR on Readdirnames) or read error: let the
		// caller's create path surface the precise problem; treat as empty here.
		return false, nil
	}
	return len(names) > 0, nil
}

// shellQuote renders s so it survives a copy-paste into a POSIX shell as a
// single argument (preset-noninteractive-2). A profile name is the basename of
// the vault dir, so it can contain spaces or shell metacharacters ("My Vault");
// interpolating it raw into a printed remedy command produces a line that splits
// into two arguments when pasted. A name of only safe characters is returned
// unchanged; anything else is wrapped in single quotes with embedded single
// quotes escaped the POSIX way ('\”). It is display-only — nothing here is
// executed — and never carries a secret.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == '/' || r == '@' || r == '%' || r == '+' || r == ':' || r == ',':
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
