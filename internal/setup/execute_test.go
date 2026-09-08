// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

const testPassword = "correct horse battery staple"

// testDeps returns a Deps whose CreateVault builds a REAL vault (real scrypt,
// real key wrap) but with the fast test KDF so the suite stays quick, and whose
// other seams are inert no-ops. A test overrides just the seam it exercises.
// Only the Deps seam is mocked (privilege boundaries + fault injection); the
// crypto, the atomic create, and the on-disk vault are real.
func testDeps() Deps {
	return Deps{
		CreateVault: func(dir, password string, opts vault.CreateOptions) error {
			return vault.CreateWithOptions(dir, password, vault.CreateOptions{Chunk: opts.Chunk, KDF: vault.FastKDFConfigForTests()})
		},
		KeychainSet:   func(string, string) error { return nil },
		ProfileLookup: func(string) (string, bool, error) { return "", false, nil },
		ProfileAdd:    func(string, string) error { return nil },
		RcloneEnsure:  func() error { return nil },
		RemoteAdd:     func(string, string, string) error { return nil },
		RemoteTest:    func(string) error { return nil },
	}
}

func vaultExists(dir string) bool {
	_, exists, err := vault.ResolveMetaDir(dir)
	return err == nil && exists
}

// T5 (§6): a failing side-effect seam does not cost the user the vault. A
// keychain failure is a non-fatal warning naming the remedy; an rclone-ensure
// failure still leaves the vault and profile, and shows the retry command.
// (The recovery-mismatch clause of §6 lives in the interactive caller, not
// Execute, and is covered by that slice.)
func TestExecuteFailuresLeaveVault(t *testing.T) {
	rows := []struct {
		name  string
		build func(t *testing.T, deps *Deps, added *[]string) Plan
		check func(t *testing.T, res Result, err error, added []string)
	}{
		{
			name: "keychain seam fails",
			build: func(t *testing.T, deps *Deps, added *[]string) Plan {
				deps.KeychainSet = func(string, string) error { return errors.New("no desktop keyring") }
				deps.ProfileAdd = func(name, dir string) error { *added = append(*added, name); return nil }
				return Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), SaveKeychain: true, Cloud: LocalOnly{}}
			},
			check: func(t *testing.T, res Result, err error, added []string) {
				if err != nil {
					t.Fatalf("a keychain failure must not fail Execute; got %v", err)
				}
				if res.KeychainSaved {
					t.Fatal("KeychainSaved must be false after a keychain failure")
				}
				if res.KeychainNote == "" {
					t.Fatal("a keychain failure must leave a remedy note")
				}
				if !vaultExists(res.VaultDir) {
					t.Fatal("the vault must still exist after a keychain failure")
				}
				if len(added) != 1 {
					t.Fatalf("the profile must still be registered; ProfileAdd calls=%d", len(added))
				}
			},
		},
		{
			name: "rclone ensure fails",
			build: func(t *testing.T, deps *Deps, added *[]string) Plan {
				deps.RcloneEnsure = func() error { return errors.New("download refused") }
				deps.ProfileAdd = func(name, dir string) error { *added = append(*added, name); return nil }
				return Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), Cloud: RcloneRemote{Name: "r", RemotePath: "x:/y"}}
			},
			check: func(t *testing.T, res Result, err error, added []string) {
				if err == nil {
					t.Fatal("an rclone-ensure failure must surface an error")
				}
				if res.FailedStep != StepRcloneEnsure {
					t.Fatalf("FailedStep=%q; want %q", res.FailedStep, StepRcloneEnsure)
				}
				if !vaultExists(res.VaultDir) {
					t.Fatal("the vault must still exist after an rclone-ensure failure")
				}
				if len(added) != 1 {
					t.Fatalf("the profile must still be registered; ProfileAdd calls=%d", len(added))
				}
				if !strings.Contains(res.CloudNote, "seavault rclone install") {
					t.Fatalf("CloudNote must show the retry command; got %q", res.CloudNote)
				}
			},
		},
	}
	if len(rows) == 0 {
		t.Fatal("failure table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			deps := testDeps()
			var added []string
			plan := row.build(t, &deps, &added)
			res, err := Execute(plan, testPassword, deps)
			row.check(t, res, err, added)
		})
	}
}

// T9 (I-S5): after a default run the footprint is exactly the vault dir, the
// profile file, and the (fake) keychain entry — no half-vault, no leftover temp
// sibling — and the Result carries no secret.
func TestExecuteFootprint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", filepath.Join(home, "app"))
	keychainDir := filepath.Join(home, "app", "keychain")

	deps := testDeps()
	// Real profile store (writes profiles.json under SEAVAULT_APP_HOME).
	deps.ProfileAdd = func(name, dir string) error { _, err := profile.Add(name, dir); return err }
	deps.ProfileLookup = func(name string) (string, bool, error) {
		e, ok, err := profile.Resolve(name)
		return e.VaultPath, ok, err
	}
	// Fake keychain: writes a marker entry instead of touching the OS keychain.
	deps.KeychainSet = func(vaultID, _ string) error {
		if err := os.MkdirAll(keychainDir, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(keychainDir, vaultID), []byte("stored"), 0o600)
	}

	vaultParent := filepath.Join(home, "Dropbox")
	if err := os.MkdirAll(vaultParent, 0o755); err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(vaultParent, "MyVault")

	plan := Plan{VaultDir: vaultDir, SaveKeychain: true, Cloud: SyncedFolder{Provider: ProviderDropbox}}
	res, err := Execute(plan, testPassword, deps)
	if err != nil {
		t.Fatal(err)
	}

	// 1. The vault exists and really opens with the password (real crypto).
	if !vaultExists(vaultDir) {
		t.Fatal("the vault must exist after a successful run")
	}
	if v, err := vault.Open(vaultDir, testPassword); err != nil {
		t.Fatalf("the created vault must open with the password: %v", err)
	} else if v.Config.VaultID != res.VaultID {
		t.Fatalf("Result.VaultID=%q but vault holds %q", res.VaultID, v.Config.VaultID)
	}

	// 2. The profile file exists.
	entries, err := profile.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "MyVault" {
		t.Fatalf("expected exactly the MyVault profile; got %+v", entries)
	}

	// 3. The fake keychain entry exists.
	if _, err := os.Stat(filepath.Join(keychainDir, res.VaultID)); err != nil {
		t.Fatalf("the keychain entry must exist: %v", err)
	}
	if !res.KeychainSaved {
		t.Fatal("KeychainSaved must be true")
	}

	// 4. No leftover temp sibling: the vault parent holds exactly the vault dir.
	siblings, err := os.ReadDir(vaultParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(siblings) != 1 || siblings[0].Name() != "MyVault" {
		var names []string
		for _, s := range siblings {
			names = append(names, s.Name())
		}
		t.Fatalf("the vault parent must hold only the vault dir (no temp sibling); got %v", names)
	}

	// 5. No secret in the Result.
	if strings.Contains(fmt.Sprintf("%+v", res), testPassword) {
		t.Fatal("the Result must not carry the password")
	}
	if res.RecoveryNote != "" {
		t.Fatalf("Execute must not set RecoveryNote (the caller owns recovery); got %q", res.RecoveryNote)
	}
}

// T11 (C8): the create is atomic. A fault injected during CreateVault leaves no
// target dir and no temp sibling; a non-empty dir without vault.json is reported
// as leftovers; an existing vault is reported distinctly (open-it-instead).
func TestExecuteAtomicCreate(t *testing.T) {
	t.Run("fault during create leaves nothing", func(t *testing.T) {
		parent := t.TempDir()
		vaultDir := filepath.Join(parent, "vault")
		deps := testDeps()
		// Simulate a crash between mkdir and config write: make the directory
		// layout, then fail before any vault.json is written.
		deps.CreateVault = func(dir, _ string, _ vault.CreateOptions) error {
			if err := os.MkdirAll(filepath.Join(dir, "SeaVaultData", "objects", "chunks"), 0o700); err != nil {
				return err
			}
			return errors.New("injected crash between mkdir and config write")
		}
		res, err := Execute(Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}, testPassword, deps)
		if err == nil {
			t.Fatal("a create fault must surface an error")
		}
		if res.FailedStep != StepCreate {
			t.Fatalf("FailedStep=%q; want %q", res.FailedStep, StepCreate)
		}
		if _, statErr := os.Stat(vaultDir); !os.IsNotExist(statErr) {
			t.Fatalf("the target dir must not exist after a create fault; stat err=%v", statErr)
		}
		// No temp sibling left behind.
		siblings, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if len(siblings) != 0 {
			var names []string
			for _, s := range siblings {
				names = append(names, s.Name())
			}
			t.Fatalf("the temp sibling must be cleaned up; parent holds %v", names)
		}
	})

	t.Run("leftovers without vault.json", func(t *testing.T) {
		vaultDir := filepath.Join(t.TempDir(), "vault")
		if err := os.MkdirAll(vaultDir, 0o755); err != nil {
			t.Fatal(err)
		}
		stray := filepath.Join(vaultDir, "leftover.txt")
		if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Execute(Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}, testPassword, testDeps())
		if !errors.Is(err, ErrVaultDirLeftovers) {
			t.Fatalf("a non-empty dir without vault.json must return ErrVaultDirLeftovers; got %v", err)
		}
		if _, statErr := os.Stat(stray); statErr != nil {
			t.Fatalf("the leftover files must be untouched; stat err=%v", statErr)
		}
	})

	t.Run("existing vault is distinct from leftovers", func(t *testing.T) {
		vaultDir := filepath.Join(t.TempDir(), "vault")
		if err := vault.CreateWithOptions(vaultDir, testPassword, vault.CreateOptions{Chunk: vault.DefaultChunkParams(), KDF: vault.FastKDFConfigForTests()}); err != nil {
			t.Fatal(err)
		}
		_, err := Execute(Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}, testPassword, testDeps())
		if !errors.Is(err, ErrVaultDirNotEmpty) {
			t.Fatalf("an existing vault must return ErrVaultDirNotEmpty; got %v", err)
		}
		if errors.Is(err, ErrVaultDirLeftovers) {
			t.Fatal("an existing vault must NOT be classified as leftovers")
		}
	})
}

// T12 (C3): a same-name profile pointing at a DIFFERENT path is refused with
// ErrProfileNameInUse and the original is never repointed; a same-name profile
// at the SAME path is idempotent.
func TestExecuteProfileCollision(t *testing.T) {
	rows := []struct {
		name        string
		lookupPath  string
		lookupFound bool
		wantErr     bool
	}{
		{"different path collides", "/somewhere/else", true, true},
		{"same path is idempotent", "SAME", true, false},
		{"no existing profile", "", false, false},
	}
	if len(rows) == 0 {
		t.Fatal("collision table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			vaultDir := filepath.Join(t.TempDir(), "vault")
			deps := testDeps()
			var addCalls int
			deps.ProfileAdd = func(string, string) error { addCalls++; return nil }
			deps.ProfileLookup = func(string) (string, bool, error) {
				p := row.lookupPath
				if p == "SAME" {
					p = vaultDir
				}
				return p, row.lookupFound, nil
			}
			res, err := Execute(Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}, testPassword, deps)
			if row.wantErr {
				if !errors.Is(err, ErrProfileNameInUse) {
					t.Fatalf("a different-path collision must return ErrProfileNameInUse; got %v", err)
				}
				if res.FailedStep != StepProfile {
					t.Fatalf("FailedStep=%q; want %q", res.FailedStep, StepProfile)
				}
				if addCalls != 0 {
					t.Fatal("ProfileAdd must NOT be called on a collision (the original stays untouched)")
				}
				// profile-collision-orphan: a pure name collision is caught BEFORE
				// any side effect, so no vault (and no keychain entry) is orphaned
				// on disk, and Result reports that nothing was built. The user
				// retries with a suffixed name against a clean slate.
				if vaultExists(vaultDir) {
					t.Fatal("a pre-create profile collision must not leave an orphaned vault")
				}
				if res.VaultID != "" {
					t.Fatalf("no vault was built on a pre-create collision, so Result.VaultID must be empty; got %q", res.VaultID)
				}
			} else {
				if err != nil {
					t.Fatalf("no collision expected; got %v", err)
				}
				if addCalls != 1 {
					t.Fatalf("ProfileAdd must be called once; calls=%d", addCalls)
				}
			}
		})
	}
}

// T15 (C9): the cloud retry remedy is branched by which step failed. An
// rclone-ensure failure names `seavault rclone install` (with the offline
// options); a RemoteTest failure on an installed runtime names
// `seavault remote test NAME` and never the install command.
func TestExecuteBranchedRemedy(t *testing.T) {
	rows := []struct {
		name       string
		wire       func(deps *Deps)
		wantStep   string
		wantSubstr []string
		notSubstr  []string
	}{
		{
			name:       "ensure failure -> rclone install",
			wire:       func(deps *Deps) { deps.RcloneEnsure = func() error { return errors.New("no runtime") } },
			wantStep:   StepRcloneEnsure,
			wantSubstr: []string{"seavault rclone install", "--offline-archive", "--from-binary"},
		},
		{
			name:       "remote test failure -> remote test NAME",
			wire:       func(deps *Deps) { deps.RemoteTest = func(string) error { return errors.New("auth failed") } },
			wantStep:   StepRemoteTest,
			wantSubstr: []string{"seavault remote test acme"},
			notSubstr:  []string{"rclone install"},
		},
	}
	if len(rows) == 0 {
		t.Fatal("remedy table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			deps := testDeps()
			row.wire(&deps)
			plan := Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), Cloud: RcloneRemote{Name: "acme", RemotePath: "acme:/vault"}}
			res, err := Execute(plan, testPassword, deps)
			if err == nil {
				t.Fatal("a cloud-step failure must surface an error")
			}
			if res.FailedStep != row.wantStep {
				t.Fatalf("FailedStep=%q; want %q", res.FailedStep, row.wantStep)
			}
			for _, want := range row.wantSubstr {
				if !strings.Contains(res.CloudNote, want) {
					t.Fatalf("CloudNote must contain %q; got %q", want, res.CloudNote)
				}
			}
			for _, no := range row.notSubstr {
				if strings.Contains(res.CloudNote, no) {
					t.Fatalf("CloudNote must NOT contain %q; got %q", no, res.CloudNote)
				}
			}
		})
	}
}

// profile-collision-orphan: a same-name-different-path profile collision is
// caught BEFORE any side effect — no vault, no temp sibling, no keychain entry
// is created. The old order committed the vault (and keychain password) first
// and only then discovered the name was taken, orphaning both.
func TestExecuteProfileCollisionLeavesNoOrphan(t *testing.T) {
	vaultDir := filepath.Join(t.TempDir(), "vault")
	deps := testDeps()
	var createCalls, keychainCalls, addCalls int
	deps.CreateVault = func(dir, pw string, opts vault.CreateOptions) error {
		createCalls++
		return testDeps().CreateVault(dir, pw, opts)
	}
	deps.KeychainSet = func(string, string) error { keychainCalls++; return nil }
	deps.ProfileAdd = func(string, string) error { addCalls++; return nil }
	deps.ProfileLookup = func(string) (string, bool, error) { return "/some/other/vault", true, nil }

	res, err := Execute(Plan{VaultDir: vaultDir, SaveKeychain: true, Cloud: LocalOnly{}}, testPassword, deps)
	if !errors.Is(err, ErrProfileNameInUse) {
		t.Fatalf("a different-path collision must return ErrProfileNameInUse; got %v", err)
	}
	if createCalls != 0 {
		t.Fatalf("CreateVault must not run when the profile name already collides; calls=%d", createCalls)
	}
	if keychainCalls != 0 {
		t.Fatalf("no keychain password may be written on a pre-create collision; calls=%d", keychainCalls)
	}
	if addCalls != 0 {
		t.Fatalf("ProfileAdd must not run on a collision; calls=%d", addCalls)
	}
	if vaultExists(vaultDir) || res.VaultID != "" {
		t.Fatalf("no vault may be orphaned on a pre-create collision; exists=%v vaultID=%q", vaultExists(vaultDir), res.VaultID)
	}
	// The temp parent holds no leftover sibling either.
	if entries, rerr := os.ReadDir(filepath.Dir(vaultDir)); rerr == nil && len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("no temp sibling may be left behind; parent holds %v", names)
	}
}

// profile-collision-orphan: the keychain password is written only AFTER a
// successful ProfileAdd. If the profile step fails, no keychain entry is left
// behind. The old order wrote the keychain first.
func TestExecuteKeychainWrittenAfterProfile(t *testing.T) {
	vaultDir := filepath.Join(t.TempDir(), "vault")
	deps := testDeps()
	var keychainCalls int
	keychainAt := -1
	profileAt := -1
	step := 0
	deps.KeychainSet = func(string, string) error { keychainCalls++; keychainAt = step; step++; return nil }
	deps.ProfileAdd = func(string, string) error { profileAt = step; step++; return errors.New("profile store is read-only") }

	res, err := Execute(Plan{VaultDir: vaultDir, SaveKeychain: true, Cloud: LocalOnly{}}, testPassword, deps)
	if err == nil {
		t.Fatal("a failing ProfileAdd must surface an error")
	}
	if res.FailedStep != StepProfile {
		t.Fatalf("FailedStep=%q; want %q", res.FailedStep, StepProfile)
	}
	if keychainCalls != 0 {
		t.Fatalf("the keychain must NOT be written when ProfileAdd fails (it runs only after a successful ProfileAdd); calls=%d (keychainAt=%d, profileAt=%d)", keychainCalls, keychainAt, profileAt)
	}
}

// profile-collision-orphan: a collision that only appears AFTER the vault is
// built (a racing Add between the pre-create check and the commit) is reported
// honestly — the Result names the created vault (VaultID set, CloudNote points
// at it), rather than silently orphaning it.
func TestExecuteProfileCollisionTOCTOUReportsCreatedVault(t *testing.T) {
	vaultDir := filepath.Join(t.TempDir(), "vault")
	deps := testDeps()
	calls := 0
	deps.ProfileLookup = func(string) (string, bool, error) {
		calls++
		if calls == 1 {
			return "", false, nil // pre-create: clear
		}
		return "/raced/in/vault", true, nil // post-create: a collision appeared
	}
	res, err := Execute(Plan{VaultDir: vaultDir, Cloud: LocalOnly{}}, testPassword, deps)
	if !errors.Is(err, ErrProfileNameInUse) {
		t.Fatalf("a post-create collision must still return ErrProfileNameInUse; got %v", err)
	}
	if res.FailedStep != StepProfile {
		t.Fatalf("FailedStep=%q; want %q", res.FailedStep, StepProfile)
	}
	// The vault WAS built (the race happened after create), so the Result must
	// say so — the caller can print what exists (I-S5/§6).
	if res.VaultID == "" || !vaultExists(vaultDir) {
		t.Fatalf("a post-create collision leaves a real vault; VaultID=%q exists=%v", res.VaultID, vaultExists(vaultDir))
	}
	if !strings.Contains(res.CloudNote, vaultDir) {
		t.Fatalf("the Result must name the created vault so the caller can report it; CloudNote=%q", res.CloudNote)
	}
}

// CLI-3/DOC-4: a SyncedFolder outcome with a known provider surfaces that
// provider's placement caveat in Result.CaveatNote (so the summary and the GUI
// can show it), while a manual/unknown-provider synced folder and the
// local/rclone outcomes carry none.
func TestExecuteSyncedFolderSurfacesCaveat(t *testing.T) {
	rows := []struct {
		name     string
		cloud    CloudChoice
		wantCav  string
		wantNone bool
	}{
		{"known provider carries its caveat", SyncedFolder{Provider: ProviderDropbox}, Caveat(ProviderDropbox), false},
		{"manual synced folder carries none", SyncedFolder{Provider: ""}, "", true},
		{"local only carries none", LocalOnly{}, "", true},
	}
	if len(rows) == 0 {
		t.Fatal("caveat table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			vaultDir := filepath.Join(t.TempDir(), "vault")
			res, err := Execute(Plan{VaultDir: vaultDir, Cloud: row.cloud}, testPassword, testDeps())
			if err != nil {
				t.Fatalf("Execute must succeed; got %v", err)
			}
			if row.wantNone {
				if res.CaveatNote != "" {
					t.Fatalf("this outcome must carry no caveat; got %q", res.CaveatNote)
				}
				return
			}
			if strings.TrimSpace(res.CaveatNote) == "" {
				t.Fatal("a known-provider synced folder must surface a non-empty caveat in Result")
			}
			if res.CaveatNote != row.wantCav {
				t.Fatalf("CaveatNote must be the provider's catalog caveat; got %q want %q", res.CaveatNote, row.wantCav)
			}
		})
	}
}

// preset-noninteractive-2 (execute.go half): the keychain-store remedy names the
// profile and shell-quotes it, so a profile name with a space ("My Vault") is
// pasteable as a single argument rather than splitting into two.
func TestExecuteKeychainRemedyShellQuotesProfileName(t *testing.T) {
	rows := []struct {
		name    string
		profile string
		want    string
	}{
		{"name with a space is quoted", "My Vault", "seavault keychain store 'My Vault'"},
		{"plain name is unquoted", "MyVault", "seavault keychain store MyVault"},
	}
	if len(rows) == 0 {
		t.Fatal("remedy table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			deps := testDeps()
			deps.KeychainSet = func(string, string) error { return errors.New("no desktop keyring") }
			plan := Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), ProfileName: row.profile, SaveKeychain: true, Cloud: LocalOnly{}}
			res, err := Execute(plan, testPassword, deps)
			if err != nil {
				t.Fatalf("a keychain failure must not fail Execute; got %v", err)
			}
			if !strings.Contains(res.KeychainNote, row.want) {
				t.Fatalf("the keychain remedy must contain a pasteable %q; got %q", row.want, res.KeychainNote)
			}
		})
	}
}
