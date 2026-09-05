// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSealFormatBumpsVersionAndMinReader is the R11 core (design D1.4, P1-20,
// Condition 14): seal-format bumps Version 2->3 AND MinReader to the format
// ceiling (3) together in one rewriteConfig; a SupportedFormat=2 reader is then
// fenced with ErrFormatTooNew while this build (SupportedFormat=3) still opens;
// unseal-format restores Version 2 / MinReader 2 and re-admits the format-2
// reader. It also covers the already-sealed / not-sealed guards. This leg needs
// no external binary so it always runs.
func TestSealFormatBumpsVersionAndMinReader(t *testing.T) {
	const pw = "correct horse battery staple"
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, pw)

	// Before seal: Version is the grace-release 2 and a SupportedFormat=2 reader is
	// admitted (the fence does not trip).
	cfg, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 {
		t.Fatalf("a fresh vault must be Version 2 (grace release), got %d", cfg.Version)
	}
	if err := formatTooNew(cfg.MinReader, 2); err != nil {
		t.Fatalf("before seal a SupportedFormat=2 reader must open (minReader=%d), got %v", cfg.MinReader, err)
	}

	// Seal.
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SealFormat(); err != nil {
		t.Fatalf("seal-format: %v", err)
	}
	if v.Config.Version != 3 {
		t.Fatalf("seal-format must bump the in-memory Version to 3, got %d", v.Config.Version)
	}
	if v.Config.MinReader != 3 {
		t.Fatalf("seal-format must raise the in-memory MinReader to 3, got %d", v.Config.MinReader)
	}

	// The bump is persisted, not just in-memory.
	sealed, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Version != 3 || sealed.MinReader != 3 {
		t.Fatalf("seal-format must persist Version=3 and MinReader=3, got Version=%d MinReader=%d", sealed.Version, sealed.MinReader)
	}

	// After seal: a SupportedFormat=2 reader is fenced with the typed, hedged
	// ErrFormatTooNew; this build (SupportedFormat=3) still opens.
	if err := formatTooNew(sealed.MinReader, 2); !errors.Is(err, ErrFormatTooNew) {
		t.Fatalf("after seal a SupportedFormat=2 reader must be fenced with ErrFormatTooNew, got %v", err)
	}
	if _, err := Open(root, pw); err != nil {
		t.Fatalf("this build (SupportedFormat=%d) must still open a sealed vault, got %v", SupportedFormat, err)
	}

	// A double-seal is a legible no-op, not a silent epoch churn.
	vSealed, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	epochBefore := vSealed.Config.FormatEpoch
	if err := vSealed.SealFormat(); !errors.Is(err, ErrAlreadySealed) {
		t.Fatalf("re-sealing an already-sealed vault must return ErrAlreadySealed, got %v", err)
	}
	if reread, _ := ReadConfig(root); reread.FormatEpoch != epochBefore {
		t.Fatalf("a refused double-seal must not bump FormatEpoch (was %d, now %d)", epochBefore, reread.FormatEpoch)
	}

	// Unseal restores the grace-release Version/MinReader and re-admits a
	// SupportedFormat=2 reader.
	if err := vSealed.UnsealFormat(); err != nil {
		t.Fatalf("unseal-format: %v", err)
	}
	unsealed, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if unsealed.Version != 2 || unsealed.MinReader != 2 {
		t.Fatalf("unseal-format must restore Version=2 and MinReader=2, got Version=%d MinReader=%d", unsealed.Version, unsealed.MinReader)
	}
	if err := formatTooNew(unsealed.MinReader, 2); err != nil {
		t.Fatalf("after unseal a SupportedFormat=2 reader must open again (minReader=%d), got %v", unsealed.MinReader, err)
	}
	if _, err := Open(root, pw); err != nil {
		t.Fatalf("this build must open the unsealed vault, got %v", err)
	}

	// Unsealing an already-unsealed vault is a legible no-op.
	vUnsealed, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := vUnsealed.UnsealFormat(); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("unsealing an unsealed vault must return ErrNotSealed, got %v", err)
	}
}

// TestUnsealFormatRefusedAfterDirIDReKey proves the A3 guard (design D1.4,
// Condition 14): once a directory-ID re-key has run (CryptoConfig.DirIDEpoch > 0
// — the marker A3 will set), unseal-format refuses with ErrUnsealAfterReKey
// because lowering the Version would re-admit readers that can no longer decode
// the re-keyed manifests. It writes the marker through the real MAC'd config
// path (rewriteConfig), so it also proves DirIDEpoch is MAC-covered and survives
// a reopen.
func TestUnsealFormatRefusedAfterDirIDReKey(t *testing.T) {
	const pw = "correct horse battery staple"
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, pw)

	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SealFormat(); err != nil {
		t.Fatalf("seal-format: %v", err)
	}
	// Simulate A3's directory-ID re-key by setting the marker through the MAC'd
	// config path (what A3 would do). The tag is recomputed, so a reopen verifies.
	if err := v.rewriteConfig(func(c *VaultConfig) error { c.Crypto.DirIDEpoch = 1; return nil }); err != nil {
		t.Fatalf("set DirIDEpoch marker: %v", err)
	}

	reopened, err := Open(root, pw)
	if err != nil {
		t.Fatalf("a vault carrying a MAC'd DirIDEpoch must open (the marker is covered, not tampering), got %v", err)
	}
	if reopened.Config.Crypto.DirIDEpoch != 1 {
		t.Fatalf("DirIDEpoch must survive a reopen, got %d", reopened.Config.Crypto.DirIDEpoch)
	}
	if err := reopened.UnsealFormat(); !errors.Is(err, ErrUnsealAfterReKey) {
		t.Fatalf("unseal after a dir-ID re-key must refuse with ErrUnsealAfterReKey, got %v", err)
	}
	// The refused unseal wrote nothing: the vault is still sealed.
	if still, _ := ReadConfig(root); still.Version != 3 {
		t.Fatalf("a refused unseal must leave the vault sealed (Version 3), got %d", still.Version)
	}
}

// TestReaderSignalRecordedOnOpen is the Condition 14 device-signal leg: each Open
// records THIS device's reader signal (DeviceID + SupportedFormat) into the
// device-local, never-synced inventory seal-format prints, and ReaderInventory
// reads it back.
func TestReaderSignalRecordedOnOpen(t *testing.T) {
	// A fresh app-home so the inventory reflects only this test's opens.
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	const pw = "correct horse battery staple"
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, pw)

	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if v.DeviceID() == "" {
		t.Skip("device id unavailable in this environment; reader-signal recording is best-effort")
	}
	inv := v.ReaderInventory()
	if len(inv) == 0 {
		t.Fatal("Open must record this device's reader signal; ReaderInventory is empty")
	}
	var found *ReaderRecord
	for i := range inv {
		if inv[i].DeviceID == v.DeviceID() {
			found = &inv[i]
		}
	}
	if found == nil {
		t.Fatalf("this device (%s) must appear in the reader inventory %+v", v.DeviceID(), inv)
	}
	if found.SupportedFormat != SupportedFormat {
		t.Fatalf("the reader signal must record SupportedFormat=%d, got %d", SupportedFormat, found.SupportedFormat)
	}
	if found.Version != v.Config.Version {
		t.Fatalf("the reader signal must record the seen Version=%d, got %d", v.Config.Version, found.Version)
	}
	if found.LastSeen == "" {
		t.Fatal("the reader signal must record a LastSeen timestamp")
	}
}

// TestSealFormatCrossVersion016Refusal is the R11 interop leg (design D1.4,
// Conditions 3/14): build the merge-base 0.16 binary, have it create a .seavault
// vault it can open; before seal it opens; after this build seal-formats it the
// 0.16 binary hard-refuses on its OWN Version fence ("unsupported vault version
// 3"); after unseal-format it opens again. It skips when git/go or the fixture
// commit are unavailable, exactly like TestCrossVersion015Fixture.
func TestSealFormatCrossVersion016Refusal(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable; skipping cross-version seal-format test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable; skipping cross-version seal-format test")
	}
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	top, err := runFixtureCmd(t, "", os.Environ(), "git", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Skipf("not a git checkout (%v); skipping", err)
	}
	repoRoot := strings.TrimSpace(top)
	if out, err := runFixtureCmd(t, repoRoot, os.Environ(), "git", "cat-file", "-e", legacy015Commit+"^{commit}"); err != nil {
		t.Skipf("fixture commit %s not present in this (shallow?) checkout; skipping: %v\n%s", legacy015Commit, err, out)
	}

	work := filepath.Join(t.TempDir(), "old-src")
	if out, err := runFixtureCmd(t, repoRoot, os.Environ(), "git", "worktree", "add", "--detach", work, legacy015Commit); err != nil {
		t.Fatalf("git worktree add %s: %v\n%s", legacy015Commit, err, out)
	}
	defer runFixtureCmd(t, repoRoot, os.Environ(), "git", "worktree", "remove", "--force", work)

	oldBin := filepath.Join(t.TempDir(), "seavault-legacy")
	buildEnv := append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := runFixtureCmd(t, work, buildEnv, "go", "build", "-o", oldBin, "./cmd/seavault"); err != nil {
		t.Fatalf("build legacy binary: %v\n%s", err, out)
	}

	const pw = "correct horse battery staple"
	pwEnv := append(os.Environ(), "SEAVAULT_PASSWORD="+pw, "SEAVAULT_APP_HOME="+t.TempDir())

	// The legacy binary creates a .seavault vault it can open.
	oldVault := filepath.Join(t.TempDir(), "oldvault")
	if out, err := runFixtureCmd(t, "", pwEnv, oldBin, "init", "--kdf", "pbkdf2", "--pbkdf2-iterations", "1000", oldVault); err != nil {
		t.Fatalf("legacy init: %v\n%s", err, out)
	}
	if !fileExists(filepath.Join(oldVault, ".seavault", "vault.json")) {
		t.Fatal("the legacy binary must create a hidden .seavault vault")
	}
	// Before seal the legacy binary opens it.
	if out, err := runFixtureCmd(t, "", pwEnv, oldBin, "list", oldVault); err != nil {
		t.Fatalf("before seal the legacy binary must open the vault: %v\n%s", err, out)
	}

	// This build seals it.
	v, err := Open(oldVault, pw)
	if err != nil {
		t.Fatalf("this build must open the legacy vault to seal it: %v", err)
	}
	if err := v.SealFormat(); err != nil {
		t.Fatalf("seal-format on a legacy vault: %v", err)
	}

	// After seal the legacy binary hard-refuses on its own Version fence.
	sealOut, sealErr := runFixtureCmd(t, "", pwEnv, oldBin, "list", oldVault)
	if sealErr == nil {
		t.Fatalf("after seal-format the legacy binary must refuse the vault, but list succeeded:\n%s", sealOut)
	}
	if !strings.Contains(sealOut, "unsupported vault version 3") {
		t.Fatalf("the legacy binary must refuse a sealed vault with its own version fence; got:\n%s", sealOut)
	}

	// Unseal re-admits the legacy binary.
	vSealed, err := Open(oldVault, pw)
	if err != nil {
		t.Fatalf("this build must open the sealed vault to unseal it: %v", err)
	}
	if err := vSealed.UnsealFormat(); err != nil {
		t.Fatalf("unseal-format: %v", err)
	}
	if out, err := runFixtureCmd(t, "", pwEnv, oldBin, "list", oldVault); err != nil {
		t.Fatalf("after unseal-format the legacy binary must open the vault again: %v\n%s", err, out)
	}
}

// TestSealClearsLegacyWrapUnsealRestores is the tombstone for conditions/F3
// (design D3.1): seal-format must clear the 0.16-readable legacy top-level wrap
// so a hostile Version-downgraded config cannot let a forgotten 0.16 peer unwrap
// via the retained legacy fields, while keeping the vault openable (the credential
// survives as a password WrapEntry) and letting unseal-format restore 0.16 access.
func TestSealClearsLegacyWrapUnsealRestores(t *testing.T) {
	const pw = "correct horse battery staple"
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, pw)

	// A fresh vault carries only the legacy top-level wrap (no WrapEntries yet).
	cfg, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WrappedKeys == "" {
		t.Fatal("precondition: a fresh vault must carry the legacy top-level wrap")
	}

	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SealFormat(); err != nil {
		t.Fatalf("SealFormat: %v", err)
	}

	sealed, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	// conditions/F3: the legacy top-level wrap is gone.
	if sealed.WrappedKeys != "" || sealed.WrapNonce != "" {
		t.Fatalf("seal must clear the legacy top-level wrap, got WrappedKeys=%q WrapNonce=%q", sealed.WrappedKeys, sealed.WrapNonce)
	}
	// Openability preserved: the credential survived as a password WrapEntry.
	if _, ok := firstBarePasswordEntry(sealed.WrapEntries); !ok {
		t.Fatal("seal must migrate the credential into a password WrapEntry before clearing the legacy wrap")
	}
	// The concrete F3 exploit is denied: a hostile server downgrades Version 3->2;
	// the legacy-only unwrap path a 0.16 peer uses now finds an empty wrap.
	if keys, err := sealed.unlockWithLegacyOnly(pw); err == nil {
		t.Fatalf("a Version-downgraded sealed config must not unwrap via the legacy fields, but it did (keys len %d)", len(keys.MasterKey))
	}
	// The sealed vault still opens for a current (A2) reader via the WrapEntry.
	if _, err := Open(root, pw); err != nil {
		t.Fatalf("sealed vault must still open for a current reader: %v", err)
	}

	// Unseal restores the legacy wrap so a 0.16 peer can unwrap again (R11).
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.UnsealFormat(); err != nil {
		t.Fatalf("UnsealFormat: %v", err)
	}
	unsealed, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if unsealed.WrappedKeys == "" || unsealed.WrapNonce == "" {
		t.Fatal("unseal must restore the legacy top-level wrap so a 0.16 peer can unwrap again")
	}
	if _, err := unsealed.unlockWithLegacyOnly(pw); err != nil {
		t.Fatalf("after unseal the legacy fields must unwrap (0.16 path): %v", err)
	}
	if _, err := Open(root, pw); err != nil {
		t.Fatalf("unsealed vault must still open: %v", err)
	}
}

// unlockWithLegacyOnly unwraps using ONLY the top-level legacy fields, modelling
// exactly what a 0.16 peer (which ignores WrapEntries) does. It is the test lens
// for conditions/F3.
func (cfg VaultConfig) unlockWithLegacyOnly(secret string) (Keys, error) {
	return unwrapKeys(secret, cfg.KDF, cfg.WrapNonce, cfg.WrappedKeys)
}
