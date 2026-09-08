// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/setup"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// redactSecret renders secret-bearing output for a FAILURE MESSAGE without
// disclosing it: its length plus a short SHA-256 prefix. `recovery generate`
// stdout carries the freshly minted 24 words + compact base32, so it must never
// be echoed verbatim into a test log (testing discipline).
func redactSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("len=%d sha256=%s", len(s), hex.EncodeToString(sum[:])[:12])
}

// fastVault creates a real vault at dir with the fast test KDF (real crypto, no
// stub) and returns the password used.
func fastVault(t *testing.T, dir, pw string) {
	t.Helper()
	if err := vault.CreateWithOptions(dir, pw, vault.CreateOptions{Chunk: vault.DefaultChunkParams(), KDF: vault.FastKDFConfigForTests()}); err != nil {
		t.Fatalf("create vault: %v", err)
	}
}

// TestAnnotateSetupErrorLeftovers (H2 — ADM-5): a leftovers error surfaced by the
// non-interactive --preset path names the remedy; any other error is unchanged.
func TestAnnotateSetupErrorLeftovers(t *testing.T) {
	leftovers := fmt.Errorf("%w: /some/dir", setup.ErrVaultDirLeftovers)
	got := annotateSetupError(leftovers)
	if !errors.Is(got, setup.ErrVaultDirLeftovers) {
		t.Fatalf("the annotated error must still wrap ErrVaultDirLeftovers; got %v", got)
	}
	for _, want := range []string{"remove that directory", "different --vault"} {
		if !strings.Contains(got.Error(), want) {
			t.Fatalf("the leftovers remedy must name %q; got %q", want, got.Error())
		}
	}
	other := errors.New("some unrelated failure")
	if annotateSetupError(other).Error() != other.Error() {
		t.Fatalf("a non-leftovers error must pass through unchanged; got %q", annotateSetupError(other))
	}
}

// TestProfileRemovePrintsWhatItRemoved (H2 — DOC-6): `profile remove` names the
// profile it removed and states the vault data was left in place.
func TestProfileRemovePrintsWhatItRemoved(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "V")
	fastVault(t, dir, "pw-remove")
	if _, err := profile.Add("gone", dir); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	out, err := captureStdout(t, func() error { return cmdProfile([]string{"remove", "gone"}) })
	if err != nil {
		t.Fatalf("profile remove must succeed: %v", err)
	}
	if !strings.Contains(out, "removed profile gone") {
		t.Fatalf("profile remove must name what it removed; got %q", out)
	}
	if !strings.Contains(out, dir) || !strings.Contains(out, "left in place") {
		t.Fatalf("profile remove must state the vault data was left in place at the path; got %q", out)
	}
}

// TestRecoveryDeferralReminder (H2 — CLI-4): the pure helper returns the "no
// recovery key" reminder for a vault whose wrap entries carry no recovery entry
// (an empty array — a fresh vault — included, since the password lives in the
// legacy wrap); a vault WITH a recovery entry yields no reminder. Every row is
// asserted.
func TestRecoveryDeferralReminder(t *testing.T) {
	rows := []struct {
		name       string
		refs       []vault.WrapEntryRef
		wantRemind bool
	}{
		{"keyless: password only", []vault.WrapEntryRef{{ID: "a", Type: vault.WrapTypePassword}}, true},
		{"has recovery key", []vault.WrapEntryRef{{ID: "a", Type: vault.WrapTypePassword}, {ID: "b", Type: vault.WrapTypeRecovery}}, false},
		{"keyless: fresh vault (empty wrap-entry array)", nil, true},
	}
	if len(rows) == 0 {
		t.Fatal("empty table exercises nothing")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := recoveryDeferralReminder(r.refs, "MyVault")
			if r.wantRemind {
				if got == "" {
					t.Fatal("a keyless vault must produce a reminder")
				}
				if !strings.Contains(got, "no recovery key") || !strings.Contains(got, "recovery generate MyVault") {
					t.Fatalf("the reminder must name the risk and the pasteable remedy; got %q", got)
				}
			} else if got != "" {
				t.Fatalf("a vault with a key (or unknown) must produce no reminder; got %q", got)
			}
		})
	}
}

// TestProfileListShowsKeylessMarker (H2 — CLI-4): `profile list --status` names a
// keyless vault's missing recovery key, and reports "recovery key set" once one
// is minted.
func TestProfileListShowsKeylessMarker(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "V")
	const pw = "pw-keyless"
	fastVault(t, dir, pw)
	if _, err := profile.Add("v", dir); err != nil {
		t.Fatalf("profile add: %v", err)
	}

	out, err := captureStdout(t, func() error { return cmdProfile([]string{"list", "--status"}) })
	if err != nil {
		t.Fatalf("profile list --status must succeed: %v", err)
	}
	if !strings.Contains(out, "no recovery key") {
		t.Fatalf("a keyless vault must be flagged in profile list --status; got %q", out)
	}

	// Mint a recovery key (real crypto), then the marker must flip.
	v, err := vault.Open(dir, pw)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	_, commit, err := v.PrepareRecovery()
	if err != nil {
		t.Fatalf("prepare recovery: %v", err)
	}
	if err := commit(); err != nil {
		t.Fatalf("commit recovery: %v", err)
	}
	out2, err := captureStdout(t, func() error { return cmdProfile([]string{"list", "--status"}) })
	if err != nil {
		t.Fatalf("profile list --status must succeed: %v", err)
	}
	if !strings.Contains(out2, "recovery key set") {
		t.Fatalf("a vault with a recovery key must be reported as such; got %q", out2)
	}
	if strings.Contains(out2, "no recovery key") {
		t.Fatalf("a vault WITH a recovery key must not be flagged keyless; got %q", out2)
	}
}

// TestRecoveryGenerateWordsCompactAndTypedError (§2.5 CLI / C1): `recovery
// generate` prints the up-front password note, the 24 numbered words, and the
// compact base32 form; a word-shaped read-back that fails strict decode is
// rejected with the SPECIFIC typed word/checksum error (never a generic wrong-
// secret error), and nothing is committed.
func TestRecoveryGenerateWordsCompactAndTypedError(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "V")
	const pw = "pw-generate"
	fastVault(t, dir, pw)
	t.Setenv("SEAVAULT_PASSWORD", pw)
	// The read-back is interactive-only now (DOCS-1): the removed
	// SEAVAULT_RECOVERY_PHRASE env hook no longer satisfies it, so drive the
	// interactive read-back through the seams. The supplied phrase is 24 wordlist
	// words with a bad checksum (word-shaped), so RecoveryPhraseCheck returns the
	// typed ErrRecoveryChecksum rather than the generic wrong-secret error.
	setRecoverySeams(t, true, strings.TrimSpace(strings.Repeat("abandon ", 24)), nil)

	out, err := captureStdout(t, func() error { return cmdRecoveryGenerate([]string{dir}) })
	if err == nil {
		t.Fatal("a mismatched read-back must fail the command")
	}
	// The typed word/checksum error, not the generic mismatch.
	if !strings.Contains(err.Error(), "checksum does not match") {
		t.Fatalf("a word-shaped bad read-back must surface the typed checksum error; got %v", err)
	}
	if strings.Contains(err.Error(), "the recovery phrase did not match; nothing was written") {
		t.Fatalf("the generic wrong-secret message must NOT be used for a word-shaped input; got %v", err)
	}

	// The up-front password note.
	if !strings.Contains(out, "you'll be asked for the vault password") {
		t.Fatalf("recovery generate must print the password note; got redacted stdout {%s}", redactSecret(out))
	}
	// The compact base32 form label.
	if !strings.Contains(out, "Compact form (base32)") {
		t.Fatalf("recovery generate must show the compact form; got redacted stdout {%s}", redactSecret(out))
	}
	// 24 numbered word lines.
	wordLines := 0
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		if dot := strings.Index(s, ". "); dot > 0 {
			allDigits := true
			for _, r := range s[:dot] {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				wordLines++
			}
		}
	}
	if wordLines != 24 {
		t.Fatalf("recovery generate must show 24 numbered words; got %d in redacted stdout {%s}", wordLines, redactSecret(out))
	}

	// Nothing was committed (a mismatch aborts).
	cfg, err := vault.ReadConfig(dir)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, we := range cfg.WrapEntries {
		if we.Type == vault.WrapTypeRecovery {
			t.Fatal("a mismatched read-back must commit NO recovery key")
		}
	}
}

// TestNoOpenInertUnderPreset (M1): under --preset, --no-open changes nothing (it
// is never even read) and the "open the app" trailer is dropped either way.
func TestNoOpenInertUnderPreset(t *testing.T) {
	const pw = "preset-inert-pw"
	t.Setenv("SEAVAULT_PASSWORD", pw)

	home1 := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", home1)
	dirA := filepath.Join(t.TempDir(), "MyVault")
	outA, errA := captureStdout(t, func() error {
		return cmdSetup([]string{"--preset", "local", "--vault", dirA, "--no-keychain"})
	})
	if errA != nil {
		t.Fatalf("preset without --no-open must succeed: %v", errA)
	}

	home2 := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", home2)
	dirB := filepath.Join(t.TempDir(), "MyVault")
	outB, errB := captureStdout(t, func() error {
		return cmdSetup([]string{"--preset", "local", "--vault", dirB, "--no-keychain", "--no-open"})
	})
	if errB != nil {
		t.Fatalf("preset WITH --no-open must succeed identically: %v", errB)
	}

	// Normalise the only legitimate difference (the vault path) and compare.
	normA := strings.ReplaceAll(outA, dirA, "VAULT")
	normB := strings.ReplaceAll(outB, dirB, "VAULT")
	if normA != normB {
		t.Fatalf("--no-open must be inert under --preset; output differs:\nwithout:\n%s\nwith:\n%s", normA, normB)
	}
	if strings.Contains(outB, "Next: open it with") {
		t.Fatalf("the open-the-app trailer must be dropped under --preset; got:\n%s", outB)
	}
}
