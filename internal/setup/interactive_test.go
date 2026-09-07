// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// confirmRecord captures one Confirm call so a test can assert on the question
// and, crucially for I-S4 (C14), the defaultYes it was presented with.
type confirmRecord struct {
	question   string
	defaultYes bool
}

// scriptPrompter is the scripted Prompter the wizard tests drive with (design
// §3.2: "a queue of answers"). Each interaction type reads from its own queue;
// an exhausted or sentinel queue entry yields the offered default, modelling
// Enter-accepts-default. It RECORDS every Confirm call (question + defaultYes) so
// I-S4 can be asserted, and captures the shown recovery phrase so the recovery
// re-type can reflect it (a user who wrote it down and typed it back).
type scriptPrompter struct {
	t *testing.T

	selects  []int  // Select answers; a value <0 (or exhausted) means "the default"
	confirms []bool // Confirm answers; exhausted means "the default"
	texts    []string
	secrets  []string // Secret answers for the NON-recovery prompts (the password)

	// recoveryReType is called with the phrase captured from Show and returns
	// what to type at the recovery re-type gate. Nil reflects the phrase exactly
	// (a match).
	recoveryReType func(phrase string) string

	// recording / capture
	shown        []string
	confirmCalls []confirmRecord
	lastPhrase   string

	si, ci, ti, ei int
}

func (s *scriptPrompter) Select(title string, options []Option, defaultIdx int) (int, error) {
	if s.si < len(s.selects) {
		v := s.selects[s.si]
		s.si++
		if v < 0 || v >= len(options) {
			return defaultIdx, nil
		}
		return v, nil
	}
	return defaultIdx, nil
}

func (s *scriptPrompter) Confirm(question string, defaultYes bool) (bool, error) {
	s.confirmCalls = append(s.confirmCalls, confirmRecord{question: question, defaultYes: defaultYes})
	if s.ci < len(s.confirms) {
		v := s.confirms[s.ci]
		s.ci++
		return v, nil
	}
	return defaultYes, nil
}

func (s *scriptPrompter) Text(label, def string) (string, error) {
	if s.ti < len(s.texts) {
		v := s.texts[s.ti]
		s.ti++
		if strings.TrimSpace(v) == "" {
			return def, nil
		}
		return v, nil
	}
	return def, nil
}

func (s *scriptPrompter) Secret(label string) (string, error) {
	if strings.Contains(strings.ToLower(label), "recovery phrase") {
		if s.recoveryReType != nil {
			return s.recoveryReType(s.lastPhrase), nil
		}
		return s.lastPhrase, nil // reflect what was shown (a match)
	}
	if s.ei < len(s.secrets) {
		v := s.secrets[s.ei]
		s.ei++
		return v, nil
	}
	s.t.Fatalf("unexpected Secret(%q) with no queued answer", label)
	return "", nil
}

func (s *scriptPrompter) Show(msg string) {
	s.shown = append(s.shown, msg)
	if looksLikeRecoveryPhrase(msg) {
		s.lastPhrase = msg
	}
}

func (s *scriptPrompter) shownContains(sub string) bool {
	for _, m := range s.shown {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// looksLikeRecoveryPhrase recognises the one shown line that is the grouped
// recovery phrase: only base32 characters, dashes and spaces, canonicalising to
// exactly the 52-character phrase length. Prose lines (the intro, the caveat)
// carry lowercase and punctuation and never match.
func looksLikeRecoveryPhrase(s string) bool {
	n := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			n++
		case r == '-' || r == ' ':
		default:
			return false
		}
	}
	return n == 52
}

func countRecoveryEntries(t *testing.T, vaultDir string) int {
	t.Helper()
	cfg, err := vault.ReadConfig(vaultDir)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	n := 0
	for _, e := range cfg.WrapEntries {
		if e.Type == vault.WrapTypeRecovery {
			n++
		}
	}
	return n
}

// T2 (§3.2/§3.3): the scripted prompter drives every default. The wizard creates
// a vault that opens with the password, registers the profile exactly once, calls
// the keychain seam exactly once, presents the keychain question with
// defaultYes=true (I-S4, C14), runs the recovery ceremony to a committed key, and
// leaves NO secret in the Result or any shown line.
func TestRunInteractiveDefaultFlow(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Dropbox"), 0o755); err != nil {
		t.Fatal(err)
	}

	deps := testDeps()
	var keychainCalls, profileAdds int
	deps.KeychainSet = func(string, string) error { keychainCalls++; return nil }
	deps.ProfileAdd = func(string, string) error { profileAdds++; return nil }

	var openedProfile string
	pr := &scriptPrompter{
		t:       t,
		secrets: []string{testPassword, testPassword}, // choose + confirm
		// selects empty  -> location defaults to the single detected provider
		// confirms empty -> keychain=yes, recovery=now, open=yes (all defaults)
		// texts empty    -> the recovery save-path is skipped
		// recoveryReType nil -> the re-type reflects the shown phrase (a match)
	}
	opts := RunOptions{
		Home:    home,
		GOOS:    "linux",
		OpenApp: func(p string) error { openedProfile = p; return nil },
	}

	res, err := RunInteractive(pr, deps, opts)
	if err != nil {
		t.Fatalf("the default flow must succeed; got %v", err)
	}

	wantDir := filepath.Join(home, "Dropbox", defaultVaultName)
	if res.VaultDir != wantDir {
		t.Fatalf("vault dir = %q; want %q (inside the detected Dropbox folder)", res.VaultDir, wantDir)
	}
	if res.ProfileName != defaultVaultName {
		t.Fatalf("profile name = %q; want %q", res.ProfileName, defaultVaultName)
	}

	// The vault really opens with the typed password (real crypto).
	v, err := vault.Open(res.VaultDir, testPassword)
	if err != nil {
		t.Fatalf("the created vault must open with the password: %v", err)
	}
	if v.Config.VaultID != res.VaultID {
		t.Fatalf("Result.VaultID=%q but the vault holds %q", res.VaultID, v.Config.VaultID)
	}

	if profileAdds != 1 {
		t.Fatalf("the profile must be registered exactly once; ProfileAdd calls=%d", profileAdds)
	}

	// I-S4 (C14): the keychain question was presented, with defaultYes=true. This
	// is asserted before the downstream store so a flipped default surfaces here.
	var sawKeychainConfirm bool
	for _, c := range pr.confirmCalls {
		if strings.Contains(strings.ToLower(c.question), "keychain") {
			sawKeychainConfirm = true
			if !c.defaultYes {
				t.Fatalf("the keychain question must default to yes (I-S4); defaultYes=%v for %q", c.defaultYes, c.question)
			}
		}
	}
	if !sawKeychainConfirm {
		t.Fatal("I-S4: the keychain storage question must be presented as an explicit Confirm")
	}

	if keychainCalls != 1 {
		t.Fatalf("the keychain seam must be called exactly once; calls=%d", keychainCalls)
	}
	if !res.KeychainSaved {
		t.Fatal("KeychainSaved must be true after a successful keychain store")
	}

	// The recovery ceremony committed exactly one recovery key.
	if n := countRecoveryEntries(t, res.VaultDir); n != 1 {
		t.Fatalf("the default flow must commit exactly one recovery key; got %d", n)
	}
	if !strings.Contains(res.RecoveryNote, "recovery key was created") {
		t.Fatalf("RecoveryNote must confirm the key was created; got %q", res.RecoveryNote)
	}

	// I-S6: the detected provider's caveat was surfaced.
	if !pr.shownContains("Make available offline") {
		t.Fatalf("the Dropbox caveat must be shown when its folder is chosen; shown=%v", pr.shown)
	}

	// Step 5 opened the app for the created profile.
	if openedProfile != res.ProfileName {
		t.Fatalf("the open step must launch the created profile; opened %q, profile %q", openedProfile, res.ProfileName)
	}

	// I-S1: no secret in the Result or in any shown line.
	if strings.Contains(fmt.Sprintf("%+v", res), testPassword) {
		t.Fatal("the Result must not carry the password")
	}
	for _, m := range pr.shown {
		if strings.Contains(m, testPassword) {
			t.Fatalf("a shown line leaked the password: %q", m)
		}
	}
}

// T5 interactive half (§6): a recovery read-back mismatch writes NO recovery
// entry and the wizard still COMPLETES, deferring recovery with a reminder — the
// vault and profile survive.
func TestRunInteractiveRecoveryMismatchDefers(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Dropbox"), 0o755); err != nil {
		t.Fatal(err)
	}

	deps := testDeps()
	var profileAdds int
	deps.ProfileAdd = func(string, string) error { profileAdds++; return nil }

	pr := &scriptPrompter{
		t:       t,
		secrets: []string{testPassword, testPassword},
		// Confirm order: keychain=yes, recovery-decision=yes, synced-upload
		// check=yes, recovery try-again=NO (defer), open=no.
		confirms:       []bool{true, true, true, false, false},
		recoveryReType: func(string) string { return "these are not the right recovery words at all" },
	}

	res, err := RunInteractive(pr, deps, RunOptions{Home: home, GOOS: "linux"})
	if err != nil {
		t.Fatalf("a recovery mismatch must not fail the wizard; got %v", err)
	}
	if !vaultExists(res.VaultDir) {
		t.Fatal("the vault must still exist after a recovery mismatch")
	}
	if profileAdds != 1 {
		t.Fatalf("the profile must still be registered; ProfileAdd calls=%d", profileAdds)
	}
	if n := countRecoveryEntries(t, res.VaultDir); n != 0 {
		t.Fatalf("a recovery mismatch must write NO recovery entry; got %d", n)
	}
	if !strings.Contains(res.RecoveryNote, "No recovery key was set up") ||
		!strings.Contains(res.RecoveryNote, "recovery generate") {
		t.Fatalf("RecoveryNote must be the defer reminder naming the remedy; got %q", res.RecoveryNote)
	}
}

// T5 interactive half (§3.3 step 2 / §6): password confirmation mismatch is
// bounded — three tries, then a typed failure with NOTHING created (Execute never
// runs, so no vault dir appears).
func TestRunInteractivePasswordMismatchBounded(t *testing.T) {
	home := t.TempDir()
	vaultDir := filepath.Join(home, "custom-vault")

	deps := testDeps()
	var created int
	deps.CreateVault = func(dir, pw string, opts vault.CreateOptions) error {
		created++
		return testDeps().CreateVault(dir, pw, opts)
	}

	pr := &scriptPrompter{
		t: t,
		// No provider detected -> the location is a Text prompt.
		texts: []string{vaultDir},
		// Three mismatched choose/confirm pairs.
		secrets: []string{"aaaa", "bbbb", "aaaa", "bbbb", "aaaa", "bbbb"},
	}

	_, err := RunInteractive(pr, deps, RunOptions{Home: home, GOOS: "linux"})
	if err == nil {
		t.Fatal("three confirm mismatches must fail the wizard")
	}
	if !strings.Contains(err.Error(), "did not match") {
		t.Fatalf("the failure must name the mismatch; got %v", err)
	}
	if created != 0 {
		t.Fatalf("no vault may be created when the password never confirms; CreateVault calls=%d", created)
	}
	if vaultExists(vaultDir) {
		t.Fatal("no vault dir may exist after a bounded password failure")
	}
}
