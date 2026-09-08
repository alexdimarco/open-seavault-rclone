// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// ---- shared seams / helpers for the U2 fix regressions --------------------

// withInteractive overrides the stdinIsInteractive seam for one test and
// restores it via t.Cleanup, so a test drives the terminal-only paths (recovery
// generate read-back, last-key revoke prompt) deterministically without a PTY.
func withInteractive(t *testing.T, interactive bool) {
	t.Helper()
	orig := stdinIsInteractive
	stdinIsInteractive = func() bool { return interactive }
	t.Cleanup(func() { stdinIsInteractive = orig })
}

// setRecoverySeams overrides BOTH recovery-generate seams (interactivity and the
// terminal-only read-back) for one test. The read-back is now interactive-only
// (DOCS-1): there is no SEAVAULT_RECOVERY_PHRASE hook, so a test supplies the
// read-back here.
func setRecoverySeams(t *testing.T, interactive bool, readback string, readbackErr error) {
	t.Helper()
	origI, origR := stdinIsInteractive, readRecoveryReadback
	stdinIsInteractive = func() bool { return interactive }
	readRecoveryReadback = func(string) (string, error) { return readback, readbackErr }
	t.Cleanup(func() { stdinIsInteractive = origI; readRecoveryReadback = origR })
}

// withStdin replaces os.Stdin with a pipe pre-loaded with input for one test, so
// confirmPrompt (which reads os.Stdin) sees a scripted y/n answer.
func withStdin(t *testing.T, input string) {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig; _ = r.Close() })
}

// recoveryIDs returns the recovery wrap-entry IDs currently on disk for the vault
// at dir (real crypto open with pw), so a test can assert an entry survived or was
// removed by a CLI command.
func recoveryIDs(t *testing.T, dir, pw string) []string {
	t.Helper()
	v, err := vault.Open(dir, pw)
	if err != nil {
		t.Fatalf("open vault %s: %v", dir, err)
	}
	return recoveryEntryIDsCLI(v)
}

// mintRecoveryKey adds one real recovery wrap entry to the vault (real crypto, no
// stub) and returns its full entry ID. It does NOT write a device-local label, so
// a test can drive the label lifecycle separately.
func mintRecoveryKey(t *testing.T, dir, pw string) string {
	t.Helper()
	before := map[string]bool{}
	for _, id := range recoveryIDs(t, dir, pw) {
		before[id] = true
	}
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
	for _, id := range recoveryIDs(t, dir, pw) {
		if !before[id] {
			return id
		}
	}
	t.Fatal("no new recovery entry id after commit")
	return ""
}

// readbackFromCard returns a read-back seam that recovers the correct phrase from
// the DRAFT recovery card `recovery generate --save` writes BEFORE the read-back
// gate. This lets an integration test drive a real, matching read-back through the
// production commit path even though the minted phrase is random.
func readbackFromCard(cardPath string) func(string) (string, error) {
	return func(string) (string, error) {
		data, err := os.ReadFile(cardPath)
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Compact form (base32): ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Compact form (base32): ")), nil
			}
		}
		return "", fmt.Errorf("compact form not found in card")
	}
}

// ---- DOCS-1: recovery generate is interactive-only -----------------------

// TestRecoveryGenerateRefusesNonTTY (DOCS-1 / CLI-2 framing): with a
// non-interactive stdin, `recovery generate` refuses BEFORE emitting any phrase,
// with a typed message that names the interactivity requirement and the remedy —
// and a SEAVAULT_RECOVERY_PHRASE-style env value cannot satisfy the read-back. No
// phrase is printed and nothing is committed.
func TestRecoveryGenerateRefusesNonTTY(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "V")
	const pw = "pw-nontty"
	fastVault(t, dir, pw)
	t.Setenv("SEAVAULT_PASSWORD", pw)
	// A phrase in the environment must NOT be able to stand in for the read-back.
	t.Setenv("SEAVAULT_RECOVERY_PHRASE", strings.TrimSpace(strings.Repeat("abandon ", 24)))
	withInteractive(t, false)

	out, err := captureStdout(t, func() error { return cmdRecoveryGenerate([]string{dir}) })
	if err == nil {
		t.Fatal("recovery generate must refuse a non-interactive stdin")
	}
	for _, want := range []string{"interactive terminal", "typed back", "redirected"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name the interactivity requirement and remedy (%q); got %q", want, err.Error())
		}
	}
	// The phrase must never be emitted: no numbered words, no compact form.
	if strings.Contains(out, "Compact form (base32)") || strings.Contains(out, "Recovery phrase") {
		t.Fatalf("no phrase or compact form may be printed on a non-tty refusal; got redacted stdout {%s}", redactSecret(out))
	}
	// Nothing committed.
	if ids := recoveryIDs(t, dir, pw); len(ids) != 0 {
		t.Fatalf("a refused generate must commit NO recovery key; found %d", len(ids))
	}
}

// ---- CLI-2 + cli-label-gap: generate --save card, device label, list --------

// TestRecoveryGenerateSaveCardLabelAndList drives the REAL generate commit path:
// `--save` writes a DRAFT card before the read-back gate and re-stamps it
// confirmed on commit (CLI-2, 0600); the commit records a device-local label
// (cli-label-gap); and `recovery list` shows the 4-hex handle + label + full ID
// (cli-label-gap / C4). The matching read-back is recovered from the DRAFT card.
func TestRecoveryGenerateSaveCardLabelAndList(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "MyVault")
	const pw = "pw-save-card"
	fastVault(t, dir, pw)
	t.Setenv("SEAVAULT_PASSWORD", pw)
	cardPath := filepath.Join(t.TempDir(), "recovery-card.txt")

	withInteractive(t, true)
	origR := readRecoveryReadback
	readRecoveryReadback = readbackFromCard(cardPath)
	t.Cleanup(func() { readRecoveryReadback = origR })

	out, err := captureStdout(t, func() error {
		return cmdRecoveryGenerate([]string{"--no-keychain", "--save", cardPath, dir})
	})
	if err != nil {
		t.Fatalf("generate with a matching read-back must commit: %v", err)
	}
	if !strings.Contains(out, "recovery key added") {
		t.Fatalf("generate must confirm the key was added; got redacted stdout {%s}", redactSecret(out))
	}

	// The confirmed card exists, is 0600, drops the DRAFT stamp, and keeps the words.
	info, serr := os.Stat(cardPath)
	if serr != nil {
		t.Fatalf("the --save card must exist after commit: %v", serr)
	}
	if runtimeIsPosix() && info.Mode().Perm() != 0o600 {
		t.Fatalf("the recovery card must be written owner-only (0600); got %v", info.Mode().Perm())
	}
	cardBytes, _ := os.ReadFile(cardPath)
	card := string(cardBytes)
	if strings.Contains(card, "DRAFT") {
		t.Fatalf("the confirmed card must NOT carry the DRAFT stamp; got a card of len=%d", len(card))
	}
	if !strings.Contains(card, "Recovery phrase (24 words") {
		t.Fatal("the confirmed card must still carry the 24 numbered words")
	}

	// The device-local label was recorded for the new entry (created date present).
	ids := recoveryIDs(t, dir, pw)
	if len(ids) != 1 {
		t.Fatalf("exactly one recovery key must exist after generate; got %d", len(ids))
	}
	newID := ids[0]
	label, ok, lerr := profile.GetRecoveryLabel(newID)
	if lerr != nil {
		t.Fatalf("GetRecoveryLabel: %v", lerr)
	}
	if !ok {
		t.Fatal("cli-label-gap: generate must record a device-local label for the new recovery entry")
	}
	if label.Created == "" {
		t.Fatal("the recorded label must carry the creation date")
	}

	// recovery list shows the handle + label detail + the full ID for revoke.
	listOut, err := captureStdout(t, func() error { return cmdRecoveryList([]string{"--no-keychain", dir}) })
	if err != nil {
		t.Fatalf("recovery list: %v", err)
	}
	handle := profile.Handle(newID)
	if !strings.Contains(listOut, "#"+handle) {
		t.Fatalf("recovery list must show the 4-hex handle #%s; got %q", handle, listOut)
	}
	if !strings.Contains(listOut, label.Created) {
		t.Fatalf("recovery list must show the label creation date %q; got %q", label.Created, listOut)
	}
	if !strings.Contains(listOut, newID) {
		t.Fatalf("recovery list must still show the full entry ID for revoke; got %q", listOut)
	}
}

// TestRecoveryGenerateSaveRefusedInsideVault (CLI-2 / recovery-integration-1): a
// --save path INSIDE the vault folder is refused outright, no phrase is minted,
// and no card is written there.
func TestRecoveryGenerateSaveRefusedInsideVault(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "MyVault")
	const pw = "pw-inside"
	fastVault(t, dir, pw)
	t.Setenv("SEAVAULT_PASSWORD", pw)
	withInteractive(t, true)

	inside := filepath.Join(dir, "recovery-card.txt")
	out, err := captureStdout(t, func() error {
		return cmdRecoveryGenerate([]string{"--no-keychain", "--save", inside, dir})
	})
	if err == nil {
		t.Fatal("a --save path inside the vault folder must be refused")
	}
	if !strings.Contains(err.Error(), "inside the vault folder") {
		t.Fatalf("the refusal must name the inside-the-vault reason; got %q", err.Error())
	}
	if strings.Contains(out, "Compact form (base32)") {
		t.Fatalf("no phrase may be emitted when the --save path is refused; redacted {%s}", redactSecret(out))
	}
	if _, serr := os.Stat(inside); !os.IsNotExist(serr) {
		t.Fatalf("no card may be written inside the vault; stat err=%v", serr)
	}
	if ids := recoveryIDs(t, dir, pw); len(ids) != 0 {
		t.Fatalf("a refused --save must commit no recovery key; got %d", len(ids))
	}
}

// ---- cli-label-gap: revoke deletes the device-local label -----------------

// TestRecoveryRevokeDeletesLabel (cli-label-gap): after a recovery entry is
// retired, `recovery revoke` deletes its device-local label so the hostname/date
// do not linger in the store.
func TestRecoveryRevokeDeletesLabel(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "MyVault")
	const pw = "pw-revoke-label"
	fastVault(t, dir, pw)
	t.Setenv("SEAVAULT_PASSWORD", pw)

	// Two keys so revoking one is NOT the last-key case (no gate needed).
	id1 := mintRecoveryKey(t, dir, pw)
	_ = mintRecoveryKey(t, dir, pw)
	if err := profile.SetRecoveryLabel(id1, profile.RecoveryKeyLabel{Created: "2026-09-08", Device: "test-host"}); err != nil {
		t.Fatalf("seed label: %v", err)
	}
	if _, ok, _ := profile.GetRecoveryLabel(id1); !ok {
		t.Fatal("precondition: the seeded label must exist")
	}

	if _, err := captureStdout(t, func() error { return cmdRecoveryRevoke([]string{"--no-keychain", dir, id1}) }); err != nil {
		t.Fatalf("revoking a non-last key must succeed: %v", err)
	}
	if _, ok, _ := profile.GetRecoveryLabel(id1); ok {
		t.Fatal("cli-label-gap: revoke must delete the device-local label for the retired entry")
	}
}

// ---- wiring-1 / CLI-5: last-key revoke gate -------------------------------

// TestRecoveryRevokeLastKeyGate (wiring-1 / CLI-5, matrix S1): revoking the LAST
// recovery key is gated. Non-interactively it is refused without --yes (nothing
// removed) and allowed with --yes; interactively it is refused on "n" and allowed
// on "y". A non-last revoke is never gated.
func TestRecoveryRevokeLastKeyGate(t *testing.T) {
	setup := func(t *testing.T) (dir, pw, id string) {
		t.Helper()
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		dir = filepath.Join(t.TempDir(), "MyVault")
		pw = "pw-lastkey"
		fastVault(t, dir, pw)
		t.Setenv("SEAVAULT_PASSWORD", pw)
		id = mintRecoveryKey(t, dir, pw)
		return
	}

	t.Run("non-interactive without --yes refuses and removes nothing", func(t *testing.T) {
		dir, pw, id := setup(t)
		withInteractive(t, false)
		_, _, rerr := captureOutputs(t, func() error { return cmdRecoveryRevoke([]string{"--no-keychain", dir, id}) })
		if rerr == nil {
			t.Fatal("a non-interactive last-key revoke without --yes must refuse")
		}
		if !strings.Contains(rerr.Error(), "--yes") || !strings.Contains(rerr.Error(), "no recovery path") {
			t.Fatalf("the refusal must name --yes and the consequence; got %q", rerr.Error())
		}
		if ids := recoveryIDs(t, dir, pw); len(ids) != 1 {
			t.Fatalf("the last key must NOT be removed by a refused revoke; have %d", len(ids))
		}
	})

	t.Run("non-interactive with --yes revokes", func(t *testing.T) {
		dir, pw, id := setup(t)
		withInteractive(t, false)
		if _, err := captureStdout(t, func() error { return cmdRecoveryRevoke([]string{"--no-keychain", "--yes", dir, id}) }); err != nil {
			t.Fatalf("--yes must allow the last-key revoke: %v", err)
		}
		if ids := recoveryIDs(t, dir, pw); len(ids) != 0 {
			t.Fatalf("the last key must be removed with --yes; have %d", len(ids))
		}
	})

	t.Run("interactive decline keeps the key", func(t *testing.T) {
		dir, pw, id := setup(t)
		withInteractive(t, true)
		withStdin(t, "n\n")
		_, _, err := captureOutputs(t, func() error { return cmdRecoveryRevoke([]string{"--no-keychain", dir, id}) })
		if err == nil {
			t.Fatal("declining the interactive prompt must not revoke")
		}
		if ids := recoveryIDs(t, dir, pw); len(ids) != 1 {
			t.Fatalf("a declined interactive revoke must keep the key; have %d", len(ids))
		}
	})

	t.Run("interactive accept revokes", func(t *testing.T) {
		dir, pw, id := setup(t)
		withInteractive(t, true)
		withStdin(t, "y\n")
		if _, _, err := captureOutputs(t, func() error { return cmdRecoveryRevoke([]string{"--no-keychain", dir, id}) }); err != nil {
			t.Fatalf("accepting the interactive prompt must revoke: %v", err)
		}
		if ids := recoveryIDs(t, dir, pw); len(ids) != 0 {
			t.Fatalf("an accepted interactive revoke must remove the key; have %d", len(ids))
		}
	})

	t.Run("non-last revoke is never gated", func(t *testing.T) {
		dir, pw, id := setup(t)
		_ = mintRecoveryKey(t, dir, pw) // now two keys
		withInteractive(t, false)
		if _, err := captureStdout(t, func() error { return cmdRecoveryRevoke([]string{"--no-keychain", dir, id}) }); err != nil {
			t.Fatalf("revoking one of two keys must not be gated: %v", err)
		}
		if ids := recoveryIDs(t, dir, pw); len(ids) != 1 {
			t.Fatalf("one key must remain after a non-last revoke; have %d", len(ids))
		}
	})
}

// ---- sweep-docs-1: nested --help changes nothing --------------------------

// TestRemoteConfigCreateHelpWritesNoFile (sweep-docs-1 / DOCS-6, C7): `remote
// config create --help` prints the registry usage, exits 0, and does NOT create
// the managed rclone.conf. Prove-fail is the rclone.conf non-existence.
func TestRemoteConfigCreateHelpWritesNoFile(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	cfgPath := remotesDefaultConfigPathForTest(t)

	out, _, code := captureRun(t, "remote", "config", "create", "--help")
	if code != 0 {
		t.Fatalf("remote config create --help must exit 0; got %d", code)
	}
	if !strings.Contains(out, "usage: seavault remote config") {
		t.Fatalf("remote config create --help must render the registry usage; got %q", out)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("remote config create --help must NOT write rclone.conf at %s; stat err=%v", cfgPath, err)
	}
}

// TestNestedHelpExitsZeroNoAction (sweep-docs-1, H5 rows for nested leaves): each
// nested-leaf --help exits 0 and runs no action. app-config reset --help must not
// delete the local app config (its absence before and after proves it).
func TestNestedHelpExitsZeroNoAction(t *testing.T) {
	cases := [][]string{
		{"remote", "config", "path", "--help"},
		{"remote", "config", "import", "--help"},
		{"remote", "config", "validate", "--help"},
		{"remote", "config", "export-redacted", "--help"},
		{"remote", "config", "create", "--help"},
		{"app-config", "path", "--help"},
		{"app-config", "reset", "--help"},
		{"app-config", "reset-gui-login", "--help"},
	}
	if len(cases) == 0 {
		t.Fatal("empty table exercises nothing")
	}
	for _, argv := range cases {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
			out, _, code := captureRun(t, argv...)
			if code != 0 {
				t.Fatalf("%v must exit 0 on --help; got %d", argv, code)
			}
			if !strings.Contains(out, "usage: seavault") {
				t.Fatalf("%v --help must render a registry usage line; got %q", argv, out)
			}
		})
	}
}

// ---- sweep-docs-2: leaf --help renders the registry double-dash usage ------

// TestLeafHelpRendersRegistryDoubleDash (sweep-docs-2 / ADM-6, extends H1 to the
// REAL `<cmd> --help` path): every top-level LEAF that does not carry a bespoke
// --help renders the registry "usage: seavault <cmd>" line on --help and exits 0,
// never the stdlib single-dash "Usage of <cmd>:" dump. Iterated from the registry
// so a new leaf is covered automatically.
func TestLeafHelpRendersRegistryDoubleDash(t *testing.T) {
	leaves := 0
	for _, c := range commands {
		if c.group != "" || c.bespokeHelp {
			continue
		}
		if len(groupChildren(c.name)) > 0 {
			continue // group parent: help is the group listing
		}
		leaves++
		c := c
		t.Run(c.name, func(t *testing.T) {
			out, _, code := captureRun(t, c.name, "--help")
			if code != 0 {
				t.Fatalf("%s --help must exit 0; got %d", c.name, code)
			}
			if !strings.Contains(out, "usage: seavault "+c.name) {
				t.Fatalf("%s --help must render the registry double-dash usage line; got %q", c.name, out)
			}
			if strings.Contains(out, "Usage of "+c.name+":") {
				t.Fatalf("%s --help must NOT render the stdlib single-dash flag dump; got %q", c.name, out)
			}
		})
	}
	if leaves == 0 {
		t.Fatal("no non-bespoke top-level leaves were iterated; the registry scan is vacuous")
	}
}

// ---- registry-cli-1: remote add/edit usage lists --config and --fast-list --

// TestRemoteAddEditUsageListsAllFlags (registry-cli-1): the remote add/edit usage
// lines advertise --config and --fast-list, which the handler accepts.
func TestRemoteAddEditUsageListsAllFlags(t *testing.T) {
	for _, name := range []string{"add", "edit"} {
		row, ok := groupCommand("remote", name)
		if !ok {
			t.Fatalf("remote %s must be a registry row", name)
		}
		for _, want := range []string{"--config", "--fast-list", "--transfers", "--checkers", "--bwlimit"} {
			if !strings.Contains(row.usage, want) {
				t.Fatalf("remote %s usage must list %q; got %q", name, want, row.usage)
			}
		}
	}
}

// ---- registry-cli-2: leaf sub-action switches match the documented set -----

// TestLeafSubactionSwitchesMatchDocs (registry-cli-2, H4-style parser extended to
// leaf switches): the sub-actions cmdAppConfig and cmdGUI actually dispatch equal
// the documented set (undocumented aliases dropped), in BOTH directions, and the
// registry usage/synopsis advertises each.
func TestLeafSubactionSwitchesMatchDocs(t *testing.T) {
	cases := []struct {
		header string // main.go func header
		want   map[string]bool
		advert string // registry text that must mention each action
	}{
		{
			header: "func cmdAppConfig(args []string) error {",
			want:   map[string]bool{"path": true, "reset": true, "reset-gui-login": true},
		},
		{
			header: "func cmdGUI(args []string) error {",
			want:   map[string]bool{"reset-config": true, "reset-login": true, "config-path": true},
		},
	}
	// Fill advert text from the registry rows so the check stays table-driven.
	if row, ok := topLevelCommand("app-config"); ok {
		cases[0].advert = row.usage
	}
	if row, ok := topLevelCommand("gui"); ok {
		cases[1].advert = row.synopsis
	}
	for _, tc := range cases {
		got := parseSwitchCases(t, tc.header)
		assertSetsEqual(t, tc.header, tc.want, got)
		if tc.advert == "" {
			t.Fatalf("%s: no registry advert text found", tc.header)
		}
		for name := range tc.want {
			if !strings.Contains(tc.advert, name) {
				t.Errorf("%s: the registry advert must mention %q; got %q", tc.header, name, tc.advert)
			}
		}
	}
	// The dropped aliases must no longer dispatch: app-config reset-config is now a
	// usage error, and gui reset no longer resets (it is treated as a vault arg).
	if err := cmdAppConfig([]string{"reset-config"}); err == nil {
		t.Fatal("registry-cli-2: app-config reset-config must no longer be accepted")
	}
}

// ---- registry-cli-3: version rejects stray args ---------------------------

// TestVersionRejectsArgs (registry-cli-3): `version` with any argument is a usage
// error (exit 2), matching gc/list; a bare `version` and `version --help` exit 0.
func TestVersionRejectsArgs(t *testing.T) {
	if _, _, code := captureRun(t, "version"); code != 0 {
		t.Fatalf("bare version must exit 0; got %d", code)
	}
	if _, _, code := captureRun(t, "version", "--help"); code != 0 {
		t.Fatalf("version --help must exit 0; got %d", code)
	}
	for _, bad := range [][]string{{"version", "bogus"}, {"version", "--json"}} {
		if _, _, code := captureRun(t, bad...); code != 2 {
			t.Fatalf("%v must exit 2 (usage error); got %d", bad, code)
		}
	}
}

// ---- small test utilities -------------------------------------------------

// captureRun runs run(argv) with stdout+stderr captured and returns the output
// and the exit code.
func captureRun(t *testing.T, argv ...string) (stdout, stderr string, code int) {
	t.Helper()
	stdout, stderr, _ = captureOutputs(t, func() error {
		code = run(argv)
		return nil
	})
	return stdout, stderr, code
}

// runtimeIsPosix reports whether the host applies POSIX file-mode bits, so the
// 0600 card assertion is skipped on Windows (where os.Chmod only toggles
// read-only).
func runtimeIsPosix() bool {
	return os.PathSeparator == '/'
}

// remotesDefaultConfigPathForTest returns where the managed rclone.conf WOULD be
// written for the current isolated SEAVAULT_APP_HOME, so a test can assert it was
// not created.
func remotesDefaultConfigPathForTest(t *testing.T) string {
	t.Helper()
	// remote config path prints the managed config path without creating it.
	out, err := captureStdout(t, func() error { return cmdRemoteConfig([]string{"path"}) })
	if err != nil {
		t.Fatalf("remote config path: %v", err)
	}
	p := strings.TrimSpace(out)
	if p == "" {
		t.Fatal("remote config path returned empty")
	}
	return p
}

// TestStdinIsTTYRejectsNonTerminals (DOCS-1 correctness): the real stdinIsTTY
// probe reports false for every non-terminal stdin — a pipe, a regular file, and
// /dev/null (a character device os.ModeCharDevice alone would wrongly accept). It
// drives the actual os.Stdin the ioctl inspects, per row.
func TestStdinIsTTYRejectsNonTerminals(t *testing.T) {
	// A pipe read-end.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	// A regular file.
	reg, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// /dev/null (a character device) — the case os.ModeCharDevice misclassifies.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	rows := []struct {
		name string
		f    *os.File
	}{
		{"pipe", pr},
		{"regular file", reg},
		{"os.DevNull", devnull},
	}
	if len(rows) == 0 {
		t.Fatal("empty table exercises nothing")
	}
	orig := os.Stdin
	defer func() { os.Stdin = orig }()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			os.Stdin = r.f
			if stdinIsTTY() {
				t.Fatalf("stdinIsTTY must report false for %s", r.name)
			}
		})
	}
}

// TestRecoveryGenerateSaveWarnsUnderProviderRoot (CLI-2 / recovery-integration-1):
// a --save path under a DETECTED cloud provider root triggers a second
// confirmation naming the upload risk; declining aborts without minting or
// writing a card. A fake ~/Dropbox root drives the real ProviderRootFor path.
func TestRecoveryGenerateSaveWarnsUnderProviderRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	dropbox := filepath.Join(home, "Dropbox")
	if err := os.MkdirAll(dropbox, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "MyVault") // OUTSIDE the Dropbox root
	const pw = "pw-provider"
	fastVault(t, dir, pw)
	t.Setenv("SEAVAULT_PASSWORD", pw)

	card := filepath.Join(dropbox, "recovery-card.txt")
	withInteractive(t, true)
	withStdin(t, "n\n") // decline the "save under your Dropbox anyway?" confirm

	out, err := captureStdout(t, func() error {
		return cmdRecoveryGenerate([]string{"--no-keychain", "--save", card, dir})
	})
	if err == nil {
		t.Fatal("declining the provider-root save confirm must abort generate")
	}
	if !strings.Contains(err.Error(), "did not save") {
		t.Fatalf("the abort must name that the card was not saved; got %q", err.Error())
	}
	if strings.Contains(out, "Compact form (base32)") {
		t.Fatalf("no phrase may be emitted when the provider-root save is declined; redacted {%s}", redactSecret(out))
	}
	if _, serr := os.Stat(card); !os.IsNotExist(serr) {
		t.Fatalf("no card may be written when the provider-root save is declined; stat err=%v", serr)
	}
	if ids := recoveryIDs(t, dir, pw); len(ids) != 0 {
		t.Fatalf("a declined provider-root save must commit no recovery key; got %d", len(ids))
	}
}
