// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countShown returns how many shown lines contain sub.
func countShown(shown []string, sub string) int {
	n := 0
	for _, m := range shown {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// TestCaveatShownExactlyOnce (H2 — "caveat once", CLI-2): in an accept-defaults
// interactive run that lands inside a detected Dropbox folder, the provider
// caveat text is shown EXACTLY once across all output (no Select+pr.Show double
// and no summary repeat), while the Result still carries CaveatNote for the GUI
// and --preset callers.
func TestCaveatShownExactlyOnce(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Dropbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	pr := &scriptPrompter{
		t:       t,
		secrets: []string{testPassword, testPassword},
		// selects empty -> the single detected Dropbox folder is chosen.
		// confirms empty -> recovery-decision=yes, synced-upload=yes, open=yes.
		// recoveryReType nil -> the re-type matches; ceremony commits.
	}
	res, err := RunInteractive(pr, testDeps(), RunOptions{
		Home: home, GOOS: "linux", NoKeychain: true, NoOpen: true,
	})
	if err != nil {
		t.Fatalf("the accept-defaults Dropbox flow must succeed; got %v", err)
	}
	// The exact caveat substring the Dropbox catalog entry carries.
	const marker = "Make available offline"
	if got := countShown(pr.shown, marker); got != 1 {
		t.Fatalf("the provider caveat must be shown exactly once; got %d occurrences in shown=%v", got, pr.shown)
	}
	if res.CaveatNote != Caveat(ProviderDropbox) {
		t.Fatalf("the Result must still carry the Dropbox caveat for the GUI/preset callers; got %q", res.CaveatNote)
	}
}

// TestStripLeadingNoteLabel (H2 — "no doubled Note", CLI-2): a preflight note
// that already begins with "note:" is rendered under the summary's "Note:" label
// without doubling into "Note: note:".
func TestStripLeadingNoteLabel(t *testing.T) {
	rows := []struct {
		in, want string
	}{
		{"note: keep the folder available offline", "keep the folder available offline"},
		{"Note: something", "something"},
		{"no prefix here", "no prefix here"},
	}
	if len(rows) == 0 {
		t.Fatal("empty table exercises nothing")
	}
	for _, r := range rows {
		if got := stripLeadingNoteLabel(r.in); got != r.want {
			t.Fatalf("stripLeadingNoteLabel(%q)=%q want %q", r.in, got, r.want)
		}
	}

	// Through SummaryLines: the rendered Note line must not contain a lowercase
	// "note:" after the label.
	res := Result{VaultDir: "/v", ProfileName: "p", PreflightNote: "note: new vaults keep their data in SeaVaultData"}
	var noteLine string
	for _, line := range SummaryLines(res, false, true) {
		if strings.Contains(line, "Note:") {
			noteLine = line
		}
	}
	if noteLine == "" {
		t.Fatal("SummaryLines must render a Note line for a set PreflightNote")
	}
	if strings.Contains(noteLine, "note:") {
		t.Fatalf("the Note line must not double the label into \"Note: note:\"; got %q", noteLine)
	}
	if !strings.Contains(noteLine, "new vaults keep their data") {
		t.Fatalf("the Note line must keep the note body; got %q", noteLine)
	}
}

// TestKeychainFailureIsPlainWithSeparateDetail (H2 — CLI-1): a keychain-store
// failure yields a PLAIN summary one-liner (no raw exec error, but the pasteable
// remedy) while the raw error is preserved separately in KeychainErrDetail for
// --debug.
func TestKeychainFailureIsPlainWithSeparateDetail(t *testing.T) {
	deps := testDeps()
	const raw = "secret-tool: exit status 1: no keyring daemon"
	deps.KeychainSet = func(string, string) error { return errors.New(raw) }
	plan := Plan{VaultDir: filepath.Join(t.TempDir(), "vault"), SaveKeychain: true, Cloud: LocalOnly{}}
	res, err := Execute(plan, testPassword, deps)
	if err != nil {
		t.Fatalf("a keychain failure must not fail Execute; got %v", err)
	}
	if strings.Contains(res.KeychainNote, raw) || strings.Contains(res.KeychainNote, "secret-tool") {
		t.Fatalf("the plain summary one-liner must NOT carry the raw exec error; got %q", res.KeychainNote)
	}
	if !strings.Contains(res.KeychainNote, "seavault keychain store") {
		t.Fatalf("the plain one-liner must still name the pasteable remedy; got %q", res.KeychainNote)
	}
	if res.KeychainErrDetail != raw {
		t.Fatalf("the raw error must be preserved in KeychainErrDetail for --debug; got %q want %q", res.KeychainErrDetail, raw)
	}
}

// TestSummaryOpenTrailerSuppressed (H2/M1 — ADM-1): offerOpen=false drops the
// "Next: open it with …" trailer (a scripted --preset fleet run never launches
// the GUI), while offerOpen=true keeps it.
func TestSummaryOpenTrailerSuppressed(t *testing.T) {
	res := Result{VaultDir: "/v", ProfileName: "p"}
	withHint := strings.Join(SummaryLines(res, false, true), "\n")
	if !strings.Contains(withHint, "Next: open it with") {
		t.Fatalf("offerOpen=true must keep the open trailer; got:\n%s", withHint)
	}
	noHint := strings.Join(SummaryLines(res, false, false), "\n")
	if strings.Contains(noHint, "Next: open it with") {
		t.Fatalf("offerOpen=false must drop the open trailer; got:\n%s", noHint)
	}
}

// TestRecoveryCardTextStamp (§2.5/C6): the draft card carries the DRAFT stamp and
// the confirmed card does not; both carry the words and the compact form.
func TestRecoveryCardTextStamp(t *testing.T) {
	words := []string{"abandon", "ability", "able"}
	const compact = "AAAA-BBBB-CCCC"
	draft := recoveryCardText("MyVault", words, compact, false, true)
	confirmed := recoveryCardText("MyVault", words, compact, false, false)
	if !strings.Contains(draft, recoveryDraftStamp) {
		t.Fatalf("the draft card must carry the DRAFT stamp; got:\n%s", draft)
	}
	if strings.Contains(confirmed, recoveryDraftStamp) {
		t.Fatalf("the confirmed card must NOT carry the DRAFT stamp; got:\n%s", confirmed)
	}
	for _, c := range []string{draft, confirmed} {
		if !strings.Contains(c, compact) {
			t.Fatalf("every card must carry the compact form; got:\n%s", c)
		}
		if !strings.Contains(c, "abandon") {
			t.Fatalf("every card must carry the words; got:\n%s", c)
		}
	}
}

// dropboxHome builds a home with a detected Dropbox folder so the location step
// pre-answers a SyncedFolder and the recovery ceremony runs.
func dropboxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Dropbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestRecoveryCeremonyShowsWordsAndCompact (§2.5): the wizard show-once step lists
// the 24 numbered words AND the compact base32 form.
func TestRecoveryCeremonyShowsWordsAndCompact(t *testing.T) {
	home := dropboxHome(t)
	pr := &scriptPrompter{
		t:       t,
		secrets: []string{testPassword, testPassword},
		// recoveryReType nil -> match -> commit.
	}
	res, err := RunInteractive(pr, testDeps(), RunOptions{Home: home, GOOS: "linux", NoKeychain: true, NoOpen: true})
	if err != nil {
		t.Fatalf("the ceremony must succeed; got %v", err)
	}
	// 24 numbered word lines ("   1. word") were shown.
	wordLines := 0
	for _, m := range pr.shown {
		s := strings.TrimSpace(m)
		if len(s) > 3 && s[0] >= '1' && s[0] <= '9' && strings.Contains(s, ". ") {
			// crude but sufficient: a line like "1. abandon" / "24. word".
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
	}
	if wordLines != 24 {
		t.Fatalf("the ceremony must show 24 numbered word lines; got %d (shown=%v)", wordLines, pr.shown)
	}
	if !pr.shownContains("Compact form (base32)") {
		t.Fatalf("the ceremony must show the compact base32 form label; shown=%v", pr.shown)
	}
	if n := countRecoveryEntries(t, res.VaultDir); n != 1 {
		t.Fatalf("the ceremony must commit exactly one recovery key; got %d", n)
	}
}

// TestRecoverySaveCardDraftRewrittenOnCommit (§2.5/C6): the saved card is stamped
// DRAFT while written before the read-back, then RE-WRITTEN without the stamp
// once the read-back commits.
func TestRecoverySaveCardDraftRewrittenOnCommit(t *testing.T) {
	home := dropboxHome(t)
	savePath := filepath.Join(t.TempDir(), "recovery-card.txt")
	pr := &scriptPrompter{
		t:       t,
		secrets: []string{testPassword, testPassword},
		texts:   []string{savePath},
		// recoveryReType nil -> match -> commit.
	}
	res, err := RunInteractive(pr, testDeps(), RunOptions{Home: home, GOOS: "linux", NoKeychain: true, NoOpen: true})
	if err != nil {
		t.Fatalf("the recovery-save flow must succeed; got %v", err)
	}
	if n := countRecoveryEntries(t, res.VaultDir); n != 1 {
		t.Fatalf("the re-type gate must still commit a key; got %d", n)
	}
	data, rerr := os.ReadFile(savePath)
	if rerr != nil {
		t.Fatalf("the save-to-file branch must write the card: %v", rerr)
	}
	if strings.Contains(string(data), recoveryDraftStamp) {
		t.Fatalf("after commit the card must be re-written WITHOUT the DRAFT stamp; got:\n%s", string(data))
	}
	if strings.TrimSpace(pr.lastPhrase) == "" || !strings.Contains(string(data), pr.lastPhrase) {
		t.Fatalf("the confirmed card must still contain the shown phrase; file=%q phrase=%q", string(data), pr.lastPhrase)
	}
}

// TestRecoverySaveCardKeepsDraftOnDefer (§2.5/C6): a card written before the gate
// that never commits (a mismatch, then decline-retry) KEEPS its DRAFT stamp, so a
// printed-early card is honestly marked unconfirmed.
func TestRecoverySaveCardKeepsDraftOnDefer(t *testing.T) {
	home := dropboxHome(t)
	savePath := filepath.Join(t.TempDir(), "recovery-card.txt")
	pr := &scriptPrompter{
		t:       t,
		secrets: []string{testPassword, testPassword},
		texts:   []string{savePath},
		// synced-upload=yes; retry-after-mismatch=no (defer); delete-abandoned=no.
		confirms:       []bool{true, true, false, false},
		recoveryReType: func(string) string { return "totally wrong phrase not matching" },
	}
	res, err := RunInteractive(pr, testDeps(), RunOptions{Home: home, GOOS: "linux", NoKeychain: true, NoOpen: true})
	if err != nil {
		t.Fatalf("a deferred recovery must still return a created vault; got err %v", err)
	}
	if n := countRecoveryEntries(t, res.VaultDir); n != 0 {
		t.Fatalf("a mismatch must commit NO recovery key; got %d", n)
	}
	data, rerr := os.ReadFile(savePath)
	if rerr != nil {
		t.Fatalf("the card file must exist (it was offered for deletion but kept): %v", rerr)
	}
	if !strings.Contains(string(data), recoveryDraftStamp) {
		t.Fatalf("an uncommitted card must KEEP its DRAFT stamp; got:\n%s", string(data))
	}
}
