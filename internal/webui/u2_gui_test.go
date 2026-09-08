// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/keychain"
)

// indexPage renders the index for a request path (e.g. "/", "/?create=1") on a
// logged-in session and returns the HTML body. It fails the test on a non-200.
func indexPage(t *testing.T, s *Server, path string) string {
	t.Helper()
	req := authReq(s, httptest.NewRequest(http.MethodGet, path, nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index %q failed: %d %s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

// bodyTag returns the literal "<body ...>" opening tag so a test can assert on
// the server-chosen view class without matching CSS or JS occurrences of the
// same token elsewhere in the page.
func bodyTag(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, "<body ")
	if i < 0 {
		t.Fatal("index page has no <body> tag")
	}
	j := strings.Index(page[i:], ">")
	if j < 0 {
		t.Fatal("index page has an unterminated <body> tag")
	}
	return page[i : i+j+1]
}

// TestG1FourDestinationStructure proves matrix row G1 (design §2.1): the page has
// exactly four destination controls, every pre-U2 panel id appears under exactly
// one destination, the Advanced container carries `hidden` by default, and the
// Show-advanced toggle's source is present. The Go httptest harness runs no JS
// (design C8), so this asserts server-rendered markup and JS source only.
func TestG1FourDestinationStructure(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")

	// Exactly four destination controls (the four tab buttons).
	if n := strings.Count(page, `class="destination-tab`); n != 4 {
		t.Fatalf("want exactly 4 destination-tab controls, got %d", n)
	}
	for _, label := range []string{`>Files</button>`, `>Cloud sync</button>`, `>Security</button>`, `>Advanced</button>`} {
		if !strings.Contains(page, label) {
			t.Fatalf("destination bar missing control %q", label)
		}
	}
	// The four destination containers exist.
	for _, dest := range []string{`id="dest-files"`, `id="dest-cloud"`, `id="dest-security"`, `id="dest-advanced"`} {
		if !strings.Contains(page, dest) {
			t.Fatalf("missing destination container %q", dest)
		}
	}

	// Every pre-U2 panel id appears under exactly one destination: assert each is
	// present exactly once (no duplication across destinations). Assert on EVERY
	// row; a zero/absent id is a failure.
	panelIDs := []string{
		`id="vault-panel"`, `id="upload-panel"`, `id="export-panel"`, `id="files-panel"`,
		`id="remote-panel"`, `id="keys-panel"`, `id="password-recovery-panel"`,
		`id="legacy-files-panel"`, `id="move-panel"`, `id="managed-tools-panel"`, `id="settings-panel"`,
	}
	for _, id := range panelIDs {
		if c := strings.Count(page, id); c != 1 {
			t.Fatalf("panel %s must appear exactly once (under one destination), got %d", id, c)
		}
	}

	// The Advanced container carries `hidden` by default.
	if !strings.Contains(page, `id="dest-advanced" data-destination="advanced" aria-label="Advanced" hidden>`) {
		t.Fatal("the Advanced destination container must carry hidden by default (G1)")
	}
	// The Show-advanced toggle's source is present (button + handler + localStorage).
	for _, want := range []string{`id="showAdvancedToggle"`, `onclick="toggleAdvanced()"`, `function toggleAdvanced(`, `localStorage.setItem('sv_show_advanced'`, `function showDestination(`} {
		if !strings.Contains(page, want) {
			t.Fatalf("advanced-toggle source missing %q (G1)", want)
		}
	}
}

// TestI_U1PanelControlIdsPresent is the I-U1 presence test: the restructure moves
// markup only, so EVERY pre-U2 panel/control id still exists on the page. Assert
// on every row.
func TestI_U1PanelControlIdsPresent(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")
	ids := []string{
		"id=\"cfgCertFile\"",
		"id=\"cfgKeyFile\"",
		"id=\"cfgLogMax\"",
		"id=\"cfgLogPath\"",
		"id=\"cfgLogPersist\"",
		"id=\"cfgPassword\"",
		"id=\"cfgProtocol\"",
		"id=\"cfgRcloneChannel\"",
		"id=\"cfgRsyncRuntime\"",
		"id=\"cfgRsyncSource\"",
		"id=\"cfgSelfSigned\"",
		"id=\"cfgUsername\"",
		"id=\"cfgWSLSource\"",
		"id=\"davBreadcrumb\"",
		"id=\"davDropZone\"",
		"id=\"davFileInput\"",
		"id=\"davFolderInput\"",
		"id=\"davTable\"",
		"id=\"davTree\"",
		"id=\"dependencyList\"",
		"id=\"exportDest\"",
		"id=\"exportOverwrite\"",
		"id=\"export-panel\"",
		"id=\"exportPath\"",
		"id=\"exportZip\"",
		"id=\"fileInput\"",
		"id=\"files\"",
		"id=\"files-panel\"",
		"id=\"fileSummary\"",
		"id=\"folderInput\"",
		"id=\"folderSummary\"",
		"id=\"folderSupportHint\"",
		"id=\"gcPreview\"",
		"id=\"guiAuthStatus\"",
		"id=\"kdf\"",
		"id=\"keychainStatusBox\"",
		"id=\"keys-panel\"",
		"id=\"largeDryRun\"",
		"id=\"largeSkipExisting\"",
		"id=\"legacy-files-panel\"",
		"id=\"localPutMethod\"",
		"id=\"localRsyncBinary\"",
		"id=\"localSourcePath\"",
		"id=\"managed-tools-panel\"",
		"id=\"moveDest\"",
		"id=\"move-panel\"",
		"id=\"moveProfile\"",
		"id=\"moveReplace\"",
		"id=\"moveSource\"",
		"id=\"moveUpdateRemotes\"",
		"id=\"password\"",
		"id=\"password-recovery-panel\"",
		"id=\"profile\"",
		"id=\"profiles\"",
		"id=\"pwNew\"",
		"id=\"pwNewConfirm\"",
		"id=\"rcloneFromBinary\"",
		"id=\"rcloneSignature\"",
		"id=\"rcloneStatus\"",
		"id=\"rcloneVersion\"",
		"id=\"recoveryList\"",
		"id=\"recoveryPhrase\"",
		"id=\"recoveryPhraseBox\"",
		"id=\"recoveryPhraseStep\"",
		"id=\"recoveryReadback\"",
		"id=\"recoveryReadbackStep\"",
		"id=\"redeemNew\"",
		"id=\"redeemNewConfirm\"",
		"id=\"redeemPhrase\"",
		"id=\"remoteBackend\"",
		"id=\"remoteBandwidth\"",
		"id=\"remoteCheckers\"",
		"id=\"remoteFastList\"",
		"id=\"remoteName\"",
		"id=\"remoteOutput\"",
		"id=\"remote-panel\"",
		"id=\"remotePath\"",
		"id=\"remotes\"",
		"id=\"remoteTransfers\"",
		"id=\"remoteType\"",
		"id=\"remoteVault\"",
		"id=\"rsyncFromBinary\"",
		"id=\"rsyncOfflineArchive\"",
		"id=\"rsyncRuntimeBaseURL\"",
		"id=\"rsyncStatus\"",
		"id=\"rsyncVersion\"",
		"id=\"savePassword\"",
		"id=\"settings-panel\"",
		"id=\"setupDone\"",
		"id=\"setupKeychain\"",
		"id=\"setupLocCaveat\"",
		"id=\"setupMessage\"",
		"id=\"setupPassword\"",
		"id=\"setupPassword2\"",
		"id=\"setupPassword2Error\"",
		"id=\"setupProviders\"",
		"id=\"setupRcloneFields\"",
		"id=\"setupRecoveryPhrase\"",
		"id=\"setupRecoveryPhraseBox\"",
		"id=\"setupRecoveryPhraseStep\"",
		"id=\"setupRecoveryReadback\"",
		"id=\"setupRecoveryReadbackStep\"",
		"id=\"setupRecoveryStart\"",
		"id=\"setupRemoteName\"",
		"id=\"setupRemotePath\"",
		"id=\"setupReview\"",
		"id=\"setup-stepper\"",
		"id=\"setupVaultPath\"",
		"id=\"sshKeyName\"",
		"id=\"sshKeyPath\"",
		"id=\"sshKeys\"",
		"id=\"status\"",
		"id=\"upload-panel\"",
		"id=\"uploadPath\"",
		"id=\"uploadPathHint\"",
		"id=\"vault-panel\"",
		"id=\"vaultPath\"",
		"id=\"vaultSelect\"",
		"id=\"webdavReadOnly\"",
		"id=\"webdavStatusBox\"",
		// header / result-panel / modal ids that also predate U2:
		"id=\"compatWarning\"", "id=\"recoveryReminder\"", "id=\"noticeBanner\"",
		"id=\"message\"", "id=\"progress\"", "id=\"progressText\"", "id=\"webdavQuickBox\"",
		"id=\"availableVaults\"", "id=\"vaultPasswordModal\"", "id=\"modalVaultPassword\"",
		"id=\"vaultPasswordTitle\"", "id=\"vaultPasswordTarget\"", "id=\"modalSavePassword\"",
	}
	if len(ids) == 0 {
		t.Fatal("the presence table must not be empty")
	}
	for _, id := range ids {
		if !strings.Contains(page, id) {
			t.Fatalf("pre-U2 id %s disappeared in the restructure (I-U1)", id)
		}
	}
}

// TestG2WelcomeBackView proves matrix row G2 (design §2.2, review C5). No vault
// open lands on the Welcome-back view (never the stepper) whether or not profiles
// exist; the Create button reaches the stepper; a vault open lands on Files. The
// harness runs no JS, so the LANDING VIEW is proven from the server-chosen body
// class and the Welcome-back markup is proven present.
func TestG2WelcomeBackView(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Fresh server (zero profiles, no vault): Welcome-back is the landing view,
	// NOT the stepper (C5). data-first-run stays true (the stepper is still served
	// in the DOM), but the view class is welcome, not stepper.
	fresh := indexPage(t, s, "/")
	if bt := bodyTag(t, fresh); !strings.Contains(bt, `class="view-welcome"`) {
		t.Fatalf("zero-profile fresh load must land on Welcome-back, got body tag %q", bt)
	}
	if bt := bodyTag(t, fresh); strings.Contains(bt, "view-stepper") {
		t.Fatalf("zero profiles must NOT auto-land on the stepper (C5), got body tag %q", bt)
	}
	// Welcome-back markup: saved-vault list, folder picker calling /api/open, a
	// password field, Open, Create-a-new-vault, and Go-to-the-full-app.
	for _, want := range []string{
		`id="welcome-back"`,
		`id="welcomeVaultList"`,
		`id="welcomeVaultPath"`,
		`id="welcomePassword"`,
		`onclick="welcomeOpen()"`,
		`function welcomeOpen(`,
		`api('/api/open'`,
		`href="/?create=1"`,
		`href="/?app=1"`,
		`function renderWelcomeVaults(`,
	} {
		if !strings.Contains(fresh, want) {
			t.Fatalf("Welcome-back view missing %q (G2/C5)", want)
		}
	}

	// 2. The Create button reaches the first-run stepper.
	created := indexPage(t, s, "/?create=1")
	if bt := bodyTag(t, created); !strings.Contains(bt, "view-stepper") {
		t.Fatalf("/?create=1 must reach the stepper, got body tag %q", bt)
	}
	if !strings.Contains(created, "Set up your encrypted vault") {
		t.Fatal("/?create=1 must render the stepper markup")
	}

	// 3. Profiles exist but no vault open: still Welcome-back, with the list.
	initRR := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         filepath.Join(t.TempDir(), "cloud", "beta"),
		"password":          "passphrase",
		"profile":           "beta",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if initRR.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", initRR.Code, initRR.Body.String())
	}

	// 3a. With the vault open, the index lands on the app (Files).
	openPage := indexPage(t, s, "/")
	if bt := bodyTag(t, openPage); !strings.Contains(bt, "view-app") {
		t.Fatalf("an open vault must land on the app (Files), got body tag %q", bt)
	}

	// 3b. Close the vault: profiles remain, no vault open -> Welcome-back again.
	closeRR := postJSON(t, s, "/api/close", map[string]any{})
	if closeRR.Code != http.StatusOK {
		t.Fatalf("close failed: %d %s", closeRR.Code, closeRR.Body.String())
	}
	returning := indexPage(t, s, "/")
	if bt := bodyTag(t, returning); !strings.Contains(bt, "view-welcome") {
		t.Fatalf("a returning user with profiles and no open vault must land on Welcome-back, got body tag %q", bt)
	}
	if !strings.Contains(returning, `id="welcomeVaultList"`) {
		t.Fatal("the returning-user Welcome-back must carry the saved-vault list container (G2)")
	}
}

// TestG4PasswordChangeMessageAndHeader proves matrix row G4 (design §2.4): the
// change-password success message is a plain, brace-free sentence (never the raw
// JSON body), and the Password-and-recovery panel header names the open vault.
func TestG4PasswordChangeMessageAndHeader(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	initRR := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          "passphrase",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if initRR.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", initRR.Code, initRR.Body.String())
	}
	page := indexPage(t, s, "/")

	// The plain-language, brace-free password-change sentence is the humanize
	// output for a change (no raw JSON dump).
	const pwSentence = "Password changed. The old password no longer opens this vault. Other devices will need the new password after vault.json syncs."
	if strings.Contains(pwSentence, "{") {
		t.Fatal("the change-password success sentence must contain no '{' (design G4)")
	}
	if !strings.Contains(page, pwSentence) {
		t.Fatal("the humanize() password-change branch must render the plain sentence (G4)")
	}
	if !strings.Contains(page, "if(obj.passwordChanged)") {
		t.Fatal("humanize() must branch on passwordChanged so the change never renders as JSON (G4)")
	}

	// The Password-and-recovery panel header names the open vault.
	want := "Password and recovery key &mdash; " + filepath.Base(vaultPath)
	if !strings.Contains(page, want) {
		t.Fatalf("the Password-and-recovery header must name the open vault %q (G4)", want)
	}
}

// TestM1HumanizeAndKeychainAndInlineValidation proves the parts of matrix row M1
// (design §2.4/C9) in this slice: the humanize() recovery-saved sentence; the
// keychain-unavailable message leads with a plain line before the technical
// detail; and the change-password fields carry inline mismatch validation and a
// light strength hint.
func TestM1HumanizeAndKeychainAndInlineValidation(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")

	// humanize() recovery-saved sentence (plain, brace-free). Pin the branch AND a
	// tail unique to the humanize output — the showHuman title "Recovery key saved"
	// exists independently of humanize(), so it alone would not prove the sentence.
	if !strings.Contains(page, "if(obj.recoverySaved){ return 'Recovery key saved'") {
		t.Fatal("humanize() must branch on recoverySaved to render a plain sentence (M1)")
	}
	if !strings.Contains(page, "Keep the recovery phrase on paper, away from this computer.") {
		t.Fatal("humanize() recovery-saved branch must render the plain sentence (M1)")
	}

	// Inline password validation + light strength hint on the change-password fields.
	for _, want := range []string{
		`id="pwNewConfirmError"`,
		`id="pwStrengthHint"`,
		`pwFieldNote('pwNewConfirmError'`,
		`addEventListener('input', pwLiveMatch)`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("change-password inline validation missing %q (M1)", want)
		}
	}

	// Keychain-unavailable message leads with a plain line BEFORE the technical
	// detail (asserted directly on the server function that composes it).
	st := keychain.Status{Available: false, Summary: "OS keychain unavailable", Backend: "secret-service", Detail: "no Secret Service daemon"}
	msg := keychainUnavailableMessage(st)
	const lead = "This computer's keychain isn't available right now"
	if !strings.HasPrefix(msg, lead) {
		t.Fatalf("keychain-unavailable message must lead with the plain line, got %q", msg)
	}
	leadAt := strings.Index(msg, lead)
	detailAt := strings.Index(msg, "OS keychain unavailable")
	if detailAt < 0 || detailAt < leadAt {
		t.Fatalf("the plain lead line must come BEFORE the technical detail, got %q", msg)
	}
	// The message still carries the actionable detail (not a vacuous lead-only).
	if !strings.Contains(msg, "secret-service") || !strings.Contains(msg, "Enter the vault password manually") {
		t.Fatalf("keychain message must keep the technical detail after the lead, got %q", msg)
	}
}
