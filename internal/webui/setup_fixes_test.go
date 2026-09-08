// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/setup"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// TestSetupRunCloudStepSoftFailureOpensVault proves the api-setup-1 fix: when
// setup.Execute fails at a POST-CREATE cloud step (rclone install / remote add /
// remote test), handleSetupRun does NOT abandon the fully-created vault with a
// "could not create the vault" 400. It opens the vault into the session and
// returns 200 with the step-branched CloudNote as a warning (§6/C9, I-S5). The
// rclone-ensure failure is injected through the setupDeps seam so the path is
// deterministic without a real runtime. A create/profile failure (no VaultID)
// must still take the 400 hard-failure path — asserted in the same test so the
// soft path is not over-broad. The password never appears in the 200 body.
func TestSetupRunCloudStepSoftFailureOpensVault(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	// Real create + profile (DefaultDeps), only the network-touching RcloneEnsure
	// is faulted — exactly the privilege boundary the discipline permits mocking.
	deps := setup.DefaultDeps()
	deps.RcloneEnsure = func() error { return errors.New("rclone runtime not ready in test") }
	s.setupDeps = &deps

	const password = "cloud-soft-fail-PW-4a91f3e0"
	vaultDir := filepath.Join(t.TempDir(), "softfail")

	rr := postJSON(t, s, "/api/setup/run", map[string]any{
		"vaultPath":    vaultDir,
		"password":     password,
		"saveKeychain": false,
		"cloud":        map[string]any{"mode": "rclone", "remoteName": "myremote", "remotePath": "myremote:vault"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("cloud-step soft failure must return 200 with the vault opened, got %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode body: %v body=%s", err, body)
	}
	if ok, _ := decoded["ok"].(bool); !ok {
		t.Fatalf("soft-failure body must carry ok=true: %s", body)
	}
	if opened, _ := decoded["opened"].(bool); !opened {
		t.Fatalf("soft-failure body must carry opened=true: %s", body)
	}
	result, _ := decoded["result"].(map[string]any)
	if result == nil {
		t.Fatalf("soft-failure body missing result object: %s", body)
	}
	if vid, _ := result["vaultId"].(string); strings.TrimSpace(vid) == "" {
		t.Fatalf("soft-failure result.vaultId must be set (the vault exists): %s", body)
	}
	if fs, _ := result["failedStep"].(string); fs != setup.StepRcloneEnsure {
		t.Fatalf("soft-failure result.failedStep = %q; want %q: %s", fs, setup.StepRcloneEnsure, body)
	}
	cloudNote, _ := result["cloudNote"].(string)
	if !strings.Contains(cloudNote, "seavault rclone install") {
		t.Fatalf("soft-failure result.cloudNote must name the rclone-install retry, got %q", cloudNote)
	}
	// The warning surfaced to the stepper carries the CloudNote (not a create
	// error), so the GUI renders it instead of "could not create the vault".
	warnings, _ := decoded["warnings"].([]any)
	if len(warnings) == 0 {
		t.Fatalf("soft-failure body must carry a warning: %s", body)
	}
	foundWarn := false
	for _, w := range warnings {
		if ws, _ := w.(string); strings.Contains(ws, "seavault rclone install") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("soft-failure warnings must include the CloudNote: %s", body)
	}

	// I-S1: the password must never appear in the 200 body.
	if strings.Contains(body, password) {
		t.Fatalf("password leaked into the soft-failure body: %s", body)
	}

	// The vault was opened into the session (the SAME wiring the success path
	// uses), so a returning index render is no longer first-run.
	s.mu.Lock()
	openedVault := s.vault
	openedPath := s.vaultPath
	s.mu.Unlock()
	if openedVault == nil {
		t.Fatal("the created vault must be opened into the session on a cloud-step soft failure")
	}
	if filepath.Clean(openedPath) != filepath.Clean(vaultDir) {
		t.Fatalf("session vault path = %q; want %q", openedPath, vaultDir)
	}
	// The vault really exists on disk and opens with the password.
	if v, oerr := vault.Open(vaultDir, password); oerr != nil {
		t.Fatalf("the created vault must open with the password: %v", oerr)
	} else {
		_ = v
	}

	// Gating check: a PRE-CREATE failure (no VaultID) must still be a 400 hard
	// error, not softened to 200. A second run at the same, now-existing dir
	// fails vaultDirState before any vault is built.
	rr2 := postJSON(t, s, "/api/setup/run", map[string]any{
		"vaultPath":    vaultDir,
		"password":     password,
		"saveKeychain": false,
		"cloud":        map[string]any{"mode": "rclone", "remoteName": "myremote", "remotePath": "myremote:vault"},
	})
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("a pre-create failure (existing dir) must stay a 400 hard error, got %d %s", rr2.Code, rr2.Body.String())
	}
	var decoded2 map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &decoded2); err != nil {
		t.Fatalf("decode second body: %v", err)
	}
	if res2, _ := decoded2["result"].(map[string]any); res2 != nil {
		if vid, _ := res2["vaultId"].(string); vid != "" {
			t.Fatalf("a pre-create failure must not report a VaultID: %s", rr2.Body.String())
		}
	}
}

// TestStatusRecoveryMissingReminder proves the recovery-integration-3 fix: the
// status response signals recoveryMissing while an open vault holds no recovery
// entry, so the full page can re-surface a deferred recovery key on every load
// until one exists; and the banner markup + render wiring are present in the
// page. Once a recovery entry is committed, recoveryMissing clears.
func TestStatusRecoveryMissingReminder(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, _ := openedVaultServer(t, "vault-pw-recmiss")

	statusRecoveryMissing := func() (open, missing bool) {
		t.Helper()
		var resp struct {
			Open            bool `json:"open"`
			RecoveryMissing bool `json:"recoveryMissing"`
		}
		if code := getJSON(t, s, "/api/status", &resp); code != http.StatusOK {
			t.Fatalf("status failed: %d", code)
		}
		return resp.Open, resp.RecoveryMissing
	}

	// A freshly-opened vault has no recovery key: the reminder must fire.
	open, missing := statusRecoveryMissing()
	if !open {
		t.Fatal("vault must be open")
	}
	if !missing {
		t.Fatal("recoveryMissing must be true for a vault with no recovery entry")
	}

	// Commit a recovery entry through the real ceremony.
	genRR := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if genRR.Code != http.StatusOK {
		t.Fatalf("recovery generate failed: %d %s", genRR.Code, genRR.Body.String())
	}
	var gen struct {
		Phrase string `json:"phrase"`
	}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatal(err)
	}
	if gen.Phrase == "" {
		t.Fatal("recovery generate must return a phrase")
	}
	commitRR := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": gen.Phrase})
	if commitRR.Code != http.StatusOK {
		t.Fatalf("recovery commit failed: %d %s", commitRR.Code, commitRR.Body.String())
	}

	// With a recovery entry present, the reminder must clear.
	open, missing = statusRecoveryMissing()
	if !open {
		t.Fatal("vault must still be open")
	}
	if missing {
		t.Fatal("recoveryMissing must be false once a recovery entry exists")
	}

	// The reminder banner element and its render wiring exist in the page.
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	pageRR := httptest.NewRecorder()
	s.ServeHTTP(pageRR, req)
	page := pageRR.Body.String()
	for _, want := range []string{`id="recoveryReminder"`, "function renderRecoveryReminder", "s.recoveryMissing", "dismissRecoveryReminder"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page is missing the recovery-reminder wiring %q", want)
		}
	}
}

// singleSession inserts one GUI session into s and returns a function that
// issues a GET for path carrying THAT stable cookie (unlike authReq, which mints
// a fresh session per call). It is how the GUI-4 skip/return flow is walked
// across several index renders on one browser session.
func singleSession(t *testing.T, s *Server) func(path string) string {
	t.Helper()
	cookie := newTestSession(s, true)
	return func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", path, rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
}

// TestSetupStepperBackToGuided proves the GUI-4 fix: "Skip to advanced" is not a
// one-way door. On one stable session, skipping renders the full page with a
// "Back to guided setup" link (while the first-run trigger still holds), the
// skip sticks across a plain reload, and following the link clears the skip and
// returns to the stepper.
func TestSetupStepperBackToGuided(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	get := singleSession(t, s)

	// 1. Fresh first-run: the stepper renders, no "Back to guided setup" link.
	first := get("/")
	if !strings.Contains(first, `data-first-run="true"`) {
		t.Fatalf("fresh session must render the first-run stepper: %q...", first[:min(200, len(first))])
	}
	if strings.Contains(first, `href="/?guided=1"`) {
		t.Fatal("the first-run stepper must not show a Back-to-guided link")
	}

	// 2. Skip to advanced: the full page renders AND offers the return link.
	skipped := get("/?advanced=1")
	if !strings.Contains(skipped, `data-first-run="false"`) {
		t.Fatal("after skip the full page must render (data-first-run=false)")
	}
	if !strings.Contains(skipped, `href="/?guided=1"`) || !strings.Contains(skipped, "Back to guided setup") {
		t.Fatal("after skip the full page must offer a Back-to-guided-setup link (GUI-4)")
	}

	// 3. The skip sticks across a plain reload, and the return link persists
	// while the first-run trigger still holds.
	reloaded := get("/")
	if !strings.Contains(reloaded, `data-first-run="false"`) {
		t.Fatal("the skip must stick across a plain reload")
	}
	if !strings.Contains(reloaded, `href="/?guided=1"`) {
		t.Fatal("the Back-to-guided link must persist while first-run still holds")
	}

	// 4. Following the return link clears the skip: the stepper renders again.
	returned := get("/?guided=1")
	if !strings.Contains(returned, `data-first-run="true"`) {
		t.Fatal("Back to guided setup must return to the first-run stepper (not a one-way door)")
	}
	if strings.Contains(returned, `href="/?guided=1"`) {
		t.Fatal("the stepper must not still show the Back-to-guided link after returning")
	}
}

// TestSetupStepperCopyMatchesFlow proves the GUI-1 fix: the intro copy and the
// first step label describe the REAL flow (location AND cloud, then password,
// create, recovery, done) rather than the stale "Three steps" / "1. Location".
func TestSetupStepperCopyMatchesFlow(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index failed: %d", rr.Code)
	}
	page := rr.Body.String()

	if strings.Contains(page, "Three steps") {
		t.Fatal("the stale \"Three steps\" intro must be gone (GUI-1)")
	}
	if !strings.Contains(page, "A few quick steps") {
		t.Fatal("the intro must describe the real multi-step flow (GUI-1)")
	}
	// The first dot names location AND cloud transport, which is what step 0
	// actually collects.
	if !strings.Contains(page, "1. Location &amp; cloud") {
		t.Fatal("the first step label must read \"Location & cloud\" (GUI-1)")
	}
	if strings.Contains(page, ">1. Location<") {
		t.Fatal("the bare \"1. Location\" label must be gone (GUI-1)")
	}
	// The rest of the flow labels remain intact — assert on every row.
	for _, dot := range []string{"2. Password", "3. Create", "4. Recovery key", "5. Done"} {
		if !strings.Contains(page, dot) {
			t.Fatalf("the step rail must keep the %q dot", dot)
		}
	}
}

// TestSetupStepperInlinePasswordMismatch proves the GUI-6 fix: the
// password-mismatch error is rendered BESIDE the confirm field (an inline error
// element wired into setupNext), not only in the top banner, and a live
// match/mismatch indicator is wired to the password inputs.
func TestSetupStepperInlinePasswordMismatch(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	page := rr.Body.String()

	// The inline error element sits beside the confirm-password input.
	if !strings.Contains(page, `id="setupPassword2Error"`) {
		t.Fatal("the password step must carry an inline error element beside the confirm field (GUI-6)")
	}
	// setupNext's mismatch branch writes into that inline element, not only the
	// top banner.
	if !strings.Contains(page, `setupFieldError('setupPassword2Error', 'The password and its confirmation do not match.')`) {
		t.Fatal("the mismatch must be rendered beside the field via setupFieldError (GUI-6)")
	}
	// A live match indicator is wired to the password inputs.
	if !strings.Contains(page, `addEventListener('input', setupLiveMatch)`) {
		t.Fatal("a live match/mismatch indicator must be wired to the password inputs (GUI-6)")
	}
}

// TestSetupReadbackBlocksDrop proves the recovery-integration-4 fix: the
// recovery re-type inputs block drag-and-drop text drop (ondrop/ondragover), not
// only clipboard paste (onpaste), on BOTH the setup stepper and the general
// recovery panel.
func TestSetupReadbackBlocksDrop(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	page := rr.Body.String()

	inputs := []struct {
		name string
		want string
	}{
		{"setup re-type field", `<input id="setupRecoveryReadback" autocomplete="off" onpaste="return false" ondrop="return false" ondragover="return false"`},
		{"recovery-panel re-type field", `<input id="recoveryReadback" autocomplete="off" onpaste="return false" ondrop="return false" ondragover="return false"`},
	}
	for _, in := range inputs {
		if !strings.Contains(page, in.want) {
			t.Fatalf("the %s must block drag-and-drop as well as paste (recovery-integration-4)", in.name)
		}
	}
}
