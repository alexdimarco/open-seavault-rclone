// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// TestRecoveryGenerateSetsNoStore proves adversarial finding recovery-gui-2: the
// /api/recovery/generate response carries the freshly minted phrase and 24 words,
// so it must be marked non-cacheable (Cache-Control: no-store, Pragma: no-cache)
// so no phrase lingers in a cache or the browser history.
func TestRecoveryGenerateSetsNoStore(t *testing.T) {
	s, _ := openedVaultServer(t, "oldpw")

	rr := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("generate must succeed on an open vault, got %d %s", rr.Code, rr.Body.String())
	}
	// The body genuinely carries phrase material (guard against a vacuous pass).
	if !strings.Contains(rr.Body.String(), `"phrase"`) || !strings.Contains(rr.Body.String(), `"words"`) {
		t.Fatalf("precondition: the generate response must carry phrase material, got %s", rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("the phrase-bearing generate response must set Cache-Control: no-store, got %q", got)
	}
	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("the phrase-bearing generate response must set Pragma: no-cache, got %q", got)
	}
}

// TestRecoveryRevokeDeletesLabel proves adversarial finding wordlist-labels-3: the
// GUI revoke path retires the entry's device-local label record, so a revoked key
// leaves no orphaned hostname/date behind. A second, surviving key keeps its record.
func TestRecoveryRevokeDeletesLabel(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	if rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath, "password": "oldpw",
		"kdf": "argon2id", "argon2Time": 2, "argon2MemoryKiB": 19456, "argon2Parallelism": 1,
	}); rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}

	// Two committed recovery keys; the commit writes a device-local label per entry.
	generateAndCommitRecovery(t, s)
	generateAndCommitRecovery(t, s)

	ids := func() []string {
		var list struct {
			Entries []recoveryEntryDTO `json:"entries"`
		}
		if code := getJSON(t, s, "/api/recovery/list", &list); code != http.StatusOK {
			t.Fatalf("list: %d", code)
		}
		out := make([]string, 0, len(list.Entries))
		for _, e := range list.Entries {
			out = append(out, e.ID)
		}
		return out
	}
	start := ids()
	if len(start) != 2 {
		t.Fatalf("precondition: two recovery keys, got %d", len(start))
	}
	// Both entries must have a label record before the revoke (else the test proves
	// nothing about deletion).
	for _, id := range start {
		if _, ok, err := profile.GetRecoveryLabel(id); err != nil || !ok {
			t.Fatalf("precondition: entry %s must have a device-local label record (ok=%v err=%v)", id[:4], ok, err)
		}
	}

	revoked := start[0]
	survivor := start[1]

	// Revoke one (non-last, so no confirm needed): its label record must be gone.
	if rr := postJSON(t, s, "/api/recovery/revoke", map[string]any{"id": revoked}); rr.Code != http.StatusOK {
		t.Fatalf("non-last revoke must succeed, got %d %s", rr.Code, rr.Body.String())
	}
	if _, ok, err := profile.GetRecoveryLabel(revoked); err != nil {
		t.Fatalf("label lookup after revoke errored: %v", err)
	} else if ok {
		t.Fatalf("the revoked entry %s must have no device-local label record left (orphan)", revoked[:4])
	}
	// The surviving entry keeps its record.
	if _, ok, err := profile.GetRecoveryLabel(survivor); err != nil || !ok {
		t.Fatalf("the surviving entry %s must keep its label record (ok=%v err=%v)", survivor[:4], ok, err)
	}
}

// TestGUIOwnPanelHeadingsRenamedByJob proves friction Type II GUI-OWN-1: the panel
// <h2> headings the owner lands on (not just the section-list nav links) carry the
// design §2.1 job-named copy, and the old jargon headings are gone. Element ids are
// unchanged (asserted by the I-U1 presence test); this asserts the visible copy.
func TestGUIOwnPanelHeadingsRenamedByJob(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")

	// The job-named panel headings (design §2.1 shown-names) must all be present.
	wantHeadings := []string{
		`<h2>Your vault</h2>`,
		`<h2>Switch vault</h2>`,
		`<h2>Add files</h2>`,
		`<h2>Get files out</h2>`,
		`<h2>Browse files</h2>`,
		`<h2>Cloud sync</h2>`,
		`<h2>SFTP keys</h2>`,
	}
	for _, h := range wantHeadings {
		if !strings.Contains(page, h) {
			t.Fatalf("panel heading %q missing (GUI-OWN-1 / §2.1 job rename)", h)
		}
	}

	// The old-jargon panel headings must be gone (exact <h2> form; the unchanged
	// Help guide still carries numbered "3. WebDAV.../4. Remote..." text, so only the
	// bare panel-heading forms are asserted absent).
	goneHeadings := []string{
		`<h2>Open or create vault</h2>`,
		`<h2>Saved vault locations</h2>`,
		`<h2>Upload into encrypted archive</h2>`,
		`<h2>Export plaintext from vault</h2>`,
		`<h2>WebDAV file manager</h2>`,
		`<h2>Remote repositories</h2>`,
		`<h2>SSH keys for rclone SFTP</h2>`,
	}
	for _, h := range goneHeadings {
		if strings.Contains(page, h) {
			t.Fatalf("old-jargon panel heading %q still present; the restructure must rename it by job (GUI-OWN-1)", h)
		}
	}
}

// TestWelcomeBackRedeemAffordancePresent proves friction Type II GUI-D2-4 (the
// server-rendered half, harness runs no JS per C8): the Welcome-back view carries a
// "Forgot your password? Use a recovery key" affordance with its OWN vault-path
// field and a redeem action wired to /api/recovery/redeem, so a locked-out owner
// reaches redeem without opening the vault or hunting the Security destination.
func TestWelcomeBackRedeemAffordancePresent(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")

	// The affordance lives inside the Welcome-back section, not only in the full app.
	wb := page
	if i := strings.Index(page, `id="welcome-back"`); i >= 0 {
		if j := strings.Index(page[i:], `</section>`); j >= 0 {
			wb = page[i : i+j]
		}
	}
	for _, want := range []string{
		`id="welcomeRedeem"`,
		`Forgot your password`,
		`id="welcomeRedeemVaultPath"`,
		`id="welcomeRedeemPhrase"`,
		`id="welcomeRedeemNew"`,
		`id="welcomeRedeemNewConfirm"`,
		`onclick="welcomeRedeem()"`,
	} {
		if !strings.Contains(wb, want) {
			t.Fatalf("Welcome-back redeem affordance missing %q (GUI-D2-4)", want)
		}
	}
	// The redeem handler must post to the existing redeem endpoint carrying the
	// vault path (the locked-out redeem contract).
	fn := page
	if i := strings.Index(page, `async function welcomeRedeem(`); i >= 0 {
		fn = page[i:]
		if j := strings.Index(fn, "\n}"); j >= 0 {
			fn = fn[:j]
		}
	} else {
		t.Fatal("welcomeRedeem() JS handler is missing (GUI-D2-4)")
	}
	for _, want := range []string{`/api/recovery/redeem`, `vaultPath:vp`} {
		if !strings.Contains(fn, want) {
			t.Fatalf("welcomeRedeem() must post %q to the redeem endpoint (GUI-D2-4)", want)
		}
	}
}

// TestWelcomeBackRedeemByPathLockedOut proves the behavioural half of GUI-D2-4: a
// returning owner on a bare second device (zero profiles, no vault open) redeems by
// vault PATH through /api/recovery/redeem — the endpoint opens via the phrase, so no
// prior unlock is needed — and the new password opens the vault while the old fails.
func TestWelcomeBackRedeemByPathLockedOut(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	// Creator server: build a vault (no profile saved) with a committed recovery key.
	creator, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "synced", "seavault")
	if rr := postJSON(t, creator, "/api/init", map[string]any{
		"vaultPath": vaultPath, "password": "oldpw",
		"kdf": "argon2id", "argon2Time": 2, "argon2MemoryKiB": 19456, "argon2Parallelism": 1,
	}); rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	phrase, _ := generateAndCommitRecovery(t, creator)
	if phrase == "" {
		t.Fatal("precondition: a committed recovery phrase is required")
	}
	// Release the creator's open vault to mirror the second-device, nothing-open state.
	postJSON(t, creator, "/api/close", map[string]any{})

	// Second device: a fresh server with zero profiles and no vault open.
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Open            bool `json:"open"`
		AvailableVaults []struct {
			VaultPath string `json:"vaultPath"`
		} `json:"availableVaults"`
	}
	if code := getJSON(t, s, "/api/status", &st); code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	if st.Open {
		t.Fatal("precondition: the second device must have no vault open")
	}
	if len(st.AvailableVaults) != 0 {
		t.Fatalf("precondition: the second device must have zero profiles, got %d", len(st.AvailableVaults))
	}

	// Redeem by path from the locked-out state.
	rr := postJSON(t, s, "/api/recovery/redeem", map[string]any{
		"vaultPath": vaultPath, "phrase": phrase, "newPassword": "newpw",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("redeem by path from a locked-out second device must succeed, got %d %s", rr.Code, rr.Body.String())
	}
	if _, err := vault.Open(vaultPath, "newpw"); err != nil {
		t.Fatalf("the redeem's new password must open the vault: %v", err)
	}
	if _, err := vault.Open(vaultPath, "oldpw"); err == nil {
		t.Fatal("the old password must not open the vault after a redeem")
	}
}

// TestSecurityRedeemPanelHasOwnVaultPathField proves friction Type II GUI-D2-4/5:
// the Security-destination redeem panel carries its OWN vault-path field, its hint
// no longer points "above" at the moved #vaultPath input, and the redeem handler
// reads that field first.
func TestSecurityRedeemPanelHasOwnVaultPathField(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")

	if !strings.Contains(page, `id="redeemVaultPath"`) {
		t.Fatal("the Security redeem panel must carry its own vault-path field id=redeemVaultPath (GUI-D2-4/5)")
	}
	// The stale hint pointing "above" at the moved #vaultPath input must be gone.
	if strings.Contains(page, `select or enter the vault path above`) {
		t.Fatal("the redeem hint must not tell the owner to enter the vault path \"above\" (the field moved) (GUI-D2-4/5)")
	}
	// The redeem handler reads its own field first.
	fn := page
	if i := strings.Index(page, `async function redeemRecovery(`); i >= 0 {
		fn = page[i:]
		if j := strings.Index(fn, "\n}"); j >= 0 {
			fn = fn[:j]
		}
	} else {
		t.Fatal("redeemRecovery() JS handler is missing")
	}
	if !strings.Contains(fn, `$('redeemVaultPath')`) {
		t.Fatal("redeemRecovery() must read its own redeemVaultPath field (GUI-D2-4/5)")
	}
}
