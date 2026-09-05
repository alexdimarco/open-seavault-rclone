// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// openedVaultServer creates and opens a vault through /api/init and returns the
// server (with that vault open) and the vault path.
func openedVaultServer(t *testing.T, password string) (*Server, string) {
	t.Helper()
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          password,
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	return s, vaultPath
}

// The GUI password-change endpoint is CSRF-gated (a state-changing POST without
// the browser token is refused) and, with the token, rotates the vault: the new
// password opens and the old one no longer does (design D3.4, §5 GUI panel).
func TestGUIPasswordChangeCSRFAndRotation(t *testing.T) {
	s, vaultPath := openedVaultServer(t, "oldpw")

	// CSRF: a POST WITHOUT the X-SeaVault-Token header is forbidden, and must not
	// rotate anything.
	req := httptest.NewRequest(http.MethodPost, "/api/password-change", strings.NewReader(`{"newPassword":"newpw"}`))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("password-change without the CSRF token must be 403, got %d %s", rr.Code, rr.Body.String())
	}
	if _, err := vault.Open(vaultPath, "oldpw"); err != nil {
		t.Fatalf("a CSRF-rejected change must not rotate the password: %v", err)
	}

	// With the token, the change goes through.
	rr2 := postJSON(t, s, "/api/password-change", map[string]any{"newPassword": "newpw"})
	if rr2.Code != http.StatusOK {
		t.Fatalf("password-change with the CSRF token must succeed, got %d %s", rr2.Code, rr2.Body.String())
	}
	if _, err := vault.Open(vaultPath, "newpw"); err != nil {
		t.Fatalf("the new password must open the vault: %v", err)
	}
	if _, err := vault.Open(vaultPath, "oldpw"); err == nil {
		t.Fatal("the old password must no longer open the vault after a GUI change")
	}
}

// The GUI recovery panel enforces the mandatory read-back before committing an
// entry (Condition 12), and redeem consumes the entry and sets a new password
// (Condition 1). Every mutation is CSRF-gated via serveAuthorized.
func TestGUIRecoveryReadbackAndRedeem(t *testing.T) {
	s, vaultPath := openedVaultServer(t, "oldpw")

	// generate returns a phrase but writes nothing yet.
	rr := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("recovery generate failed: %d %s", rr.Code, rr.Body.String())
	}
	var gen struct {
		Phrase string `json:"phrase"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &gen); err != nil {
		t.Fatal(err)
	}
	if gen.Phrase == "" {
		t.Fatal("recovery generate must return a phrase")
	}

	listEntries := func() int {
		var resp struct {
			Entries []recoveryEntryDTO `json:"entries"`
		}
		if code := getJSON(t, s, "/api/recovery/list", &resp); code != http.StatusOK {
			t.Fatalf("recovery list failed: %d", code)
		}
		return len(resp.Entries)
	}

	// A WRONG read-back is rejected and writes no entry.
	rrw := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": "not the phrase"})
	if rrw.Code == http.StatusOK {
		t.Fatal("a wrong read-back must not commit a recovery entry")
	}
	if n := listEntries(); n != 0 {
		t.Fatalf("no recovery entry may exist before a matching read-back, got %d", n)
	}

	// A CORRECT read-back commits exactly one entry.
	rrc := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": gen.Phrase})
	if rrc.Code != http.StatusOK {
		t.Fatalf("a matching read-back must commit the recovery entry: %d %s", rrc.Code, rrc.Body.String())
	}
	if n := listEntries(); n != 1 {
		t.Fatalf("exactly one recovery entry must exist after commit, got %d", n)
	}

	// Redeem consumes the entry and sets a new password.
	rrr := postJSON(t, s, "/api/recovery/redeem", map[string]any{"phrase": gen.Phrase, "newPassword": "redeemed"})
	if rrr.Code != http.StatusOK {
		t.Fatalf("recovery redeem failed: %d %s", rrr.Code, rrr.Body.String())
	}
	if _, err := vault.Open(vaultPath, "redeemed"); err != nil {
		t.Fatalf("the redeem's new password must open the vault: %v", err)
	}
	if _, err := vault.Open(vaultPath, "oldpw"); err == nil {
		t.Fatal("the old password must not open after a redeem")
	}
	if n := listEntries(); n != 0 {
		t.Fatalf("redeem must consume the recovery entry, got %d remaining", n)
	}
}
