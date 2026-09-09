// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestU4GUIOwn4ReadbackNamesFirstDifferingWord proves the design §3 P-GUI GUI-OWN 4
// behaviour row (I-P1): when a word-shaped read-back differs from the pending phrase,
// the commit failure names the 1-based index of the FIRST differing word — a
// server-side diff against the phrase the server holds — and no phrase material
// (no correct word) appears in the response. Word k (here k=7) is mistyped.
func TestU4GUIOwn4ReadbackNamesFirstDifferingWord(t *testing.T) {
	s, _ := openedVaultServer(t, "oldpw")

	genRR := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if genRR.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", genRR.Code, genRR.Body.String())
	}
	var gen struct {
		Words []string `json:"words"`
	}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatal(err)
	}
	if len(gen.Words) != 24 {
		t.Fatalf("generate must return 24 words, got %d", len(gen.Words))
	}

	// Mistype exactly word 7 (1-based) to a token that is NOT in the wordlist, so
	// the read-back stays word-shaped (23 known + 1 unknown) and the first six words
	// still match the pending phrase — the first divergence is unambiguously word 7.
	const k = 7
	correctWordK := gen.Words[k-1]
	bad := append([]string(nil), gen.Words...)
	bad[k-1] = "zzzzzz"
	rr := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": strings.Join(bad, " ")})
	if rr.Code == http.StatusOK {
		t.Fatal("a mistyped-word read-back must not commit")
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// The read-back error names the 1-based index of the first differing word.
	if !strings.Contains(body.Error, "word 7") {
		t.Fatalf("the read-back error must name the first differing word as word 7, got %q", body.Error)
	}
	// No phrase material: the correct word at the mistyped position must not appear
	// as a token anywhere in the response (the server diffs internally only).
	for _, tok := range strings.Fields(body.Error) {
		clean := strings.ToLower(strings.Trim(tok, ".,;:\"'"))
		if clean == strings.ToLower(correctWordK) {
			t.Fatalf("the read-back error must not leak any phrase word, but token %q matched the correct word 7", tok)
		}
	}
}

// TestU4GUID2_1CloseClearsSetupSkipped proves the design §3 P-GUI GUI-D2 1 behaviour
// row (I-P1): /api/close clears the per-session setupSkipped flag, so a session that
// skipped to advanced and then closed the vault lands on Welcome-back again on the
// next index render (not the sticky app view). One stable session is used across the
// GET /?advanced=1, the POST /api/close, and the GET /.
func TestU4GUID2_1CloseClearsSetupSkipped(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	cookie := newTestSession(s, true)
	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, rr.Code)
		}
		return rr.Body.String()
	}
	post := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-open-seavault-rclone-Token", s.token)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr
	}

	// Skip to advanced: the session sticks the app view.
	skipped := get("/?advanced=1")
	if bt := bodyTag(t, skipped); !strings.Contains(bt, "view-app") {
		t.Fatalf("precondition: /?advanced=1 must land on the app view, got body tag %q", bt)
	}

	// Close the (unopened) vault: this must clear setupSkipped.
	if rr := post("/api/close"); rr.Code != http.StatusOK {
		t.Fatalf("close: %d %s", rr.Code, rr.Body.String())
	}

	// The next index render is Welcome-back, not the sticky app view.
	after := get("/")
	if bt := bodyTag(t, after); !strings.Contains(bt, "view-welcome") {
		t.Fatalf("after /api/close the next index render must be Welcome-back, got body tag %q", bt)
	}
}

// TestU4GUIOwn6RollbackWordingIsGUINeutral proves the design §3 P-GUI GUI-OWN 6 row:
// the rolled-back /api/open refusal (canAcceptRollback branch) is worded for the GUI
// — it names the "I restored this from a backup" control and never the CLI
// --accept-rollback flag. The rollback is set up as in the S2 matrix row.
func TestU4GUIOwn6RollbackWordingIsGUINeutral(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	if rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath, "password": "pw0",
		"kdf": "argon2id", "argon2Time": 2, "argon2MemoryKiB": 19456, "argon2Parallelism": 1,
	}); rr.Code != http.StatusOK {
		t.Fatalf("init: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postJSON(t, s, "/api/password-change", map[string]any{"newPassword": "pw1"}); rr.Code != http.StatusOK {
		t.Fatalf("password-change #1: %d %s", rr.Code, rr.Body.String())
	}
	cfgPath := metaConfigPath(t, vaultPath)
	snap, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if rr := postJSON(t, s, "/api/password-change", map[string]any{"newPassword": "pw2"}); rr.Code != http.StatusOK {
		t.Fatalf("password-change #2: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postJSON(t, s, "/api/close", map[string]any{}); rr.Code != http.StatusOK {
		t.Fatalf("close: %d %s", rr.Code, rr.Body.String())
	}
	if err := os.WriteFile(cfgPath, snap, 0o600); err != nil {
		t.Fatal(err)
	}

	rr := postJSON(t, s, "/api/open", map[string]any{"vaultPath": vaultPath, "password": "pw1"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("a rolled-back open must be 400, got %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error             string `json:"error"`
		CanAcceptRollback bool   `json:"canAcceptRollback"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.CanAcceptRollback {
		t.Fatalf("precondition: the rolled-back open must carry canAcceptRollback:true, got %s", rr.Body.String())
	}
	// GUI-neutral: names the GUI control, never the CLI flag.
	if strings.Contains(body.Error, "--accept-rollback") {
		t.Fatalf("the GUI rolled-back message must not name the CLI --accept-rollback flag, got %q", body.Error)
	}
	if !strings.Contains(body.Error, "I restored this from a backup") {
		t.Fatalf("the GUI rolled-back message must point at the \"I restored this from a backup\" control, got %q", body.Error)
	}
}

// TestU4PGUICopyRows proves the design §3 P-GUI copy rows on the single served index
// page: GUI-OWN 5 (drop the raw-ID column, keep the handle), GUI-D2 2 (enter its
// folder path), GUI-D2 3 (recovery-key match hint), GUI-D2 5 (redeem placeholder
// names both forms), GUI-D2 6 (advanced toggle relabelled "Keep advanced visible"),
// and DOCS-2 (the read-back disclaimer covers the unknown-word case). Every row
// asserts; a zero count or a still-present forbidden string fails the row.
func TestU4PGUICopyRows(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")
	rows := []struct {
		row     string
		want    string // must be present (skipped when "")
		wantMin int    // minimum occurrences of want (0 -> at least 1)
		absent  string // must NOT be present (skipped when "")
	}{
		{"GUI-OWN 5 header drops raw-ID column", "<thead><tr><th>Recovery key</th><th></th></tr></thead>", 0, "<th>ID</th>"},
		{"GUI-OWN 5 no raw-id code cell rendered", "function listRecovery(", 0, "<code>'+esc(r.id)+'</code>"},
		{"GUI-D2 2 enter its folder path", "I already have a vault &mdash; enter its folder path", 0, "choose its folder"},
		{"GUI-D2 3 recovery-key match hint", "matches the number printed on that key", 0, ""},
		{"GUI-D2 5 redeem placeholder names both forms", "placeholder=\"24 words, or the compact XXXX-XXXX form\"", 2, ""},
		{"GUI-D2 6 advanced toggle relabelled", ">Keep advanced visible</button>", 0, ">Show advanced</button>"},
		{"DOCS-2 disclaimer covers the unknown-word case", "not in the recovery wordlist", 0, ""},
	}
	for _, r := range rows {
		if r.want != "" {
			min := r.wantMin
			if min == 0 {
				min = 1
			}
			if c := strings.Count(page, r.want); c < min {
				t.Errorf("[%s] page must contain %q at least %d time(s), got %d", r.row, r.want, min, c)
			}
		}
		if r.absent != "" && strings.Contains(page, r.absent) {
			t.Errorf("[%s] page must NOT contain %q", r.row, r.absent)
		}
	}
}
