// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// metaConfigPath returns the on-disk vault.json path for a GUI-created vault,
// trying the preferred SeaVaultData layout then the legacy hidden one.
func metaConfigPath(t *testing.T, vaultPath string) string {
	t.Helper()
	for _, name := range []string{"SeaVaultData", ".seavault"} {
		p := filepath.Join(vaultPath, name, vault.ConfigFileName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("no %s found under %s", vault.ConfigFileName, vaultPath)
	return ""
}

// generateAndCommitRecovery runs the real recovery ceremony (generate → commit)
// against an open vault and returns the committed base32 phrase and its 24 words.
func generateAndCommitRecovery(t *testing.T, s *Server) (phrase string, words []string) {
	t.Helper()
	genRR := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if genRR.Code != http.StatusOK {
		t.Fatalf("recovery generate failed: %d %s", genRR.Code, genRR.Body.String())
	}
	var gen struct {
		Phrase string   `json:"phrase"`
		Words  []string `json:"words"`
	}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode generate: %v", err)
	}
	if gen.Phrase == "" || len(gen.Words) != 24 {
		t.Fatalf("generate must return a phrase and 24 words, got phrase-empty=%v words=%d", gen.Phrase == "", len(gen.Words))
	}
	commitRR := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": gen.Phrase})
	if commitRR.Code != http.StatusOK {
		t.Fatalf("recovery commit failed: %d %s", commitRR.Code, commitRR.Body.String())
	}
	return gen.Phrase, gen.Words
}

// TestG2RecoveryGenerateWordsAndLabels proves slice behaviours (a) and (c): the
// generate endpoint returns the 24 numbered words alongside the base32 compact
// form (design §2.5), and after commit the list endpoint carries the stable 4-hex
// handle and the device-local label record written at commit (design §2.6). Every
// asserted row fails on an empty/zero value.
func TestG2RecoveryGenerateWordsAndLabels(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	if rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath, "password": "passphrase",
		"kdf": "argon2id", "argon2Time": 2, "argon2MemoryKiB": 19456, "argon2Parallelism": 1,
	}); rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}

	// Generate: 24 words + the compact base32 form. Assert the words re-encode the
	// SAME secret as the compact phrase (real primitives, no mock).
	genRR := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if genRR.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", genRR.Code, genRR.Body.String())
	}
	var gen struct {
		Phrase string   `json:"phrase"`
		Words  []string `json:"words"`
	}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatal(err)
	}
	if len(gen.Words) != 24 {
		t.Fatalf("generate must return exactly 24 words, got %d", len(gen.Words))
	}
	for i, w := range gen.Words {
		if strings.TrimSpace(w) == "" {
			t.Fatalf("word %d must not be empty", i+1)
		}
	}
	if gen.Phrase == "" {
		t.Fatal("generate must return the base32 compact form beneath the words")
	}
	wantWords, err := vault.RecoveryPhraseWords(gen.Phrase)
	if err != nil {
		t.Fatalf("compact form must re-encode to words: %v", err)
	}
	if strings.Join(wantWords, " ") != strings.Join(gen.Words, " ") {
		t.Fatal("the 24 words must be the word form of the SAME secret as the compact base32 phrase")
	}

	// Commit with the compact phrase read-back; the label record is written after.
	if rr := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": gen.Phrase}); rr.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rr.Code, rr.Body.String())
	}

	// List carries the stable handle and the device-local label detail.
	var list struct {
		Entries []recoveryEntryDTO `json:"entries"`
	}
	if code := getJSON(t, s, "/api/recovery/list", &list); code != http.StatusOK {
		t.Fatalf("recovery list: %d", code)
	}
	if len(list.Entries) != 1 {
		t.Fatalf("exactly one recovery entry after commit, got %d", len(list.Entries))
	}
	e := list.Entries[0]
	if e.ID == "" {
		t.Fatal("list entry must keep the full entry ID for revoke/redeem")
	}
	if len(e.Handle) != 4 || e.Handle != e.ID[:4] {
		t.Fatalf("list entry must carry the stable 4-hex handle (first 4 of the ID), got handle=%q id=%q", e.Handle, e.ID)
	}
	if !e.HasRecord {
		t.Fatal("the commit must have written a device-local label record (hasRecord)")
	}
	if e.Created == "" || e.Device == "" {
		t.Fatalf("the label record must carry created and device, got created=%q device=%q", e.Created, e.Device)
	}
	if !strings.Contains(e.Display, e.Handle) {
		t.Fatalf("the display label must show the handle #%s, got %q", e.Handle, e.Display)
	}
}

// TestG3CloudRuntimeOnDemand proves matrix row G3 (design §2.3): the status/install
// endpoint contract and the consent-gating source. The httptest harness runs no JS
// (C8), so this asserts the endpoint contract and the server-rendered source only.
func TestG3CloudRuntimeOnDemand(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	// /api/rclone/status reports the runtime missing on a fresh app home.
	var st map[string]any
	if code := getJSON(t, s, "/api/rclone/status", &st); code != http.StatusOK {
		t.Fatalf("rclone status: %d", code)
	}
	installed, ok := st["installed"].(bool)
	if !ok {
		t.Fatalf("rclone status must report an installed boolean, got %v", st["installed"])
	}
	if installed {
		t.Fatal("on a fresh app home the runtime must report installed=false (G3)")
	}

	page := indexPage(t, s, "/")
	// The consent-gating source: a function that consults the EXISTING status
	// endpoint and, when missing, reveals a consent step that calls the EXISTING
	// install endpoint. Assert every row.
	wants := []string{
		`id="cloudRuntimeConsent"`,
		`onclick="ensureRcloneRuntime()"`,
		`function ensureRcloneRuntime(`,
		`api('/api/rclone/status')`,
		`function cloudRuntimeInstall(`,
		`api('/api/rclone/install'`,
		`Download rclone`,
		`rclone.org`,
	}
	for _, w := range wants {
		if !strings.Contains(page, w) {
			t.Fatalf("Cloud-sync runtime-on-demand source missing %q (G3)", w)
		}
	}
	// The consent flow must reuse the EXISTING install route, not introduce a new
	// download path: the only install endpoint the consent source names is
	// /api/rclone/install.
	for _, forbidden := range []string{`/api/rclone/download`, `/api/cloud/install`, `/api/rclone/install-runtime`} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("the runtimes-on-demand flow must not introduce a new download path (%q) (G3/I-U6)", forbidden)
		}
	}
}

// TestS1RevokeLastKeyConfirm proves matrix row S1 (design §2.7, I-U4): revoking the
// last recovery key is refused with 409 unless the request carries confirm; a
// non-last key revokes without confirm; the confirmed last-key revoke succeeds.
func TestS1RevokeLastKeyConfirm(t *testing.T) {
	s, _ := openedVaultServer(t, "oldpw")

	// Commit two recovery keys.
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

	// With two keys, revoking one WITHOUT confirm succeeds (it is not the last).
	if rr := postJSON(t, s, "/api/recovery/revoke", map[string]any{"id": start[0]}); rr.Code != http.StatusOK {
		t.Fatalf("a non-last revoke without confirm must succeed, got %d %s", rr.Code, rr.Body.String())
	}
	afterOne := ids()
	if len(afterOne) != 1 {
		t.Fatalf("one key must remain after the first revoke, got %d", len(afterOne))
	}

	// The remaining key is the LAST: revoke WITHOUT confirm is refused with 409 and
	// the entry survives.
	rr409 := postJSON(t, s, "/api/recovery/revoke", map[string]any{"id": afterOne[0]})
	if rr409.Code != http.StatusConflict {
		t.Fatalf("revoking the last key without confirm must be 409, got %d %s", rr409.Code, rr409.Body.String())
	}
	if len(ids()) != 1 {
		t.Fatal("a refused last-key revoke must leave the key in place")
	}

	// WITH confirm the last-key revoke succeeds and no keys remain.
	rrOK := postJSON(t, s, "/api/recovery/revoke", map[string]any{"id": afterOne[0], "confirm": true})
	if rrOK.Code != http.StatusOK {
		t.Fatalf("the confirmed last-key revoke must succeed, got %d %s", rrOK.Code, rrOK.Body.String())
	}
	if len(ids()) != 0 {
		t.Fatal("the confirmed last-key revoke must remove the entry")
	}
}

// TestS2GUIAcceptRollback proves matrix row S2 (design §2.7, I-U5): a rolled-back
// config makes /api/open refuse with a body carrying canAcceptRollback; a re-submit
// with acceptRollback AND the re-entered password opens; acceptRollback WITHOUT a
// password is rejected with 400. internal/vault/rollback_test.go is untouched.
func TestS2GUIAcceptRollback(t *testing.T) {
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
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	// Advance the epoch/anchor with two password changes, snapshotting the config
	// after the first so it is a genuine rollback (lower epoch than the anchor
	// high-water) when replayed.
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
	// Replay the earlier config: on-disk epoch now sits below the device anchor.
	if err := os.WriteFile(cfgPath, snap, 0o600); err != nil {
		t.Fatal(err)
	}

	// A plain open refuses with the rolled-back gate and surfaces canAcceptRollback.
	rrRoll := postJSON(t, s, "/api/open", map[string]any{"vaultPath": vaultPath, "password": "pw1"})
	if rrRoll.Code != http.StatusBadRequest {
		t.Fatalf("a rolled-back open must be 400, got %d %s", rrRoll.Code, rrRoll.Body.String())
	}
	var rollBody struct {
		Error             string `json:"error"`
		CanAcceptRollback bool   `json:"canAcceptRollback"`
	}
	if err := json.Unmarshal(rrRoll.Body.Bytes(), &rollBody); err != nil {
		t.Fatal(err)
	}
	if !rollBody.CanAcceptRollback {
		t.Fatalf("the rolled-back open payload must carry canAcceptRollback:true, got %s", rrRoll.Body.String())
	}
	if rollBody.Error == "" {
		t.Fatal("the rolled-back open must still carry the strict-gate error message")
	}

	// acceptRollback WITHOUT a re-entered password is rejected (400): acceptance
	// always re-supplies the credential.
	rrNoPw := postJSON(t, s, "/api/open", map[string]any{"vaultPath": vaultPath, "acceptRollback": true})
	if rrNoPw.Code != http.StatusBadRequest {
		t.Fatalf("acceptRollback without a password must be 400, got %d %s", rrNoPw.Code, rrNoPw.Body.String())
	}
	// The rejection must come from the explicit accept-rollback guard (which names
	// re-supplying the credential for a restored backup) — proving the guard fired
	// BEFORE any keychain fallback, not the generic password-required path.
	if !strings.Contains(rrNoPw.Body.String(), "restored backup") {
		t.Fatalf("acceptRollback without a password must be rejected by the explicit guard naming a restored backup, got %s", rrNoPw.Body.String())
	}
	// It must not carry canAcceptRollback, which is only for the plain-open refusal.
	if strings.Contains(rrNoPw.Body.String(), "canAcceptRollback") {
		t.Fatalf("the missing-password rejection must not re-offer accept-rollback, got %s", rrNoPw.Body.String())
	}

	// acceptRollback WITH the re-entered password opens the restored config.
	rrOK := postJSON(t, s, "/api/open", map[string]any{"vaultPath": vaultPath, "password": "pw1", "acceptRollback": true})
	if rrOK.Code != http.StatusOK {
		t.Fatalf("acceptRollback with the re-entered password must open, got %d %s", rrOK.Code, rrOK.Body.String())
	}
}

// TestS3PrintCardDraftAndPhraseNotReserved proves matrix row S3 (design §2.5/C6,
// I-U7): the pre-commit print-card source carries the DRAFT stamp and the
// post-commit (confirmed) render does not; and the server never re-serves the
// phrase after generate or commit. The harness runs no JS (C8): the card claims are
// proven from the server-rendered source, the no-re-serve claim from the endpoints.
func TestS3PrintCardDraftAndPhraseNotReserved(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	page := indexPage(t, s, "/")

	// Card source: the pre-commit card is stamped DRAFT (gated on the draft flag),
	// the confirmed reprint is not. Assert every row.
	for _, w := range []string{
		`function recoveryPrintCard(`,
		`function recoveryPrintConfirmedCard(`,
		`function recoveryCardHTML(draft)`,
		`recoveryCardHTML(true)`,  // pre-commit draft card
		`recoveryCardHTML(false)`, // confirmed card
		`id="recoveryConfirmedCard"`,
	} {
		if !strings.Contains(page, w) {
			t.Fatalf("print-card source missing %q (S3)", w)
		}
	}
	// The DRAFT stamp text is emitted ONLY in the draft branch of recoveryCardHTML.
	if !strings.Contains(page, `draft ? '<div class="draft-stamp"`) {
		t.Fatal("the DRAFT stamp must be gated on the draft flag (S3)")
	}
	if !strings.Contains(page, `DRAFT &mdash; not confirmed until you complete the read-back`) {
		t.Fatal("the pre-commit card must carry the DRAFT stamp copy (S3)")
	}
	// The confirmed-print function body must not itself carry a DRAFT stamp: it
	// renders through recoveryCardHTML(false).
	confIdx := strings.Index(page, `function recoveryPrintConfirmedCard(`)
	if confIdx < 0 {
		t.Fatal("recoveryPrintConfirmedCard must exist")
	}
	confBody := page[confIdx:]
	if end := strings.Index(confBody, "\n}"); end > 0 {
		confBody = confBody[:end]
	}
	if strings.Contains(confBody, "DRAFT") {
		t.Fatal("the confirmed-print function must not stamp DRAFT (S3)")
	}

	// The server never re-serves the phrase. Open a vault, run the ceremony, and
	// confirm the committed phrase and its words are absent from every readable
	// surface (list, status) both before and after commit.
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	if rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath, "password": "passphrase",
		"kdf": "argon2id", "argon2Time": 2, "argon2MemoryKiB": 19456, "argon2Parallelism": 1,
	}); rr.Code != http.StatusOK {
		t.Fatalf("init: %d %s", rr.Code, rr.Body.String())
	}
	// Generate parks the phrase (show-once) but no GET re-serves it.
	genRR := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if genRR.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", genRR.Code, genRR.Body.String())
	}
	var gen struct {
		Phrase string   `json:"phrase"`
		Words  []string `json:"words"`
	}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatal(err)
	}
	assertPhraseAbsent := func(when string) {
		var listBody map[string]any
		if code := getJSON(t, s, "/api/recovery/list", &listBody); code != http.StatusOK {
			t.Fatalf("%s: list: %d", when, code)
		}
		raw, _ := json.Marshal(listBody)
		if strings.Contains(string(raw), gen.Phrase) {
			t.Fatalf("%s: /api/recovery/list must not carry the phrase", when)
		}
		var statusBody map[string]any
		if code := getJSON(t, s, "/api/status", &statusBody); code != http.StatusOK {
			t.Fatalf("%s: status: %d", when, code)
		}
		rawS, _ := json.Marshal(statusBody)
		if strings.Contains(string(rawS), gen.Phrase) {
			t.Fatalf("%s: /api/status must not carry the phrase", when)
		}
	}
	// Before commit (the cancel window): no GET re-serves the phrase.
	assertPhraseAbsent("pre-commit")
	// Commit, then confirm the phrase is still never re-served.
	if rr := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": gen.Phrase}); rr.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rr.Code, rr.Body.String())
	}
	assertPhraseAbsent("post-commit")
}

// TestM1DisclaimerAndRevokeBody proves the slice's M1 rows (design §5/§8 C9): the
// mistyped-word read-back message carries the "usability aid, not a security
// control" disclaimer; and the revoke-last 409 body names the consequence ("no
// recovery path"). Each message is asserted so a future wording edit is a visible
// diff, not a silent regression.
func TestM1DisclaimerAndRevokeBody(t *testing.T) {
	s, _ := openedVaultServer(t, "oldpw")

	// Generate, then read back with a single mistyped word: the checksum catches it
	// and the commit returns the word/checksum message WITH the disclaimer copy,
	// not the generic mismatch line. Uses the 24-word form (not the compact base32).
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
	// Corrupt exactly one word to a different valid wordlist word so the input stays
	// word-shaped (24 known tokens) and fails only on the checksum.
	bad := append([]string(nil), gen.Words...)
	if bad[0] == "abandon" {
		bad[0] = "ability"
	} else {
		bad[0] = "abandon"
	}
	mistyped := strings.Join(bad, " ")
	rr := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": mistyped})
	if rr.Code == http.StatusOK {
		t.Fatal("a mistyped-word read-back must not commit")
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Error, "usability aid, not a security control") {
		t.Fatalf("the mistyped-word message must carry the usability-aid disclaimer, got %q", body.Error)
	}
	if !strings.Contains(strings.ToLower(body.Error), "checksum") {
		t.Fatalf("the mistyped-word message must name the checksum failure, got %q", body.Error)
	}

	// The disclaimer copy is also present as static GUI hint text on the read-back
	// step (a wording change is a visible diff).
	page := indexPage(t, s, "/")
	if !strings.Contains(page, "That checksum is a usability aid, not a security control.") {
		t.Fatal("the read-back step must carry the usability-aid disclaimer copy (M1)")
	}

	// Commit the recovery key for real, then the revoke-last 409 body names the
	// consequence. A fresh generate replaces the pending one left by the mistyped
	// read-back above.
	generateAndCommitRecovery(t, s)
	var list struct {
		Entries []recoveryEntryDTO `json:"entries"`
	}
	if code := getJSON(t, s, "/api/recovery/list", &list); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if len(list.Entries) != 1 {
		t.Fatalf("exactly one recovery key expected, got %d", len(list.Entries))
	}
	rr409 := postJSON(t, s, "/api/recovery/revoke", map[string]any{"id": list.Entries[0].ID})
	if rr409.Code != http.StatusConflict {
		t.Fatalf("revoke-last without confirm must be 409, got %d %s", rr409.Code, rr409.Body.String())
	}
	if !strings.Contains(rr409.Body.String(), "no recovery path") {
		t.Fatalf("the revoke-last 409 body must name the consequence (\"no recovery path\"), got %s", rr409.Body.String())
	}
}
