// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

// U4 fix tranche — FIXER B webui rows, each red-first:
//
//	peer-spoofing-2            the GUI-login keychain-read-error branch RELEASES the
//	                          reservation (does not clear the streak as Success did).
//	concurrency-reservation-2b a panic inside the open verifier does not leak the
//	                          reservation (the deferred Release returns pending).
//	wiring-2                  GET /api/auth-limits/self reports the viewer's OWN lock
//	                          state (session-gated) and the index carries the banner.
//	W2-6                      POST /api/auth-limits/clear frees ONE peer while the
//	                          limiter stays on; it is session+CSRF gated and logs.
//
// Real handlers throughout (httptest against the real Server.ServeHTTP); the only
// seams are the injected clock, the open-verify fault, and the login keychain read.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/authlimit"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// smallLimiter builds a limiter with a low peer threshold and no throttle sleep,
// on a fixed clock, so a lockout is reached in a few calls and the test is fast.
func smallLimiter(peerThreshold int) *authlimit.Limiter {
	return authlimit.New(authlimit.Policy{
		FailuresBeforeLock:        peerThreshold,
		AccountFailuresBeforeLock: 20,
		Window:                    time.Hour,
		LockStart:                 time.Minute,
		LockMax:                   time.Minute,
		FailureDelay:              0,
		MaxKeys:                   1000,
	}, func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
}

// ---- peer-spoofing-2 ----

func TestLoginKeychainErrorReleasesReservationNotSuccess(t *testing.T) {
	hash, err := hashGUIPassword("correct-pw")
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true, PasswordHash: hash}}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.AuthLimiter = smallLimiter(3)
	// The keychain read always fails (hermetic; the real OS keychain is never
	// touched), so switching PasswordHash off routes handleLogin into the
	// keychain-read-error branch under test.
	s.guiLoginKeychainGet = func(string) (string, error) { return "", errors.New("keychain unavailable in test") }

	const peer = "203.0.113.7:5555"
	postLogin := func() *httptest.ResponseRecorder {
		form := url.Values{"username": {"alex"}, "password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "127.0.0.1"
		req.RemoteAddr = peer
		req.AddCookie(newTestSession(s, false))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr
	}
	setHash := func(h string) { s.mu.Lock(); s.config.GUI.PasswordHash = h; s.mu.Unlock() }

	// Two wrong-password logins accumulate two failures on the peer key (threshold 3).
	for i := 0; i < 2; i++ {
		if rr := postLogin(); rr.Code != http.StatusOK {
			t.Fatalf("wrong login %d: code %d, want 200 re-render", i, rr.Code)
		}
	}
	// One login on the legacy keychain path (PasswordHash empty) hits the
	// keychain-read-error branch. It must RELEASE the reservation without clearing
	// the streak.
	setHash("")
	if rr := postLogin(); rr.Code != http.StatusOK {
		t.Fatalf("keychain-error login: code %d, want 200 remedy re-render", rr.Code)
	}
	// Restore the hash and send ONE more wrong password. With Release (the fix) the
	// streak survived at 2, so this third failure locks the peer and the following
	// probe is 429. With Success (the bug) the streak was cleared, so the peer is
	// not locked and the probe re-renders 200.
	setHash(hash)
	postLogin() // the third real failure
	probe := postLogin()
	if probe.Code != http.StatusTooManyRequests {
		t.Fatalf("after a keychain-read error the failure streak must survive (Release, not Success): probe code %d, want 429; the branch wrongly cleared the accumulated lockout progress", probe.Code)
	}
}

// ---- concurrency-reservation-2b ----

func TestOpenPanicReleasesReservation(t *testing.T) {
	// A real vault so the FINAL correct-password open (through the default verifier)
	// actually succeeds when the reservation was returned.
	dir := t.TempDir() + "/vault"
	if err := vault.CreateWithOptions(dir, "correct-pw", vault.CreateOptions{Chunk: vault.DefaultChunkParams(), KDF: vault.FastKDFConfigForTests()}); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.AuthLimiter = smallLimiter(3)
	realOpen := s.openVaultFn

	openReq := func(pw string) (code int, recovered bool) {
		body, _ := json.Marshal(map[string]any{"vaultPath": dir, "password": pw})
		req := httptest.NewRequest(http.MethodPost, "/api/open", strings.NewReader(string(body)))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-open-seavault-rclone-Token", s.token)
		req.AddCookie(newTestSession(s, true))
		rr := httptest.NewRecorder()
		func() {
			defer func() {
				if p := recover(); p != nil {
					recovered = true
				}
			}()
			s.ServeHTTP(rr, req)
		}()
		return rr.Code, recovered
	}

	// Inject a verifier that panics AFTER the reservation was taken. Send exactly
	// FailuresBeforeLock panicking opens; each panic must be caught and each
	// reservation returned by the deferred Release.
	s.openVaultFn = func(string, string, bool) (*vault.Vault, error) { panic("injected verifier panic") }
	for i := 0; i < 3; i++ {
		_, recovered := openReq("whatever")
		if !recovered {
			t.Fatalf("panicking open %d did not panic through the handler as set up", i)
		}
	}

	// Restore the real verifier. If every reservation was returned (the fix), the
	// peer key holds pending=0 and this correct-password open is ALLOWED and
	// succeeds. If the panics leaked their reservations (no defer Release), pending
	// reached the threshold and this open is denied 429 before the verifier runs.
	s.openVaultFn = realOpen
	code, _ := openReq("correct-pw")
	if code == http.StatusTooManyRequests {
		t.Fatalf("a correct open after panicking attempts returned 429: the panics leaked their reservations (the deferred Release did not run)")
	}
	if code != http.StatusOK {
		t.Fatalf("correct open after panics: code %d, want 200 (the vault should open once the reservation was returned)", code)
	}
}

// ---- wiring-2: per-viewer self endpoint + banner ----

func TestAuthLimitSelfReportsOwnLockState(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.AuthLimiter = smallLimiter(3)
	s.openVaultFn = func(string, string, bool) (*vault.Vault, error) { return nil, errors.New("wrong password") }

	self := func() authLimitSelfResponse {
		req := httptest.NewRequest(http.MethodGet, "/api/auth-limits/self", nil)
		req.Host = "127.0.0.1"
		req.AddCookie(newTestSession(s, true))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("/api/auth-limits/self: code %d, want 200", rr.Code)
		}
		var resp authLimitSelfResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode self: %v (body %q)", err, rr.Body.String())
		}
		return resp
	}
	failOpen := func() {
		body, _ := json.Marshal(map[string]any{"vaultPath": t.TempDir(), "password": "x"})
		req := httptest.NewRequest(http.MethodPost, "/api/open", strings.NewReader(string(body)))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-open-seavault-rclone-Token", s.token)
		req.AddCookie(newTestSession(s, true))
		s.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Before any failure: not locked.
	if st := self(); st.Locked {
		t.Fatalf("fresh viewer must not be locked: %+v", st)
	}
	// Lock the open surface for this peer (three failing opens at threshold 3).
	for i := 0; i < 3; i++ {
		failOpen()
	}
	st := self()
	if !st.Locked || st.RetryAfterSeconds <= 0 {
		t.Fatalf("after the burst the viewer's own open lock must be reported: %+v", st)
	}
}

func TestAuthLimitSelfRequiresSession(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.AuthLimiter = smallLimiter(3)
	req := httptest.NewRequest(http.MethodGet, "/api/auth-limits/self", nil)
	req.Host = "127.0.0.1" // no session cookie
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("the self endpoint must be session-gated: no-session code %d, want 403", rr.Code)
	}
}

func TestIndexRendersAuthLimitBannerWiring(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index: code %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`id="authLimitBanner"`, "refreshAuthLimitSelf", "/api/auth-limits/self", "startAuthLimitCountdown", "maybeAuthLimitLocked"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the served index must carry the auth-limit banner wiring %q; it was absent (the banner is not built)", want)
		}
	}
}

// ---- W2-6: the GUI clear-lock lever ----

func TestAuthLimitClearGUIFreesOnePeer(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.AuthLimiter = smallLimiter(3)
	s.openVaultFn = func(string, string, bool) (*vault.Vault, error) { return nil, errors.New("wrong password") }
	var mu sync.Mutex
	var logs []string
	s.AuthLogf = func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, a...))
	}

	failOpen := func() int {
		body, _ := json.Marshal(map[string]any{"vaultPath": t.TempDir(), "password": "x"})
		req := httptest.NewRequest(http.MethodPost, "/api/open", strings.NewReader(string(body)))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-open-seavault-rclone-Token", s.token)
		req.AddCookie(newTestSession(s, true))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr.Code
	}
	selfLocked := func() bool {
		req := httptest.NewRequest(http.MethodGet, "/api/auth-limits/self", nil)
		req.Host = "127.0.0.1"
		req.AddCookie(newTestSession(s, true))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		var resp authLimitSelfResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		return resp.Locked
	}

	// Lock this peer's open surface, then a fourth open is denied 429.
	for i := 0; i < 3; i++ {
		failOpen()
	}
	if failOpen() != http.StatusTooManyRequests {
		t.Fatal("setup: the peer's open surface should be locked (429) before the clear")
	}
	if !selfLocked() {
		t.Fatal("setup: self endpoint should report locked before the clear")
	}

	// A clear WITHOUT the CSRF token is refused (state-changing POST). This proves
	// the lever cannot be driven without the session's token.
	{
		body, _ := json.Marshal(map[string]any{"peer": "192.0.2.1"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth-limits/clear", strings.NewReader(string(body)))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(newTestSession(s, true)) // session but NO token
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("a clear without the CSRF token must be refused: code %d, want 403", rr.Code)
		}
	}
	// A clear with NO session at all is refused too.
	{
		body, _ := json.Marshal(map[string]any{"peer": "192.0.2.1"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth-limits/clear", strings.NewReader(string(body)))
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("a clear without a session must be refused: code %d, want 403", rr.Code)
		}
	}

	// The authorized clear frees this peer (192.0.2.1, the httptest default).
	body, _ := json.Marshal(map[string]any{"peer": "192.0.2.1"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth-limits/clear", strings.NewReader(string(body)))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-open-seavault-rclone-Token", s.token)
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorized clear: code %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Cleared []string `json:"cleared"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode clear response: %v", err)
	}
	if len(resp.Cleared) == 0 {
		t.Fatal("the clear response must name what was cleared; it was empty")
	}
	joined := strings.Join(resp.Cleared, "\n")
	if !strings.Contains(joined, "192.0.2.1") {
		t.Fatalf("the clear response must name the freed peer; got %q", joined)
	}
	// After the clear, the viewer is no longer locked and can open again.
	if selfLocked() {
		t.Fatal("after the clear the peer must no longer be locked")
	}
	// An operator log line named what was cleared and by whom, with no credential.
	mu.Lock()
	logsJoined := strings.Join(logs, "\n")
	mu.Unlock()
	if !strings.Contains(logsJoined, "auth-limit: cleared peer 192.0.2.1 by ") {
		t.Fatalf("the clear must log one operator line naming what and by whom; got:\n%s", logsJoined)
	}
}
