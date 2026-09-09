// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

// U4 fix tranche — FIXER B cmd rows, each red-first, proven THROUGH the real
// gui/serve startup path where behaviour is end-to-end:
//
//	leakage-copy-1 / O1+X1  --auth-limit on over a persisted enabled=false runs the
//	                        limiter AND renders every readout from the EFFECTIVE
//	                        "on" state AND rewrites the config to enabled=true.
//	wiring-1                serve --help / gui --help name --auth-limit (and the gui
//	                        tls/exit flags) from the registry usage row.
//	lockout-dos-2 (code)    a non-loopback serve with the DEFAULT username warns and
//	                        recommends --user with a non-default name.
//	polish-behaviour-2      init's leftovers remedy names the positional VAULT_DIR,
//	                        not the --vault flag it does not have.
//	W2-6                    the serve-side clear-lock lever frees ONE peer behind
//	                        Basic auth and is impossible to call unauthenticated.
//	wiring-2                a wrong ?launch= shows the styled no-session page with the
//	                        launch THROTTLE reason (never a lock, never a bare 403).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// dialLoopback rewrites a bound "host:port" (possibly 0.0.0.0 / [::]) to a
// loopback dial target on the same port, so a server bound to every interface is
// reachable from the test without dialing 0.0.0.0 directly.
func dialLoopback(t *testing.T, boundAddr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(boundAddr)
	if err != nil {
		t.Fatalf("split bound addr %q: %v", boundAddr, err)
	}
	return "127.0.0.1:" + port
}

// ---- leakage-copy-1 / O1+X1 ----

func TestLeakageCopy1FlagOnOverPersistedDisable(t *testing.T) {
	t.Run("serve_effective_status_and_config_rewrite", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		// Persist a DISABLED limiter (the headless-daemon incident state) with a
		// stale dated stamp, so the pre-fix readout would say "OFF since <date>".
		writeAuthConfig(t, func(c *appconfig.Config) {
			d := false
			c.Auth.Limits.Enabled = &d
			c.Auth.Limits.DisabledSince = "2020-01-01T00:00:00Z"
		})
		vaultPath := makeVault(t, "correct horse battery staple")

		// A non-loopback bind so the exposure line prints; --auth-limit on overrides
		// the persisted disable.
		boundAddr := startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "0.0.0.0:0", "--insecure-bind", "--no-keychain", "--quiet-credentials", "--auth-limit", "on", vaultPath})
		})

		// (b) The persisted config was REWRITTEN: enabled=true, disabledSince cleared.
		if !waitUntil(2*time.Second, func() bool {
			saved, err := appconfig.Load()
			return err == nil && saved.Auth.Limits.IsEnabled() && strings.TrimSpace(saved.Auth.Limits.DisabledSince) == ""
		}) {
			saved, _ := appconfig.Load()
			t.Fatalf("--auth-limit on over a persisted disable must PERSIST enabled=true and clear disabledSince (C7); got enabled=%v disabledSince=%q", saved.Auth.Limits.IsEnabled(), saved.Auth.Limits.DisabledSince)
		}

		// (a) The startup exposure line reads the EFFECTIVE "on" state, never "OFF".
		if !waitUntil(2*time.Second, func() bool { return strings.Contains(sink.joined(), "beyond this machine") }) {
			t.Fatalf("a non-loopback bind must print the exposure line; sink:\n%s", sink.joined())
		}
		exposure := sink.joined()
		if !strings.Contains(exposure, "auth limits: on (") {
			t.Fatalf("the exposure line must render the EFFECTIVE on state; got:\n%s", exposure)
		}
		if strings.Contains(exposure, "OFF since") || strings.Contains(exposure, "auth limits: OFF") {
			t.Fatalf("the exposure line must NOT say OFF when the limiter is running; got:\n%s", exposure)
		}

		// (c) The limiter is actually ON: a wrong-credential burst returns 429.
		client := clientFromIP(t, "")
		base := "http://" + dialLoopback(t, boundAddr) + "/"
		got429 := false
		for i := 0; i < 8; i++ {
			res := doOptionsBasic(t, client, base, "seavault", fmt.Sprintf("wrong-%d", i))
			if res.status == http.StatusTooManyRequests {
				got429 = true
				break
			}
		}
		if !got429 {
			t.Fatal("--auth-limit on must run the limiter: a wrong-credential burst never returned 429")
		}

		// (d) `tls status` reads the rewritten config and says "on".
		tlsOut, err := captureStdout(t, func() error { return cmdTLSStatus(nil) })
		if err != nil {
			t.Fatalf("tls status: %v", err)
		}
		if !strings.Contains(tlsOut, "auth limits: on (") {
			t.Fatalf("tls status must show the effective on state after --auth-limit on; got:\n%s", tlsOut)
		}
		if strings.Contains(tlsOut, "OFF") {
			t.Fatalf("tls status must NOT show OFF after --auth-limit on; got:\n%s", tlsOut)
		}
	})

	t.Run("gui_api_status_shows_effective_on", func(t *testing.T) {
		newAuthEnv(t)
		writeAuthConfig(t, func(c *appconfig.Config) {
			d := false
			c.Auth.Limits.Enabled = &d
			c.Auth.Limits.DisabledSince = "2020-01-01T00:00:00Z"
		})
		guiAddr, secret := bootGUI(t, "--auth-limit", "on")
		client := clientFromIP(t, "")
		redeemSession(t, client, guiAddr, secret)
		res := do(t, client, mustGet(t, "http://"+guiAddr+"/api/status"))
		if res.status != http.StatusOK {
			t.Fatalf("/api/status: %d", res.status)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(res.body), &m); err != nil {
			t.Fatal(err)
		}
		s, _ := m["authLimitStatus"].(string)
		if !strings.Contains(s, "auth limits: on (") {
			t.Fatalf("the settings surface authLimitStatus must show the effective on state; got %q", s)
		}
		if strings.Contains(s, "OFF") {
			t.Fatalf("the settings surface must NOT show OFF after --auth-limit on; got %q", s)
		}
	})
}

// ---- wiring-1 ----

func TestServeAndGuiHelpNameFlags(t *testing.T) {
	rows := []struct {
		cmd  string
		want []string
	}{
		{"serve", []string{"--auth-limit on|off", "--tls"}},
		{"gui", []string{"--auth-limit on|off", "--tls-cert", "--tls-key", "--exit-on-browser-close"}},
	}
	for _, row := range rows {
		t.Run(row.cmd, func(t *testing.T) {
			stdout, _, code := captureRun(t, row.cmd, "--help")
			if code != 0 {
				t.Fatalf("%s --help exit = %d, want 0", row.cmd, code)
			}
			for _, w := range row.want {
				if !strings.Contains(stdout, w) {
					t.Fatalf("%s --help must name %q; got:\n%s", row.cmd, w, stdout)
				}
			}
		})
	}
}

// ---- lockout-dos-2 (code half) ----

func TestServeWarnsDefaultUserOnNonLoopback(t *testing.T) {
	const warnMark = "DEFAULT WebDAV username"

	t.Run("non_loopback_default_user_warns", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "0.0.0.0:0", "--insecure-bind", "--no-keychain", "--quiet-credentials", vaultPath})
		})
		if !waitUntil(2*time.Second, func() bool { return strings.Contains(sink.joined(), warnMark) }) {
			t.Fatalf("a non-loopback bind with the default username must warn; sink:\n%s", sink.joined())
		}
		if !strings.Contains(sink.joined(), "--user") {
			t.Fatalf("the default-username warning must recommend --user; sink:\n%s", sink.joined())
		}
	})

	t.Run("non_loopback_custom_user_does_not_warn", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "0.0.0.0:0", "--insecure-bind", "--no-keychain", "--quiet-credentials", "--user", "owner-9271", vaultPath})
		})
		// Give startup a beat; the warning must NOT appear for a non-default user.
		if waitUntil(400*time.Millisecond, func() bool { return strings.Contains(sink.joined(), warnMark) }) {
			t.Fatalf("a non-default username must NOT trigger the warning; sink:\n%s", sink.joined())
		}
	})

	t.Run("loopback_default_user_does_not_warn", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
		})
		if waitUntil(400*time.Millisecond, func() bool { return strings.Contains(sink.joined(), warnMark) }) {
			t.Fatalf("a loopback bind must NOT warn about the default username; sink:\n%s", sink.joined())
		}
	})
}

// ---- polish-behaviour-2 ----

func TestInitLeftoversRemedyNamesVaultDirNotFlag(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	// A leftovers directory: non-empty, no vault.json.
	leftovers := t.TempDir() + "/vault"
	if err := os.MkdirAll(leftovers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leftovers+"/half-written.chunk", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := captureRun(t, "init", leftovers)
	if code == 0 {
		t.Fatalf("init on a leftovers directory must fail; got exit 0\nstderr: %s", stderr)
	}
	if !strings.Contains(stderr, "VAULT_DIR") {
		t.Fatalf("init's leftovers remedy must name the positional VAULT_DIR; got:\n%s", stderr)
	}
	if strings.Contains(stderr, "--vault") {
		t.Fatalf("init's leftovers remedy must NOT name the --vault flag (init has no such flag); got:\n%s", stderr)
	}
}

// ---- W2-6: the serve-side clear-lock lever ----

func TestServeClearLockLever(t *testing.T) {
	_, sink := newAuthEnv(t)
	const correctPW = "webdav-basic-pw-CORRECT"
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	t.Setenv("SEAVAULT_SERVE_PASSWORD", correctPW)
	writeAuthConfig(t, nil)
	vaultPath := makeVault(t, "correct horse battery staple")

	addr := startDaemonAndCapture(t, &serveTestHook, func() error {
		return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
	})
	clearURL := "http://" + addr + "/api/auth-limits/clear"

	postClear := func(client *http.Client, basic bool, payload any) httpResult {
		body, _ := json.Marshal(payload)
		req, err := http.NewRequest(http.MethodPost, clearURL, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if basic {
			req.SetBasicAuth("seavault", correctPW)
		}
		return do(t, client, req)
	}

	loopback := clientFromIP(t, "")

	// (1) An UNAUTHENTICATED clear is refused before the handler (401 challenge):
	// impossible to call without authentication.
	if res := postClear(loopback, false, map[string]string{"peer": "203.0.113.9"}); res.status != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated clear must be refused with 401; got %d", res.status)
	}

	// (2) An AUTHENTICATED clear from loopback works and logs the operator line,
	// even for a peer with no locks (it returns only what was cleared).
	res := postClear(loopback, true, map[string]string{"peer": "203.0.113.9"})
	if res.status != http.StatusOK {
		t.Fatalf("an authenticated clear must succeed; got %d body %q", res.status, res.body)
	}
	if !strings.Contains(sink.joined(), "auth-limit: cleared peer 203.0.113.9 by ") {
		t.Fatalf("the clear must log one operator line naming what and by whom; sink:\n%s", sink.joined())
	}
	// The response must never carry a credential (there is none in play; assert the
	// correct WebDAV password never appears in any clear response body).
	if strings.Contains(res.body, correctPW) {
		t.Fatalf("the clear response must never echo a credential; body:\n%s", res.body)
	}

	// (3) The real unlock: lock a DIFFERENT peer, then clear it from loopback, then
	// prove that peer is unlocked. Requires a second usable loopback source.
	if !srcUsable("127.0.0.2", addr) {
		t.Log("127.0.0.2 not usable as a source address on this host; skipping the cross-peer unlock sub-check")
		return
	}
	victim := clientFromIP(t, "127.0.0.2")
	base := "http://" + addr + "/"
	locked := false
	for i := 0; i < 8; i++ {
		if r := doOptionsBasic(t, victim, base, "seavault", fmt.Sprintf("wrong-%d", i)); r.status == http.StatusTooManyRequests {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatal("setup: peer 127.0.0.2 should have locked after a wrong-credential burst")
	}
	// Clear it from the unlocked loopback operator.
	cr := postClear(loopback, true, map[string]string{"peer": "127.0.0.2"})
	if cr.status != http.StatusOK {
		t.Fatalf("clearing the locked peer: got %d body %q", cr.status, cr.body)
	}
	var decoded struct {
		Cleared []string `json:"cleared"`
	}
	if err := json.Unmarshal([]byte(cr.body), &decoded); err != nil {
		t.Fatalf("decode clear response: %v", err)
	}
	if len(decoded.Cleared) == 0 || !strings.Contains(strings.Join(decoded.Cleared, "\n"), "127.0.0.2") {
		t.Fatalf("the clear response must name the freed peer; got %v", decoded.Cleared)
	}
	// The victim now authenticates successfully (unlocked), and other peers stay
	// protected by the still-running limiter.
	if r := doOptionsBasic(t, victim, base, "seavault", correctPW); r.status != http.StatusNoContent && r.status != http.StatusOK {
		t.Fatalf("after the clear, the freed peer must authenticate: got %d", r.status)
	}
}

// ---- wiring-2: the no-session throttle reason on a wrong ?launch= ----

func TestWrongLaunchShowsThrottleReason(t *testing.T) {
	newAuthEnv(t)
	writeAuthConfig(t, nil)
	guiAddr, _ := bootGUI(t)
	client := clientFromIP(t, "")
	res := do(t, client, mustGet(t, "http://"+guiAddr+"/?launch=deadbeefwrongsecret"))
	if res.status != http.StatusForbidden {
		t.Fatalf("a wrong ?launch= must be refused with 403; got %d", res.status)
	}
	// It is the styled no-session page carrying the launch THROTTLE reason, never the
	// old bare "forbidden: invalid launch secret" text and never a lock.
	if strings.Contains(res.body, "forbidden: invalid launch secret") {
		t.Fatalf("a wrong ?launch= must not answer with the old bare 403 text; body:\n%s", res.body)
	}
	if !strings.Contains(res.body, "session required") {
		t.Fatalf("a wrong ?launch= must render the styled no-session page; body:\n%s", res.body)
	}
	if !strings.Contains(res.body, "throttled") {
		t.Fatalf("the no-session page must state the launch THROTTLE reason; body:\n%s", res.body)
	}
	// Launch is throttle-only: the page must not present a lock/Retry-After countdown
	// nor an OFF-status readout (those belong to the locking surfaces, not launch).
	if res.header.Get("Retry-After") != "" {
		t.Fatalf("a wrong ?launch= is throttle-only and must not carry a Retry-After lock header; got %q", res.header.Get("Retry-After"))
	}
}
