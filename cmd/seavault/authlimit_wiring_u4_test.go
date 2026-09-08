// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

// U4 slice R2 — the auth-limit WIRING, proven THROUGH THE REAL gui/serve startup
// path (the U3 integration-harness lesson: a slice is not wired until a test
// boots the real command and drives the real listener). Rows delivered here:
//
//	B1  WebDAV Basic lockout end to end (401 burst → 429 + Retry-After, no
//	    WWW-Authenticate; correct-while-locked still 429; unlock by the injected
//	    clock; a second peer unaffected).
//	G1  the four GUI surfaces: login (429 re-render + minutes + Retry-After),
//	    launch (throttle-only, never 429, correct redeems after the burst — C1),
//	    open (429 JSON {error, retryAfterSeconds} + Retry-After), redeem
//	    (throttle-only, never 429, correct redeems after the burst — C2).
//	H1  the peer is the TCP address, never X-Forwarded-For/X-Real-IP (I-R1).
//	S1  no credential, secret, or phrase in any log line or any 429/re-render body
//	    (I-R2); every lock line uses operator words and a minutes duration.
//	O1  --auth-limit off is loud and unprotected; a config-file disable records
//	    disabledSince, re-warns hourly on the injected clock, and shows in `tls
//	    status`/the settings surface; default is on (I-R4/C7).
//	X1  a non-loopback bind prints the exposure line; loopback does not (§2.3).
//	W1  authlimit is called from internal/localdav and internal/webui non-test.
//	W2  the CLI redeem path holds NO authlimit reference (a fixed delay only).
//
// The clock is injected (authLimitClock) so lock/window expiry and the hourly
// re-warning are deterministic; FailureDelay is a real sleep (a small value is
// configured so a burst is fast but the delay is measurable). Real listeners and
// real handlers throughout; the only seams are the clock, the log sink, and the
// re-warn cadence.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/authlimit"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
	"github.com/alexdimarco/open-seavault-rclone/internal/xcrypto/argon2"
)

// ---- test seams: injected clock, captured log sink ----

type authTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func newAuthTestClock() *authTestClock {
	return &authTestClock{t: time.Unix(1_700_000_000, 0).UTC()}
}
func (c *authTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *authTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type authLogSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *authLogSink) logf(format string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf(format, a...))
}
func (s *authLogSink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}
func (s *authLogSink) joined() string { return strings.Join(s.all(), "\n") }
func (s *authLogSink) countContaining(sub string) int {
	n := 0
	for _, ln := range s.all() {
		if strings.Contains(ln, sub) {
			n++
		}
	}
	return n
}

// newAuthEnv gives a test its own app-home, an injected clock, and a captured
// auth-limit log sink, restoring the package seams on cleanup. It also sets the
// re-warn cadence to production defaults (a subtest overrides them when it drives
// the hourly re-warning).
func newAuthEnv(t *testing.T) (*authTestClock, *authLogSink) {
	t.Helper()
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	clk := newAuthTestClock()
	sink := &authLogSink{}
	prevClock, prevLogf := authLimitClock, authLimitLogf
	prevEvery, prevTick := authLimitWarnEvery, authLimitWarnTick
	authLimitClock = clk.now
	authLimitLogf = sink.logf
	authLimitWarnEvery = time.Hour
	authLimitWarnTick = time.Minute
	t.Cleanup(func() {
		authLimitClock = prevClock
		authLimitLogf = prevLogf
		authLimitWarnEvery = prevEvery
		authLimitWarnTick = prevTick
	})
	return clk, sink
}

// writeAuthConfig persists an appconfig into the test's app-home with a small,
// measurable FailureDelay (so a wrong-credential burst is fast but the throttle
// is observable), then lets mutate tweak it (enable/disable, GUI password, …).
func writeAuthConfig(t *testing.T, mutate func(*appconfig.Config)) {
	t.Helper()
	cfg := appconfig.Default()
	cfg.Auth.Limits.FailureDelay = "40ms"
	if mutate != nil {
		mutate(&cfg)
	}
	if err := appconfig.Save(cfg); err != nil {
		t.Fatalf("save appconfig: %v", err)
	}
}

// guiPasswordHash mirrors webui.hashGUIPassword (unexported) so a test can
// configure a GUI login password without the OS keychain.
func guiPasswordHash(t *testing.T, password string) string {
	t.Helper()
	var salt [16]byte
	if _, err := io.ReadFull(newDeterministicReader(password), salt[:]); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(password), salt[:], 2, 64*1024, 1, 32)
	return "argon2id$v=1$t=2$m=65536$p=1$" + base64.RawStdEncoding.EncodeToString(salt[:]) + "$" + base64.RawStdEncoding.EncodeToString(key)
}

// newDeterministicReader returns a salt source seeded from the password so the
// hash is stable within a test; the salt is not secret (it is stored in the hash)
// and this keeps the fixture reproducible without crypto/rand.
func newDeterministicReader(seed string) io.Reader {
	sum := argon2.IDKey([]byte(seed), []byte("salt-seed"), 1, 8*1024, 1, 16)
	return bytes.NewReader(sum)
}

// ---- vault fixtures ----

func makeVault(t *testing.T, password string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	if err := vault.Create(dir, password, vault.DefaultChunkParams()); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	return dir
}

func makeVaultWithRecovery(t *testing.T, password string) (dir, phrase string) {
	t.Helper()
	dir = makeVault(t, password)
	v, err := vault.Open(dir, password)
	if err != nil {
		t.Fatalf("open vault for recovery prep: %v", err)
	}
	p, commit, err := v.PrepareRecovery()
	if err != nil {
		t.Fatalf("prepare recovery: %v", err)
	}
	if err := commit(); err != nil {
		t.Fatalf("commit recovery: %v", err)
	}
	return dir, p
}

// ---- HTTP helpers ----

// clientFromIP builds an HTTP client whose outbound connections bind srcIP as the
// local address (so the server sees a chosen TCP peer). An empty srcIP uses the
// default source. Keep-alives are disabled so a fresh connection is used per
// request, keeping the peer identity explicit.
func clientFromIP(t *testing.T, srcIP string) *http.Client {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	if srcIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(srcIP)}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true},
		Jar:       jar,
		Timeout:   15 * time.Second,
	}
}

// srcUsable reports whether srcIP can be used as a local bind address for a
// connection to dial (some non-Linux hosts have only 127.0.0.1 as loopback).
func srcUsable(srcIP, dial string) bool {
	d := &net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(srcIP)}}
	c, err := d.Dial("tcp", dial)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

type httpResult struct {
	status int
	header http.Header
	body   string
}

func doOptionsBasic(t *testing.T, client *http.Client, base, user, pass string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodOptions, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(user, pass)
	return do(t, client, req)
}

func do(t *testing.T, client *http.Client, req *http.Request) httpResult {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResult{status: resp.StatusCode, header: resp.Header.Clone(), body: string(b)}
}

var launchSecretRE = regexp.MustCompile(`launch=([^\s"'&]+)`)

func parseLaunchSecret(out string) string {
	m := launchSecretRE.FindStringSubmatch(out)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// syncBuffer is a mutex-guarded byte buffer for capturing redirected stdout.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// bootGUI boots `seavault gui` through the REAL startup path and returns the
// bound address and the one-time launch secret (parsed from the startup output;
// the printed URL carries a placeholder :0 port, so callers rebuild the redeem
// URL from the real bound address).
//
// It redirects os.Stdout ONLY for the boot window — every gui startup print
// (including the launch URL) lands before the serving hook fires, and the server
// makes no further os.Stdout writes once it is serving — then restores os.Stdout
// immediately. Scoping the capture keeps it from colliding, under -race, with
// other tests in this package that redirect os.Stdout/os.Stdin of their own.
func bootGUI(t *testing.T, extraArgs ...string) (addr, launchSecret string) {
	t.Helper()
	real := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw
	sb := &syncBuffer{}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(sb, pr) }()

	args := append([]string{"--addr", "127.0.0.1:0", "--no-open", "--exit-on-browser-close=false"}, extraArgs...)
	addr = startDaemonAndCapture(t, &guiTestHook, func() error { return cmdGUI(args) })

	// The hook fires after the startup goroutine's last os.Stdout write, so this
	// restore is ordered after it (no data race) and the rest of the test runs on
	// the real stdout.
	os.Stdout = real
	_ = pw.Close()
	<-done
	_ = pr.Close()

	launchSecret = parseLaunchSecret(sb.String())
	if launchSecret == "" {
		t.Fatalf("no launch secret in gui startup output:\n%s", sb.String())
	}
	return addr, launchSecret
}

// redeemSession redeems the launch secret on client, giving it a session cookie.
func redeemSession(t *testing.T, client *http.Client, addr, secret string) {
	t.Helper()
	res := do(t, client, mustGet(t, "http://"+addr+"/?launch="+secret))
	if res.status != http.StatusOK && res.status != http.StatusFound {
		t.Fatalf("launch redemption: status %d, body %q", res.status, res.body)
	}
}

func mustGet(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// browserToken reads the CSRF/browser token the session must present on POSTs.
func browserToken(t *testing.T, client *http.Client, addr string) string {
	t.Helper()
	res := do(t, client, mustGet(t, "http://"+addr+"/api/status"))
	if res.status != http.StatusOK {
		t.Fatalf("/api/status: %d %q", res.status, res.body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.body), &m); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	tok, _ := m["browserToken"].(string)
	if tok == "" {
		t.Fatalf("no browserToken in status: %s", res.body)
	}
	return tok
}

func postJSON(t *testing.T, client *http.Client, u, token string, payload any) httpResult {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-open-seavault-rclone-Token", token)
	}
	return do(t, client, req)
}

func postForm(t *testing.T, client *http.Client, u string, form url.Values) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Do NOT follow the redirect a successful login issues, so the test sees the
	// 302 (success) vs 200 re-render (failure) vs 429 (locked) distinctly.
	client2 := *client
	client2.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return do(t, &client2, req)
}

// ---- B1 ----

func TestB1BasicAuthLockoutThroughServe(t *testing.T) {
	clk, _ := newAuthEnv(t)
	const correctPW = "webdav-basic-pw-CORRECT"
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	t.Setenv("SEAVAULT_SERVE_PASSWORD", correctPW)
	writeAuthConfig(t, nil) // default: limiter on
	vaultPath := makeVault(t, "correct horse battery staple")

	addr := startDaemonAndCapture(t, &serveTestHook, func() error {
		return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
	})
	base := "http://" + addr + "/"
	client := clientFromIP(t, "")

	// Five wrong attempts: 401 each, with the WWW-Authenticate challenge and a
	// measured FailureDelay (40ms configured).
	for i := 0; i < 5; i++ {
		start := time.Now()
		res := doOptionsBasic(t, client, base, "seavault", fmt.Sprintf("wrong-%d", i))
		if res.status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, res.status)
		}
		if res.header.Get("WWW-Authenticate") == "" {
			t.Fatalf("attempt %d: 401 must carry WWW-Authenticate", i)
		}
		if el := time.Since(start); el < 25*time.Millisecond {
			t.Fatalf("attempt %d: FailureDelay not applied (elapsed %v < 25ms)", i, el)
		}
	}

	// Sixth attempt: locked → 429 + Retry-After, and NO WWW-Authenticate.
	res := doOptionsBasic(t, client, base, "seavault", "wrong-6")
	if res.status != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt: status %d, want 429", res.status)
	}
	if res.header.Get("Retry-After") == "" {
		t.Fatalf("429 must carry a Retry-After header")
	}
	if res.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("429 must NOT carry WWW-Authenticate (the client would keep re-prompting)")
	}

	// Correct credentials WHILE LOCKED are still denied (the lock precedes the
	// compare).
	res = doOptionsBasic(t, client, base, "seavault", correctPW)
	if res.status != http.StatusTooManyRequests {
		t.Fatalf("correct-while-locked: status %d, want 429", res.status)
	}

	// A SECOND peer is unaffected by peer A's lock (source-IP isolation).
	if srcUsable("127.0.0.2", addr) {
		other := clientFromIP(t, "127.0.0.2")
		res = doOptionsBasic(t, other, base, "seavault", correctPW)
		if res.status != http.StatusNoContent && res.status != http.StatusOK {
			t.Fatalf("second peer with correct creds: status %d, want 2xx (unaffected by peer A lock)", res.status)
		}
	} else {
		t.Log("127.0.0.2 not usable as a source address on this host; skipping the second-peer sub-check")
	}

	// Drive the injected clock past the lock; the correct credential now succeeds
	// (LockStart default 30s).
	clk.advance(31 * time.Second)
	res = doOptionsBasic(t, client, base, "seavault", correctPW)
	if res.status != http.StatusNoContent && res.status != http.StatusOK {
		t.Fatalf("after unlock: status %d, want 2xx", res.status)
	}
}

// ---- H1 ----

func TestH1PeerIsTCPAddressNotHeader(t *testing.T) {
	// PeerKey unit truth H1 names: an IPv4-mapped IPv6 peer keys as its IPv4.
	if got := authlimit.PeerKey("[::ffff:203.0.113.9]:443"); got != "203.0.113.9" {
		t.Fatalf("PeerKey IPv4-mapped: got %q want %q", got, "203.0.113.9")
	}

	clk, _ := newAuthEnv(t)
	const correctPW = "webdav-basic-pw-CORRECT"
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	t.Setenv("SEAVAULT_SERVE_PASSWORD", correctPW)
	writeAuthConfig(t, nil)
	vaultPath := makeVault(t, "correct horse battery staple")

	addr := startDaemonAndCapture(t, &serveTestHook, func() error {
		return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
	})
	base := "http://" + addr + "/"
	client := clientFromIP(t, "")

	// Same TCP peer, a DIFFERENT spoofed X-Forwarded-For / X-Real-IP on every
	// request: if the header were the key, no request would ever accumulate. It
	// locks at the sixth, proving the TCP peer is the key (I-R1).
	locked := false
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequest(http.MethodOptions, base, nil)
		req.SetBasicAuth("seavault", fmt.Sprintf("wrong-%d", i))
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		req.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i+1))
		res := do(t, client, req)
		if res.status == http.StatusTooManyRequests {
			locked = true
			break
		}
		if res.status != http.StatusUnauthorized {
			t.Fatalf("header-spoof attempt %d: status %d, want 401", i, res.status)
		}
	}
	if !locked {
		t.Fatalf("spoofed forwarding headers were treated as the peer: the TCP peer never locked")
	}

	// Control: rotating the REAL TCP source address (distinct loopback IPs) never
	// locks, because each is a distinct peer.
	rotated := 0
	for i := 2; i <= 7; i++ {
		ip := fmt.Sprintf("127.0.0.%d", i)
		if !srcUsable(ip, addr) {
			continue
		}
		c := clientFromIP(t, ip)
		res := doOptionsBasic(t, c, base, "seavault", "wrong-rotated")
		if res.status == http.StatusTooManyRequests {
			t.Fatalf("rotating real source %s should be a distinct peer, but got 429", ip)
		}
		if res.status != http.StatusUnauthorized {
			t.Fatalf("rotating source %s: status %d, want 401", ip, res.status)
		}
		rotated++
	}
	if rotated == 0 {
		t.Log("no alternate loopback source addresses usable; the rotating-source control was skipped")
	}
	_ = clk
}

// ---- G1 ----

func TestG1GUISurfaces(t *testing.T) {
	t.Run("login_burst_locks_and_rerenders", func(t *testing.T) {
		clk, _ := newAuthEnv(t)
		const guiUser, guiPass = "vaultadmin", "gui-pass-CORRECT"
		writeAuthConfig(t, func(c *appconfig.Config) {
			c.GUI.Username = guiUser
			c.GUI.PasswordConfigured = true
			c.GUI.PasswordHash = guiPasswordHash(t, guiPass)
		})
		addr, secret := bootGUI(t)
		client := clientFromIP(t, "")
		redeemSession(t, client, addr, secret)
		loginURL := "http://" + addr + "/login"

		for i := 0; i < 5; i++ {
			res := postForm(t, client, loginURL, url.Values{"username": {guiUser}, "password": {fmt.Sprintf("wrong-%d", i)}})
			if res.status != http.StatusOK {
				t.Fatalf("wrong login %d: status %d, want 200 re-render", i, res.status)
			}
			if !strings.Contains(res.body, "Invalid") {
				t.Fatalf("wrong login %d: re-render must show the invalid-credentials message", i)
			}
		}
		// Sixth: locked → 429 re-render with the minutes countdown and Retry-After.
		res := postForm(t, client, loginURL, url.Values{"username": {guiUser}, "password": {"wrong-6"}})
		if res.status != http.StatusTooManyRequests {
			t.Fatalf("sixth login: status %d, want 429", res.status)
		}
		if res.header.Get("Retry-After") == "" {
			t.Fatalf("locked login re-render must carry Retry-After")
		}
		if !strings.Contains(res.body, "minute") {
			t.Fatalf("locked login re-render must show a minutes countdown; body:\n%s", res.body)
		}
		// Correct credentials while locked are still denied.
		res = postForm(t, client, loginURL, url.Values{"username": {guiUser}, "password": {guiPass}})
		if res.status != http.StatusTooManyRequests {
			t.Fatalf("correct login while locked: status %d, want 429", res.status)
		}
		// After the clock advances past the lock, the correct login succeeds (302).
		clk.advance(31 * time.Second)
		res = postForm(t, client, loginURL, url.Values{"username": {guiUser}, "password": {guiPass}})
		if res.status != http.StatusFound {
			t.Fatalf("correct login after unlock: status %d, want 302 (success resets)", res.status)
		}
	})

	t.Run("launch_is_throttle_only_never_locks", func(t *testing.T) {
		_, _ = newAuthEnv(t)
		writeAuthConfig(t, nil)
		addr, secret := bootGUI(t)
		client := clientFromIP(t, "")
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		launchBase := "http://" + addr + "/?launch="

		// A long burst of wrong launch secrets: 403 each, a measured FailureDelay,
		// and NEVER 429 (C1/I-R9). A lock here would deny the only path to a session.
		for i := 0; i < 12; i++ {
			start := time.Now()
			res := do(t, client, mustGet(t, launchBase+fmt.Sprintf("wrong-secret-%d", i)))
			if res.status == http.StatusTooManyRequests {
				t.Fatalf("launch attempt %d returned 429; launch must be throttle-only, never locked", i)
			}
			if res.status != http.StatusForbidden {
				t.Fatalf("launch attempt %d: status %d, want 403", i, res.status)
			}
			if el := time.Since(start); el < 25*time.Millisecond {
				t.Fatalf("launch attempt %d: FailureDelay not applied (elapsed %v)", i, el)
			}
		}
		// The correct launch secret redeems IMMEDIATELY after the burst (never gated).
		res := do(t, client, mustGet(t, launchBase+secret))
		if res.status != http.StatusFound {
			t.Fatalf("correct launch after burst: status %d, want 302 redemption (I-R9)", res.status)
		}
		if res.header.Get("Set-Cookie") == "" {
			t.Fatalf("correct launch redemption must set the session cookie")
		}
	})

	t.Run("open_locks_with_429_json", func(t *testing.T) {
		clk, _ := newAuthEnv(t)
		writeAuthConfig(t, nil) // no GUI password → the session is logged in on redeem
		const vaultPW = "open-vault-pw-CORRECT"
		vaultPath := makeVault(t, vaultPW)
		addr, secret := bootGUI(t)
		client := clientFromIP(t, "")
		redeemSession(t, client, addr, secret)
		token := browserToken(t, client, addr)
		openURL := "http://" + addr + "/api/open"

		for i := 0; i < 5; i++ {
			res := postJSON(t, client, openURL, token, map[string]any{"vaultPath": vaultPath, "password": fmt.Sprintf("wrong-%d", i)})
			if res.status != http.StatusBadRequest {
				t.Fatalf("wrong open %d: status %d, want 400", i, res.status)
			}
		}
		res := postJSON(t, client, openURL, token, map[string]any{"vaultPath": vaultPath, "password": "wrong-6"})
		if res.status != http.StatusTooManyRequests {
			t.Fatalf("sixth open: status %d, want 429", res.status)
		}
		if res.header.Get("Retry-After") == "" {
			t.Fatalf("locked open must carry Retry-After")
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(res.body), &body); err != nil {
			t.Fatalf("429 open body is not JSON: %v (%s)", err, res.body)
		}
		if _, ok := body["error"].(string); !ok {
			t.Fatalf("429 open JSON must carry an error string; got %s", res.body)
		}
		if _, ok := body["retryAfterSeconds"]; !ok {
			t.Fatalf("429 open JSON must carry retryAfterSeconds; got %s", res.body)
		}
		// After the clock advances past the lock, the correct password opens (200).
		clk.advance(31 * time.Second)
		res = postJSON(t, client, openURL, token, map[string]any{"vaultPath": vaultPath, "password": vaultPW})
		if res.status != http.StatusOK {
			t.Fatalf("correct open after unlock: status %d, want 200 (%s)", res.status, res.body)
		}
	})

	t.Run("redeem_is_throttle_only_never_locks", func(t *testing.T) {
		_, _ = newAuthEnv(t)
		writeAuthConfig(t, nil)
		const vaultPW = "redeem-vault-pw"
		vaultPath, phrase := makeVaultWithRecovery(t, vaultPW)
		addr, secret := bootGUI(t)
		client := clientFromIP(t, "")
		redeemSession(t, client, addr, secret)
		token := browserToken(t, client, addr)
		redeemURL := "http://" + addr + "/api/recovery/redeem"

		// A long burst of wrong phrases: 400 each, NEVER 429, and every error body
		// carries retryAfterSeconds (C2/I-R9).
		for i := 0; i < 12; i++ {
			res := postJSON(t, client, redeemURL, token, map[string]any{
				"vaultPath":   vaultPath,
				"phrase":      fmt.Sprintf("wrong wrong wrong phrase attempt number %d", i),
				"newPassword": "irrelevant-new-pw",
			})
			if res.status == http.StatusTooManyRequests {
				t.Fatalf("redeem attempt %d returned 429; redeem must be throttle-only, never locked (C2)", i)
			}
			if res.status != http.StatusBadRequest {
				t.Fatalf("redeem attempt %d: status %d, want 400", i, res.status)
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(res.body), &body); err != nil {
				t.Fatalf("redeem error body is not JSON: %v", err)
			}
			if _, ok := body["retryAfterSeconds"]; !ok {
				t.Fatalf("redeem error JSON must carry retryAfterSeconds; got %s", res.body)
			}
		}
		// The CORRECT phrase still redeems immediately after the burst (I-R9).
		res := postJSON(t, client, redeemURL, token, map[string]any{
			"vaultPath":   vaultPath,
			"phrase":      phrase,
			"newPassword": "brand-new-password-123",
		})
		if res.status != http.StatusOK {
			t.Fatalf("correct redeem after burst: status %d, want 200 (%s)", res.status, res.body)
		}
	})
}

// ---- S1 ----

func TestS1NoCredentialInLogsOrBodies(t *testing.T) {
	_, sink := newAuthEnv(t)
	const (
		webdavPW = "webdav-basic-pw-SECRET"
		vaultPW  = "vault-open-pw-SECRET"
		guiUser  = "vaultadmin"
		guiPass  = "gui-login-pw-SECRET"
	)
	// A collector of every response body the limited surfaces produced, so S1 can
	// scan bodies as well as the log sink.
	var bodies []string
	var secrets []string
	record := func(r httpResult) httpResult { bodies = append(bodies, r.body); return r }

	// --- WebDAV basic surface (serve) — burst to a lock ("WebDAV auth"). ---
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	t.Setenv("SEAVAULT_SERVE_PASSWORD", webdavPW)
	secrets = append(secrets, webdavPW)
	writeAuthConfig(t, nil)
	vaultPath := makeVault(t, "correct horse battery staple")
	serveAddr := startDaemonAndCapture(t, &serveTestHook, func() error {
		return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
	})
	sc := clientFromIP(t, "")
	for i := 0; i < 6; i++ {
		record(doOptionsBasic(t, sc, "http://"+serveAddr+"/", "seavault", webdavPW+"-typo"))
	}

	// --- GUI login surface (gui WITH a password) — burst to a lock ("GUI login"),
	//     capturing every re-render. ---
	writeAuthConfig(t, func(c *appconfig.Config) {
		c.GUI.Username = guiUser
		c.GUI.PasswordConfigured = true
		c.GUI.PasswordHash = guiPasswordHash(t, guiPass)
	})
	secrets = append(secrets, guiPass)
	loginAddr, loginSecret := bootGUI(t)
	secrets = append(secrets, loginSecret)
	lc := clientFromIP(t, "")
	redeemSession(t, lc, loginAddr, loginSecret)
	for i := 0; i < 6; i++ {
		record(postForm(t, lc, "http://"+loginAddr+"/login", url.Values{"username": {guiUser}, "password": {guiPass + "-typo"}}))
	}

	// --- GUI open surface (gui with NO password → the redeemed session is logged
	//     in) — burst /api/open to a lock ("vault open"), capturing every body. ---
	writeAuthConfig(t, nil)
	secrets = append(secrets, vaultPW)
	openVaultPath := makeVault(t, vaultPW)
	openAddr, openSecret := bootGUI(t)
	secrets = append(secrets, openSecret)
	oc := clientFromIP(t, "")
	redeemSession(t, oc, openAddr, openSecret)
	token := browserToken(t, oc, openAddr)
	for i := 0; i < 6; i++ {
		record(postJSON(t, oc, "http://"+openAddr+"/api/open", token, map[string]any{"vaultPath": openVaultPath, "password": vaultPW + "-typo"}))
	}

	// Every secret the process holds must be absent from BOTH the log sink and every
	// captured body (I-R2).
	haystack := sink.joined() + "\n" + strings.Join(bodies, "\n")
	for _, secretVal := range secrets {
		if strings.Contains(haystack, secretVal) {
			t.Fatalf("I-R2 violated: a secret appears in a log line or a response body")
		}
	}
	// The log sink must carry the operator lock lines (basic + login + open), each
	// in operator WORDS and a MINUTES duration, never the raw surface enum.
	logs := sink.joined()
	for _, phrase := range []string{"WebDAV auth", "GUI login", "vault open"} {
		if !strings.Contains(logs, phrase) {
			t.Fatalf("lock log missing the operator phrase %q; got:\n%s", phrase, logs)
		}
	}
	if !strings.Contains(logs, "minute") {
		t.Fatalf("lock log lines must state a minutes duration; got:\n%s", logs)
	}
	// Every lock line must also carry the remedy so an operator knows the escape
	// hatch (C6), and never the raw surface enum on its own (SurfaceWords maps it).
	if !strings.Contains(logs, "--auth-limit off") {
		t.Fatalf("lock log lines must name the incident remedy (--auth-limit off); got:\n%s", logs)
	}
}

// ---- O1 ----

func TestO1OffSwitchAndPersistentDisable(t *testing.T) {
	t.Run("default_is_on", func(t *testing.T) {
		newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		addr := startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
		})
		client := clientFromIP(t, "")
		got429 := false
		for i := 0; i < 8; i++ {
			res := doOptionsBasic(t, client, "http://"+addr+"/", "seavault", fmt.Sprintf("wrong-%d", i))
			if res.status == http.StatusTooManyRequests {
				got429 = true
				break
			}
		}
		if !got429 {
			t.Fatalf("default config must protect: a wrong-credential burst never locked")
		}
	})

	t.Run("flag_off_is_loud_and_unprotected", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		addr := startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", "--auth-limit", "off", vaultPath})
		})
		// The loud startup warning names the flag.
		if !waitUntil(2*time.Second, func() bool { return strings.Contains(sink.joined(), "--auth-limit") }) {
			t.Fatalf("--auth-limit off must print the loud warning naming the flag; sink:\n%s", sink.joined())
		}
		if !strings.Contains(strings.ToUpper(sink.joined()), "OFF") {
			t.Fatalf("the off warning must say the limiter is OFF; sink:\n%s", sink.joined())
		}
		// Unprotected: a long wrong-credential burst never returns 429.
		client := clientFromIP(t, "")
		for i := 0; i < 10; i++ {
			res := doOptionsBasic(t, client, "http://"+addr+"/", "seavault", fmt.Sprintf("wrong-%d", i))
			if res.status == http.StatusTooManyRequests {
				t.Fatalf("with --auth-limit off, attempt %d returned 429; the limiter must be disabled", i)
			}
			if res.status != http.StatusUnauthorized {
				t.Fatalf("with --auth-limit off, attempt %d: status %d, want 401", i, res.status)
			}
		}
	})

	t.Run("config_disable_records_rewarns_and_shows_status", func(t *testing.T) {
		clk, sink := newAuthEnv(t)
		authLimitWarnEvery = time.Hour
		authLimitWarnTick = 5 * time.Millisecond
		disabled := false
		writeAuthConfig(t, func(c *appconfig.Config) { c.Auth.Limits.Enabled = &disabled })

		guiAddr, secret := bootGUI(t)

		// The loud warning fired at startup.
		if !waitUntil(2*time.Second, func() bool { return sink.countContaining("--auth-limit") >= 1 }) {
			t.Fatalf("a config-file disable must print the loud warning; sink:\n%s", sink.joined())
		}
		// disabledSince was recorded to the persisted config.
		saved, err := appconfig.Load()
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(saved.Auth.Limits.DisabledSince) == "" {
			t.Fatalf("a config-file disable must record auth.limits.disabledSince")
		}

		// Driving the injected clock past an hour re-emits the warning.
		warnCount := sink.countContaining("--auth-limit")
		clk.advance(61 * time.Minute)
		if !waitUntil(3*time.Second, func() bool { return sink.countContaining("--auth-limit") > warnCount }) {
			t.Fatalf("advancing the clock past an hour must re-emit the OFF warning; sink:\n%s", sink.joined())
		}

		// `tls status` shows "OFF since <date>" with the re-enable remedy.
		tlsOut, statusErr := captureStdout(t, func() error { return cmdTLSStatus(nil) })
		if statusErr != nil {
			t.Fatalf("tls status: %v", statusErr)
		}
		if !strings.Contains(tlsOut, "OFF since") {
			t.Fatalf("tls status must show \"auth limits: OFF since <date>\"; got:\n%s", tlsOut)
		}
		if !strings.Contains(tlsOut, "--auth-limit on") && !strings.Contains(tlsOut, "auth.limits.enabled=true") {
			t.Fatalf("tls status OFF line must name the re-enable remedy; got:\n%s", tlsOut)
		}

		// The GUI settings surface (the /api/status response) shows it too.
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
		if s, _ := m["authLimitStatus"].(string); !strings.Contains(s, "OFF since") {
			t.Fatalf("settings surface authLimitStatus must show \"OFF since <date>\"; got %q", s)
		}
	})
}

// ---- X1 ----

func TestX1ExposureLineForNonLoopbackOnly(t *testing.T) {
	t.Run("loopback_prints_nothing", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "127.0.0.1:0", "--no-keychain", "--quiet-credentials", vaultPath})
		})
		// Give startup a beat, then assert the exposure line was NOT emitted.
		if waitUntil(500*time.Millisecond, func() bool { return strings.Contains(sink.joined(), "beyond this machine") }) {
			t.Fatalf("a loopback bind must NOT print the exposure line; sink:\n%s", sink.joined())
		}
	})

	t.Run("non_loopback_prints_exposure_line", func(t *testing.T) {
		_, sink := newAuthEnv(t)
		t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
		t.Setenv("SEAVAULT_SERVE_PASSWORD", "pw-CORRECT")
		writeAuthConfig(t, nil)
		vaultPath := makeVault(t, "correct horse battery staple")
		startDaemonAndCapture(t, &serveTestHook, func() error {
			return cmdServe([]string{"--addr", "0.0.0.0:0", "--insecure-bind", "--no-keychain", "--quiet-credentials", vaultPath})
		})
		if !waitUntil(2*time.Second, func() bool { return strings.Contains(sink.joined(), "beyond this machine") }) {
			t.Fatalf("a non-loopback bind must print the exposure line; sink:\n%s", sink.joined())
		}
		if !strings.Contains(sink.joined(), "auth limits:") {
			t.Fatalf("the exposure line must name the auth-limit state; sink:\n%s", sink.joined())
		}
	})
}

// ---- W1 (wiring grep) ----

func TestW1AuthlimitWiredFromSurfaces(t *testing.T) {
	// Each surface package must not merely mention the type — it must CALL the
	// limiter (Attempt) from non-test code, or the surface is unguarded (W1).
	for _, f := range []string{
		"../../internal/localdav/server.go",
		"../../internal/webui/server.go",
	} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if !strings.Contains(string(src), "AuthLimiter.Attempt(") {
			t.Fatalf("%s never calls AuthLimiter.Attempt (W1): the surface is not wired into the limiter", f)
		}
	}
	// And the command startup actually constructs the limiter and injects it into
	// both surfaces.
	main, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"authlimit.New(", "dav.AuthLimiter =", "s.AuthLimiter ="} {
		if !strings.Contains(string(main), want) {
			t.Fatalf("cmd/seavault startup missing %q; gui/serve are not fully wired (W1)", want)
		}
	}
}

// ---- W2 (CLI redeem carries no limiter) ----

func TestW2CLIRedeemHasNoAuthlimit(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := extractFunc(string(src), "func cmdRecoveryRedeem(")
	if fn == "" {
		t.Fatalf("could not locate cmdRecoveryRedeem in main.go")
	}
	if strings.Contains(fn, "authlimit") {
		t.Fatalf("the CLI redeem path must hold NO authlimit reference (C2/W2); found one:\n%s", fn)
	}
	// It must still apply the fixed throttle the design mandates.
	if !strings.Contains(fn, "cliRedeemFailureDelay") {
		t.Fatalf("the CLI redeem path must apply the fixed FailureDelay (cliRedeemFailureDelay)")
	}
}

// extractFunc returns the source of the function whose signature line contains
// marker, from that line to the next top-level "func " (a crude but sufficient
// slice for a grep-style guard).
func extractFunc(src, marker string) string {
	i := strings.Index(src, marker)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	// Find the next top-level func after the signature line.
	next := strings.Index(rest[1:], "\nfunc ")
	if next < 0 {
		return rest
	}
	return rest[:next+1]
}
