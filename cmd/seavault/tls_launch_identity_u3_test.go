// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/tlsconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/webui"
)

// TestFirstConfirmedNameSkipsWildcards (launch-allowlist-1, C1): a cross-device
// launch link must be an openable, concrete name — never a wildcard. The first
// concrete confirmed name (allow-host or SAN) wins; a leading wildcard is
// skipped; wildcard-only input yields "" so launchAddrForBind falls back to the
// bind address.
func TestFirstConfirmedNameSkipsWildcards(t *testing.T) {
	type row struct {
		name       string
		allowHosts []string
		certNames  []string
		want       string
	}
	rows := []row{
		{"concrete allow-host wins over a wildcard SAN", []string{"vault.example.com"}, []string{"*.example.com"}, "vault.example.com"},
		{"wildcard allow-host is skipped; concrete SAN wins", []string{"*.example.com"}, []string{"host.example.com"}, "host.example.com"},
		{"wildcard-only inputs yield no name", []string{"*.example.com"}, []string{"*.example.com"}, ""},
		{"first concrete SAN wins, skipping the leading wildcard SAN", nil, []string{"*.example.com", "concrete.example.com"}, "concrete.example.com"},
		{"a spaced wildcard is still skipped", []string{"  *.example.com  "}, []string{"named.example.com"}, "named.example.com"},
	}
	if len(rows) == 0 {
		t.Fatal("empty table")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := firstConfirmedName(r.allowHosts, r.certNames)
			if got != r.want {
				t.Fatalf("firstConfirmedName(%q, %q) = %q, want %q", r.allowHosts, r.certNames, got, r.want)
			}
			if strings.Contains(got, "*") {
				t.Fatalf("firstConfirmedName returned a wildcard %q; a launch link must be openable", got)
			}
		})
	}
}

// TestLaunchAddrForBindWildcardFallsBackToBind (launch-allowlist-1, C1): a
// non-loopback TLS bind whose only certificate name is a wildcard advertises the
// bind address, not an unopenable https://*.example.com.
func TestLaunchAddrForBindWildcardFallsBackToBind(t *testing.T) {
	got := launchAddrForBind("192.168.1.5:8787", true, nil, []string{"*.example.com"})
	if got != "192.168.1.5:8787" {
		t.Fatalf("launchAddr = %q, want the bind address (no confirmed concrete name)", got)
	}
	if strings.Contains(got, "*") {
		t.Fatalf("launchAddr %q carries a wildcard; a launch link must be openable", got)
	}
	// A confirmed concrete name (as merged from tls.allowHosts) still wins over a
	// wildcard SAN.
	got = launchAddrForBind("192.168.1.5:8787", true, []string{"vault.example.com"}, []string{"*.example.com"})
	if got != "vault.example.com:8787" {
		t.Fatalf("launchAddr = %q, want vault.example.com:8787", got)
	}
}

// startGUIAndCaptureServer runs cmdGUI, capturing the live *http.Server and its
// bound address the guiTestHook publishes, and returns the underlying
// *webui.Server so a test can read the identity fields (LoginHintURL) the launch
// path set. It registers cleanup that shuts the server down so cmdGUI returns.
func startGUIAndCaptureServer(t *testing.T, run func() error) *webui.Server {
	t.Helper()
	type ready struct {
		srv  *http.Server
		addr string
	}
	readyCh := make(chan ready, 1)
	prev := guiTestHook
	guiTestHook = func(srv *http.Server, addr string) { readyCh <- ready{srv, addr} }
	t.Cleanup(func() { guiTestHook = prev })

	doneCh := make(chan error, 1)
	go func() { doneCh <- run() }()

	var r ready
	select {
	case r = <-readyCh:
	case err := <-doneCh:
		t.Fatalf("gui returned before serving: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("gui did not reach the serving hook")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = r.srv.Shutdown(ctx)
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
		}
	})
	srv, ok := r.srv.Handler.(*webui.Server)
	if !ok {
		t.Fatalf("captured handler is %T, want *webui.Server", r.srv.Handler)
	}
	return srv
}

// freeLoopbackPort returns a currently-free 127.0.0.1 port as a string.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	return port
}

// TestGUILaunchHintSetForPlaintextListener (launch-hint-loopback-1): the
// no-session login hint is set for a PLAINTEXT (http) listener too, carrying the
// address this server actually serves — not the hardcoded http://127.0.0.1:8787.
// Before the fix LoginHintURL was set only for https, so an http listener on any
// non-default port advertised the wrong hardcoded example.
func TestGUILaunchHintSetForPlaintextListener(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	port := freeLoopbackPort(t)
	addr := net.JoinHostPort("127.0.0.1", port)

	s := startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{
			"--addr", addr,
			"--no-open",
			"--exit-on-browser-close=false",
		})
	})

	want := "http://" + addr + "/?launch=…"
	if s.LoginHintURL == "" {
		t.Fatal("LoginHintURL is empty for a plaintext listener; the login hint must carry the served address (launch-hint-loopback-1)")
	}
	if s.LoginHintURL != want {
		t.Fatalf("LoginHintURL = %q, want %q (the real served address, not the hardcoded :8787)", s.LoginHintURL, want)
	}
	if strings.Contains(s.LoginHintURL, ":8787") {
		t.Fatalf("LoginHintURL %q carries the hardcoded default port instead of the bound port %s", s.LoginHintURL, port)
	}
}

// TestGUILaunchLinkMergesConfigAllowHosts (launch-allowlist-1, C1): a wildcard
// certificate resolved from the shared tls section, a persisted tls.allowHosts
// concrete name, and a non-loopback bind with NO --allow-host flag on this run
// must advertise the concrete name — never https://*.example.com. Before the fix
// cmdGUI passed only the (empty) CLI --allow-host list, so the wildcard SAN
// leaked into the launch link.
func TestGUILaunchLinkMergesConfigAllowHosts(t *testing.T) {
	ip, ok := firstNonLoopbackIPv4()
	if !ok {
		t.Skip("no non-loopback IPv4 interface on this machine; launch-allowlist wiring test skipped")
	}
	appHome := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", appHome)

	ca := newU3CA(t)
	certPEM, keyPEM := ca.issue(t, []string{"*.example.com"}, nil)
	certPath, keyPath := writePairFiles(t, t.TempDir(), certPEM, keyPEM)

	// Persist the wizard's result: the shared tls section points at the wildcard
	// pair and records the concrete allow-host name (as `tls use --allow-host`
	// would). This `gui` run passes NO --allow-host of its own.
	persisted := appconfig.Config{
		Version: appconfig.Version,
		GUI:     appconfig.GUIConfig{Protocol: "https"},
		TLS:     appconfig.TLSSection{CertFile: certPath, KeyFile: keyPath, AllowHosts: []string{"vault.example.com"}},
	}
	if err := appconfig.Save(persisted); err != nil {
		t.Fatal(err)
	}

	addr := net.JoinHostPort(ip.String(), "0")
	s := startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{
			"--addr", addr,
			"--no-open",
			"--exit-on-browser-close=false",
		})
	})

	if s.LoginHintURL == "" {
		t.Fatal("LoginHintURL is empty; a TLS listener must advertise a launch hint")
	}
	if strings.Contains(s.LoginHintURL, "*") {
		t.Fatalf("launch hint %q carries the wildcard SAN; the persisted tls.allowHosts concrete name was ignored (launch-allowlist-1)", s.LoginHintURL)
	}
	if !strings.HasPrefix(s.LoginHintURL, "https://vault.example.com:") {
		t.Fatalf("launch hint = %q, want the concrete https://vault.example.com:<port> from tls.allowHosts", s.LoginHintURL)
	}
}

// TestStartupWildcardSANGuidance (launch-allowlist-1): the startup allowlist
// warning for a WILDCARD SAN must not tell the operator to add the wildcard
// itself with --allow-host (the exact-match guard drops wildcards, C5, so that is
// a dead end). It names the wildcard as such, states that exact names are
// required, and points at a concrete example.
func TestStartupWildcardSANGuidance(t *testing.T) {
	ca := newU3CA(t)
	certPEM, keyPEM := ca.issue(t, []string{"*.example.com"}, nil)
	certPath, keyPath := writePairFiles(t, t.TempDir(), certPEM, keyPEM)
	cfg := appconfig.Config{Version: appconfig.Version, TLS: appconfig.TLSSection{CertFile: certPath, KeyFile: keyPath}}
	resolved, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: cfg, Purpose: tlsconfig.PurposeServe})
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	// A LAN bind with no matching allowlist entry: the wildcard is not admitted.
	logTLSStartup(&log, "gui", resolved, allowedHostsForBind("192.168.1.5:8787", nil, nil))
	out := log.String()
	if out == "" {
		t.Fatal("empty startup log for a wildcard SAN")
	}
	if !strings.Contains(out, "is a wildcard") || !strings.Contains(out, "exact names only") {
		t.Fatalf("wildcard guidance did not name the wildcard / exact-names constraint; got:\n%s", out)
	}
	if !strings.Contains(out, "host.example.com") {
		t.Fatalf("wildcard guidance did not offer a concrete example name; got:\n%s", out)
	}
	if strings.Contains(out, `"*.example.com" is not in the Host allowlist`) {
		t.Fatalf("wildcard SAN still routed through the dead-end \"add it with --allow-host\" guidance; got:\n%s", out)
	}
}

// TestStartTLSReloaderWaitJoinsGoroutine (re-fix, U3 F-B teardown race):
// startTLSReloader must return a wait func that blocks until the reloader
// goroutine has fully returned, so cmdGUI/cmdServe drain the goroutine — and the
// serving.json write Run performs unconditionally at startup — before the
// command returns. Before the join, `go rl.Run(ctx)` was fire-and-forget: the
// startup write could land after the command returned and race a caller's
// teardown. That is the TempDir RemoveAll flake the verifier reproduced ~20-30%
// in TestGUILaunchLinkMergesConfigAllowHosts (the reloader recreating
// <appHome>/config/tls/serving.json after shutdown cleanup returned).
//
// Deterministic discriminator: while ctx is live the reloader goroutine is still
// running (blocked in its poll select after the startup write), so a joining
// wait must NOT return yet; a fire-and-forget startTLSReloader returns a no-op
// wait that returns at once — the RED. After cancel, wait must return promptly.
func TestStartTLSReloaderWaitJoinsGoroutine(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	ca := newU3CA(t)
	certPEM, keyPEM := ca.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	certPath, keyPath := writePairFiles(t, t.TempDir(), certPEM, keyPEM)
	cfg := appconfig.Config{Version: appconfig.Version, TLS: appconfig.TLSSection{CertFile: certPath, KeyFile: keyPath}}
	resolved, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: cfg, Purpose: tlsconfig.PurposeServe})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Source == tlsconfig.SourceNone {
		t.Fatal("resolved source is none; the join test needs a live reloader source")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := startTLSReloader(ctx, resolved, "test")

	returned := make(chan struct{})
	go func() { wait(); close(returned) }()

	select {
	case <-returned:
		t.Fatal("wait() returned before the reloader context was cancelled; startTLSReloader does not join its goroutine (a leaked reloader can write serving.json after the command returns and race teardown)")
	case <-time.After(250 * time.Millisecond):
		// Good: still blocked while ctx is live.
	}

	cancel()
	select {
	case <-returned:
		// Good: cancelling drains the goroutine and wait returns.
	case <-time.After(5 * time.Second):
		t.Fatal("wait() did not return after the reloader context was cancelled; the goroutine was not joined")
	}
}
