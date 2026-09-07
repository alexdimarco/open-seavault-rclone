// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// TestSetupStepperFirstRunAndAuth proves design §7 row T6: a fresh server with
// no profiles and no open vault serves the first-run stepper from the index
// handler; after /api/setup/run opens a vault the index serves the full page;
// and every /api/setup/* route sits behind the existing session auth — a
// no-session request gets the serveNoSession 403 and a session that exists but
// is not logged in (a GUI password is configured) gets the 401 login-required
// path. The 403/401 codes were verified against server.go (serveNoSession's
// /api/ branch returns 403; serveLoginRequired's /api/ branch returns 401)
// before being asserted here.
func TestSetupStepperFirstRunAndAuth(t *testing.T) {
	// Isolate the profile store so the first-run trigger (empty profile list)
	// holds regardless of what other tests in this package wrote.
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	indexBody := func() string {
		t.Helper()
		req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("index request failed: %d %s", rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}

	// 1. Fresh server, no profiles, no vault open: the index handler renders the
	// first-run stepper.
	first := indexBody()
	for _, want := range []string{`data-first-run="true"`, `id="setup-stepper"`, "Set up your encrypted vault"} {
		if !strings.Contains(first, want) {
			t.Fatalf("first-run index is missing %q", want)
		}
	}
	if strings.Contains(first, `data-first-run="false"`) {
		t.Fatalf("first-run index must not also mark data-first-run=false")
	}

	// 2. After /api/setup/run opens a vault, the index handler renders the full
	// page (the first-run trigger no longer holds because a vault is open).
	vaultDir := filepath.Join(t.TempDir(), "myvault")
	runRR := postJSON(t, s, "/api/setup/run", map[string]any{
		"vaultPath":    vaultDir,
		"password":     "passphrase-open",
		"saveKeychain": false,
		"cloud":        map[string]any{"mode": "local"},
	})
	if runRR.Code != http.StatusOK {
		t.Fatalf("/api/setup/run failed: %d %s", runRR.Code, runRR.Body.String())
	}
	full := indexBody()
	if !strings.Contains(full, `data-first-run="false"`) {
		t.Fatalf("after setup run the index must render the full page (data-first-run=false)")
	}
	if strings.Contains(full, `data-first-run="true"`) {
		t.Fatalf("after setup run the index must not still be first-run")
	}

	// 3. Every /api/setup/* route is behind the existing session auth. Assert on
	// every row of the endpoint table.
	endpoints := []struct {
		name   string
		method string
		path   string
	}{
		{"detect", http.MethodGet, "/api/setup/detect"},
		{"validate", http.MethodPost, "/api/setup/validate"},
		{"run", http.MethodPost, "/api/setup/run"},
	}

	// 3a. No session at all -> serveNoSession -> 403 for /api/*.
	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
		req.Host = "127.0.0.1" // pass the Host allowlist; carry no session cookie.
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s with no session: want 403, got %d %s", ep.name, rr.Code, rr.Body.String())
		}
	}

	// 3b. Session present but not logged in (a GUI password is configured) ->
	// serveLoginRequired -> 401 for /api/*.
	sAuth, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
		req.Host = "127.0.0.1"
		req.AddCookie(newTestSession(sAuth, false)) // a session that has not logged in
		if ep.method != http.MethodGet {
			req.Header.Set("X-open-seavault-rclone-Token", sAuth.token)
		}
		rr := httptest.NewRecorder()
		sAuth.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s with a not-logged-in session: want 401, got %d %s", ep.name, rr.Code, rr.Body.String())
		}
	}
}

// TestSetupRunNeverLeaksPassword proves design §7 row T13 (I-S1, C13): the
// password never appears in the SUCCESS body of /api/setup/run, the ERROR body
// of /api/setup/run, or anything written to the standard logger during the run.
// Both bodies are decoded and asserted to carry real content (a success result
// with a vault path; an error message) so the check is not a vacuous pass, then
// every sink is asserted free of the password substring.
func TestSetupRunNeverLeaksPassword(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	// Capture anything the run writes through the standard logger.
	var logSink bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&logSink)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()

	const password = "s3cr3t-PASSWORD-never-log-7c1e9f2a"
	vaultDir := filepath.Join(t.TempDir(), "myvault")

	// Success run.
	okRR := postJSON(t, s, "/api/setup/run", map[string]any{
		"vaultPath":    vaultDir,
		"password":     password,
		"saveKeychain": false,
		"cloud":        map[string]any{"mode": "local"},
	})
	if okRR.Code != http.StatusOK {
		t.Fatalf("/api/setup/run success: %d %s", okRR.Code, okRR.Body.String())
	}
	successBody := okRR.Body.String()
	var okDecoded map[string]any
	if err := json.Unmarshal([]byte(successBody), &okDecoded); err != nil {
		t.Fatalf("decode success body: %v body=%s", err, successBody)
	}
	result, _ := okDecoded["result"].(map[string]any)
	if result == nil {
		t.Fatalf("success body missing result object: %s", successBody)
	}
	if vp, _ := result["vaultPath"].(string); strings.TrimSpace(vp) == "" {
		t.Fatalf("success body result.vaultPath is empty: %s", successBody)
	}

	// Error run: a second run at the same path is refused (an existing vault).
	errRR := postJSON(t, s, "/api/setup/run", map[string]any{
		"vaultPath":    vaultDir,
		"password":     password,
		"saveKeychain": false,
		"cloud":        map[string]any{"mode": "local"},
	})
	if errRR.Code == http.StatusOK {
		t.Fatalf("second /api/setup/run at an existing vault must fail, got 200: %s", errRR.Body.String())
	}
	errorBody := errRR.Body.String()
	var errDecoded map[string]any
	if err := json.Unmarshal([]byte(errorBody), &errDecoded); err != nil {
		t.Fatalf("decode error body: %v body=%s", err, errorBody)
	}
	if msg, _ := errDecoded["error"].(string); strings.TrimSpace(msg) == "" {
		t.Fatalf("error body missing error message: %s", errorBody)
	}

	// Every sink must be free of the password. Assert on every row.
	sinks := []struct {
		name    string
		content string
	}{
		{"success response body", successBody},
		{"error response body", errorBody},
		{"captured standard log", logSink.String()},
	}
	for _, sink := range sinks {
		if strings.Contains(sink.content, password) {
			t.Fatalf("password leaked into the %s: %s", sink.name, sink.content)
		}
	}
}
