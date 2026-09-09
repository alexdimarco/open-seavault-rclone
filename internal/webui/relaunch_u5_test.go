// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/bundlelaunch"
)

// TestRelaunchEndpointGating (M10 / I-M7 / C10): the loopback /api/relaunch
// endpoint hands back the running instance's launch link ONLY when the caller is
// on loopback, the endpoint is enabled, and the app-data lock token matches. It
// is session-less. Every row asserts.
func TestRelaunchEndpointGating(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const launchURL = "http://127.0.0.1:8787/?launch=fixture-launch-value"

	req := func(remoteAddr, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/relaunch", nil)
		r.Host = "127.0.0.1"
		r.RemoteAddr = remoteAddr
		if tok != "" {
			r.Header.Set(bundlelaunch.RelaunchTokenHeader, tok)
		}
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, r)
		return rr
	}

	// Not enabled yet (SetRelaunch has not run): a loopback caller with any token
	// gets 404, never a session or a link.
	if rr := req("127.0.0.1:5555", token); rr.Code != http.StatusNotFound {
		t.Fatalf("disabled endpoint: code = %d, want 404", rr.Code)
	}

	s.SetRelaunch(token, launchURL)

	// Loopback + correct token → 200 and the launch link, no Set-Cookie (session-less).
	rr := req("127.0.0.1:5555", token)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorized relaunch: code = %d, want 200", rr.Code)
	}
	if sc := rr.Result().Header.Get("Set-Cookie"); sc != "" {
		t.Fatalf("relaunch must mint no session cookie; got Set-Cookie %q", sc)
	}
	var body struct {
		LaunchURL string `json:"launchURL"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode relaunch body: %v", err)
	}
	if body.LaunchURL != launchURL {
		t.Fatalf("relaunch returned the wrong launch link (match=%v)", body.LaunchURL == launchURL)
	}

	// Wrong token from loopback → 403, and the body must not carry the link.
	rrWrong := req("127.0.0.1:5555", "wrong-token-value")
	if rrWrong.Code != http.StatusForbidden {
		t.Fatalf("wrong token: code = %d, want 403", rrWrong.Code)
	}
	if strings.Contains(rrWrong.Body.String(), "launchURL") {
		t.Fatal("a rejected relaunch must not return the launch link")
	}

	// Missing token from loopback → 403.
	if rrNone := req("127.0.0.1:5555", ""); rrNone.Code != http.StatusForbidden {
		t.Fatalf("missing token: code = %d, want 403", rrNone.Code)
	}

	// A non-loopback peer, even with the correct token, is refused before the token
	// is even consulted.
	rrRemote := req("203.0.113.7:9999", token)
	if rrRemote.Code != http.StatusForbidden {
		t.Fatalf("non-loopback peer: code = %d, want 403", rrRemote.Code)
	}
	if strings.Contains(rrRemote.Body.String(), "launchURL") {
		t.Fatal("a non-loopback relaunch must not return the launch link")
	}
}
