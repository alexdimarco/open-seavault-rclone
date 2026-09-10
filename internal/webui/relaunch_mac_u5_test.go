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

// TestRelaunchResponseCarriesResponderMAC (relaunch-lock-log-1): an authorized
// /api/relaunch response authenticates the RESPONDER — it returns a MAC that is
// HMAC-SHA256 of the launch URL keyed by the lock token, so a second launch can
// verify this instance holds the token before opening anything. The MAC must be
// present, non-empty, and verify; a squatting responder that never held the token
// cannot produce it.
func TestRelaunchResponseCarriesResponderMAC(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const launchURL = "http://127.0.0.1:8787/?launch=fixture-launch-value"
	s.SetRelaunch(token, launchURL)

	r := httptest.NewRequest(http.MethodGet, "/api/relaunch", nil)
	r.Host = "127.0.0.1"
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set(bundlelaunch.RelaunchTokenHeader, token)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("authorized relaunch: code = %d, want 200", rr.Code)
	}
	var body struct {
		LaunchURL string `json:"launchURL"`
		MAC       string `json:"mac"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode relaunch body: %v", err)
	}
	if body.MAC == "" {
		t.Fatal("relaunch response must carry a responder MAC (relaunch-lock-log-1)")
	}
	if !bundlelaunch.VerifyRelaunchMAC(token, body.LaunchURL, body.MAC) {
		t.Fatal("the returned MAC must verify as HMAC-SHA256(token, launchURL)")
	}
	// A responder that does NOT hold the token could not have produced this MAC.
	if bundlelaunch.VerifyRelaunchMAC("a-different-token", body.LaunchURL, body.MAC) {
		t.Fatal("the MAC must not verify under a different token")
	}
	// The launch secret must not leak into anything but the JSON launchURL itself.
	if strings.Count(rr.Body.String(), "fixture-launch-value") != 1 {
		t.Fatal("the launch value must appear only in the launchURL field")
	}
}
