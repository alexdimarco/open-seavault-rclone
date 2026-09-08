// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// TestSessionCookieSecureFollowsTLSActive (row G1, C2): with gui.protocol still
// http, an active resolved TLS certificate (TLSActive) marks the re-issued
// session cookie Secure — the cookie follows the resolved TLS state, not the
// persisted protocol. The negative control (protocol http, TLSActive false) must
// NOT mark it Secure, so the assertion is not vacuous.
func TestSessionCookieSecureFollowsTLSActive(t *testing.T) {
	now := time.Now()
	type row struct {
		name       string
		tlsActive  bool
		wantSecure bool
	}
	rows := []row{
		{"tls-active over http protocol marks the cookie Secure", true, true},
		{"plain http without TLS leaves the cookie insecure", false, false},
	}
	if len(rows) == 0 {
		t.Fatal("empty table")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
			if err != nil {
				t.Fatal(err)
			}
			s.TLSActive = r.tlsActive
			cookie := insertSession(t, s, true, now.Add(3*time.Hour), now.Add(-2*time.Hour))
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			req.Host = "127.0.0.1"
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("/api/status = %d, want 200", rr.Code)
			}
			var set *http.Cookie
			for _, c := range rr.Result().Cookies() {
				if c.Name == guiSessionCookie {
					set = c
				}
			}
			if set == nil {
				t.Fatal("the stale session cookie was not re-issued")
			}
			if set.Secure != r.wantSecure {
				t.Fatalf("re-issued cookie Secure = %v, want %v", set.Secure, r.wantSecure)
			}
		})
	}
}

// TestNoSessionPageUsesLoginHintURL (row G1, C1): the no-session page shows the
// server's LoginHintURL for a network-facing TLS listener instead of the
// hardcoded loopback link; with no hint set it falls back to the loopback
// example exactly as before.
func TestNoSessionPageUsesLoginHintURL(t *testing.T) {
	t.Run("network-facing hint replaces the loopback link", func(t *testing.T) {
		s, err := New("")
		if err != nil {
			t.Fatal(err)
		}
		s.LoginHintURL = "https://vault.example:8787/?launch=…"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-session page = %d, want 403", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "https://vault.example:8787/?launch=") {
			t.Fatalf("no-session page did not show the network-facing launch hint; body:\n%s", body)
		}
		if strings.Contains(body, "http://127.0.0.1:8787/?launch=") {
			t.Fatalf("no-session page still shows the hardcoded loopback link for a TLS listener; body:\n%s", body)
		}
	})

	t.Run("no hint falls back to the loopback example", func(t *testing.T) {
		s, err := New("")
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-session page = %d, want 403", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "http://127.0.0.1:8787/?launch=") {
			t.Fatalf("default no-session page lost the loopback example; body:\n%s", rr.Body.String())
		}
	})
}

// TestSettingsSaveTLSManagedReconciliation (row G2, C3): once the shared tls.*
// section is configured, a Settings save never runs the self-signed generator
// and never un-clears a wizard-cleared legacy gui.certFile, and the toggle is
// rendered as managed-by-tls-setup; with tls.* empty the save behaves exactly as
// before (an https toggle materializes the self-signed floor).
func TestSettingsSaveTLSManagedReconciliation(t *testing.T) {
	t.Run("tls.* configured: toggle managed; save preserves cleared legacy + no self-signed", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		persisted := appconfig.Config{
			Version: appconfig.Version,
			GUI:     appconfig.GUIConfig{Protocol: "https"}, // legacy certFile/keyFile deliberately empty (wizard cleared them)
			TLS:     appconfig.TLSSection{CertFile: "/etc/seavault/leaf.crt", KeyFile: "/etc/seavault/leaf.key", AllowHosts: []string{"vault.example"}},
		}
		if err := appconfig.Save(persisted); err != nil {
			t.Fatal(err)
		}
		s, err := NewWithConfig("", persisted)
		if err != nil {
			t.Fatal(err)
		}

		var got struct {
			TLSManaged     bool   `json:"tlsManaged"`
			TLSManagedHint string `json:"tlsManagedHint"`
		}
		if code := getJSON(t, s, "/api/app-config", &got); code != http.StatusOK {
			t.Fatalf("GET /api/app-config = %d", code)
		}
		if !got.TLSManaged {
			t.Fatal("tlsManaged must be true once tls.* is configured")
		}
		if !strings.Contains(got.TLSManagedHint, "seavault tls reset") {
			t.Fatalf("tlsManagedHint %q does not name `seavault tls reset`", got.TLSManagedHint)
		}

		// A save that tries to flip to http and resurrect a legacy certFile.
		attempt := appconfig.Config{
			Version: appconfig.Version,
			GUI:     appconfig.GUIConfig{Protocol: "http", CertFile: "/tmp/resurrected.crt", KeyFile: "/tmp/resurrected.key"},
			TLS:     appconfig.TLSSection{CertFile: "/etc/seavault/leaf.crt", KeyFile: "/etc/seavault/leaf.key", AllowHosts: []string{"vault.example"}},
		}
		rr := postJSON(t, s, "/api/app-config", map[string]any{"config": attempt})
		if rr.Code != http.StatusOK {
			t.Fatalf("POST /api/app-config = %d body=%s", rr.Code, rr.Body.String())
		}
		loaded, err := appconfig.Load()
		if err != nil {
			t.Fatal(err)
		}
		if loaded.GUI.CertFile != "" {
			t.Fatalf("wizard-cleared legacy gui.certFile was resurrected: %q", loaded.GUI.CertFile)
		}
		if loaded.GUI.SelfSigned {
			t.Fatal("the self-signed generator ran despite tls.* being managed (GUI.SelfSigned set)")
		}
		if loaded.GUI.Protocol != "https" {
			t.Fatalf("managed toggle was not inert: protocol became %q", loaded.GUI.Protocol)
		}
		if loaded.TLS.CertFile != "/etc/seavault/leaf.crt" {
			t.Fatalf("tls section was mutated by the form: %q", loaded.TLS.CertFile)
		}
	})

	t.Run("tls.* empty: toggle live; https save materializes the self-signed floor", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		persisted := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
		if err := appconfig.Save(persisted); err != nil {
			t.Fatal(err)
		}
		s, err := NewWithConfig("", persisted)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			TLSManaged bool `json:"tlsManaged"`
		}
		if code := getJSON(t, s, "/api/app-config", &got); code != http.StatusOK {
			t.Fatalf("GET /api/app-config = %d", code)
		}
		if got.TLSManaged {
			t.Fatal("tlsManaged must be false when tls.* is empty")
		}
		attempt := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "https"}}
		rr := postJSON(t, s, "/api/app-config", map[string]any{"config": attempt})
		if rr.Code != http.StatusOK {
			t.Fatalf("POST /api/app-config = %d body=%s", rr.Code, rr.Body.String())
		}
		loaded, err := appconfig.Load()
		if err != nil {
			t.Fatal(err)
		}
		if loaded.GUI.CertFile == "" || !loaded.GUI.SelfSigned {
			t.Fatalf("with tls.* empty an https save must materialize the self-signed floor; got certFile=%q selfSigned=%v", loaded.GUI.CertFile, loaded.GUI.SelfSigned)
		}
	})
}
