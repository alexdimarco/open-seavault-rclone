// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// TestIndexShowsQuitOnCloseHint (friction A/C3): when exit-on-browser-close is
// enabled — the default for a bundle launch that has no Dock icon — the GUI page
// carries a plain in-tab line telling the user that closing the tab quits the
// app. It is absent when that behaviour is off, so the line is never a lie.
func TestIndexShowsQuitOnCloseHint(t *testing.T) {
	const line = "Closing this tab quits the app."

	// Off by default: no EnableBrowserCloseShutdown, so the line must be absent.
	off, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
	if err != nil {
		t.Fatal(err)
	}
	offRR := httptest.NewRecorder()
	off.ServeHTTP(offRR, authReq(off, httptest.NewRequest(http.MethodGet, "/", nil)))
	if offRR.Code != http.StatusOK {
		t.Fatalf("index (off) = %d", offRR.Code)
	}
	if strings.Contains(offRR.Body.String(), line) {
		t.Fatal("the quit-on-close line must NOT appear when browser-close shutdown is disabled")
	}

	// Enabled (as cmd gui does before serving): the line must be present.
	on, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
	if err != nil {
		t.Fatal(err)
	}
	on.EnableBrowserCloseShutdown(10)
	onRR := httptest.NewRecorder()
	on.ServeHTTP(onRR, authReq(on, httptest.NewRequest(http.MethodGet, "/", nil)))
	if onRR.Code != http.StatusOK {
		t.Fatalf("index (on) = %d", onRR.Code)
	}
	if !strings.Contains(onRR.Body.String(), line) {
		t.Fatalf("the GUI page must carry %q when exit-on-browser-close is enabled (friction A/C3)", line)
	}
}
