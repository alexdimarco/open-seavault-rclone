// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Same flaw as rsyncbin: a bare string-prefix test let http://localhost.evil.tld/
// and http://localhost@evil.tld/ bypass the "official rclone hosts only" guard.

func TestAllowedDownloadURLLoopbackIsExactHostOnly(t *testing.T) {
	bad := []string{
		"http://localhost.evil.tld/x",
		"http://localhost@evil.tld/x",
		"http://127.0.0.1.evil.tld/x",
		"http://127.0.0.1@evil.tld/x",
		"http://localhostevil.tld/x",
		"https://downloads.rclone.org.evil.tld/x",
	}
	for _, u := range bad {
		if err := allowedDownloadURL(u); err == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
	good := []string{
		"http://127.0.0.1:9/x", "http://localhost:8080/x", "http://[::1]:9/x",
		"https://downloads.rclone.org/v1.74.0/rclone.zip", "https://rclone.org/KEYS",
	}
	for _, u := range good {
		if err := allowedDownloadURL(u); err != nil {
			t.Errorf("%q must be allowed: %v", u, err)
		}
	}
}

func TestFetchRefusesRedirectToDisallowedURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://runtime.evil.invalid/payload", http.StatusFound)
	}))
	defer srv.Close()
	i := NewInstaller()
	_, err := i.fetch(context.Background(), srv.URL+"/x", 1024)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a redirect to a disallowed URL must be refused by the URL guard, got: %v", err)
	}
}
