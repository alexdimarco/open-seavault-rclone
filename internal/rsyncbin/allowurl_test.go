// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncbin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The guard waved through any URL that merely STARTED with http://127.0.0.1 or
// http://localhost, so http://localhost.evil.tld/ (a normal public hostname) or
// http://localhost@evil.tld/ (userinfo; the real host is evil.tld) were fetched
// over plain HTTP, checksum file and all, and the binary was then executed.

func TestAllowedDownloadURLLoopbackIsExactHostOnly(t *testing.T) {
	i := NewInstaller()
	bad := []string{
		"http://localhost.evil.tld/x",
		"http://localhost@evil.tld/x",
		"http://localhost:80@evil.tld/x",
		"http://127.0.0.1.evil.tld/x",
		"http://127.0.0.1@evil.tld/x",
		"http://localhostevil.tld/x",
		"http://127.0.0.10.evil.tld/x",
	}
	for _, u := range bad {
		if err := i.allowedDownloadURL(u); err == nil {
			t.Errorf("%q must be rejected (not a loopback host)", u)
		}
	}
	good := []string{"http://127.0.0.1:9/x", "http://localhost:8080/x", "http://[::1]:9/x"}
	for _, u := range good {
		if err := i.allowedDownloadURL(u); err != nil {
			t.Errorf("real loopback %q must be allowed: %v", u, err)
		}
	}
}

// A permitted host that answers 302 to an unpermitted URL must not be followed.
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
