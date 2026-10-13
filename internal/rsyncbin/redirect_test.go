// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncbin

import (
	"net/http"
	"net/url"
	"testing"
)

// A request that STARTED on a remote https host must never be redirected onto a
// loopback address (a GET against a local service the user did not ask for);
// loopback is only acceptable for hops of a request that began on loopback.
func TestRedirectHopToLoopbackOnlyFromLoopbackOrigin(t *testing.T) {
	i := NewInstaller()
	mk := func(u string) *http.Request {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: pu}
	}
	rows := []struct {
		name       string
		origin     string
		hop        string
		wantReject bool
	}{
		{"remote https to loopback", "https://download.samba.org/pub/rsync/x", "http://127.0.0.1:8080/admin", true},
		{"remote https to localhost", "https://download.samba.org/pub/rsync/x", "http://localhost/x", true},
		{"loopback to loopback", "http://127.0.0.1:9/x", "http://127.0.0.1:9/y", false},
		{"remote https to remote https", "https://download.samba.org/pub/rsync/x", "https://mirror.example.net/x", false},
		{"remote https to remote http", "https://download.samba.org/pub/rsync/x", "http://mirror.example.net/x", true},
	}
	for _, r := range rows {
		err := i.redirectHop(mk(r.hop), []*http.Request{mk(r.origin)})
		if r.wantReject && err == nil {
			t.Errorf("%s: %s -> %s must be refused", r.name, r.origin, r.hop)
		}
		if !r.wantReject && err != nil {
			t.Errorf("%s: %s -> %s must be allowed: %v", r.name, r.origin, r.hop, err)
		}
	}
}
