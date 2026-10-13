// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import (
	"net/http"
	"net/url"
	"testing"
)

// An official https host must never be able to redirect the installer onto a
// loopback address; loopback hops are only for requests that began on loopback.
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
		{"official to loopback", "https://downloads.rclone.org/v1/x.zip", "http://127.0.0.1:8080/admin", true},
		{"official to localhost", "https://downloads.rclone.org/v1/x.zip", "http://localhost/x", true},
		{"official to other host", "https://downloads.rclone.org/v1/x.zip", "https://evil.example.net/x", true},
		{"loopback to loopback", "http://127.0.0.1:9/x", "http://127.0.0.1:9/y", false},
		{"official to official", "https://downloads.rclone.org/v1/x.zip", "https://downloads.rclone.org/v1/y.zip", false},
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
