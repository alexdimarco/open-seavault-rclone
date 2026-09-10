// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package bundlelaunch

import "testing"

// TestRelaunchMACRoundTrip (relaunch-lock-log-1): the responder MAC is a stable
// HMAC-SHA256 over the launch URL keyed by the lock token; VerifyRelaunchMAC
// accepts the matching tag and rejects a wrong token, a wrong URL, an empty tag,
// and a malformed tag. Each row asserts; the table cannot be vacuous.
func TestRelaunchMACRoundTrip(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const url = "http://127.0.0.1:8787/?launch=fixture-secret"

	mac := RelaunchMAC(token, url)
	if len(mac) != 64 {
		t.Fatalf("MAC length = %d, want 64 hex chars", len(mac))
	}
	if RelaunchMAC(token, url) != mac {
		t.Fatal("RelaunchMAC must be deterministic for the same token+URL")
	}

	rows := []struct {
		name   string
		token  string
		url    string
		tag    string
		wantOK bool
	}{
		{"correct tag", token, url, mac, true},
		{"wrong token", "ff" + token[2:], url, mac, false},
		{"tampered URL", token, "http://127.0.0.1:8787/?launch=EVIL", mac, false},
		{"empty tag", token, url, "", false},
		{"garbage tag", token, url, "not-hex", false},
	}
	seen := 0
	for _, r := range rows {
		seen++
		if got := VerifyRelaunchMAC(r.token, r.url, r.tag); got != r.wantOK {
			t.Fatalf("%s: VerifyRelaunchMAC = %v, want %v", r.name, got, r.wantOK)
		}
	}
	if seen != len(rows) {
		t.Fatalf("ran %d rows, want %d", seen, len(rows))
	}
}

// TestValidLoopbackLaunchURL (relaunch-lock-log-1): only an http(s) URL on a
// loopback host and the exact expected port is acceptable; an external host, a
// public IP, a foreign port, and a non-http scheme are all refused, so a
// squatting responder cannot redirect the launch off the machine.
func TestValidLoopbackLaunchURL(t *testing.T) {
	rows := []struct {
		name string
		raw  string
		port int
		want bool
	}{
		{"loopback http exact port", "http://127.0.0.1:8787/?launch=x", 8787, true},
		{"loopback https exact port", "https://127.0.0.1:8787/?launch=x", 8787, true},
		{"ipv6 loopback exact port", "http://[::1]:8787/?launch=x", 8787, true},
		{"external host", "http://attacker.example/phish?launch=EVIL", 8787, false},
		{"public ip", "http://203.0.113.7:8787/?launch=x", 8787, false},
		{"loopback wrong port", "http://127.0.0.1:9999/?launch=x", 8787, false},
		{"non-http scheme", "file:///etc/passwd", 8787, false},
		{"loopback no port", "http://127.0.0.1/?launch=x", 8787, false},
		{"garbage", "://::::", 8787, false},
	}
	seen := 0
	for _, r := range rows {
		seen++
		if got := ValidLoopbackLaunchURL(r.raw, r.port); got != r.want {
			t.Fatalf("%s: ValidLoopbackLaunchURL(%q,%d) = %v, want %v", r.name, r.raw, r.port, got, r.want)
		}
	}
	if seen != len(rows) {
		t.Fatalf("ran %d rows, want %d", seen, len(rows))
	}
}
