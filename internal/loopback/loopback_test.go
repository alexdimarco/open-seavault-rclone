// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package loopback

import "testing"

func TestHostAllowed(t *testing.T) {
	type row struct {
		name  string
		host  string
		extra []string
		want  bool
	}
	rows := []row{
		{"loopback-v4", "127.0.0.1", nil, true},
		{"loopback-v4-port", "127.0.0.1:8787", nil, true},
		{"localhost", "localhost", nil, true},
		{"localhost-upper-port", "LOCALHOST:1", nil, true},
		{"loopback-v6-bracket-port", "[::1]:8787", nil, true},
		{"loopback-v6-bare", "::1", nil, true},
		// net.ParseIP does not accept the classful shorthand "127.1"; it is not
		// a valid dotted-quad, so it is treated as a name and rejected.
		{"classful-shorthand", "127.1", nil, false},
		// Hexadecimal integer forms of 127.0.0.1 are not parsed by ParseIP.
		{"hex-integer-loopback", "0x7f000001", nil, false},
		{"loopback-prefixed-name", "127.0.0.1.evil.example", nil, false},
		{"localhost-trailing-dot", "localhost.", nil, false},
		{"foreign-name", "evil.example", nil, false},
		{"empty", "", nil, false},
		{"extra-name-allowed", "vault.lan", []string{"vault.lan"}, true},
		{"extra-name-absent", "vault.lan", nil, false},
		// An IPv4-mapped IPv6 address of a loopback IPv4 is loopback.
		{"v4-mapped-loopback", "[::ffff:127.0.0.1]:1", nil, true},
		// II-1 (friction Operator C4): a non-loopback IP literal is inert unless
		// it is explicitly listed in extra. Before the fix HostAllowed returned
		// ip.IsLoopback() for ANY IP literal and never consulted extra, so
		// "--allow-host 192.168.1.5" was silently ignored.
		{"extra-ip-allowed", "192.168.1.5:8765", []string{"192.168.1.5"}, true},
		{"extra-ip-absent", "192.168.1.5:8765", nil, false},
		{"extra-ip-v6-allowed", "[fd00::5]:1", []string{"fd00::5"}, true},
		// No canonicalisation beyond net.ParseIP: leading-zero octets do not
		// parse (ParseIP -> nil), so the entry falls to string equality and the
		// dotted-quad host does not match it.
		{"extra-ip-no-leading-zero-canon", "192.168.1.5", []string{"192.168.001.005"}, false},
		// A loopback IP is always allowed, independent of extra.
		{"loopback-ignores-extra", "127.0.0.1", []string{"192.168.1.5"}, true},
		// The unspecified address is never loopback and never auto-allowed.
		{"unspecified-not-allowed", "0.0.0.0", nil, false},
	}
	if len(rows) == 0 {
		t.Fatal("empty HostAllowed table exercises nothing")
	}

	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			if got := HostAllowed(r.host, r.extra); got != r.want {
				t.Fatalf("HostAllowed(%q, %v) = %v, want %v", r.host, r.extra, got, r.want)
			}
		})
		asserted++
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

// TestHostAllowedExtraCaseInsensitive documents that extra names match
// case-insensitively, like localhost.
func TestHostAllowedExtraCaseInsensitive(t *testing.T) {
	if !HostAllowed("Vault.LAN:443", []string{"vault.lan"}) {
		t.Fatal("extra names must match case-insensitively and ignore the port")
	}
}
