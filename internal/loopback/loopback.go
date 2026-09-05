// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

// Package loopback provides the Host-header allowlist that keeps the local
// HTTP listeners (the GUI and the WebDAV redirector) reachable only under Host
// names that identify this machine's loopback interface. This defeats DNS
// rebinding: a page served from evil.example that resolves to 127.0.0.1 still
// sends "Host: evil.example", which is rejected.
package loopback

import (
	"net"
	"strings"
)

// HostAllowed reports whether rawHost (an HTTP Host header value, which may
// carry a port and/or IPv6 brackets) names this loopback listener.
//
// It allows: any IP that net.ParseIP considers loopback (127.0.0.0/8 and::1,
// including the IPv4-mapped form::ffff:127.0.0.1); a NON-loopback IP literal
// only when it matches an entry of extra (compared with net.IP.Equal when that
// entry parses as an IP, else case-insensitively as a string); the name
// "localhost" (case-insensitive); and any entry of extra (case-insensitive) for
// name hosts. An empty or unparsable host is not allowed. No DNS lookups are
// ever performed.
//
// Before this returned ip.IsLoopback for ANY IP literal and returned
// BEFORE consulting extra, so "--allow-host 192.168.1.5" was silently inert and
// the documented --insecure-bind LAN workflow could not work. Honouring IP
// entries STRENGTHENS the gate: loopback stays auto-allowed, a non-loopback IP is
// allowed only when the operator explicitly listed it.
func HostAllowed(rawHost string, extra []string) bool {
	host := hostOnly(rawHost)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return true
		}
		for _, e := range extra {
			if eip := net.ParseIP(strings.TrimSpace(e)); eip != nil {
				if ip.Equal(eip) {
					return true
				}
			} else if strings.EqualFold(host, e) {
				return true
			}
		}
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	for _, e := range extra {
		if strings.EqualFold(host, e) {
			return true
		}
	}
	return false
}

// hostOnly strips a trailing port and any IPv6 brackets from an HTTP Host value.
func hostOnly(rawHost string) string {
	h := strings.TrimSpace(rawHost)
	if h == "" {
		return ""
	}
	// net.SplitHostPort removes a trailing:port and, for bracketed IPv6 hosts,
	// the surrounding brackets.
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	// No parseable trailing port: a bare host, or a bare IPv6 literal whose
	// colons make SplitHostPort fail. Strip surrounding brackets if present.
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}
