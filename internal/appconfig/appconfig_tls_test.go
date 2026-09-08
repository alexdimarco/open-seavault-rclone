// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package appconfig

import (
	"encoding/json"
	"testing"
)

// TestTLSSectionRoundTripAndNormalize proves the shared U3 `tls` section is
// persisted, reloaded, and normalized: paths are trimmed, the allow-host list is
// trimmed/de-duplicated/emptied-to-nil, and the legacy gui.certFile/keyFile
// fields stay readable alongside it (compatibility with pre-U3 installs).
func TestTLSSectionRoundTripAndNormalize(t *testing.T) {
	cfg := Default()
	cfg.TLS.CertFile = "  /etc/tls/leaf.crt  "
	cfg.TLS.KeyFile = "\t/etc/tls/leaf.key\n"
	cfg.TLS.AllowHosts = []string{" vault.example.org ", "vault.example.org", "", "  ", "lan.example.org"}
	// Legacy fields must remain readable next to the shared section.
	cfg.GUI.CertFile = " /legacy/gui.crt "
	cfg.GUI.KeyFile = " /legacy/gui.key "

	norm := Normalize(cfg)

	if norm.TLS.CertFile != "/etc/tls/leaf.crt" {
		t.Fatalf("tls.certFile not trimmed: got %q", norm.TLS.CertFile)
	}
	if norm.TLS.KeyFile != "/etc/tls/leaf.key" {
		t.Fatalf("tls.keyFile not trimmed: got %q", norm.TLS.KeyFile)
	}
	wantHosts := []string{"vault.example.org", "lan.example.org"}
	if len(norm.TLS.AllowHosts) != len(wantHosts) {
		t.Fatalf("tls.allowHosts not de-duplicated/cleaned: got %v want %v", norm.TLS.AllowHosts, wantHosts)
	}
	for i, w := range wantHosts {
		if norm.TLS.AllowHosts[i] != w {
			t.Fatalf("tls.allowHosts[%d] = %q, want %q (order must be preserved)", i, norm.TLS.AllowHosts[i], w)
		}
	}
	if norm.GUI.CertFile != "/legacy/gui.crt" || norm.GUI.KeyFile != "/legacy/gui.key" {
		t.Fatalf("legacy gui cert/key not preserved: got %q / %q", norm.GUI.CertFile, norm.GUI.KeyFile)
	}

	// A JSON round-trip through the on-disk shape keeps the section.
	data, err := json.Marshal(norm)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	back = Normalize(back)
	if back.TLS.CertFile != "/etc/tls/leaf.crt" || back.TLS.KeyFile != "/etc/tls/leaf.key" {
		t.Fatalf("tls section lost across JSON round-trip: %+v", back.TLS)
	}
	if len(back.TLS.AllowHosts) != 2 {
		t.Fatalf("tls.allowHosts lost across JSON round-trip: %v", back.TLS.AllowHosts)
	}

	// An empty allow-host list normalizes to nil (no empty [] noise on disk).
	empty := Default()
	empty.TLS.AllowHosts = []string{"", "  "}
	if got := Normalize(empty).TLS.AllowHosts; got != nil {
		t.Fatalf("all-empty allowHosts must normalize to nil, got %v", got)
	}
}
