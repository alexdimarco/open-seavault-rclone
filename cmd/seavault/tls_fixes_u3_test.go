// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// issueLeafAt mints a CA-signed leaf with an explicit validity window, so the
// tls-check tests can exercise expired and not-yet-valid leaves.
func issueLeafAt(t *testing.T, ca u3CA, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key := u3GenKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          u3Serial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return u3CertPEM(der), u3KeyPEM(t, key)
}

// TestEnsureLoopbackBindEveryInterfaceAdvisory (guard-warning-allzero-1): the
// every-interface advisory must fire for the explicit wildcard binds
// (0.0.0.0, ::, [::]) as well as the empty host, and must NOT fire for a concrete
// LAN IP. Before the fix it fired only for the empty host.
func TestEnsureLoopbackBindEveryInterfaceAdvisory(t *testing.T) {
	rows := []struct {
		name string
		addr string
	}{
		{"empty", ":8787"},
		{"ipv4-unspecified", "0.0.0.0:8787"},
		{"ipv6-unspecified", "[::]:8787"},
	}
	if len(rows) == 0 {
		t.Fatal("advisory table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			// tlsOn, CA (not self-signed): admitted, and the every-interface
			// advisory must be present.
			warnings, err := ensureLoopbackBind(r.addr, false, true, false, false)
			if err != nil {
				t.Fatalf("a TLS bind to %q must be admitted: %v", r.addr, err)
			}
			if !containsStr(warnings, everyInterfaceWarning) {
				t.Fatalf("bind %q must carry the every-interface advisory; got %#v", r.addr, warnings)
			}
		})
	}

	// A concrete LAN IP must not over-fire the advisory.
	w, err := ensureLoopbackBind("192.168.1.5:8787", false, true, false, false)
	if err != nil {
		t.Fatalf("a TLS bind to a LAN IP must be admitted: %v", err)
	}
	if containsStr(w, everyInterfaceWarning) {
		t.Fatalf("a concrete LAN IP must not carry the every-interface advisory; got %#v", w)
	}

	// Without TLS, an unspecified bind is still refused (I-T1 unchanged).
	if _, err := ensureLoopbackBind("0.0.0.0:8787", false, false, false, false); err == nil {
		t.Fatal("plaintext 0.0.0.0 without --insecure-bind must be refused")
	}
}

// TestTLSCheckOutOfWindowExitsNonZero (friction A3-c6): `tls check` must exit
// non-zero on an expired or not-yet-valid leaf, matching the docs ("exits
// non-zero on any error — use it in a health check"). A still-valid leaf passes.
// Before the fix, Validate returned only a warning for an out-of-window leaf and
// `tls check` printed OK and exited 0.
func TestTLSCheckOutOfWindowExitsNonZero(t *testing.T) {
	ca := newU3CA(t)
	dir := t.TempDir()
	now := time.Now()

	persist := func(t *testing.T, certPath, keyPath string) {
		t.Helper()
		cfg, err := appconfig.Load()
		if err != nil {
			t.Fatal(err)
		}
		cfg.TLS.CertFile = certPath
		cfg.TLS.KeyFile = keyPath
		cfg.GUI.Protocol = "https"
		if err := appconfig.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("expired exits non-zero", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		certPEM, keyPEM := issueLeafAt(t, ca, "vault.example", now.AddDate(-1, 0, 0), now.Add(-time.Hour))
		certPath, keyPath := writePairFiles(t, mkdir(t, dir, "expired"), certPEM, keyPEM)
		persist(t, certPath, keyPath)
		out, err := captureStdout(t, func() error { return cmdTLS([]string{"check"}) })
		if err == nil {
			t.Fatalf("tls check on an expired leaf must exit non-zero; output=%q", out)
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Fatalf("the failure must name the expiry; got %v", err)
		}
		assertNoKeyBytesCmd(t, err.Error()+out, keyPath)
	})

	t.Run("not-yet-valid exits non-zero", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		certPEM, keyPEM := issueLeafAt(t, ca, "vault.example", now.Add(48*time.Hour), now.AddDate(1, 0, 0))
		certPath, keyPath := writePairFiles(t, mkdir(t, dir, "future"), certPEM, keyPEM)
		persist(t, certPath, keyPath)
		out, err := captureStdout(t, func() error { return cmdTLS([]string{"check"}) })
		if err == nil {
			t.Fatalf("tls check on a not-yet-valid leaf must exit non-zero; output=%q", out)
		}
		if !strings.Contains(err.Error(), "not valid until") {
			t.Fatalf("the failure must name the not-yet-valid window; got %v", err)
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		certPEM, keyPEM := issueLeafAt(t, ca, "vault.example", now.Add(-time.Hour), now.AddDate(1, 0, 0))
		certPath, keyPath := writePairFiles(t, mkdir(t, dir, "valid"), certPEM, keyPEM)
		persist(t, certPath, keyPath)
		out, err := captureStdout(t, func() error { return cmdTLS([]string{"check"}) })
		if err != nil {
			t.Fatalf("tls check on a valid leaf must exit 0; got %v", err)
		}
		if !strings.Contains(out, "OK") {
			t.Fatalf("tls check on a valid leaf must print OK; got %q", out)
		}
	})
}
