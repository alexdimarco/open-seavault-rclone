// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/tlsconfig"
)

// assertNoKeyBytesCmd fails when output carries any base64 body line of the key
// file, or a PRIVATE KEY header (I-T2). The key PATH is allowed; the bytes are not.
func assertNoKeyBytesCmd(t *testing.T, output, keyPath string) {
	t.Helper()
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if strings.Contains(output, "PRIVATE KEY") {
		t.Fatalf("output contains a PRIVATE KEY header — key material leaked")
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 40 && !strings.Contains(line, "PRIVATE KEY") && strings.Contains(output, line) {
			t.Fatalf("output contains a private-key body line — key material leaked")
		}
	}
}

// TestTLSCommandsUseStatusCheckReset (row U1, C12): the non-interactive companions
// persist, report, validate, and reset. `tls use` and `tls reset` print the same
// status summary `tls status` prints; `tls check` exits non-zero on a mismatch;
// `tls use` refuses a mismatched pair and persists nothing; no command prints key
// material.
func TestTLSCommandsUseStatusCheckReset(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newU3CA(t)
	dir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, []string{"vault.example"}, nil)
	certPath, keyPath := writePairFiles(t, dir, certPEM, keyPEM)

	// tls use --cert --key --allow-host: validate + persist + print the summary.
	out, err := captureStdout(t, func() error {
		return cmdTLS([]string{"use", "--cert", certPath, "--key", keyPath, "--allow-host", "vault.example"})
	})
	if err != nil {
		t.Fatalf("tls use: %v", err)
	}
	if !strings.Contains(out, "tls source: config") {
		t.Fatalf("tls use summary missing the source line:\n%s", out)
	}
	if !strings.Contains(out, "vault.example") {
		t.Fatalf("tls use summary missing the certificate name:\n%s", out)
	}
	if !strings.Contains(out, "allowlist: vault.example") {
		t.Fatalf("tls use summary missing the allowlist:\n%s", out)
	}
	assertNoKeyBytesCmd(t, out, keyPath)

	cfg, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CertFile != certPath || cfg.TLS.KeyFile != keyPath {
		t.Fatalf("tls use did not persist the pair: cert=%q key=%q", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	if cfg.GUI.Protocol != "https" {
		t.Fatalf("tls use did not set gui.protocol=https: %q", cfg.GUI.Protocol)
	}
	if !containsStr(cfg.TLS.AllowHosts, "vault.example") {
		t.Fatalf("tls use did not persist the allow-host: %v", cfg.TLS.AllowHosts)
	}

	// tls status reports the same summary.
	out, err = captureStdout(t, func() error { return cmdTLS([]string{"status"}) })
	if err != nil {
		t.Fatalf("tls status: %v", err)
	}
	if !strings.Contains(out, "tls source: config") || !strings.Contains(out, "vault.example") {
		t.Fatalf("tls status summary wrong:\n%s", out)
	}
	assertNoKeyBytesCmd(t, out, keyPath)

	// tls check on a matching pair succeeds (exit 0).
	if _, err := captureStdout(t, func() error { return cmdTLS([]string{"check"}) }); err != nil {
		t.Fatalf("tls check on a matching pair must succeed: %v", err)
	}

	// tls check on a mismatched configured pair errors (exit 1), typed.
	mmCertPEM, _ := ca.issue(t, []string{"vault.example"}, nil)
	_, mmWrongKeyPEM := ca.issue(t, []string{"vault.example"}, nil)
	mmDir := mkdir(t, dir, "mismatch")
	mmCert, mmKey := writePairFiles(t, mmDir, mmCertPEM, mmWrongKeyPEM)
	cfgMM, _ := appconfig.Load()
	cfgMM.TLS.CertFile = mmCert
	cfgMM.TLS.KeyFile = mmKey
	if err := appconfig.Save(cfgMM); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return cmdTLS([]string{"check"}) }); err == nil {
		t.Fatal("tls check on a mismatched pair must return an error (exit 1)")
	} else if !errors.Is(err, tlsconfig.ErrKeyMismatch) {
		t.Fatalf("tls check error = %v, want ErrKeyMismatch", err)
	}

	// tls reset returns to the default and prints source=none.
	out, err = captureStdout(t, func() error { return cmdTLS([]string{"reset"}) })
	if err != nil {
		t.Fatalf("tls reset: %v", err)
	}
	if !strings.Contains(out, "tls source: none") {
		t.Fatalf("tls reset summary must report source none:\n%s", out)
	}
	assertNoKeyBytesCmd(t, out, keyPath)
	cfgReset, _ := appconfig.Load()
	if cfgReset.TLS.CertFile != "" || cfgReset.TLS.KeyFile != "" {
		t.Fatalf("tls reset did not clear the shared section: cert=%q key=%q", cfgReset.TLS.CertFile, cfgReset.TLS.KeyFile)
	}
	if cfgReset.GUI.Protocol != "http" {
		t.Fatalf("tls reset did not set gui.protocol=http: %q", cfgReset.GUI.Protocol)
	}

	// tls use refuses a mismatched pair and persists nothing (config stays clean).
	if err := cmdTLS([]string{"use", "--cert", mmCert, "--key", mmKey}); err == nil {
		t.Fatal("tls use must refuse a mismatched pair")
	}
	cfgAfter, _ := appconfig.Load()
	if cfgAfter.TLS.CertFile != "" {
		t.Fatalf("a refused tls use must persist nothing; got %q", cfgAfter.TLS.CertFile)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
