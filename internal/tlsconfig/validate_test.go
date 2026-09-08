// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// keyBodyLines returns the base64 body lines of a PEM key (the secret-bearing
// lines, excluding the -----BEGIN/END----- delimiters), for the I-T2 leak check.
func keyBodyLines(keyPEM []byte) []string {
	var body []string
	for _, ln := range strings.Split(string(keyPEM), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "-----") {
			continue
		}
		if len(ln) >= 20 {
			body = append(body, ln)
		}
	}
	return body
}

// assertNoKeyMaterial fails if text leaks the PEM header or any base64 body line
// of the private key (I-T2: key material never appears in an error or warning).
func assertNoKeyMaterial(t *testing.T, text string, keyPEM []byte) {
	t.Helper()
	// The armored key block ("-----BEGIN [RSA/EC] PRIVATE KEY-----") always ends
	// its BEGIN line with "PRIVATE KEY-----"; a bare mention of the words
	// "private key" in a diagnostic is harmless and must not trip this.
	if strings.Contains(text, "PRIVATE KEY-----") {
		t.Fatalf("output leaked a PEM private-key armor block: %q", text)
	}
	for _, ln := range keyBodyLines(keyPEM) {
		if strings.Contains(text, ln) {
			t.Fatalf("output leaked private key material")
		}
	}
}

// TestR2Validate is the Validate table (I-T2, C7): each row asserts the typed
// error OR the warning it must produce, and no row's output carries key material.
func TestR2Validate(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()

	type row struct {
		name        string
		write       func(dir string) (certPath, keyPath string, keyPEM []byte)
		wantErrIs   error
		wantWarnHas string // substring that must appear in some warning (when no error)
		wantNoWarn  bool   // when true, expect zero warnings
		wantSelf    bool   // expected Info.SelfSigned (only checked when no error)
	}

	rows := []row{
		{
			name: "valid-byo",
			write: func(dir string) (string, string, []byte) {
				c, k, _ := ca.issue(t, leafSpec{cn: "valid.example"})
				cp, kp := writePair(t, dir, c, k)
				return cp, kp, k
			},
			wantNoWarn: true, wantSelf: false,
		},
		{
			name: "self-signed-detected", // C7: issuer==subject
			write: func(dir string) (string, string, []byte) {
				c, k, _ := selfSigned(t, leafSpec{cn: "ss.example"})
				cp, kp := writePair(t, dir, c, k)
				return cp, kp, k
			},
			wantNoWarn: true, wantSelf: true,
		},
		{
			name: "mismatched-key",
			write: func(dir string) (string, string, []byte) {
				c, _, _ := ca.issue(t, leafSpec{cn: "mm.example"})
				wrong := keyToPEM(t, genKey(t))
				cp, kp := writePair(t, dir, c, wrong)
				return cp, kp, wrong
			},
			wantErrIs: ErrKeyMismatch,
		},
		{
			name: "expired",
			write: func(dir string) (string, string, []byte) {
				c, k, _ := ca.issue(t, leafSpec{cn: "old.example", notBefore: now.AddDate(-1, 0, 0), notAfter: now.Add(-time.Hour)})
				cp, kp := writePair(t, dir, c, k)
				return cp, kp, k
			},
			wantWarnHas: "expired",
		},
		{
			name: "not-yet-valid",
			write: func(dir string) (string, string, []byte) {
				c, k, _ := ca.issue(t, leafSpec{cn: "future.example", notBefore: now.Add(48 * time.Hour), notAfter: now.AddDate(1, 0, 0)})
				cp, kp := writePair(t, dir, c, k)
				return cp, kp, k
			},
			wantWarnHas: "not valid until",
		},
		{
			name: "expiring-soon",
			write: func(dir string) (string, string, []byte) {
				c, k, _ := ca.issue(t, leafSpec{cn: "soon.example", notBefore: now.Add(-time.Hour), notAfter: now.Add(10 * 24 * time.Hour)})
				cp, kp := writePair(t, dir, c, k)
				return cp, kp, k
			},
			wantWarnHas: "expires in",
		},
		{
			name: "unparsable-cert",
			write: func(dir string) (string, string, []byte) {
				cp := filepath.Join(dir, "leaf.crt")
				if err := os.WriteFile(cp, []byte("this is not a certificate"), 0o600); err != nil {
					t.Fatal(err)
				}
				k := keyToPEM(t, genKey(t))
				kp := filepath.Join(dir, "leaf.key")
				if err := os.WriteFile(kp, k, 0o600); err != nil {
					t.Fatal(err)
				}
				return cp, kp, k
			},
			wantErrIs: ErrCertParse,
		},
		{
			name: "unparsable-key",
			write: func(dir string) (string, string, []byte) {
				c, _, _ := ca.issue(t, leafSpec{cn: "badkey.example"})
				cp := filepath.Join(dir, "leaf.crt")
				if err := os.WriteFile(cp, c, 0o600); err != nil {
					t.Fatal(err)
				}
				kp := filepath.Join(dir, "leaf.key")
				garbage := []byte("-----BEGIN PRIVATE KEY-----\nnotbase64\n-----END PRIVATE KEY-----\n")
				if err := os.WriteFile(kp, garbage, 0o600); err != nil {
					t.Fatal(err)
				}
				return cp, kp, garbage
			},
			wantErrIs: ErrKeyParse,
		},
	}

	if len(rows) == 0 {
		t.Fatal("R2 table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			certPath, keyPath, keyPEM := r.write(t.TempDir())
			info, err := Validate(certPath, keyPath)

			var out strings.Builder
			if err != nil {
				out.WriteString(err.Error())
			}
			for _, w := range info.Warnings {
				out.WriteString("\n")
				out.WriteString(w)
			}
			assertNoKeyMaterial(t, out.String(), keyPEM)

			if r.wantErrIs != nil {
				if !errors.Is(err, r.wantErrIs) {
					t.Fatalf("Validate error = %v, want errors.Is %v", err, r.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate unexpected error: %v", err)
			}
			if info.SelfSigned != r.wantSelf {
				t.Fatalf("Info.SelfSigned = %v, want %v", info.SelfSigned, r.wantSelf)
			}
			if len(info.Names) == 0 {
				t.Fatal("Info.Names must be non-empty for a parseable leaf")
			}
			if info.NotAfter.IsZero() {
				t.Fatal("Info.NotAfter must be set")
			}
			if info.Fingerprint == "" {
				t.Fatal("Info.Fingerprint must be set")
			}
			if r.wantNoWarn {
				if len(info.Warnings) != 0 {
					t.Fatalf("expected no warnings, got %v", info.Warnings)
				}
			}
			if r.wantWarnHas != "" {
				if !warnContains(info.Warnings, r.wantWarnHas) {
					t.Fatalf("warnings %v must contain %q", info.Warnings, r.wantWarnHas)
				}
			}
		})
	}
}

// TestR2ValidateWorldReadableKey (I-T2) is Unix-only: a group/world-readable key
// file produces a warning naming chmod 600, without leaking key material.
func TestR2ValidateWorldReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	ca := newTestCA(t)
	c, k, _ := ca.issue(t, leafSpec{cn: "perms.example"})
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, c, k)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := Validate(certPath, keyPath)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !warnContains(info.Warnings, "chmod 600") {
		t.Fatalf("world-readable key must warn naming chmod 600, got %v", info.Warnings)
	}
	assertNoKeyMaterial(t, strings.Join(info.Warnings, "\n"), k)
}

func warnContains(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
