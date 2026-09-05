// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package keychain

import (
	"errors"
	"strings"
	"testing"
)

// TestSecurityCommandLineQuoting covers the all-OS half of: the helper wraps
// each value in double quotes and escapes embedded quotes and backslashes so the
// literal account and secret survive `security`'s interactive parser, and the
// service/flag skeleton is exactly as the design specifies.
func TestSecurityCommandLineQuoting(t *testing.T) {
	got := securityCommandLine(`acc"ount`, `p\a"ss`)
	// The command verb and flags, in order.
	for _, want := range []string{
		"add-generic-password -U",
		` -s "SeaVault"`,
		` -a "acc\"ount"`,
		` -w "p\\a\"ss"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("securityCommandLine missing %q\n got: %s", want, got)
		}
	}
	// A plain value round-trips inside quotes with nothing escaped.
	if plain := securityCommandLine("vault-1", "hunter2"); !strings.Contains(plain, ` -a "vault-1" -w "hunter2"`) {
		t.Errorf("plain command line malformed: %s", plain)
	}
}

// TestSecretIsStorable covers the control-character refusal of on every OS:
// a control byte in either the account or the secret yields ErrSecretNotStorable,
// while ordinary printable UTF-8 (including spaces and high runes) is storable.
func TestSecretIsStorable(t *testing.T) {
	bad := []struct {
		account, secret string
	}{
		{"vault", "line1\nline2"},
		{"vault", "tab\there"},
		{"vault", "bell\x07"},
		{"vault", "del\x7f"},
		{"vault", "nul\x00end"},
		{"acc\x1fount", "ok"},
	}
	for _, tc := range bad {
		if err := secretIsStorable(tc.account, tc.secret); !errors.Is(err, ErrSecretNotStorable) {
			t.Errorf("secretIsStorable(%q,%q) = %v, want ErrSecretNotStorable", tc.account, tc.secret, err)
		}
	}
	good := []struct {
		account, secret string
	}{
		{"vault-1", "correct horse battery staple"},
		{"vault-1", "pÿ€ssphrase with spaces"},
		{"vault-1", `symbols !@#$%^&*()_+-="'`},
	}
	for _, tc := range good {
		if err := secretIsStorable(tc.account, tc.secret); err != nil {
			t.Errorf("secretIsStorable(%q,%q) = %v, want nil", tc.account, tc.secret, err)
		}
	}
}
