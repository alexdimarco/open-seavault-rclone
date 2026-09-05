// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package keychain

import (
	"errors"
	"strings"
)

// ErrSecretNotStorable is returned when a password or account cannot be stored
// in the OS keychain because it contains a control character. On macOS the
// keychain is written through `security -i`, whose interactive reader is
// line-oriented, so a newline or other control byte would desynchronise the
// command stream; rather than risk that, the store is refused up front (design
// D8.1, P2 darwin-keychain-secret-in-argv). The vault still opens with the
// password typed at the prompt or supplied via SEAVAULT_PASSWORD.
var ErrSecretNotStorable = errors.New("the OS keychain cannot store a password containing control characters; the vault still opens with the password typed or via SEAVAULT_PASSWORD")

// hasControlByte reports whether s contains any byte in 0x00–0x1F or 0x7F.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x1f || c == 0x7f {
			return true
		}
	}
	return false
}

// secretIsStorable rejects an account or secret that carries a control
// character (design D8.1). It is defined in this non-tagged file so the refusal
// is testable on every OS even though only the darwin Set path calls it.
func secretIsStorable(account, secret string) error {
	if hasControlByte(account) || hasControlByte(secret) {
		return ErrSecretNotStorable
	}
	return nil
}

// securityCommandLine builds the single command line fed to `security -i` on
// stdin: `add-generic-password -U -s SeaVault -a <account> -w <secret>` with
// each value double-quoted and its `"` and `\` escaped so `security`'s
// interactive parser receives the literal account and secret (design D8.1).
// Keeping this pure and non-tagged lets the quoting be tested on every OS. The
// secret never appears in argv — only ["security","-i"] is exec'd — so it does
// not leak into a process listing.
func securityCommandLine(account, secret string) string {
	return "add-generic-password -U -s " + quoteSecurityArg(Service) +
		" -a " + quoteSecurityArg(account) +
		" -w " + quoteSecurityArg(secret)
}

func quoteSecurityArg(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}
