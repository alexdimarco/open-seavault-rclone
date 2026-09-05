// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/hmac"
	"encoding/base32"
	"strings"
)

// recoveryPhraseBits is the entropy of a minted recovery secret (
// ): a fresh 256-bit value. 32 bytes of base32 (no padding) render as 52
// characters, grouped for legibility below.
const recoveryPhraseBits = 256

// recoveryGroupSize is the number of base32 characters per printed group. 52
// characters split into 13 groups of 4 (the design "grouped phrase").
const recoveryGroupSize = 4

// recoveryB32 is RFC 4648 base32 with padding stripped — cgo-free, zero-module
// (stdlib encoding/base32). Uppercase A–Z and 2–7 only, which canonicalRecovery
// re-derives from any user input regardless of case or grouping.
var recoveryB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// mintRecoverySecret draws a fresh 256-bit recovery value and returns both its
// canonical wrap secret (the ungrouped base32 string fed to the KDF) and the
// grouped display phrase shown to the owner once.
// The random bytes never leave this function; only the derived strings do.
func mintRecoverySecret() (secret, phrase string, err error) {
	raw, err := randomBytes(recoveryPhraseBits / 8)
	if err != nil {
		return "", "", err
	}
	canon := recoveryB32.EncodeToString(raw)
	return canon, groupRecovery(canon), nil
}

// groupRecovery renders a canonical base32 string as space-free groups joined by
// "-" for one-time display, e.g. ABCD-EFGH-... A caller may print it however it
// likes; canonicalRecovery reverses any grouping/spacing on read-back.
func groupRecovery(canon string) string {
	var b strings.Builder
	for i := 0; i < len(canon); i += recoveryGroupSize {
		if i > 0 {
			b.WriteByte('-')
		}
		end := i + recoveryGroupSize
		if end > len(canon) {
			end = len(canon)
		}
		b.WriteString(canon[i:end])
	}
	return b.String()
}

// canonicalRecovery reduces any user-entered phrase to the exact wrap secret:
// upper-case, keep only the base32 alphabet (A–Z, 2–7), drop every space, dash,
// or stray character. So "abcd efgh", "ABCD-EFGH", and "abcdefgh" all canonicalise
// identically, and a recovery phrase read back or redeemed with different grouping
// still derives the same wrap key.
func canonicalRecovery(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '2' && r <= '7':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RecoveryPhraseMatches reports whether a read-back or redeemed phrase matches the
// minted phrase after canonicalisation, compared in constant time (
// the mandatory read-back). An empty canonical form never matches,
// so an all-whitespace or empty read-back always aborts.
func RecoveryPhraseMatches(minted, input string) bool {
	want := canonicalRecovery(minted)
	got := canonicalRecovery(input)
	if want == "" || got == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(got))
}
