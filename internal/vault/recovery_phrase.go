// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/hmac"
	"encoding/base32"
	"errors"
	"fmt"
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

// canonicalRecovery reduces a BASE32 phrase to the exact wrap secret: upper-case,
// keep only the base32 alphabet (A–Z, 2–7), drop every space, dash, or stray
// character. So "abcd efgh", "ABCD-EFGH", and "abcdefgh" all canonicalise
// identically, and a recovery phrase read back or redeemed with different grouping
// still derives the same wrap key.
//
// It is intentionally lossy — it strips anything outside the base32 alphabet — so
// it must only ever see input the discriminator (canonicalRecoverySecret) has
// already classified as base32. A word phrase must NOT be routed here, or a
// mistyped word would be silently stripped to a wrong base32 secret and surface as
// a generic wrong-secret error instead of a mistyped-word message (review C1).
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

// canonicalRecoverySecret reduces ANY recovery input to the exact wrap secret,
// discriminating a word phrase from a base32 phrase FIRST (design U2 §2.5 / review
// condition C1). The rule, after whitespace tokenization:
//
//   - Word-shaped input — exactly 24 tokens, OR 20–28 tokens the majority of which
//     are wordlist words (a miscounted phrase) — is decoded STRICTLY. A valid
//     phrase yields its canonical base32 secret; an invalid one returns the typed
//     ErrRecoveryWordCount / ErrRecoveryWordUnknown / ErrRecoveryChecksum error and
//     NEVER falls through to base32 stripping.
//   - Anything else is a base32 phrase, canonicalised exactly as before.
//
// So redeem/read-back accept either form for the SAME secret (a base32 phrase and
// its 24-word form both reduce to one string), while a single mistyped word is
// caught as a word error rather than mapped to a wrong secret.
func canonicalRecoverySecret(input string) (string, error) {
	tokens := strings.Fields(input)
	n := len(tokens)
	inList := 0
	for _, t := range tokens {
		if _, ok := recoveryWordIndex[strings.ToLower(t)]; ok {
			inList++
		}
	}
	wordShaped := n == recoveryWordCount || (n >= 20 && n <= 28 && inList*2 > n)
	if wordShaped {
		secret, err := DecodeRecoveryWords(tokens)
		if err != nil {
			return "", err
		}
		return recoveryB32.EncodeToString(secret[:]), nil
	}
	return canonicalRecovery(input), nil
}

// errRecoveryReadbackMismatch is the generic, secret-free failure for a read-back
// or redeemed phrase that does not match — used when the input is base32-shaped
// (or empty). A word-shaped input that fails to decode surfaces the specific typed
// word error instead, so the owner learns a word was mistyped rather than seeing a
// generic mismatch.
var errRecoveryReadbackMismatch = errors.New("the recovery phrase did not match")

// RecoveryPhraseCheck reports why a read-back or redeemed phrase does or does not
// match the minted phrase. It returns nil on a match; the typed
// ErrRecoveryWord*/ErrRecoveryChecksum error when the input is a word phrase that
// fails strict decode (so the read-back path can show a mistyped-word message);
// and errRecoveryReadbackMismatch otherwise. The comparison is constant-time and
// the returned error never contains either secret.
func RecoveryPhraseCheck(minted, input string) error {
	want := canonicalRecovery(minted)
	got, err := canonicalRecoverySecret(input)
	if err != nil {
		return err
	}
	if want == "" || got == "" || !hmac.Equal([]byte(want), []byte(got)) {
		return errRecoveryReadbackMismatch
	}
	return nil
}

// RecoveryPhraseMatches reports whether a read-back or redeemed phrase matches the
// minted phrase after canonicalisation, compared in constant time (
// the mandatory read-back). An empty canonical form never matches,
// so an all-whitespace or empty read-back always aborts. It is the boolean facade
// over RecoveryPhraseCheck; callers that need the specific mistyped-word message
// call RecoveryPhraseCheck instead.
func RecoveryPhraseMatches(minted, input string) bool {
	return RecoveryPhraseCheck(minted, input) == nil
}

// RecoveryPhraseWords returns the 24-word form of a base32 recovery phrase so
// generate (CLI and GUI) can show the words by DEFAULT alongside the compact
// base32 form the same secret already produces (design U2 §2.5). It is a pure
// re-encoding of the SAME 256-bit secret — no new secret, no re-wrap, nothing
// written to vault.json — and accepts any grouping/case of the minted phrase. A
// phrase that is not a 32-byte base32 secret returns an error rather than a
// truncated word list.
func RecoveryPhraseWords(phrase string) ([]string, error) {
	raw, err := recoveryB32.DecodeString(canonicalRecovery(phrase))
	if err != nil {
		return nil, err
	}
	if len(raw) != recoveryEntropyBytes {
		return nil, fmt.Errorf("recovery phrase is %d bytes, expected %d", len(raw), recoveryEntropyBytes)
	}
	var secret [recoveryEntropyBytes]byte
	copy(secret[:], raw)
	return EncodeRecoveryWords(secret), nil
}
