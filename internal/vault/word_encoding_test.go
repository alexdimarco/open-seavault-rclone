// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"strings"
	"testing"
)

// Word/base32 discriminator hardening (review word-encoding-1 and word-encoding-2).
// These are ADDED tests in a new file — the pre-U2 recovery_phrase_test.go is never
// edited (matrix Z1). They pin: (1) RecoveryPhraseWords rejects a NON-CANONICAL
// base32 phrase so the word form and the base32 form can never name different wrap
// secrets, and (2) a base32 phrase split into 24 whitespace chunks falls through to
// base32 canonicalisation instead of being misrouted to the word decoder.

// splitIntoTokens splits s into exactly n whitespace-joinable chunks of near-equal
// length (the earlier chunks absorb the remainder).
func splitIntoTokens(s string, n int) []string {
	toks := make([]string, 0, n)
	base := len(s) / n
	extra := len(s) % n
	i := 0
	for k := 0; k < n; k++ {
		size := base
		if k < extra {
			size++
		}
		toks = append(toks, s[i:i+size])
		i += size
	}
	return toks
}

// TestWordEncoding1_NonCanonicalBase32Rejected (review word-encoding-1): the final
// base32 character of a 32-byte secret carries 1 real bit and 4 trailing bits that
// canonical encoding forces to zero; encoding/base32 decodes non-zero trailing bits
// leniently. A non-canonical phrase therefore decodes to the SAME 32 bytes as its
// canonical form, so RecoveryPhraseWords would otherwise hand back words that name a
// DIFFERENT wrap secret than the phrase the owner holds (the KDF keys off the base32
// STRING). RecoveryPhraseWords must reject it.
func TestWordEncoding1_NonCanonicalBase32Rejected(t *testing.T) {
	var raw [recoveryEntropyBytes]byte
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	canon := recoveryB32.EncodeToString(raw[:])
	if len(canon) != 52 {
		t.Fatalf("a 256-bit base32 secret must be 52 chars, got %d", len(canon))
	}
	// The canonical phrase yields 24 words.
	words, err := RecoveryPhraseWords(canon)
	if err != nil {
		t.Fatalf("a canonical phrase must yield words, got %v", err)
	}
	if len(words) != 24 {
		t.Fatalf("canonical phrase must yield 24 words, got %d", len(words))
	}

	// Build a NON-CANONICAL variant: the canonical final char has value 0 or 16
	// (a multiple of 16 — trailing bits zero). Bumping it by one keeps the same real
	// bit but sets a trailing bit, so it decodes to the SAME 32 bytes.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	last := strings.IndexByte(alphabet, canon[51])
	if last != 0 && last != 16 {
		t.Fatalf("canonical final char must carry zero trailing bits (alphabet index 0 or 16), got index %d", last)
	}
	nonCanon := canon[:51] + string(alphabet[last+1])

	// Both decode to the SAME 32 bytes — proving the disagreement is real.
	rawCanon, err := recoveryB32.DecodeString(canon)
	if err != nil {
		t.Fatal(err)
	}
	rawNon, err := recoveryB32.DecodeString(nonCanon)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawCanon) != 32 || len(rawNon) != 32 || string(rawCanon) != string(rawNon) {
		t.Fatalf("the two phrases must decode to the same 32 bytes for this regression to bite (lens %d/%d, equal=%v)",
			len(rawCanon), len(rawNon), string(rawCanon) == string(rawNon))
	}

	// ... yet the non-canonical phrase must be REJECTED, not silently re-encoded to
	// words that name a different wrap secret than the phrase itself.
	if _, err := RecoveryPhraseWords(nonCanon); err == nil {
		t.Fatal("a non-canonical base32 phrase must be rejected by RecoveryPhraseWords (word/base32 disagreement)")
	}
}

// TestWordEncoding2_Base32SplitInto24ChunksFallsThroughToBase32 (review
// word-encoding-2): a base32 phrase split into EXACTLY 24 whitespace chunks must NOT
// be misrouted to the word decoder (where it would surface a spurious 'word not in
// wordlist' error). Gating the 24-token count on a wordlist majority makes it fall
// through to base32 canonicalisation and redeem the same secret.
func TestWordEncoding2_Base32SplitInto24ChunksFallsThroughToBase32(t *testing.T) {
	var raw [recoveryEntropyBytes]byte
	for i := range raw {
		raw[i] = byte(i*11 + 5)
	}
	canon := recoveryB32.EncodeToString(raw[:]) // the true wrap secret, 52 chars.
	if len(canon) != 52 {
		t.Fatalf("a 256-bit base32 secret must be 52 chars, got %d", len(canon))
	}

	toks := splitIntoTokens(canon, 24)
	if len(toks) != 24 {
		t.Fatalf("fixture must be 24 whitespace chunks, got %d", len(toks))
	}
	chunked := strings.Join(toks, " ")

	// Fewer than half the chunks are wordlist words (it is a base32 phrase, not a
	// word phrase), so under the majority rule it is not word-shaped.
	inList := 0
	for _, tk := range toks {
		if _, ok := recoveryWordIndex[strings.ToLower(tk)]; ok {
			inList++
		}
	}
	if inList*2 > len(toks) {
		t.Fatalf("fixture unexpectedly word-heavy (%d/24 chunks in wordlist); adjust the fixture", inList)
	}

	// A base32 phrase split into 24 chunks must canonicalise (via base32) to the
	// SAME wrap secret, not be rejected as a bad word phrase.
	got, err := canonicalRecoverySecret(chunked)
	if err != nil {
		t.Fatalf("a 24-chunk base32 phrase must fall through to base32, got typed word error %v", err)
	}
	if got != canon {
		t.Fatalf("24-chunk base32 must canonicalise to the same wrap secret (match=%v)", got == canon)
	}
	// It still redeems as the same secret through the read-back facade.
	if !RecoveryPhraseMatches(canon, chunked) {
		t.Fatal("a 24-chunk base32 phrase must match the minted phrase")
	}
}
