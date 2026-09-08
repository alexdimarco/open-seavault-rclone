// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// W4 (crossversion, I-U2): a recovery phrase ISSUED as base32 — exactly what
// 0.15–0.18 minted and a user wrote down — redeems in this build BOTH by its
// base32 form AND by the 24-word form of the same secret, opening the same entry.
// No re-wrap, no config change: the word layer is pure encoding.
func TestW4_Base32PhraseRedeemsByBothForms(t *testing.T) {
	isolateAppHome(t)
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, rotOldPassword)
	v, err := Open(root, rotOldPassword)
	if err != nil {
		t.Fatal(err)
	}
	// PrepareRecovery mints the SAME grouped base32 phrase 0.15–0.18 issued.
	base32Phrase, commit, err := v.PrepareRecovery()
	if err != nil {
		t.Fatalf("PrepareRecovery: %v", err)
	}
	if base32Phrase == "" || !strings.Contains(base32Phrase, "-") {
		t.Fatalf("expected a grouped base32 phrase (non-empty, hyphen-grouped), got len %d hyphenated=%v", len(base32Phrase), strings.Contains(base32Phrase, "-"))
	}
	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The 24-word form of the exact same secret (what a 0.18 owner would also have).
	words, err := RecoveryPhraseWords(base32Phrase)
	if err != nil {
		t.Fatalf("RecoveryPhraseWords: %v", err)
	}
	if len(words) != 24 {
		t.Fatalf("word form must be 24 words, got %d", len(words))
	}
	wordPhrase := strings.Join(words, " ")

	// Redeem by base32.
	vB, idB, err := OpenWithRecovery(root, base32Phrase, OpenOptions{})
	if err != nil {
		t.Fatalf("base32 form must redeem: %v", err)
	}
	if vB == nil || idB == "" {
		t.Fatal("base32 redeem returned no vault/entry ID")
	}
	// Redeem by the word form of the same secret.
	vW, idW, err := OpenWithRecovery(root, wordPhrase, OpenOptions{})
	if err != nil {
		t.Fatalf("word form of the SAME base32 secret must also redeem: %v", err)
	}
	if vW == nil || idW == "" {
		t.Fatal("word redeem returned no vault/entry ID")
	}
	// Same underlying entry both times.
	if idB != idW {
		t.Fatalf("both forms must open the same recovery entry, got %q vs %q", idB, idW)
	}
}

// W6 (review C1): a 24-token phrase with one bad word — at the GUI read-back path
// AND at the redeem path — surfaces the TYPED word/checksum error, NEVER the
// generic wrong-secret error. A word-shaped input must never fall through to
// base32 stripping (which would map a mistyped word to a wrong secret).
func TestW6_BadWordSurfacesTypedErrorNotWrongSecret(t *testing.T) {
	isolateAppHome(t)
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, rotOldPassword)
	v, err := Open(root, rotOldPassword)
	if err != nil {
		t.Fatal(err)
	}
	base32Phrase, commit, err := v.PrepareRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	words, err := RecoveryPhraseWords(base32Phrase)
	if err != nil {
		t.Fatal(err)
	}

	// Corruption A: replace one word with a NON-wordlist token -> ErrRecoveryWordUnknown.
	unknownForm := strings.Join(replaceAt(words, 5, "notarealbip39word"), " ")
	// Corruption B: 24 valid words that fail the checksum -> ErrRecoveryChecksum.
	checksumForm := strings.TrimSpace(strings.Repeat("abandon ", 24))

	cases := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"unknown word", unknownForm, ErrRecoveryWordUnknown},
		{"bad checksum", checksumForm, ErrRecoveryChecksum},
	}
	if len(cases) == 0 {
		t.Fatal("no corruption cases")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Read-back path: RecoveryPhraseCheck surfaces the typed word error.
			rbErr := RecoveryPhraseCheck(base32Phrase, c.input)
			if !errors.Is(rbErr, c.wantErr) {
				t.Fatalf("read-back: want %v, got %v", c.wantErr, rbErr)
			}
			if errors.Is(rbErr, errRecoveryReadbackMismatch) {
				t.Fatal("read-back: a bad WORD must not degrade to the generic mismatch")
			}
			if RecoveryPhraseMatches(base32Phrase, c.input) {
				t.Fatal("read-back: a bad-word phrase must not match")
			}

			// Redeem path: OpenWithRecovery surfaces the typed word error, NOT
			// errWrongSecret.
			_, _, redErr := OpenWithRecovery(root, c.input, OpenOptions{})
			if !errors.Is(redErr, c.wantErr) {
				t.Fatalf("redeem: want %v, got %v", c.wantErr, redErr)
			}
			if errors.Is(redErr, errWrongSecret) {
				t.Fatalf("redeem: a bad word must NOT surface errWrongSecret, got %v", redErr)
			}
		})
	}
}

// TestWordMiscount_23And25WordsSurfaceTypedCountError (W-verifier coverage gap):
// the 20–28-token MISCOUNT branch of the discriminator (here 23 and 25 wordlist
// words) must surface the typed ErrRecoveryWordCount through BOTH the read-back path
// (RecoveryPhraseCheck) AND the redeem path (OpenWithRecovery) — never the generic
// wrong-secret line — so a returning owner who drops or doubles a word is told the
// count is wrong rather than that the phrase is bad.
func TestWordMiscount_23And25WordsSurfaceTypedCountError(t *testing.T) {
	isolateAppHome(t)
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, rotOldPassword)
	v, err := Open(root, rotOldPassword)
	if err != nil {
		t.Fatal(err)
	}
	base32Phrase, commit, err := v.PrepareRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	words, err := RecoveryPhraseWords(base32Phrase)
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 24 {
		t.Fatalf("word form must be 24 words, got %d", len(words))
	}

	rows := []struct {
		name  string
		input string
	}{
		{"twentythree words (dropped one)", strings.Join(words[:23], " ")},
		{"twentyfive words (doubled one)", strings.Join(append(append([]string(nil), words...), words[0]), " ")},
	}
	if len(rows) == 0 {
		t.Fatal("no miscount rows")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			// The row must genuinely exercise the 20–28 miscount branch: a majority-
			// wordlist token stream whose count is not 24.
			if n := len(strings.Fields(r.input)); n == 24 || n < 20 || n > 28 {
				t.Fatalf("row must have 20–28 tokens and not 24 to hit the miscount branch, got %d", n)
			}
			// Read-back path.
			rbErr := RecoveryPhraseCheck(base32Phrase, r.input)
			if !errors.Is(rbErr, ErrRecoveryWordCount) {
				t.Fatalf("read-back: want ErrRecoveryWordCount, got %v", rbErr)
			}
			if errors.Is(rbErr, errRecoveryReadbackMismatch) {
				t.Fatal("read-back: a miscount must not degrade to the generic mismatch")
			}
			// Redeem path.
			_, _, redErr := OpenWithRecovery(root, r.input, OpenOptions{})
			if !errors.Is(redErr, ErrRecoveryWordCount) {
				t.Fatalf("redeem: want ErrRecoveryWordCount, got %v", redErr)
			}
			if errors.Is(redErr, errWrongSecret) {
				t.Fatalf("redeem: a miscount must NOT surface errWrongSecret, got %v", redErr)
			}
		})
	}
}
