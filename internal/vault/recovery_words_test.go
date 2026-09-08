// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Word-based recovery phrases are an ENCODING LAYER over the same 256-bit secret
// the base32 phrase already carries (design U2 §2.5, I-U2). These tests pin the
// encoding, the strict decoder, the three accepted forms, and the vendored
// wordlist itself.

// W1: 1,000 random 32-byte secrets round-trip through words, and the word form and
// the base32 form of the SAME secret reduce to one identical wrap secret. A secret
// that did not round-trip, or whose two forms disagreed, would be an unredeemable
// printed card.
func TestW1_WordRoundTripAndCanonicalEquality(t *testing.T) {
	const iterations = 1000
	reached := 0
	for i := 0; i < iterations; i++ {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatalf("iteration %d: rand: %v", i, err)
		}
		words := EncodeRecoveryWords(secret)
		if len(words) != 24 {
			t.Fatalf("iteration %d: EncodeRecoveryWords must produce 24 words, got %d", i, len(words))
		}
		got, err := DecodeRecoveryWords(words)
		if err != nil {
			t.Fatalf("iteration %d: DecodeRecoveryWords of a freshly encoded phrase must succeed, got %v", i, err)
		}
		if got != secret {
			t.Fatalf("iteration %d: round-trip mismatch: decoded %x != secret %x", i, got, secret)
		}
		// The base32 form the CLI/GUI have shown since 0.15 and the new word form
		// must reduce to the exact same wrap secret via the discriminator.
		base32Form := recoveryB32.EncodeToString(secret[:])
		wordForm := strings.Join(words, " ")
		fromWords, err := canonicalRecoverySecret(wordForm)
		if err != nil {
			t.Fatalf("iteration %d: canonicalRecoverySecret(words) errored: %v", i, err)
		}
		fromBase32 := canonicalRecovery(base32Form)
		if fromWords != fromBase32 {
			t.Fatalf("iteration %d: word form and base32 form disagree: %q != %q", i, fromWords, fromBase32)
		}
		if fromWords != base32Form {
			t.Fatalf("iteration %d: canonical word secret %q != base32 secret %q", i, fromWords, base32Form)
		}
		reached++
	}
	if reached != iterations {
		t.Fatalf("expected %d round-trips, only reached %d", iterations, reached)
	}
}

// W2: the strict decoder returns the right TYPED error for every malformed input
// and never panics. Every row asserts; an empty result is a failure.
func TestW2_StrictDecodeTable(t *testing.T) {
	// A valid 24-word phrase (the all-zero BIP-39 vector) to mutate per row.
	valid := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	if len(valid) != 24 {
		t.Fatalf("fixture must be 24 words, got %d", len(valid))
	}

	// The all-zero vector decodes to the all-zero secret; both valid rows use it.
	var zeroSecret [32]byte
	rows := []struct {
		name       string
		words      []string
		wantErr    error    // nil means: must decode successfully
		wantSecret [32]byte // asserted only when wantErr == nil
	}{
		{"valid zero vector", append([]string(nil), valid...), nil, zeroSecret},
		{"unknown word", replaceAt(valid, 3, "notarealbip39word"), ErrRecoveryWordUnknown, zeroSecret},
		{"twentythree words", valid[:23], ErrRecoveryWordCount, zeroSecret},
		{"twentyfive words", append(append([]string(nil), valid...), "art"), ErrRecoveryWordCount, zeroSecret},
		{"empty", []string{}, ErrRecoveryWordCount, zeroSecret},
		{"nil", nil, ErrRecoveryWordCount, zeroSecret},
		{"bad checksum all abandon", strings.Fields(strings.TrimSpace(strings.Repeat("abandon ", 24))), ErrRecoveryChecksum, zeroSecret},
		{"mixed case and surrounding whitespace still valid", mixedCaseWhitespace(valid), nil, zeroSecret},
	}
	if len(rows) == 0 {
		t.Fatal("no strict-decode rows defined")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			secret, err := DecodeRecoveryWords(r.words)
			if r.wantErr == nil {
				if err != nil {
					t.Fatalf("row %q must decode, got error %v", r.name, err)
				}
				if secret != r.wantSecret {
					t.Fatalf("row %q decoded to %x, want %x", r.name, secret, r.wantSecret)
				}
				return
			}
			if !errors.Is(err, r.wantErr) {
				t.Fatalf("row %q: want error %v, got %v", r.name, r.wantErr, err)
			}
			if secret != ([32]byte{}) {
				t.Fatalf("row %q: a failed decode must return the zero secret, got %x", r.name, secret)
			}
		})
	}
}

// W3: generate emits 24 words AND the compact base32 form; all three written forms
// (grouped base32, ungrouped base32, 24 words) redeem the same secret; and a
// mistyped word at read-back yields the specific checksum MESSAGE, not a generic
// mismatch.
func TestW3_GenerateThreeFormsAndChecksumMessage(t *testing.T) {
	secret, phrase, err := mintRecoverySecret()
	if err != nil {
		t.Fatal(err)
	}
	// Generate emits the word form ...
	words, err := RecoveryPhraseWords(phrase)
	if err != nil {
		t.Fatalf("RecoveryPhraseWords: %v", err)
	}
	if len(words) != 24 {
		t.Fatalf("generate must emit 24 words, got %d", len(words))
	}
	// ... alongside the compact base32 form (the same 52-char secret).
	compact := canonicalRecovery(phrase)
	if compact != secret || len(compact) != 52 {
		t.Fatalf("compact form must be the 52-char base32 secret, got %q (len %d)", compact, len(compact))
	}

	// All three forms redeem the same minted phrase.
	forms := []struct {
		name  string
		input string
	}{
		{"grouped base32", phrase},
		{"ungrouped base32", compact},
		{"24 words", strings.Join(words, " ")},
	}
	if len(forms) == 0 {
		t.Fatal("no accepted-form rows")
	}
	for _, f := range forms {
		if !RecoveryPhraseMatches(phrase, f.input) {
			t.Fatalf("form %q must match the minted phrase", f.name)
		}
		if err := RecoveryPhraseCheck(phrase, f.input); err != nil {
			t.Fatalf("form %q must check clean, got %v", f.name, err)
		}
	}

	// A mistyped word (here: the 24th word "art" typed as "abandon", still a real
	// wordlist word) is caught by the checksum with a specific message.
	mistyped := strings.TrimSpace(strings.Repeat("abandon ", 24))
	err = RecoveryPhraseCheck(phrase, mistyped)
	if !errors.Is(err, ErrRecoveryChecksum) {
		t.Fatalf("a mistyped word must yield ErrRecoveryChecksum, got %v", err)
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("the read-back error must name the checksum, got %q", err.Error())
	}
	if RecoveryPhraseMatches(phrase, mistyped) {
		t.Fatal("a mistyped-word phrase must not match")
	}
}

// W7: the wordlist is PINNED (review C2). A published BIP-39 golden vector must
// encode to its exact known 24-word string and decode back to the exact secret,
// and the SHA-256 of the reconstructed wordlist must equal a constant held HERE in
// the test — not read from the vendored file — so a silent re-vendor is red.
func TestW7_GoldenVectorAndWordlistHash(t *testing.T) {
	// The constant lives in the test file, independent of internal/vault.
	const wantWordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

	if len(recoveryWordlist) != 2048 {
		t.Fatalf("the wordlist must have exactly 2048 words, got %d", len(recoveryWordlist))
	}
	sum := sha256.Sum256([]byte(strings.Join(recoveryWordlist, "\n") + "\n"))
	if got := hex.EncodeToString(sum[:]); got != wantWordlistSHA256 {
		t.Fatalf("wordlist SHA-256 mismatch:\n got %s\nwant %s\n(a re-vendor would make already-printed cards unredeemable)", got, wantWordlistSHA256)
	}

	// Published BIP-39 English 256-bit golden vectors: fixed entropy -> exact known
	// 24-word STRING -> the same secret back.
	vectors := []struct {
		entropyHex string
		mnemonic   string
	}{
		{
			strings.Repeat("00", 32),
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
		{
			strings.Repeat("7f", 32),
			"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		},
		{
			strings.Repeat("80", 32),
			"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		},
		{
			strings.Repeat("ff", 32),
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		},
	}
	if len(vectors) == 0 {
		t.Fatal("no golden vectors defined")
	}
	for _, v := range vectors {
		raw, err := hex.DecodeString(v.entropyHex)
		if err != nil || len(raw) != 32 {
			t.Fatalf("bad fixture entropy %q", v.entropyHex)
		}
		var secret [32]byte
		copy(secret[:], raw)

		gotWords := strings.Join(EncodeRecoveryWords(secret), " ")
		if gotWords != v.mnemonic {
			t.Fatalf("entropy %s: encode mismatch:\n got %q\nwant %q", v.entropyHex, gotWords, v.mnemonic)
		}
		decoded, err := DecodeRecoveryWords(strings.Fields(v.mnemonic))
		if err != nil {
			t.Fatalf("entropy %s: golden mnemonic must decode, got %v", v.entropyHex, err)
		}
		if decoded != secret {
			t.Fatalf("entropy %s: decode mismatch: %x != %x", v.entropyHex, decoded, secret)
		}
	}
}

func replaceAt(words []string, i int, w string) []string {
	out := append([]string(nil), words...)
	out[i] = w
	return out
}

func mixedCaseWhitespace(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if i%2 == 0 {
			out[i] = "  " + strings.ToUpper(w) + " "
		} else {
			out[i] = " " + w + "\t"
		}
	}
	return out
}
