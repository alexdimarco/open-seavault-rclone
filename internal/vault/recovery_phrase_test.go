// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"strings"
	"testing"
)

// The recovery phrase is a 256-bit secret rendered as grouped base32 (design
// D3.3). This proves the canonical wrap secret round-trips, the read-back
// tolerates regrouping/case, and a distinct or empty phrase never matches.
func TestRecoveryPhraseEncoding(t *testing.T) {
	secret, phrase, err := mintRecoverySecret()
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || phrase == "" {
		t.Fatal("mintRecoverySecret must return a non-empty secret and phrase")
	}
	// 256 bits of base32 with no padding is 52 characters — the wrap secret.
	if len(secret) != 52 {
		t.Fatalf("a 256-bit base32 secret must be 52 chars, got %d (%q)", len(secret), secret)
	}
	// The canonical form of the displayed phrase IS the wrap secret.
	if canonicalRecovery(phrase) != secret {
		t.Fatalf("canonicalRecovery(phrase)=%q must equal the wrap secret %q", canonicalRecovery(phrase), secret)
	}
	// The grouped phrase contains separators (it is grouped for legibility).
	if !strings.Contains(phrase, "-") {
		t.Fatalf("the display phrase must be grouped with separators, got %q", phrase)
	}

	// Read-back tolerance: assorted regroupings all match the minted phrase.
	variants := []struct {
		name  string
		input string
	}{
		{"exact", phrase},
		{"lowercased", strings.ToLower(phrase)},
		{"dashes to spaces", strings.ReplaceAll(phrase, "-", " ")},
		{"ungrouped", strings.ReplaceAll(phrase, "-", "")},
		{"surrounding whitespace", "   " + phrase + "\n"},
	}
	if len(variants) == 0 {
		t.Fatal("no read-back variants defined")
	}
	for _, tc := range variants {
		if !RecoveryPhraseMatches(phrase, tc.input) {
			t.Fatalf("read-back variant %q (%q) must match the minted phrase", tc.name, tc.input)
		}
	}

	// A different phrase never matches; empty/whitespace read-backs never match.
	_, other, err := mintRecoverySecret()
	if err != nil {
		t.Fatal(err)
	}
	if RecoveryPhraseMatches(phrase, other) {
		t.Fatal("a distinct minted phrase must not match")
	}
	for _, empty := range []string{"", "    ", "----", "!!!"} {
		if RecoveryPhraseMatches(phrase, empty) {
			t.Fatalf("an empty/separator-only read-back (%q) must never match", empty)
		}
	}
}
