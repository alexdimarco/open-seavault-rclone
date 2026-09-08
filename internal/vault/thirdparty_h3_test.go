// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestThirdPartyNoticesCarriesWordlistLicense (H3): THIRD_PARTY_NOTICES.md carries
// the BIP-39 wordlist license AND the SHA-256 of the ACTUAL vendored wordlist, so
// a silent re-vendor (which would make already-printed recovery cards
// unredeemable) forces the notice to be updated or turns this guard red. It is
// the doc half of the W7 pinning: W7 pins the wordlist against a constant held in
// the test; this pins the published notice against the same reconstructed bytes.
func TestThirdPartyNoticesCarriesWordlistLicense(t *testing.T) {
	if len(recoveryWordlist) != 2048 {
		t.Fatalf("the vendored wordlist must have 2048 words; got %d", len(recoveryWordlist))
	}
	sum := sha256.Sum256([]byte(strings.Join(recoveryWordlist, "\n") + "\n"))
	wantSHA := hex.EncodeToString(sum[:])

	path := filepath.Join("..", "..", "THIRD_PARTY_NOTICES.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	notices := string(b)
	if strings.TrimSpace(notices) == "" {
		t.Fatal("THIRD_PARTY_NOTICES.md is empty")
	}

	if !strings.Contains(notices, wantSHA) {
		t.Fatalf("THIRD_PARTY_NOTICES.md must record the SHA-256 of the vendored wordlist (%s); a re-vendor must update the notice", wantSHA)
	}
	// The attribution and the license grant itself must be present (every row
	// asserted; nothing here can vacuously pass).
	for _, want := range []string{
		"BIP-39",
		"wordlist",
		"Redistribution and use in source and binary forms",
	} {
		if !strings.Contains(notices, want) {
			t.Fatalf("THIRD_PARTY_NOTICES.md must carry the BIP-39 wordlist license; missing %q", want)
		}
	}
}
