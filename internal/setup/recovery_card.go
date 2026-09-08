// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"fmt"
	"strings"
	"time"
)

// recoveryDraftStamp is the DRAFT banner stamped on a recovery card that was
// printed/saved BEFORE the read-back committed (design U2 §2.5, review C6). It is
// the plain-text mirror of the GUI's draft stamp so a card printed from either UI
// carries the same warning. A confirmed (post-commit) card omits it.
const recoveryDraftStamp = "DRAFT — not confirmed until you complete the read-back; destroy this card if you cancel."

// numberedWordLines renders the 24-word recovery phrase as aligned, numbered
// lines ("   1. abandon"). It returns nil for an empty list so a caller that
// could not encode the words (a malformed phrase) simply shows none rather than a
// misleading empty block.
func numberedWordLines(words []string) []string {
	if len(words) == 0 {
		return nil
	}
	lines := make([]string, 0, len(words))
	for i, w := range words {
		lines = append(lines, fmt.Sprintf("  %2d. %s", i+1, w))
	}
	return lines
}

// recoveryCardText builds the plain-text recovery card the CLI `--save` file
// holds (design U2 §2.5): the vault name, the date, the 24 numbered words, the
// base32 compact form, and the "keep this on paper" warning. When draft is true
// it is stamped DRAFT (printed before the read-back commits); the confirmed
// reprint after commit passes draft=false. wordsUnavailable degrades the card to
// the compact form alone (the words could not be encoded), never omitting the
// secret the owner must keep. The compact form is included verbatim so the
// re-type gate and a later redeem both accept it.
func recoveryCardText(vaultName string, words []string, compact string, wordsUnavailable, draft bool) string {
	var b strings.Builder
	if draft {
		fmt.Fprintf(&b, "%s\n\n", recoveryDraftStamp)
	}
	b.WriteString("open-seavault-rclone recovery card\n")
	fmt.Fprintf(&b, "Vault: %s\n", vaultName)
	fmt.Fprintf(&b, "Printed: %s\n\n", time.Now().Format("2006-01-02"))
	if !wordsUnavailable {
		b.WriteString("Recovery phrase (24 words, in order):\n")
		for _, line := range numberedWordLines(words) {
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Compact form (base32): %s\n\n", compact)
	b.WriteString("Keep this on paper, away from the computer. Anyone holding it can open the vault.\n")
	return b.String()
}

// RecoveryCardText is the exported entry point to the recovery-card builder so
// the standalone CLI `recovery generate --save` (design U2 §2.5) writes the SAME
// card text the setup wizard's ceremony writes — the design calls for "the same
// card in text", so the CLI reuses this builder rather than re-implementing the
// format. It forwards to the unexported recoveryCardText.
func RecoveryCardText(vaultName string, words []string, compact string, wordsUnavailable, draft bool) string {
	return recoveryCardText(vaultName, words, compact, wordsUnavailable, draft)
}
