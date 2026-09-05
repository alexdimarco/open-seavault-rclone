// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"fmt"
)

// sealedVersion is the on-the-wire VaultConfig.Version a sealed vault carries
// (design D1.4, P1-20). The shipped 0.16/0.15 client fences on the raw Version
// integer (vault.go "unsupported vault version %d"), so bumping to 3 is the one
// step that actually retires those peers; an A2-and-later client is fenced by
// MinReader instead. Kept distinct from SupportedFormat (the format ceiling this
// build reads) even though both are 3 in A2.
const sealedVersion = 3

// graceVersion is the Version a vault carries throughout the A2 grace release and
// after unseal-format (design D1.1): every A2 member is additive on a Version-2
// config so a 0.16 peer keeps opening it.
const graceVersion = 2

// unsealedMinReader is the MinReader an unsealed vault carries (design D1.4):
// unseal-format drops MinReader to 2, the grace-release floor, which admits every
// A2-and-later client (SupportedFormat >= 2) and is ignored by 0.16.
const unsealedMinReader = 2

// ErrAlreadySealed is returned by SealFormat when the vault is already sealed
// (Version already at sealedVersion and MinReader already at the format ceiling):
// re-sealing would only churn the FormatEpoch for no change, so it is refused so
// a double-seal is a legible no-op rather than a silent epoch bump.
var ErrAlreadySealed = errors.New("vault format is already sealed (version 3); nothing to do")

// ErrNotSealed is returned by UnsealFormat when the vault is not sealed (Version
// below sealedVersion): there is no seal to reverse.
var ErrNotSealed = errors.New("vault format is not sealed; nothing to unseal")

// ErrUnsealAfterReKey is returned by UnsealFormat when an A3 directory-ID re-key
// has run (CryptoConfig.DirIDEpoch > 0): the manifests are re-keyed beyond what a
// Version-2 reader can decode, so re-admitting v2 readers by lowering the Version
// would hand them a vault they cannot read (design D1.4, Condition 14). There is
// no such re-key in A2, so this never fires yet; A3 sets the marker.
var ErrUnsealAfterReKey = errors.New("cannot unseal: a directory-ID re-key has run, so older readers can no longer decode this vault")

// formatTooNew reports the forward-compatibility fence (design D1.2/D1.3,
// P1-20): a vault whose MinReader exceeds the reader's supported format level is
// refused with the hedged, typed ErrFormatTooNew. It is a pure function of the
// two integers so a test can exercise the fence at any supported level (e.g. a
// SupportedFormat=2 stub against a sealed MinReader=3 vault) without mutating the
// SupportedFormat constant. prepareOpen calls it with the live SupportedFormat.
func formatTooNew(minReader, supported int) error {
	if minReader > supported {
		return fmt.Errorf("this vault needs SeaVault format %d or newer (this build supports %d): %w", minReader, supported, ErrFormatTooNew)
	}
	return nil
}

// firstBarePasswordEntry returns the first password WrapEntry that uses the
// legacy bare wrap AAD (AAD==""), whose KDF/nonce/CT can therefore be copied
// verbatim into the top-level legacy fields for a 0.16 peer to unwrap. Every
// password entry A2 writes uses the bare AAD (the D2.5 versioned-AAD write leg
// was dropped), so a rotated vault always has one.
func firstBarePasswordEntry(entries []WrapEntry) (WrapEntry, bool) {
	for _, e := range entries {
		if e.Type == WrapTypePassword && e.AAD == "" {
			return e, true
		}
	}
	return WrapEntry{}, false
}

// SealFormat is the operator's explicit end of the grace release (design D1.4,
// P1-20): in ONE rewriteConfig transaction it bumps Version 2->3 AND raises
// MinReader to this build's format ceiling (3 in A2), re-tagging the config and
// bumping FormatEpoch. After seal a 0.16/0.15 client hard-refuses on its own
// Version fence and an A2 client below format 3 is fenced by MinReader — the one
// one-way step (reversible only by UnsealFormat while no A3 re-key has run). It
// refuses an already-sealed vault so a double-seal is a legible no-op.
func (v *Vault) SealFormat() error {
	return v.rewriteConfig(func(c *VaultConfig) error {
		if c.Version >= sealedVersion && c.MinReader >= SupportedFormat {
			return ErrAlreadySealed
		}
		// conditions/F3 (design D3.1): seal retires 0.16 access, so the legacy
		// top-level password wrap — which a hostile Version-downgraded config would
		// otherwise let a forgotten 0.16 peer still unwrap — is cleared here. Preserve
		// openability first: if the credential is not already a password WrapEntry
		// (a migrated-but-never-rotated vault), migrate the legacy wrap into one
		// under the same KDF/nonce/CT, then clear the legacy fields.
		if c.WrappedKeys != "" {
			if _, ok := firstBarePasswordEntry(c.WrapEntries); !ok {
				id, err := randomHex(8)
				if err != nil {
					return err
				}
				c.WrapEntries = append(c.WrapEntries, WrapEntry{
					ID: id, Type: WrapTypePassword, KDF: c.KDF, Nonce: c.WrapNonce, CT: c.WrappedKeys,
				})
			}
			c.WrappedKeys = ""
			c.WrapNonce = ""
		}
		c.Version = sealedVersion
		c.MinReader = SupportedFormat
		return nil
	})
}

// UnsealFormat reverses SealFormat (design D1.4, Condition 14): in one
// rewriteConfig transaction it drops Version back to 2 and MinReader back to 2,
// re-admitting a 0.16 peer (Version fence passes again) and every A2-and-later
// client. It is allowed ONLY while no A3 directory-ID re-key has run
// (CryptoConfig.DirIDEpoch == 0); once one has, lowering the Version would
// re-admit readers that can no longer decode the re-keyed manifests, so it
// refuses with ErrUnsealAfterReKey. There is no such re-key in A2, so unseal is
// always allowed now. It refuses an unsealed vault with ErrNotSealed.
func (v *Vault) UnsealFormat() error {
	return v.rewriteConfig(func(c *VaultConfig) error {
		if c.Crypto.DirIDEpoch > 0 {
			return ErrUnsealAfterReKey
		}
		if c.Version < sealedVersion {
			return ErrNotSealed
		}
		// Restore the legacy top-level wrap from the bare-AAD password entry so a
		// 0.16 peer can unwrap again after unseal (design D1.4, R11): seal cleared
		// it (conditions/F3). The entry's own KDF/nonce/CT form a consistent triple.
		if c.WrappedKeys == "" {
			if e, ok := firstBarePasswordEntry(c.WrapEntries); ok {
				c.KDF = e.KDF
				c.WrapNonce = e.Nonce
				c.WrappedKeys = e.CT
			}
		}
		c.Version = graceVersion
		c.MinReader = unsealedMinReader
		return nil
	})
}
