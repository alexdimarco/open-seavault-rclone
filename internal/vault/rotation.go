// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// rewriteConfig is the single funnel every wrap/config mutation goes through
// : it copies the current config, applies mutate, bumps FormatEpoch,
// recomputes the ConfigTag over the master-derived key, publishes vault.json
// atomically (atomicWriteFile + fsyncDir, the A1 Windows-hardened rename), and
// THEN advances the device anchor high-water — config first, then anchor
// . A crash between the two leaves at worst a spurious self-rollback
// warning on this device's next Open, never an unprotected window; a crash during
// the config write leaves the prior fully-tagged config (single-file atomic
// rename), never a torn or untagged one.
//
// The mutation starts from v.Config — the config Open already read, version- and
// MAC-verified — so a concurrent on-disk change is not silently merged in; the
// concurrent-divergence case is caught at the NEXT Open. The master key
// (and thus the config-MAC key) is unchanged by any rotation, so the recomputed
// tag always verifies for the same holder.
func (v *Vault) rewriteConfig(mutate func(*VaultConfig) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	next := v.Config
	// Deep-copy the wrap-entry slice so mutate cannot alias v.Config's backing
	// array (WrapEntry is a value type with no inner pointers, so element copies
	// are independent).
	next.WrapEntries = append([]WrapEntry(nil), v.Config.WrapEntries...)
	if err := mutate(&next); err != nil {
		return err
	}
	next.FormatEpoch = v.Config.FormatEpoch + 1
	tag, err := computeConfigTag(v.keys.MasterKey, next)
	if err != nil {
		return err
	}
	next.ConfigTag = tag
	if err := v.writeConfigFile(next); err != nil {
		return err
	}
	v.Config = next
	if note := v.recordAnchor(next.FormatEpoch, true, next.ConfigTag); note != "" {
		v.anchorNote = note
	}
	return nil
}

// freshWrapKDF returns a copy of base (same algorithm and cost) with a new random
// 32-byte salt, so a rewrap derives an independent wrap key even under the same
// password (the design: fresh salt/nonce on every rotation).
func freshWrapKDF(base KDFConfig) (KDFConfig, error) {
	salt, err := randomBytes(32)
	if err != nil {
		return KDFConfig{}, err
	}
	k := base
	k.Salt = base64.StdEncoding.EncodeToString(salt)
	return k, nil
}

// passwordEntryID returns the ID of the existing password WrapEntry (stable per
// entry), or "" when there is none to reuse.
func passwordEntryID(c *VaultConfig) string {
	for _, e := range c.WrapEntries {
		if e.Type == WrapTypePassword {
			return e.ID
		}
	}
	return ""
}

// applyPasswordRewrap rewraps the SAME master||index bundle into the single
// password WrapEntry AND the legacy top-level fields under newPassword, each with
// a fresh salt/nonce. It replaces every existing
// password entry with one new entry (rotation never appends a second password
// entry) and preserves recovery entries untouched. The legacy fields are
// kept current so a 0.16 peer keeps unlocking through the grace release and the
// old password stops opening on both A1 and A2 clients. No chunk or manifest is
// rewritten — only the wrap changes. Shared by password change and recovery
// redeem so both produce an identical post-condition.
func applyPasswordRewrap(c *VaultConfig, newPassword string, keys Keys) error {
	if newPassword == "" {
		return errors.New("new password must not be empty")
	}
	id := passwordEntryID(c)
	if id == "" {
		var err error
		if id, err = randomHex(8); err != nil {
			return err
		}
	}
	entryKDF, err := freshWrapKDF(c.KDF)
	if err != nil {
		return err
	}
	entryNonce, entryCT, err := wrapKeys(newPassword, entryKDF, keys)
	if err != nil {
		return err
	}
	newEntry := WrapEntry{ID: id, Type: WrapTypePassword, KDF: entryKDF, Nonce: entryNonce, CT: entryCT}
	kept := make([]WrapEntry, 0, len(c.WrapEntries)+1)
	for _, e := range c.WrapEntries {
		if e.Type == WrapTypePassword {
			continue
		}
		kept = append(kept, e)
	}
	c.WrapEntries = append(kept, newEntry)
	// Keep the legacy top-level wrap current: fresh salt/nonce over
	// the same bundle under the new password.
	legKDF, err := freshWrapKDF(c.KDF)
	if err != nil {
		return err
	}
	legNonce, legWrapped, err := wrapKeys(newPassword, legKDF, keys)
	if err != nil {
		return err
	}
	c.KDF = legKDF
	c.WrappedKeys = legWrapped
	c.WrapNonce = legNonce
	return nil
}

// ChangePassword rotates the password of an already-unlocked vault (
// ): it rewraps the same master||index bundle into the password entry and the
// legacy fields under newPassword (fresh salt/nonce), bumps FormatEpoch, and
// re-tags the config — all in one rewriteConfig transaction. No chunk or manifest
// is rewritten, so every file put before the change still decrypts. The OS
// keychain is NOT touched here; callers refresh it via RefreshKeychainSecret
// after a successful change because the vault layer does not own
// the keychain policy.
func (v *Vault) ChangePassword(newPassword string) error {
	if newPassword == "" {
		return errors.New("new password must not be empty")
	}
	keys := v.keys
	return v.rewriteConfig(func(c *VaultConfig) error {
		return applyPasswordRewrap(c, newPassword, keys)
	})
}

// PrepareRecovery mints a fresh 256-bit recovery secret and returns its grouped
// display phrase plus a commit closure. The phrase is
// shown to the owner ONCE; the caller must obtain a read-back and verify it with
// RecoveryPhraseMatches BEFORE calling commit — commit writes the recovery
// WrapEntry (over the same master||index bundle, in one rewriteConfig
// transaction) and is the only path that persists anything. The secret lives only
// inside the returned closure and is never stored in plaintext. A vault may hold
// several recovery entries; commit APPENDS one and leaves existing ones intact.
func (v *Vault) PrepareRecovery() (phrase string, commit func() error, err error) {
	secret, phrase, err := mintRecoverySecret()
	if err != nil {
		return "", nil, err
	}
	keys := v.keys
	commit = func() error {
		return v.rewriteConfig(func(c *VaultConfig) error {
			entry, err := makeRecoveryEntry(secret, c.KDF, keys)
			if err != nil {
				return err
			}
			c.WrapEntries = append(append([]WrapEntry(nil), c.WrapEntries...), entry)
			return nil
		})
	}
	return phrase, commit, nil
}

// makeRecoveryEntry wraps the bundle under a recovery secret with a fresh KDF salt
// (same algorithm/cost as base) and a random entry ID.
func makeRecoveryEntry(secret string, base KDFConfig, keys Keys) (WrapEntry, error) {
	kdf, err := freshWrapKDF(base)
	if err != nil {
		return WrapEntry{}, err
	}
	id, err := randomHex(8)
	if err != nil {
		return WrapEntry{}, err
	}
	nonce, ct, err := wrapKeys(secret, kdf, keys)
	if err != nil {
		return WrapEntry{}, err
	}
	return WrapEntry{ID: id, Type: WrapTypeRecovery, KDF: kdf, Nonce: nonce, CT: ct}, nil
}

// RedeemRecovery completes a recovery redemption in ONE rewriteConfig transaction
// : it removes the redeemed recovery entry (identified
// by redeemedEntryID, the ID OpenWithRecovery returned) AND rewraps the bundle
// into the password entry and legacy fields under newPassword. Removing the entry
// matters because a password rewrap alone leaves master||index unchanged, so the
// leaked phrase would keep unwrapping it; the redeemed entry must be gone. The
// transaction is atomic — a crash leaves either the prior tagged config (recovery
// intact, old password) or the new one (recovery gone, new password), never a
// half state. The keychain is refreshed by the caller.
func (v *Vault) RedeemRecovery(redeemedEntryID, newPassword string) error {
	if newPassword == "" {
		return errors.New("new password must not be empty")
	}
	if redeemedEntryID == "" {
		return errors.New("no recovery entry to redeem")
	}
	keys := v.keys
	return v.rewriteConfig(func(c *VaultConfig) error {
		if !removeWrapEntry(c, redeemedEntryID, WrapTypeRecovery) {
			return fmt.Errorf("recovery entry %q not found", redeemedEntryID)
		}
		return applyPasswordRewrap(c, newPassword, keys)
	})
}

// RevokeRecovery removes a recovery WrapEntry by ID in a rewriteConfig
// transaction: a specific recovery credential is retired without
// touching the password or any other entry. It refuses to remove a password
// entry (that path is ChangePassword) or an unknown ID.
func (v *Vault) RevokeRecovery(entryID string) error {
	if entryID == "" {
		return errors.New("a recovery entry ID is required")
	}
	return v.rewriteConfig(func(c *VaultConfig) error {
		if !removeWrapEntry(c, entryID, WrapTypeRecovery) {
			return fmt.Errorf("recovery entry %q not found", entryID)
		}
		return nil
	})
}

// removeWrapEntry deletes the WrapEntry with the given ID and type from c,
// reporting whether one was removed. Filtering by wantType makes revoke/redeem
// refuse to delete the sole password entry through a recovery-typed ID mixup.
func removeWrapEntry(c *VaultConfig, id, wantType string) bool {
	kept := make([]WrapEntry, 0, len(c.WrapEntries))
	removed := false
	for _, e := range c.WrapEntries {
		if e.ID == id && e.Type == wantType {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	c.WrapEntries = kept
	return removed
}

// WrapEntryRef is a secret-free summary of a wrap entry: the ID and
// type only, so a CLI/GUI can list recovery entries for revoke without exposing
// any ciphertext or salt.
type WrapEntryRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// WrapEntryRefs returns the ID and type of every wrap entry, in on-disk order
// . It reads only v.Config, writes nothing (I2), and never returns
// wrap ciphertext or salts.
func (v *Vault) WrapEntryRefs() []WrapEntryRef {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]WrapEntryRef, 0, len(v.Config.WrapEntries))
	for _, e := range v.Config.WrapEntries {
		out = append(out, WrapEntryRef{ID: e.ID, Type: e.Type})
	}
	return out
}
