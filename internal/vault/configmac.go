// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
)

// configMACInfo is the HKDF info string for the config-MAC key.
// The key derives from the master key alone, so a server holding no master key
// can never recompute a tag: adding a recovery entry or editing any covered
// field offline invalidates the MAC.
const configMACInfo = "seavault-config-mac-v1"

// ErrConfigTampered is returned by Open when the config MAC does not verify — a
// covered field (VaultID, ChunkParams, KDF cost, MinReader, FormatEpoch, or any
// wrap entry) was edited under an intact manifest store (,
// ) — OR when a device that has previously verified a valid ConfigTag for
// this vault is now served a config with no tag at all (a strip; the design,
// ). The check runs only AFTER a successful unwrap, so a wrong
// password still fails as a wrong password with no MAC oracle.
var ErrConfigTampered = errors.New("vault.json failed its integrity check: the configuration may have been modified or rolled back; restore it from a backup or another device")

// configMACKey derives the config-MAC key from the unwrapped master key (design
// ): configMACKey = HKDF-SHA256(masterKey, "seavault-config-mac-v1").
func configMACKey(master []byte) []byte { return deriveSubkey(master, configMACInfo) }

// canonicalConfigBytes is the deterministic byte string the ConfigTag is computed
// over: the JSON of the config with ConfigTag zeroed, in struct
// declaration order. It is computed from the STRUCT (a compact json.Marshal),
// not the on-disk file bytes, so the tag is over the field VALUES and is
// unaffected by vault.json whitespace/indentation. VaultConfig has no map fields,
// so this marshal is stable across encoders.
func canonicalConfigBytes(cfg VaultConfig) ([]byte, error) {
	cfg.ConfigTag = ""
	return json.Marshal(cfg)
}

// computeConfigTag returns the base64 HMAC-SHA256 of the canonical config bytes
// under the master-derived config-MAC key.
func computeConfigTag(master []byte, cfg VaultConfig) (string, error) {
	canon, err := canonicalConfigBytes(cfg)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, configMACKey(master))
	mac.Write(canon)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyConfigTag reports whether cfg carries a ConfigTag that verifies under the
// master key, in constant time. A config with no tag returns false
// — the caller (checkConfigIntegrity) decides the no-tag disposition from the
// device anchor, never by treating an absent tag as valid.
func verifyConfigTag(master []byte, cfg VaultConfig) bool {
	want := cfg.ConfigTag
	if want == "" {
		return false
	}
	got, err := computeConfigTag(master, cfg)
	if err != nil {
		return false
	}
	return constantTimeStringEqual(got, want)
}

// checkConfigIntegrity is Open's post-unwrap config gate. With a
// tag present it verifies the MAC and, on success, latches the device anchor
// (hasTag + epoch high-water). With NO tag it consults the anchor: a device that
// has ever verified a tag for this vault treats an absent tag as a hard strip
// (ErrConfigTampered); a fresh or genuinely-legacy device (no
// anchor, or an anchor that never saw a tag) opens via TOFU. The anchor is
// device-local and best-effort — an unresolvable/unwritable appdir never blocks
// Open, it only drops rollback protection and records a note.
func (v *Vault) checkConfigIntegrity(opts OpenOptions) error {
	if v.Config.ConfigTag != "" {
		if !verifyConfigTag(v.keys.MasterKey, v.Config) {
			return ErrConfigTampered
		}
		// The tag is valid; the config is authentic. Freshness (rollback) and
		// concurrent-divergence are decided against the device anchor next.
		return v.checkFreshness(opts)
	}
	// No tag: the strip disposition is decided by the device anchor's hasTag bit.
	path, err := v.anchorPath()
	if err != nil {
		v.anchorNote = anchorUnavailableNote
		return nil
	}
	anc, existed, lerr := loadAnchor(path)
	if lerr != nil {
		// Anchor unreadable (appdir I/O error): fail open (re-TOFU), note it.
		v.anchorNote = anchorUnavailableNote
		return nil
	}
	if existed && anc.HasTag {
		// This device verified a tag for this vault before; a now-absent tag is a
		// strip, not a legacy vault. Hard refuse.
		return ErrConfigTampered
	}
	// Genuinely legacy / fresh: trust on first use. The ratchet (EnsureConfigMAC)
	// writes a tag on the first write-capable open.
	return nil
}

// checkFreshness runs the device-local freshness-anchor gate for a config whose
// ConfigTag has already verified: it compares the
// on-disk FormatEpoch to this device's high-water and either
//
//   - epoch BELOW the high-water: a rollback (a retired config replayed). With
//     --accept-rollback it clears the anchor and re-TOFUs; otherwise
//     it HARD-REFUSES with ErrConfigRolledBack, whose message carries the
//     how-to-proceed instructions so the operator makes an informed choice BEFORE
//     any vault opens (strict gate — a warning that opens anyway is weaker than a
//     refusal a present human must consciously override with --accept-rollback).
//   - epoch TIED with the high-water but a DIFFERENT recorded ConfigTag: a
//     concurrent divergent config (two devices mutated at once). Hard-refuse with
//     ErrConfigDiverged rather than silently accept whichever copy synced last
//
// .
//   - otherwise (epoch above, or a matching tie): trust it and advance the anchor.
//
// The anchor is device-local and best-effort: an unresolvable/unwritable appdir
// never blocks Open — it drops rollback protection for the open and notes it.
func (v *Vault) checkFreshness(opts OpenOptions) error {
	path, err := v.anchorPath()
	if err != nil {
		v.anchorNote = anchorUnavailableNote
		return nil
	}
	anc, existed, lerr := loadAnchor(path)
	if lerr != nil {
		v.anchorNote = anchorUnavailableNote
		return nil
	}
	epoch := v.Config.FormatEpoch
	tag := v.Config.ConfigTag
	if existed {
		switch {
		case epoch < anc.FormatEpoch:
			if opts.AcceptRollback {
				// Operator-authorised: forget the high-water so the restored config
				// re-TOFUs, then re-anchor at the restored epoch below.
				if note := v.clearAnchor(); note != "" {
					v.anchorNote = note
				}
			} else {
				// Strict gate: both interactive and non-interactive refuse. The
				// ErrConfigRolledBack message tells the operator how to proceed
				// (--accept-rollback for a deliberate restore), so a present human
				// makes an informed choice before any vault opens.
				return ErrConfigRolledBack
			}
		case epoch == anc.FormatEpoch && anc.ConfigTag != "" && !constantTimeStringEqual(tag, anc.ConfigTag):
			return ErrConfigDiverged
		}
	}
	if note := v.recordAnchor(epoch, true, tag); note != "" {
		v.anchorNote = note
	}
	return nil
}

// writeConfigFile persists cfg to this vault's vault.json through the A1 atomic
// write path (atomicWriteFile + fsyncDir, the Windows-hardened rename). It is the
// single low-level config writer the ratchet uses; 's rewriteConfig builds
// on it.
func (v *Vault) writeConfigFile(cfg VaultConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(v.MetaRoot, ConfigFileName), data, 0o600)
}

// EnsureConfigMAC is the config-MAC ratchet: on the
// first write-capable open of a legacy/untagged vault it opportunistically writes
// ONLY the ConfigTag and bumps FormatEpoch — it NEVER bumps Version (that is
// seal-format's job). It is a no-op (returns false) on a vault that already
// carries a tag, so repeated write-capable opens ratchet exactly once. In this
// slice it is the ONLY writer of the tag; rotation/rewriteConfig lands in.
//
// The write ordering is config-first, then anchor: vault.json is
// published atomically (a crash leaves either the old untagged or the new tagged
// config, never a torn one), then the device anchor is advanced to the new epoch
// with hasTag latched. A failed anchor write never fails the ratchet — the tag is
// already durable — it only drops rollback protection and records a note.
func (v *Vault) EnsureConfigMAC() (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.Config.ConfigTag != "" {
		return false, nil
	}
	next := v.Config
	next.FormatEpoch = v.Config.FormatEpoch + 1
	tag, err := computeConfigTag(v.keys.MasterKey, next)
	if err != nil {
		return false, err
	}
	next.ConfigTag = tag
	if err := v.writeConfigFile(next); err != nil {
		return false, err
	}
	v.Config = next
	if note := v.recordAnchor(next.FormatEpoch, true, next.ConfigTag); note != "" {
		v.anchorNote = note
	}
	return true, nil
}
