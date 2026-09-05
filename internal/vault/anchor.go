// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// anchorUnavailableNote is the one-time note surfaced when the device-local
// freshness anchor cannot be resolved or written: the
// app-data directory is unresolvable or read-only (a read-only mount, a backup
// image). The anchor is best-effort — its absence means TOFU (fail open) — so
// Open proceeds and never blocks; the note tells the operator that rollback
// protection is not in effect for this open.
const anchorUnavailableNote = "freshness anchoring unavailable (app data directory not writable); rollback protection is disabled for this open"

// freshnessAnchor is the device-local, never-synced record of what this device
// has seen for a vault's configuration (config half). It is
// stored PLAINTEXT under 0600 perms — exactly like the A1 gc-seen store, and for
// the same reason: a never-synced local file the in-model server
// cannot reach gains nothing from an HMAC. FormatEpoch is the highest config
// epoch this device has trusted (the rollback high-water); HasTag records
// whether this device has ever verified a valid ConfigTag for the vault — once
// true, a subsequently-absent tag is a strip and Open hard-refuses.
type freshnessAnchor struct {
	FormatEpoch int64 `json:"formatEpoch"`
	HasTag      bool  `json:"hasTag"`
	// ConfigTag is the ConfigTag this device recorded at the FormatEpoch
	// high-water: it lets Open detect a concurrent
	// divergent config — a FormatEpoch TIE with a differing ConfigTag — and refuse
	// with ErrConfigDiverged rather than silently accept whichever copy the sync
	// client kept. Additive/omitempty so an anchor written before this field
	// (epoch-only) round-trips as "" and simply cannot detect divergence (it fails
	// safe: an unknown recorded tag never manufactures a false divergence).
	ConfigTag string `json:"configTag,omitempty"`
}

// anchorStorePath is the device-local freshness anchor for a vault (design
// ): <appdir data>/vault-anchors/<anchorID>.json. It mirrors the gc-seen
// store layout (gc.go seenStorePath) and, like it, lives under appdir.DataDir so
// it is never part of the synced vault store (I2) and survives the config-reset
// flows. The id segment is v.anchorID (master-derived), NOT the plaintext
// VaultID — see.
func anchorStorePath(anchorID string) (string, error) {
	base, err := appdir.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "vault-anchors", anchorID+".json"), nil
}

// anchorInfo domain-separates the device-anchor identity key from the config-MAC
// key (configMACInfo) and the chunk/index AEAD subkeys.
const anchorInfo = "seavault-anchor-id-v1"

// anchorID is the STABLE identifier the device-local freshness anchor is keyed on
// . It is the hex HMAC-SHA256 of the fixed
// anchorInfo label under the unwrapped MASTER KEY — NOT any plaintext vault.json
// field.
//
// The has-tag strip refusal ("once a device has
// verified a tag for a vault, that vault must always present a valid tag to that
// device") is only sound if "that vault" is identified by something a hostile
// config server cannot relocate. VaultID is the wrong choice: it is
// attacker-editable plaintext, MAC-covered ONLY on the still-tagged path, so a
// server could strip the ConfigTag AND swap/blank the VaultID together, moving
// the anchor lookup to a nonexistent id (existed=false), collapsing the check to
// TOFU and laundering the strip. The master key is the
// right anchor: it is fixed by the wrap material the attacker must keep intact for
// the unwrap to succeed at all, so an anchored device re-finds its own hasTag
// anchor no matter what the plaintext VaultID says — and mutating the wrap to
// shift the master key denies access rather than laundering a strip. Keying on the
// master key also survives password rotation and recovery unlock, which preserve
// the master key by design. The check runs only AFTER a successful unwrap, so the
// master key is always available here and never leaks (the anchor id is a one-way
// HMAC, like legacyVaultID and manifest ids).
func (v *Vault) anchorID() string {
	return hmacHex(v.keys.MasterKey, []byte(anchorInfo))[:32]
}

func (v *Vault) anchorPath() (string, error) { return anchorStorePath(v.anchorID()) }

// loadAnchor reads a device's freshness anchor. A MISSING or UNPARSEABLE anchor
// fails OPEN — it returns (zero, existed=false, nil) so Open re-TOFUs (design
// ): a corrupt or absent anchor must never brick a vault, and reinstalling
// or resetting app data legitimately resets rollback protection to TOFU. Only a
// genuine I/O error (e.g. a permission failure reaching an existing file) is
// returned as an error, which the caller treats as "anchor unavailable" and
// still opens.
func loadAnchor(path string) (freshnessAnchor, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return freshnessAnchor{}, false, nil
		}
		return freshnessAnchor{}, false, err
	}
	var a freshnessAnchor
	if err := json.Unmarshal(data, &a); err != nil {
		// Unparseable: fail open (re-TOFU), exactly like a missing anchor.
		return freshnessAnchor{}, false, nil
	}
	return a, true, nil
}

// saveAnchor writes a device's freshness anchor through the A1 atomic write path
// (atomicWriteFile + fsyncDir), plaintext at 0600 —
// the same durability path the gc-seen store uses.
func saveAnchor(path string, a freshnessAnchor) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

// recordAnchor advances this device's freshness anchor to reflect a config it
// just trusted at Open or ratcheted: it raises the
// FormatEpoch high-water, records the ConfigTag seen AT that high-water (for the
// divergence tie-break), and latches HasTag true when a valid tag was seen.
// The high-water and HasTag are monotone — recordAnchor never lowers the epoch
// nor clears HasTag — so a later untagged config cannot poison the anchor
// . It is BEST-EFFORT: a failure to resolve or write the anchor is
// returned as a note and never propagated as an error, so Open (and the ratchet)
// are never blocked by an unwritable appdir. It writes only when the
// stored anchor would actually change, so a read-only re-open of an unchanged
// config touches nothing.
func (v *Vault) recordAnchor(epoch int64, hasTag bool, tag string) string {
	path, err := v.anchorPath()
	if err != nil {
		return anchorUnavailableNote
	}
	cur, existed, lerr := loadAnchor(path)
	if lerr != nil {
		// A genuine read error: treat the anchor as absent and try to (re)write it.
		cur, existed = freshnessAnchor{}, false
	}
	next := cur
	switch {
	case epoch > next.FormatEpoch:
		// A newer config: raise the high-water and adopt its tag as the recorded
		// tag for the tie-break at this epoch.
		next.FormatEpoch = epoch
		if tag != "" {
			next.ConfigTag = tag
		}
	case epoch == next.FormatEpoch && next.ConfigTag == "" && tag != "":
		// First time this device sees a tag at the already-anchored epoch (e.g. an
		// anchor written before the ConfigTag field existed): latch it so a later
		// divergent copy at this epoch is detectable.
		next.ConfigTag = tag
	}
	if hasTag {
		next.HasTag = true
	}
	if existed && next == cur {
		return ""
	}
	if err := saveAnchor(path, next); err != nil {
		return anchorUnavailableNote
	}
	return ""
}

// clearAnchor removes this device's freshness anchor for the vault so the next
// Open re-TOFUs: the operator-authorised effect of
// --accept-rollback. A missing anchor is already cleared. A genuine remove error
// (an unwritable appdir) is surfaced as the anchor-unavailable note, never as a
// hard failure — Open must still proceed.
func (v *Vault) clearAnchor() string {
	path, err := v.anchorPath()
	if err != nil {
		return anchorUnavailableNote
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return anchorUnavailableNote
	}
	return ""
}
