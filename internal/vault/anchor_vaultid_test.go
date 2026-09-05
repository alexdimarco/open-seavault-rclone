// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestStripSurvivesVaultIDMutation is the tombstone for finding
// .
//
// The has-tag freshness anchor that enforces the strip refusal (
// the review — "once a device has verified a tag for a vault, that vault must
// always present a valid tag to that device") was keyed by
// anchorStorePath(v.ID), and v.ID returns the attacker-controlled plaintext
// Config.VaultID. A hostile config server could therefore STRIP the ConfigTag AND
// swap/blank the VaultID together: the anchor lookup relocated to a nonexistent
// id, existed=false, and the no-tag path fell through to TOFU and OPENED the
// vault — laundering the strip and re-opening the forgery surface (and,
// via a replayed pre-rotation config, the rotation-rollback surface) on an
// ALREADY-ANCHORED device. VaultID is MAC-covered only on the still-tagged path
// the strip removes, so nothing else bound it.
//
// The invariant this pins: on a device that has anchored hasTag=true for a vault,
// a config that arrives with NO tag is a hard ErrConfigTampered no matter what the
// attacker does to the plaintext VaultID — because the anchor is keyed by an
// identifier derived from the unwrapped master key, which the attacker cannot
// change without breaking the unwrap itself.
func TestStripSurvivesVaultIDMutation(t *testing.T) {
	realID := "8671133c3d3de38a441d26bd0d9813f9"

	cases := []struct {
		name   string
		mutate func(*VaultConfig)
	}{
		// CONTROL: strip only, VaultID left intact. Already refused before the fix;
		// it must stay refused after it.
		{"strip only, vaultID intact", func(c *VaultConfig) {
			c.ConfigTag = ""
		}},
		// BYPASS (the finding's repro): strip the tag AND swap the VaultID to an id
		// no anchor exists for.
		{"strip + swap vaultID", func(c *VaultConfig) {
			c.ConfigTag = ""
			c.VaultID = "ffffffffffffffffffffffffffffffff"
		}},
		// BYPASS variant: strip the tag AND blank the VaultID (v.ID then falls back
		// to legacyVaultID, still not the anchored id).
		{"strip + blank vaultID", func(c *VaultConfig) {
			c.ConfigTag = ""
			c.VaultID = ""
		}},
	}
	if len(cases) == 0 {
		t.Fatal("no strip cases defined")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAppHome(t) // a fresh app home == one already-anchored device
			root := filepath.Join(t.TempDir(), "vault")
			createTestVault(t, root, r4Password)
			// Pin a known, real VaultID and then anchor hasTag=true for it: this is a
			// device that has verified a valid ConfigTag for THIS vault.
			editConfig(t, root, func(c *VaultConfig) { c.VaultID = realID })
			v := ratchetTaggedVault(t, root, r4Password)
			anc, existed := readTestAnchor(t, v)
			if !existed || !anc.HasTag {
				t.Fatalf("precondition: the ratchet must anchor hasTag=true (existed=%v anchor=%+v)", existed, anc)
			}

			// Hostile config server: strip the tag (and, in the bypass rows, relocate
			// the anchor-keying VaultID at the same time). Nothing about the device's
			// app data is touched — this is the in-model config-server adversary.
			editConfig(t, root, tc.mutate)

			got, err := Open(root, r4Password)
			if got != nil {
				t.Fatalf("Open must refuse a stripped config on an anchored device even when the VaultID is mutated (%s), but returned a vault", tc.name)
			}
			if !errors.Is(err, ErrConfigTampered) {
				t.Fatalf("a strip on an anchored-hasTag device must be ErrConfigTampered regardless of the VaultID (%s), got %v", tc.name, err)
			}
		})
	}
}
