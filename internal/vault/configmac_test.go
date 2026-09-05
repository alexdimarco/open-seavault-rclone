// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	r4Password = "correct horse battery staple"
	r4Recovery = "recovery whisky xray yankee zulu alpha"
)

// isolateAppHome points appdir.DataDir at a private temp dir so a test's
// device-local freshness anchors never touch (or read) the real app-data
// directory, and persist deterministically across Opens within the test.
func isolateAppHome(t *testing.T) {
	t.Helper()
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
}

// readTestAnchor reads the device-local freshness anchor for a specific OPEN
// vault. It resolves the anchor path exactly as production does (v.anchorPath(),
// keyed by the master-derived anchor id — finding config-server/F3), so the test
// always reads the same file Open writes, regardless of the plaintext VaultID.
func readTestAnchor(t *testing.T, v *Vault) (freshnessAnchor, bool) {
	t.Helper()
	path, err := v.anchorPath()
	if err != nil {
		t.Fatal(err)
	}
	a, existed, err := loadAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	return a, existed
}

func configTagOf(t *testing.T, root string) string {
	t.Helper()
	cfg, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.ConfigTag
}

// ratchetTaggedVault opens root, runs the write-capable ratchet, and asserts a
// tag was written — the "first write-capable open" that latches a ConfigTag and
// the device anchor (design D2.4). Returns the opened, now-anchored vault.
func ratchetTaggedVault(t *testing.T, root, password string) *Vault {
	t.Helper()
	v, err := Open(root, password)
	if err != nil {
		t.Fatalf("open to ratchet: %v", err)
	}
	wrote, err := v.EnsureConfigMAC()
	if err != nil {
		t.Fatalf("EnsureConfigMAC: %v", err)
	}
	if !wrote {
		t.Fatal("EnsureConfigMAC must ratchet a tag onto an untagged vault, but wrote nothing")
	}
	if configTagOf(t, root) == "" {
		t.Fatal("EnsureConfigMAC returned wrote=true but vault.json carries no configTag")
	}
	return v
}

// R4 (design §2, P0-3, T-A2-1): once a vault carries a ConfigMAC, flipping ANY
// MAC-covered field is caught after a CORRECT password as ErrConfigTampered; an
// untampered tagged config opens; and a WRONG password still fails as a wrong
// password — never as a MAC error (the check runs only after a successful
// unwrap, so there is no MAC oracle).
func TestConfigMACDetectsTamper(t *testing.T) {
	isolateAppHome(t)

	// A vault carrying both a password and a recovery wrap entry, then tagged.
	// The wrap-CT flip below targets the (non-unlocking) recovery entry — the case
	// the MAC exists for: the password entry still unwraps, and only the MAC
	// catches the edited recovery ciphertext.
	build := func(t *testing.T) (root string) {
		root = filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r4Password)
		v0, err := Open(root, r4Password)
		if err != nil {
			t.Fatal(err)
		}
		keys := copyKeys(v0.keys)
		pw := bareEntry(t, r4Password, keys, "11110001", WrapTypePassword)
		rec := bareEntry(t, r4Recovery, keys, "22220002", WrapTypeRecovery)
		editConfig(t, root, func(c *VaultConfig) {
			c.WrapEntries = []WrapEntry{pw, rec}
		})
		ratchetTaggedVault(t, root, r4Password)
		return root
	}

	tampers := []struct {
		name   string
		mutate func(*VaultConfig)
	}{
		{"vaultID", func(c *VaultConfig) { c.VaultID = "0000ffff0000ffff0000ffff0000ffff" }},
		{"chunk params", func(c *VaultConfig) { c.Chunk.MinSize += 7 }},
		{"kdf cost", func(c *VaultConfig) { c.KDF.MemoryKiB = 65536 }},
		{"recovery wrap ct", func(c *VaultConfig) {
			c.WrapEntries[1].CT = base64.StdEncoding.EncodeToString([]byte("tampered-recovery-ciphertext-bytes"))
		}},
	}
	if len(tampers) == 0 {
		t.Fatal("no tamper cases defined")
	}
	for _, tc := range tampers {
		t.Run("flip "+tc.name, func(t *testing.T) {
			root := build(t)
			editConfig(t, root, tc.mutate)
			v, err := Open(root, r4Password)
			if v != nil {
				t.Fatal("Open must refuse a tampered config, but returned a vault")
			}
			if !errors.Is(err, ErrConfigTampered) {
				t.Fatalf("flipping %s must yield ErrConfigTampered, got %v", tc.name, err)
			}
		})
	}

	t.Run("untampered tagged config opens", func(t *testing.T) {
		root := build(t)
		v, err := Open(root, r4Password)
		if err != nil {
			t.Fatalf("an untampered tagged config must open: %v", err)
		}
		if v == nil {
			t.Fatal("Open returned a nil vault with no error")
		}
	})

	t.Run("wrong password is wrong-password, not MAC", func(t *testing.T) {
		root := build(t)
		_, err := Open(root, "definitely not the password")
		if errors.Is(err, ErrConfigTampered) {
			t.Fatal("a wrong password must not surface as ErrConfigTampered (that would be a MAC oracle)")
		}
		if !errors.Is(err, errWrongSecret) {
			t.Fatalf("a wrong password must yield the generic wrong-secret error, got %v", err)
		}
	})
}

// R5 (design §2, D2.4, Condition 6): the has-tag ratchet and strip resolution.
// A genuinely-legacy vault (this device never anchored a tag) opens via TOFU and
// gets a tag on the first write-capable open; once a device has anchored hasTag,
// a config that arrives with the tag stripped is a HARD ErrConfigTampered; and a
// strip can never advance the device's epoch high-water (backlog B-1).
func TestConfigTagRatchetAndStrip(t *testing.T) {
	isolateAppHome(t)

	t.Run("legacy vault opens via TOFU and gets a tag on first write", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r4Password)
		if configTagOf(t, root) != "" {
			t.Fatal("precondition: a freshly-created vault must carry no configTag")
		}
		// TOFU: a fresh, never-anchored device trusts the untagged config.
		v, err := Open(root, r4Password)
		if err != nil {
			t.Fatalf("a genuinely-legacy untagged vault must open via TOFU: %v", err)
		}
		// The first write-capable open ratchets a tag.
		wrote, err := v.EnsureConfigMAC()
		if err != nil {
			t.Fatalf("EnsureConfigMAC: %v", err)
		}
		if !wrote {
			t.Fatal("the first write-capable open must ratchet a tag, but wrote nothing")
		}
		cfg, err := ReadConfig(root)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ConfigTag == "" {
			t.Fatal("vault.json must carry a configTag after the ratchet")
		}
		// The ratchet writes ONLY the tag and bumps the epoch; it must NOT bump
		// Version (design D2.4 — that is seal-format's job).
		if cfg.Version != 2 {
			t.Fatalf("the ratchet must keep Version=2, got %d", cfg.Version)
		}
		if cfg.FormatEpoch == 0 {
			t.Fatal("the ratchet must bump FormatEpoch above 0")
		}
		// The tagged config re-opens cleanly on this now-anchored device.
		if _, err := Open(root, r4Password); err != nil {
			t.Fatalf("the ratcheted config must re-open on the anchoring device: %v", err)
		}
	})

	t.Run("stripping the tag from an anchored device is a hard tamper", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r4Password)
		v := ratchetTaggedVault(t, root, r4Password)

		anc, existed := readTestAnchor(t, v)
		if !existed || !anc.HasTag {
			t.Fatalf("precondition: the ratchet must anchor hasTag=true (existed=%v anchor=%+v)", existed, anc)
		}
		highWater := anc.FormatEpoch
		if highWater == 0 {
			t.Fatal("precondition: the anchored epoch high-water must be above 0")
		}

		// Server strips the tag and tries to advance the epoch at the same time.
		editConfig(t, root, func(c *VaultConfig) {
			c.ConfigTag = ""
			c.FormatEpoch = highWater + 99
		})
		got, err := Open(root, r4Password)
		if got != nil {
			t.Fatal("Open must refuse a stripped config on an anchored device, but returned a vault")
		}
		if !errors.Is(err, ErrConfigTampered) {
			t.Fatalf("a stripped tag on an anchored-hasTag device must be ErrConfigTampered, got %v", err)
		}

		// The strip must not have advanced the epoch high-water (backlog B-1) nor
		// cleared the anchored hasTag bit.
		after, _ := readTestAnchor(t, v)
		if after.FormatEpoch != highWater {
			t.Fatalf("a strip must not advance the epoch anchor: %d -> %d", highWater, after.FormatEpoch)
		}
		if !after.HasTag {
			t.Fatal("a strip must not clear the anchored hasTag bit")
		}
	})

	t.Run("unparseable anchor fails open (re-TOFU)", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, r4Password)
		// Resolve the anchor path production will consult (the master-derived id,
		// finding config-server/F3) by opening the untagged vault once — a TOFU open
		// that records no anchor — then write garbage at exactly that path.
		v0, err := Open(root, r4Password)
		if err != nil {
			t.Fatal(err)
		}
		path, err := v0.anchorPath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{ not valid anchor json"), 0o600); err != nil {
			t.Fatal(err)
		}
		// An unparseable anchor must fail OPEN: the untagged legacy vault re-TOFUs,
		// it must not be mistaken for a strip.
		if _, err := Open(root, r4Password); err != nil {
			t.Fatalf("an unparseable anchor must fail open (re-TOFU), got %v", err)
		}
	})
}
