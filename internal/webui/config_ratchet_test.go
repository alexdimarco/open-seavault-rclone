// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// TestGUIInitRatchetsConfigMAC is the tombstone for rotation-recovery/F1 on the
// GUI init surface. /api/init creates a vault and installs it as the active,
// write-capable GUI session (s.vault, which the browser then uploads to and
// deletes from). Per design D2.4 the first write-capable open must ratchet the
// ConfigMAC so T-A2-1 config forgery is detected on this device. Before the fix
// handleInit opened via vault.Open() and never called EnsureConfigMAC, so the
// vault stayed untagged (no configTag, no freshness anchor) for the whole GUI
// session and VaultID / ChunkParams / KDF / wrap edits were accepted silently.
func TestGUIInitRatchetsConfigMAC(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          "passphrase",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	cfg, err := vault.ReadConfig(vaultPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.ConfigTag == "" {
		t.Fatal("GUI /api/init left vault.json with no configTag: the ConfigMAC ratchet did not fire on the write-capable GUI session, so T-A2-1 config forgery is undetected (rotation-recovery/F1)")
	}
	if cfg.FormatEpoch < 1 {
		t.Fatalf("GUI /api/init did not bump FormatEpoch (got %d, want >= 1): the freshness-anchor rollback fence (T-A2-2) never engages", cfg.FormatEpoch)
	}
}

// TestGUIOpenRatchetsConfigMAC is the tombstone for rotation-recovery/F1 on the
// GUI open surface. A vault created outside the GUI starts untagged (Create
// writes no ConfigTag — TOFU); opening it through /api/open installs it as the
// active write-capable session, which must ratchet the tag exactly as the CLI
// openVaultForWrite / `serve` do. Before the fix handleOpen never ratcheted, so a
// GUI-only user's vault never acquired a tag until an explicit password rotation
// — the entire P0-3 config-forgery/rollback defense stayed inert by default.
func TestGUIOpenRatchetsConfigMAC(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	if err := vault.Create(vaultPath, "passphrase", vault.DefaultChunkParams()); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	// Precondition: a freshly created vault carries no tag (the gap the finding
	// describes). If this ever fails, Create started tagging and this tombstone
	// must be re-pointed rather than silently passing.
	if pre, err := vault.ReadConfig(vaultPath); err != nil {
		t.Fatalf("read config: %v", err)
	} else if pre.ConfigTag != "" {
		t.Fatalf("precondition: a Create()d vault must start untagged, got configTag %q", pre.ConfigTag)
	}
	rr := postJSON(t, s, "/api/open", map[string]any{"vaultPath": vaultPath, "password": "passphrase"})
	if rr.Code != http.StatusOK {
		t.Fatalf("open failed: %d %s", rr.Code, rr.Body.String())
	}
	cfg, err := vault.ReadConfig(vaultPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.ConfigTag == "" {
		t.Fatal("GUI /api/open left vault.json with no configTag: the ConfigMAC ratchet did not fire on the write-capable GUI session (rotation-recovery/F1)")
	}
}
