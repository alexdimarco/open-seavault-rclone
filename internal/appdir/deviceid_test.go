// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package appdir

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeviceIDStableAndPersistedUnderDataDir proves the vector-clock writer key
// is stable across calls, persisted under DataDir (design D4.1, Condition 11),
// and well-formed. Stability is the property the vector clock depends on: a
// churning device id would mint a fresh clock entry on every open.
func TestDeviceIDStableAndPersistedUnderDataDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", home)

	first, err := DeviceID()
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}
	if !validDeviceID(first) {
		t.Fatalf("DeviceID returned a malformed id %q (want 32 lowercase hex)", first)
	}
	// A second call returns the SAME id (loaded from disk, not re-minted).
	second, err := DeviceID()
	if err != nil {
		t.Fatalf("DeviceID (second): %v", err)
	}
	if second != first {
		t.Fatalf("DeviceID must be stable across calls: first %q, second %q", first, second)
	}
	// It lives under the data dir, at device-id.json.
	dataDir, err := DataDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dataDir, "device-id.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("device id must be persisted at %s: %v", want, err)
	}
	// It is NOT stored in the app config file, so a config reset (which removes
	// appconfig.json) cannot regenerate it (Condition 11).
	cfgDir, err := ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "appconfig.json")); !os.IsNotExist(err) {
		t.Fatalf("DeviceID must not create appconfig.json (config-reset must not wipe the device id); stat err = %v", err)
	}
}

// TestDeviceIDSurvivesConfigReset models a config reset — removing appconfig.json
// (and the whole config dir) — and proves the device id is unchanged, because it
// lives under the data dir the reset flows never touch (design D4.1, Condition 11).
func TestDeviceIDSurvivesConfigReset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", home)

	before, err := DeviceID()
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}
	// Simulate the config-reset flow: wipe the entire config subtree.
	cfgDir, err := ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(cfgDir); err != nil {
		t.Fatal(err)
	}
	after, err := DeviceID()
	if err != nil {
		t.Fatalf("DeviceID after reset: %v", err)
	}
	if after != before {
		t.Fatalf("a config reset must NOT change the device id: before %q, after %q", before, after)
	}
}

// TestDeviceIDRemintsOnCorruptStore proves a corrupt/malformed store re-mints a
// valid id rather than poisoning every clock with an unparseable writer key
// (fail-safe, like the freshness anchor).
func TestDeviceIDRemintsOnCorruptStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", home)

	if _, err := DeviceID(); err != nil {
		t.Fatal(err)
	}
	dataDir, err := DataDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "device-id.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DeviceID()
	if err != nil {
		t.Fatalf("DeviceID over corrupt store: %v", err)
	}
	if !validDeviceID(got) {
		t.Fatalf("a corrupt store must re-mint a valid id, got %q", got)
	}
}
