// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package appdir

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// deviceIDFileName is the device-identity store's basename. It lives directly
// under appdir.DataDir — NOT inside
// appconfig.json — so a config reset (which os.Removes appconfig.json) does not
// regenerate it and the per-record vector clock keeps a stable writer identity
// across resets. It is the same durability tier as the gc-seen and vault-anchor
// stores, all of which live under DataDir and never sync to a remote.
const deviceIDFileName = "device-id.json"

// deviceIDStore is the on-disk shape of the device-identity file. It is a JSON
// object (not a bare string) so a future field — a creation timestamp, say — is
// an additive change, mirroring every other store in this tree.
type deviceIDStore struct {
	DeviceID string `json:"deviceId"`
}

// deviceIDPath resolves <DataDir>/device-id.json without creating anything.
func deviceIDPath() (string, error) {
	base, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, deviceIDFileName), nil
}

// validDeviceID reports whether s is a well-formed device id: 32 lowercase hex
// characters (a random 16-byte value). A malformed or empty value is treated as
// absent so a corrupt file re-mints rather than poisoning every clock with an
// unparseable writer key.
func validDeviceID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// DeviceID returns this installation's stable device identifier, creating and
// persisting it on first use. The value is a
// random 16-byte quantity rendered as 32 lowercase hex characters. It is the
// writer key of the per-record vector clock: it must be stable across app
// restarts and across a config reset, so it is stored under appdir.DataDir
// (which the reset flows never touch), not in appconfig.json.
//
// A reinstall or an app-data wipe legitimately mints a NEW id — a returning
// device with a fresh id is a genuine new causal writer, so this
// loses no data; it only grows the clock by one entry, which aging prunes.
//
// Creation is best-effort against a concurrent second process: after writing its
// candidate atomically, DeviceID re-reads the file and returns whatever landed,
// so two processes racing on first use converge on a single id rather than each
// trusting its own un-persisted value.
func DeviceID() (string, error) {
	path, err := deviceIDPath()
	if err != nil {
		return "", err
	}
	if id, ok := readDeviceID(path); ok {
		return id, nil
	}
	// First use (or a corrupt/absent file): mint a fresh id and persist it.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := writeDeviceID(path, id); err != nil {
		return "", err
	}
	// Re-read so a racing process that wrote first wins deterministically for
	// both: the file is the single source of truth once it exists.
	if landed, ok := readDeviceID(path); ok {
		return landed, nil
	}
	return id, nil
}

// readDeviceID reads and validates the persisted id. A missing, unreadable, or
// malformed file yields ("", false) so the caller mints a fresh one; only a
// well-formed value yields (id, true).
func readDeviceID(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var store deviceIDStore
	if err := json.Unmarshal(data, &store); err != nil {
		return "", false
	}
	id := strings.TrimSpace(store.DeviceID)
	if !validDeviceID(id) {
		return "", false
	}
	return id, true
}

// writeDeviceID persists the id through a temp-file + rename so a crash never
// leaves a half-written store, at 0600 like every other DataDir store.
func writeDeviceID(path, id string) error {
	data, err := json.MarshalIndent(deviceIDStore{DeviceID: id}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-device-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("persist device id: %w", err)
	}
	return nil
}
