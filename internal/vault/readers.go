// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// ReaderRecord is one device's last-seen reader signal for a vault (
// ). It is the unit of the device-local lastSeenReader inventory
// seal-format prints before retiring older readers: which DeviceID opened this
// vault, the highest format level that device can read (SupportedFormat), the
// on-disk config Version it last saw, and when. It carries no secret.
type ReaderRecord struct {
	DeviceID string `json:"deviceId"`
	// SupportedFormat is the format ceiling that device's build implements (the
	// vault.SupportedFormat constant it was compiled with). A device reporting a
	// SupportedFormat below a vault's post-seal MinReader would be fenced out — so
	// this is the field that tells the operator whether a known reader survives a
	// seal-format.
	SupportedFormat int `json:"supportedFormat"`
	// Version is the on-disk VaultConfig.Version that device last observed. It is a
	// diagnostic (a device that last saw Version 2 has not yet met a seal), not a
	// fence input.
	Version  int    `json:"version"`
	LastSeen string `json:"lastSeen"` // RFC3339Nano, UTC
}

// readerInventory is the on-disk shape of a vault's device-local reader signal
// store: a map keyed by DeviceID. It is a struct
// wrapper (not a bare map) so a future top-level field is an additive change,
// mirroring the deviceIDStore/gc-seen conventions in this tree.
type readerInventory struct {
	Readers map[string]ReaderRecord `json:"readers"`
}

// readerStorePath is the device-local lastSeenReader store for a vault (design
// ): <appdir data>/vault-readers/<vaultID>.json. Like the freshness anchor
// and gc-seen stores it lives under appdir.DataDir, so it is NEVER part of the
// synced vault store and cannot leak a DeviceID off the wire — the
// signal is honestly device-local, and thin: it records only devices that have
// opened this vault through THIS app-data directory, and a 0.16 peer (which does
// not write it at all) never appears. That weakness is why seal-format falls back
// to an explicit no-inventory warning when the map is empty.
func readerStorePath(vaultID string) (string, error) {
	base, err := appdir.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "vault-readers", vaultID+".json"), nil
}

// loadReaderInventory reads a vault's device-local reader store. A missing or
// unparseable store yields an empty inventory with no error (fail open, like the
// freshness anchor): the signal is best-effort telemetry, never a gate. Only a
// genuine I/O error reaching an existing file is returned.
func loadReaderInventory(path string) (readerInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return readerInventory{Readers: map[string]ReaderRecord{}}, nil
		}
		return readerInventory{Readers: map[string]ReaderRecord{}}, err
	}
	var inv readerInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		// Unparseable: treat as empty (fail open), exactly like a missing store.
		return readerInventory{Readers: map[string]ReaderRecord{}}, nil
	}
	if inv.Readers == nil {
		inv.Readers = map[string]ReaderRecord{}
	}
	return inv, nil
}

// recordReaderSignal upserts THIS device's entry into the vault's device-local
// reader inventory on Open. It is best-effort and
// never blocks Open: a vault with no resolvable DeviceID (degraded mode) or an
// unwritable appdir simply leaves the inventory thinner. The write goes through
// the A1 atomic path (atomicWriteFile + fsyncDir), plaintext at 0600, matching
// the anchor and gc-seen stores.
func (v *Vault) recordReaderSignal() {
	if v.deviceID == "" {
		return
	}
	path, err := readerStorePath(v.ID())
	if err != nil {
		return
	}
	inv, _ := loadReaderInventory(path)
	inv.Readers[v.deviceID] = ReaderRecord{
		DeviceID:        v.deviceID,
		SupportedFormat: SupportedFormat,
		Version:         v.Config.Version,
		LastSeen:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWriteFile(path, data, 0o600)
}

// ReaderInventory returns the device-local lastSeenReader records for this vault,
// sorted by DeviceID. It reads only the device-local
// store and writes nothing. An empty slice means this device has
// no inventory of any reader — the case seal-format turns into an explicit
// no-inventory warning.
func (v *Vault) ReaderInventory() []ReaderRecord {
	path, err := readerStorePath(v.ID())
	if err != nil {
		return nil
	}
	inv, err := loadReaderInventory(path)
	if err != nil {
		return nil
	}
	out := make([]ReaderRecord, 0, len(inv.Readers))
	for _, r := range inv.Readers {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}
