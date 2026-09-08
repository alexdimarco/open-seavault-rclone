// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// Friendly recovery-key labels (design U2 §2.6) live HERE, in the device-local
// profile store — never in the MAC-covered vault.json. A label field a 0.17 client
// did not know would change the ConfigMAC and make that client refuse the vault as
// tampered (the mixed-fleet guarantee), so labels are display-only, per device,
// and a missing record degrades to the bare handle rather than an error.
//
// Every recovery entry also carries a STABLE handle — the first four hex
// characters of its entry ID (review condition C4) — shown on the printable card
// AND in the list on every device, so a targeted revoke can never retire the wrong
// key even after earlier revokes renumber the ordinals.

// recoveryLabelsFileName is the label store's basename, a sibling of profiles.json
// under appdir.ConfigDir. It is device-local and never synced to a remote.
const recoveryLabelsFileName = "recovery-labels.json"

// handleLen is the number of leading hex characters of an entry ID that form its
// stable display handle.
const handleLen = 4

// RecoveryKeyLabel is one device-local record for a recovery entry, keyed in the
// store by that entry's full ID. It holds ONLY display metadata: a free-form
// nickname, the creation date, and the device that generated the key. It carries
// no secret, no ciphertext, and nothing that belongs in vault.json.
type RecoveryKeyLabel struct {
	Label   string `json:"label"`
	Created string `json:"created"`
	Device  string `json:"device"`
}

// LabelStore is the on-disk shape of the recovery-label file: a versioned map from
// full entry ID to its label record.
type LabelStore struct {
	Version int                         `json:"version"`
	Labels  map[string]RecoveryKeyLabel `json:"labels"`
}

// LabelsPath resolves <ConfigDir>/recovery-labels.json without creating anything.
func LabelsPath() (string, error) {
	base, err := appdir.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, recoveryLabelsFileName), nil
}

// LoadLabels reads the label store, returning an empty (version 1) store when the
// file does not exist yet. A malformed file is a real error, not a silent reset.
func LoadLabels() (LabelStore, error) {
	p, err := LabelsPath()
	if err != nil {
		return LabelStore{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return LabelStore{Version: 1, Labels: map[string]RecoveryKeyLabel{}}, nil
	}
	if err != nil {
		return LabelStore{}, err
	}
	var s LabelStore
	if err := json.Unmarshal(data, &s); err != nil {
		return LabelStore{}, err
	}
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Labels == nil {
		s.Labels = map[string]RecoveryKeyLabel{}
	}
	return s, nil
}

// SaveLabels writes the label store with 0600 perms under a 0700 config dir,
// mirroring the profile store. It never touches vault.json.
func SaveLabels(s LabelStore) error {
	p, err := LabelsPath()
	if err != nil {
		return err
	}
	s.Version = 1
	if s.Labels == nil {
		s.Labels = map[string]RecoveryKeyLabel{}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeDeviceLocalFile(p, data)
}

// writeDeviceLocalFile writes a device-local config file (profiles.json /
// recovery-labels.json) and forces restrictive permissions EVEN WHEN the file or
// its directory already exists: os.WriteFile and os.MkdirAll only apply a mode on
// creation, so a pre-existing 0644 store would otherwise stay world-readable
// (review wordlist-labels-2). The file becomes 0600 and its directory 0700. On
// Windows os.Chmod only toggles the read-only bit, which is harmless here.
func writeDeviceLocalFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// SetRecoveryLabel records (or replaces) the label for one recovery entry, keyed
// by its full entry ID. The caller writes this at generate time. It is display-
// only and touches no vault config.
func SetRecoveryLabel(entryID string, label RecoveryKeyLabel) error {
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return errors.New("a recovery entry ID is required to label a key")
	}
	s, err := LoadLabels()
	if err != nil {
		return err
	}
	s.Labels[entryID] = label
	return SaveLabels(s)
}

// DeleteRecoveryLabel removes the device-local label record for one recovery
// entry, if present. The CLI and GUI revoke paths call it so a revoked key's
// hostname/date do not linger in the store indefinitely (review wordlist-labels-3).
// A missing record is not an error; an empty ID is a no-op; the store is only
// rewritten when a record was actually removed.
func DeleteRecoveryLabel(entryID string) error {
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return nil
	}
	s, err := LoadLabels()
	if err != nil {
		return err
	}
	if _, ok := s.Labels[entryID]; !ok {
		return nil
	}
	delete(s.Labels, entryID)
	return SaveLabels(s)
}

// GetRecoveryLabel returns the stored label for an entry ID and whether a record
// exists. A missing record is not an error.
func GetRecoveryLabel(entryID string) (RecoveryKeyLabel, bool, error) {
	s, err := LoadLabels()
	if err != nil {
		return RecoveryKeyLabel{}, false, err
	}
	l, ok := s.Labels[strings.TrimSpace(entryID)]
	return l, ok, nil
}

// Handle returns the stable display handle for an entry ID: its first four hex
// characters, lower-cased. Shorter-than-four IDs return whatever they have. This
// is the one identifier shown on the card AND in the list on every device.
func Handle(entryID string) string {
	h := strings.ToLower(strings.TrimSpace(entryID))
	if len(h) > handleLen {
		h = h[:handleLen]
	}
	return h
}

// RecoveryKeyView is a listing row for one recovery entry: its full ID (for
// redeem/revoke, which always use the ID), its stable handle, its 1-based ordinal
// in on-disk order, and the device-local label record if one exists.
type RecoveryKeyView struct {
	ID        string
	Handle    string
	Ordinal   int
	HasRecord bool
	Label     string
	Created   string
	Device    string
}

// Display renders the human-facing label for a listing row: the always-present
// handle, plus the label-or-creation detail when a local record exists (design
// §2.6). With no record it degrades to the bare handle — never an error, and
// stable across earlier revokes because the handle does not renumber.
func (v RecoveryKeyView) Display() string {
	if !v.HasRecord {
		return fmt.Sprintf("Recovery key #%s", v.Handle)
	}
	detail := ""
	switch {
	case v.Created != "" && v.Device != "":
		detail = fmt.Sprintf("created %s on %s", v.Created, v.Device)
	case v.Created != "":
		detail = fmt.Sprintf("created %s", v.Created)
	case v.Device != "":
		detail = fmt.Sprintf("on %s", v.Device)
	}
	if v.Label != "" {
		if detail != "" {
			detail = v.Label + " — " + detail
		} else {
			detail = v.Label
		}
	}
	if detail == "" {
		return fmt.Sprintf("Recovery key #%s", v.Handle)
	}
	return fmt.Sprintf("Recovery key #%s — %s", v.Handle, detail)
}

// LabelledRecoveryKeys joins an ordered list of recovery entry IDs (as returned by
// the vault layer, in on-disk order) with this device's label store, producing one
// display row per entry. Ordinals are assigned in the given order; the handle and
// label come from the ID and the store. It reads the store once and never errors
// on a missing record.
func LabelledRecoveryKeys(entryIDs []string) ([]RecoveryKeyView, error) {
	s, err := LoadLabels()
	if err != nil {
		return nil, err
	}
	// Prune orphaned records: a stored label whose entry ID is not among the
	// current on-disk entries belongs to a key that has since been revoked, so its
	// hostname/date must not persist (review wordlist-labels-3). Guard on a
	// NON-EMPTY current set: an empty entryIDs is ambiguous (a closed or not-yet-
	// loaded vault, not necessarily a zero-key one), and the targeted
	// DeleteRecoveryLabel from the revoke path already cleans a last-key revoke — so
	// an empty set must never be read as "revoke every label".
	if len(entryIDs) > 0 {
		current := make(map[string]struct{}, len(entryIDs))
		for _, id := range entryIDs {
			current[id] = struct{}{}
		}
		pruned := false
		for id := range s.Labels {
			if _, keep := current[id]; !keep {
				delete(s.Labels, id)
				pruned = true
			}
		}
		if pruned {
			if err := SaveLabels(s); err != nil {
				return nil, err
			}
		}
	}
	out := make([]RecoveryKeyView, 0, len(entryIDs))
	for i, id := range entryIDs {
		view := RecoveryKeyView{ID: id, Handle: Handle(id), Ordinal: i + 1}
		if rec, ok := s.Labels[id]; ok {
			view.HasRecord = true
			view.Label = rec.Label
			view.Created = rec.Created
			view.Device = rec.Device
		}
		out = append(out, view)
	}
	return out, nil
}
