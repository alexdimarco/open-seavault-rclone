// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import "time"

type Index struct {
	Version   int                   `json:"version"`
	UpdatedAt string                `json:"updatedAt"`
	Files     map[string]FileRecord `json:"files"`
}

type FileRecord struct {
	Size       int64      `json:"size"`
	Mode       uint32     `json:"mode"`
	ModTime    string     `json:"modTime"`
	UpdatedAt  string     `json:"updatedAt,omitempty"`
	Generation int64      `json:"generation,omitempty"`
	Chunks     []ChunkRef `json:"chunks"`
	ConflictOf string     `json:"conflictOf,omitempty"`
	// Clock is the additive per-record vector clock: a map
	// from writer DeviceID to a monotonic counter, carried inside the encrypted
	// manifest body only. Additive/omitempty so a 0.16 writer (which never sets
	// it) round-trips it as absent and reconciliation falls back to Generation.
	// On each local write the device sets Clock[DeviceID] = max(existing, wallNano)
	// + 1 and joins every other entry it has seen for the path (nextRecordClock).
	Clock map[string]int64 `json:"clock,omitempty"`
	// ClockAge is the aging bookkeeping for Clock: for
	// each FOREIGN device entry it counts consecutive local writes of this record
	// that did NOT observe that device advance. When the count reaches
	// clockAgeCompactions the entry is dropped from Clock on the next write — a
	// decommissioned or reset device's stale entry ages out, keeping the encrypted
	// manifest from growing without bound. Additive/omitempty and never compared
	// for equality (sameFileRecord ignores it): it is a local optimisation hint,
	// not content, and a 0.16 peer round-trips it as absent.
	ClockAge map[string]int `json:"clockAge,omitempty"`
}

type ChunkRef struct {
	ID   string `json:"id"`
	Size int    `json:"size"`
}

func NewIndex() Index {
	return Index{Version: 2, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Files: map[string]FileRecord{}}
}
