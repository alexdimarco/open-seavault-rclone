// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

// C4: the preflight-note segment matcher fires for the org-suffixed macOS
// CloudStorage folder names (OneDrive-*, GoogleDrive-*, Box-*) the setup wizard
// recommends, while the bare names keep working and a merely prefixed-but-not-
// suffixed segment (OneDriveBackup) does not falsely match.
func TestSyncClientPreflightNoteOrgSuffixed(t *testing.T) {
	rows := []struct {
		name     string
		segments []string
		wantNote bool
	}{
		{"onedrive org-suffixed", []string{"Library", "CloudStorage", "OneDrive-Personal", "seavault"}, true},
		{"googledrive org-suffixed", []string{"Library", "CloudStorage", "GoogleDrive-me@example.com", "My Drive", "seavault"}, true},
		{"box org-suffixed", []string{"Library", "CloudStorage", "Box-Acme", "seavault"}, true},
		{"bare onedrive still matches", []string{"OneDrive", "seavault"}, true},
		{"prefixed but not dash-suffixed does not match", []string{"projects", "OneDriveBackup", "seavault"}, false},
		{"unrelated path no note", []string{"projects", "seavault"}, false},
	}
	if len(rows) == 0 {
		t.Fatal("matcher table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			root := filepath.Join(append([]string{string(filepath.Separator) + "home", "alex"}, row.segments...)...)
			note := SyncClientPreflightNote(root)
			if row.wantNote {
				if note == "" {
					t.Fatalf("root %q must produce a preflight note", root)
				}
				if !strings.Contains(note, "SeaVaultData") {
					t.Fatalf("the note must carry the create-time SeaVaultData guidance; got %q", note)
				}
			} else if note != "" {
				t.Fatalf("root %q must produce no note; got %q", root, note)
			}
		})
	}
}
