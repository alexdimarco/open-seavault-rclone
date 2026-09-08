// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestProfileSavePermsForcedOnPreexistingFile (review wordlist-labels-2, sibling
// writer): profiles.json shares the device-local perm hardening — Save must force
// 0600 on the file and 0700 on the config dir even over a pre-existing 0644 file,
// because os.WriteFile/os.MkdirAll only apply a mode on creation. Unix-only, as
// os.Chmod on Windows only toggles the read-only bit.
func TestProfileSavePermsForcedOnPreexistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits are not represented on Windows")
	}
	isolateLabelHome(t)
	p, err := ConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o644 {
		t.Fatalf("precondition: profiles.json must start 0644, got %o", fi.Mode().Perm())
	}

	if err := Save(Store{Version: 1, Profiles: []Entry{{Name: "x", VaultPath: "/tmp/x"}}}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("profiles.json must be forced to 0600 after a save over a pre-existing file, got %o", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("the config dir must be forced to 0700, got %o", di.Mode().Perm())
	}
}
