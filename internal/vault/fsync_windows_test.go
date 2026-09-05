// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package vault

import (
	"path/filepath"
	"testing"
)

// R10 (windows leg, compile-only in CI): fsyncDir is a no-op that never errors,
// even for a directory that does not exist — Windows has no directory-flush
// primitive (design D5.2). Runs on the manual Windows drill.
func TestFsyncDirIsNoOpOnWindows(t *testing.T) {
	if err := fsyncDir(t.TempDir()); err != nil {
		t.Fatalf("windows fsyncDir must be a no-op, got %v", err)
	}
	if err := fsyncDir(filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Fatalf("windows fsyncDir must be a no-op even for a missing dir, got %v", err)
	}
}
