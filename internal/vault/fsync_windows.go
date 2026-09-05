// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package vault

// fsyncDir is a no-op on Windows: there is no portable primitive to flush a
// directory handle the way FlushFileBuffers flushes a file, and NTFS metadata
// durability is handled by the filesystem journal. It stays a package var so the
// windows-tagged test can wrap it.
var fsyncDir = func(dir string) error { return nil }
