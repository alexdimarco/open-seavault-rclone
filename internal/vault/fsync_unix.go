// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !windows

package vault

import "os"

// fsyncDir flushes a directory's entries to stable storage after a rename, so a
// crash cannot lose the rename while keeping the file's data (design D5.2, P3
// atomicwrite-no-dir-fsync). It is a package var so a test hook can count
// invocations (R10) and assert the durable path is exercised for a chunk and a
// manifest write.
var fsyncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
