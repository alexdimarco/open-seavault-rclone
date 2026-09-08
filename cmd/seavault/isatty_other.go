// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !linux && !darwin && !windows

package main

import "os"

// stdinIsTTY is the portable fallback for GOOSes without a specific terminal
// probe: it uses os.ModeCharDevice, which cannot distinguish /dev/null from a
// terminal but at least rejects pipes and regular files (DOCS-1).
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
