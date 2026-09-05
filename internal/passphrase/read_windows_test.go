// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package passphrase

import "testing"

// TestWithEchoDisabledClearsAndRestores is the windows-tagged half of: the
// console read path clears ENABLE_ECHO_INPUT before reading and restores the
// original console mode afterwards. It drives the setConsoleMode
// seam so no real console is needed; it runs only on the manual Windows job.
func TestWithEchoDisabledClearsAndRestores(t *testing.T) {
	orig := setConsoleMode
	defer func() { setConsoleMode = orig }()

	var modes []uint32
	setConsoleMode = func(handle uintptr, mode uint32) error {
		modes = append(modes, mode)
		return nil
	}

	const oldMode uint32 = enableEchoInput | 0x0002 // ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT
	got, err := withEchoDisabled(0x1234, oldMode, func() (string, error) { return "secret", nil })
	if err != nil {
		t.Fatalf("withEchoDisabled: %v", err)
	}
	if got != "secret" {
		t.Fatalf("returned %q, want the fn result", got)
	}
	if len(modes) != 2 {
		t.Fatalf("setConsoleMode called %d times, want 2 (clear then restore)", len(modes))
	}
	if modes[0]&enableEchoInput != 0 {
		t.Errorf("first setConsoleMode mode %#x still has ENABLE_ECHO_INPUT set", modes[0])
	}
	if modes[0] != oldMode&^enableEchoInput {
		t.Errorf("cleared mode = %#x, want %#x", modes[0], oldMode&^enableEchoInput)
	}
	if modes[1] != oldMode {
		t.Errorf("restored mode = %#x, want original %#x", modes[1], oldMode)
	}
}
