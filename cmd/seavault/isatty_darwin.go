// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// stdinIsTTY reports whether standard input is a real terminal via the
// terminal-attributes ioctl (TIOCGETA on Darwin); see the linux variant for the
// rationale (DOCS-1). A pipe, a file, and /dev/null all report false.
func stdinIsTTY() bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TIOCGETA, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
