// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// stdinIsTTY reports whether standard input is a real terminal by attempting the
// terminal-attributes ioctl (TCGETS): it succeeds only on a tty, so a pipe, a
// regular file, and /dev/null (a character device that os.ModeCharDevice alone
// would misclassify as interactive) all correctly report false. This is what
// `recovery generate`'s interactive-only gate (DOCS-1) needs so a redirected run
// cannot capture a freshly minted phrase.
func stdinIsTTY() bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
