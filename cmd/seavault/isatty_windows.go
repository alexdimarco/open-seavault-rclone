// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var procGetConsoleModeStdin = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleMode")

// stdinIsTTY reports whether standard input is a console handle: GetConsoleMode
// succeeds only for a real console, so a pipe or redirected file reports false —
// what `recovery generate`'s interactive-only gate (DOCS-1) needs. It mirrors the
// console detection internal/passphrase already uses on Windows.
func stdinIsTTY() bool {
	var mode uint32
	ret, _, _ := procGetConsoleModeStdin.Call(os.Stdin.Fd(), uintptr(unsafe.Pointer(&mode)))
	return ret != 0
}
