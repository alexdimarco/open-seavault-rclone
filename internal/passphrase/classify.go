// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package passphrase

import (
	"errors"
	"regexp"
)

// ErrNoHiddenInput is returned when the current terminal cannot suppress echo of
// typed input and so cannot safely read a password. The message names the safe
// alternatives (P2 win-passphrase-echo-nonconsole).
var ErrNoHiddenInput = errors.New("this terminal cannot hide typed input; use Windows Terminal, PowerShell, winpty, or set SEAVAULT_PASSWORD")

// stdinMode is the decision produced by classifyStdin: how Read should obtain a
// password given what stdin turned out to be.
type stdinMode int

const (
	// stdinConsole: GetConsoleMode succeeded — read from the console with the
	// echo bit cleared, exactly as before (the design step 1).
	stdinConsole stdinMode = iota
	// stdinReadLine: stdin is a data pipe or a file (or an unrecognised type) —
	// read a line so `echo pw | seavault` keeps working. For an unrecognised
	// pseudo-terminal that presents as an anonymous pipe this may echo;
	// documents the residual and names the safe alternatives.
	stdinReadLine
	// stdinRefuse: stdin is a recognised mintty/cygwin pty that would echo —
	// refuse with ErrNoHiddenInput (the design step 2).
	stdinRefuse
	// stdinTryConin: stdin is a console-class handle whose GetConsoleMode failed
	// — try to open CONIN$ directly and, failing that, refuse (step 4).
	stdinTryConin
)

// Windows GetFileType return values (winbase.h).
const (
	fileTypeUnknown uint32 = 0x0000
	fileTypeDisk    uint32 = 0x0001
	fileTypeChar    uint32 = 0x0002
	fileTypePipe    uint32 = 0x0003
)

// minttyPipe matches the named-pipe names mintty/Cygwin/MSYS2 use for a pty,
// e.g. `\msys-1888ae32e00d56aa-pty0-to-master`. Such a pipe echoes typed input,
// so a password read over it is refused. This is a denylist: a
// pseudo-terminal that presents stdin as an unnamed pipe, or under a future
// naming, is not matched and will read (and may echo) — a conceded residual.
var minttyPipe = regexp.MustCompile(`(?i)(msys|cygwin)-.*-pty\d+-`)

// classifyStdin is the pure decision of the design, factored out of the
// Windows-only syscall probing so it can be table-tested on every OS. Given
// whether GetConsoleMode succeeded, the GetFileType class of stdin, and (for a
// pipe) its name, it returns how Read should proceed.
func classifyStdin(consoleOK bool, fileType uint32, pipeName string) stdinMode {
	if consoleOK {
		return stdinConsole
	}
	switch fileType {
	case fileTypePipe:
		if minttyPipe.MatchString(pipeName) {
			return stdinRefuse
		}
		return stdinReadLine
	case fileTypeChar:
		return stdinTryConin
	default: // fileTypeDisk, fileTypeUnknown, or anything else: treat as data.
		return stdinReadLine
	}
}
