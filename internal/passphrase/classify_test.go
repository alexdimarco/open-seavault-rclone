// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package passphrase

import "testing"

// TestClassifyStdin is the table half of R16 (design D8.2), asserted on every OS.
// Each row pins how Read must treat a given stdin: a live console reads with echo
// suppressed; a recognised mintty/cygwin pty is refused; a data pipe or file (or
// an unrecognised type) is read as a line; a console-class handle whose console
// mode could not be read falls back to CONIN$.
func TestClassifyStdin(t *testing.T) {
	cases := []struct {
		name      string
		consoleOK bool
		fileType  uint32
		pipeName  string
		want      stdinMode
	}{
		{"console ok", true, fileTypeChar, "", stdinConsole},
		{"console ok ignores filetype", true, fileTypePipe, `\msys-x-pty0-to-master`, stdinConsole},
		{"mintty msys pty", false, fileTypePipe, `\msys-1888ae32e00d56aa-pty0-to-master`, stdinRefuse},
		{"cygwin pty", false, fileTypePipe, `\cygwin-abc123def456-pty3-from-master`, stdinRefuse},
		{"anonymous pipe", false, fileTypePipe, "", stdinReadLine},
		{"unrecognised named pipe", false, fileTypePipe, `\Device\NamedPipe\rclone-mount-42`, stdinReadLine},
		{"disk file", false, fileTypeDisk, "", stdinReadLine},
		{"unknown type", false, fileTypeUnknown, "", stdinReadLine},
		{"console no mode", false, fileTypeChar, "", stdinTryConin},
	}
	for _, tc := range cases {
		if got := classifyStdin(tc.consoleOK, tc.fileType, tc.pipeName); got != tc.want {
			t.Errorf("%s: classifyStdin(%v,%#x,%q) = %d, want %d", tc.name, tc.consoleOK, tc.fileType, tc.pipeName, got, tc.want)
		}
	}
}

// TestMinttyPipePattern guards the denylist boundary: a pty name matches, and a
// plain application pipe or a name lacking the -ptyN- token does not.
func TestMinttyPipePattern(t *testing.T) {
	match := []string{
		`\msys-1888ae32e00d56aa-pty0-to-master`,
		`\cygwin-0-pty12-from-master`,
		`MSYS-DEAD-PTY7-TO-MASTER`,
	}
	for _, s := range match {
		if !minttyPipe.MatchString(s) {
			t.Errorf("minttyPipe should match %q", s)
		}
	}
	noMatch := []string{
		"",
		`\Device\NamedPipe\app-socket`,
		`\msys-1888-terminal`, // no -ptyN- token
		`pty0`,
	}
	for _, s := range noMatch {
		if minttyPipe.MatchString(s) {
			t.Errorf("minttyPipe should not match %q", s)
		}
	}
}
