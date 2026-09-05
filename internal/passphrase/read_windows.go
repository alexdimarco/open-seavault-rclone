// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package passphrase

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	enableEchoInput   = 0x0004
	fileNameInfoClass = 2 // FILE_INFO_BY_HANDLE_CLASS.FileNameInfo
	genericRead       = 0x80000000
	genericWrite      = 0x40000000
	fileShareRead     = 0x00000001
	fileShareWrite    = 0x00000002
	openExisting      = 3
	stdInputHandle    = ^uintptr(10) + 1 // STD_INPUT_HANDLE = -10 as an unsigned DWORD
)

var (
	kernel32                         = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle                 = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode               = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode               = kernel32.NewProc("SetConsoleMode")
	procGetFileType                  = kernel32.NewProc("GetFileType")
	procGetFileInformationByHandleEx = kernel32.NewProc("GetFileInformationByHandleEx")
	procCreateFileW                  = kernel32.NewProc("CreateFileW")
)

// setConsoleMode is the exec seam a windows-tagged test overrides to assert the
// mode Read applies (ENABLE_ECHO_INPUT cleared) and that the original mode is
// restored afterwards.
var setConsoleMode = func(handle uintptr, mode uint32) error {
	ret, _, err := procSetConsoleMode.Call(handle, uintptr(mode))
	if ret == 0 {
		return err
	}
	return nil
}

func getConsoleMode(handle uintptr) (uint32, bool) {
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	return mode, ret != 0
}

func stdinHandle() uintptr {
	h, _, _ := procGetStdHandle.Call(stdInputHandle)
	return h
}

func stdinFileType(handle uintptr) uint32 {
	t, _, _ := procGetFileType.Call(handle)
	return uint32(t)
}

// stdinPipeName returns the object name of a named-pipe handle via
// GetFileInformationByHandleEx(FileNameInfo), or "" for an anonymous pipe or on
// any failure. The name is what classifyStdin matches against the mintty pattern.
func stdinPipeName(handle uintptr) string {
	buf := make([]byte, 4+2*1024) // FileNameLength (uint32) + up to 1024 UTF-16 code units
	ret, _, _ := procGetFileInformationByHandleEx.Call(handle, uintptr(fileNameInfoClass), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if ret == 0 {
		return ""
	}
	nameBytes := *(*uint32)(unsafe.Pointer(&buf[0]))
	n := int(nameBytes) / 2
	if n <= 0 {
		return ""
	}
	if 4+int(nameBytes) > len(buf) {
		n = (len(buf) - 4) / 2
	}
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[4])), n))
}

// withEchoDisabled clears ENABLE_ECHO_INPUT on the console handle through the
// setConsoleMode seam, runs fn, then restores the original mode. Factoring it out
// lets a windows-tagged test assert the echo bit is cleared on the way in and the
// original mode is restored on the way out.
func withEchoDisabled(handle uintptr, oldMode uint32, fn func() (string, error)) (string, error) {
	if err := setConsoleMode(handle, oldMode&^enableEchoInput); err != nil {
		return "", err
	}
	defer setConsoleMode(handle, oldMode)
	return fn()
}

func readLine(f *os.File) (string, error) {
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return password, nil
}

// Read prompts on stderr and reads a password from stdin without echoing typed
// characters where the platform allows it. The decision of how to
// read is the pure classifyStdin; the syscall probing here only feeds it.
func Read(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)

	handle := stdinHandle()
	oldMode, consoleOK := getConsoleMode(handle)
	var ft uint32
	var pipe string
	if !consoleOK {
		ft = stdinFileType(handle)
		if ft == fileTypePipe {
			pipe = stdinPipeName(handle)
		}
	}
	switch classifyStdin(consoleOK, ft, pipe) {
	case stdinConsole:
		return withEchoDisabled(handle, oldMode, func() (string, error) { return readLine(os.Stdin) })
	case stdinReadLine:
		return readLine(os.Stdin)
	case stdinRefuse:
		return "", ErrNoHiddenInput
	case stdinTryConin:
		return readFromConin()
	default:
		return "", ErrNoHiddenInput
	}
}

// readFromConin opens the console input device (CONIN$) directly and reads a line
// with echo disabled — the fallback when stdin is a console-class handle whose
// GetConsoleMode failed (the design step 4). Any failure along the way becomes
// ErrNoHiddenInput rather than an echoing read.
func readFromConin() (string, error) {
	name, err := syscall.UTF16PtrFromString("CONIN$")
	if err != nil {
		return "", ErrNoHiddenInput
	}
	h, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(genericRead|genericWrite),
		uintptr(fileShareRead|fileShareWrite),
		0,
		uintptr(openExisting),
		0,
		0,
	)
	if h == 0 || h == uintptr(syscall.InvalidHandle) {
		return "", ErrNoHiddenInput
	}
	oldMode, ok := getConsoleMode(h)
	if !ok {
		syscall.CloseHandle(syscall.Handle(h))
		return "", ErrNoHiddenInput
	}
	f := os.NewFile(h, "CONIN$")
	if f == nil {
		syscall.CloseHandle(syscall.Handle(h))
		return "", ErrNoHiddenInput
	}
	defer f.Close()
	return withEchoDisabled(h, oldMode, func() (string, error) { return readLine(f) })
}
