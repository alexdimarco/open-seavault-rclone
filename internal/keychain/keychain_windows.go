// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package keychain

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi32       = syscall.NewLazyDLL("Advapi32.dll")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

func target(account string) string { return Service + ":" + account }

func Get(account string) (string, error) {
	targetPtr, err := syscall.UTF16PtrFromString(target(account))
	if err != nil {
		return "", err
	}
	// credPtr receives an OS-allocated pointer from CredReadW. Keep it typed as
	// unsafe.Pointer (not uintptr) so the later struct cast is a Pointer->Pointer
	// conversion; converting a stored uintptr back to a pointer is unsafe and is
	// what `go vet` flags.
	var credPtr unsafe.Pointer
	ret, _, e := procCredRead.Call(uintptr(unsafe.Pointer(targetPtr)), uintptr(credTypeGeneric), 0, uintptr(unsafe.Pointer(&credPtr)))
	if ret == 0 {
		return "", fmt.Errorf("Windows Credential Manager lookup failed: %w", e)
	}
	defer procCredFree.Call(uintptr(credPtr))
	cred := (*credential)(credPtr)
	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return "", fmt.Errorf("Windows Credential Manager returned an empty password")
	}
	blob := unsafe.Slice(cred.CredentialBlob, int(cred.CredentialBlobSize))
	return string(append([]byte(nil), blob...)), nil
}

func Set(account, secret string) error {
	targetPtr, err := syscall.UTF16PtrFromString(target(account))
	if err != nil {
		return err
	}
	userPtr, err := syscall.UTF16PtrFromString(Service)
	if err != nil {
		return err
	}
	blob := []byte(secret)
	if len(blob) == 0 {
		return fmt.Errorf("password must not be empty")
	}
	if len(blob) > 5120 {
		return fmt.Errorf("Windows Credential Manager generic credential limit is 5120 bytes")
	}
	cred := credential{Type: credTypeGeneric, TargetName: targetPtr, CredentialBlobSize: uint32(len(blob)), CredentialBlob: &blob[0], Persist: credPersistLocalMachine, UserName: userPtr}
	ret, _, e := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0)
	if ret == 0 {
		return fmt.Errorf("Windows Credential Manager store failed: %w", e)
	}
	return nil
}

func Delete(account string) error {
	targetPtr, err := syscall.UTF16PtrFromString(target(account))
	if err != nil {
		return err
	}
	ret, _, e := procCredDelete.Call(uintptr(unsafe.Pointer(targetPtr)), uintptr(credTypeGeneric), 0)
	if ret == 0 {
		return fmt.Errorf("Windows Credential Manager delete failed: %w", e)
	}
	return nil
}
