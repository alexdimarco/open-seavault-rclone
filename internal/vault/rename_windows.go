// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package vault

import (
	"errors"
	"syscall"
)

// Windows error numbers for a destination another handle is still using.
// os.Rename surfaces them as an *os.LinkError wrapping a syscall.Errno.
const (
	errorAccessDenied     = syscall.Errno(5)  // ERROR_ACCESS_DENIED
	errorSharingViolation = syscall.Errno(32) // ERROR_SHARING_VIOLATION
	errorLockViolation    = syscall.Errno(33) // ERROR_LOCK_VIOLATION
)

// isRetryableRenameError reports whether a failed rename is a transient Windows
// sharing conflict worth retrying (design D5.1).
func isRetryableRenameError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case errorAccessDenied, errorSharingViolation, errorLockViolation:
		return true
	default:
		return false
	}
}
