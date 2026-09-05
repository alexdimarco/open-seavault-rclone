// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package vault

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// R9 (windows leg, compile-only in CI): the errno classifier retries exactly the
// three transient sharing errors and nothing else (design D5.1). Runs on the
// manual Windows drill.
func TestIsRetryableRenameErrorClassifiesWindowsErrnos(t *testing.T) {
	retry := []syscall.Errno{errorAccessDenied, errorSharingViolation, errorLockViolation}
	for _, e := range retry {
		if !isRetryableRenameError(&os.LinkError{Op: "rename", Err: e}) {
			t.Fatalf("errno %d should be retryable", int(e))
		}
		if !isRetryableRenameError(e) {
			t.Fatalf("bare errno %d should be retryable", int(e))
		}
	}
	notRetry := []error{
		nil,
		errors.New("generic"),
		syscall.Errno(2), // ERROR_FILE_NOT_FOUND
		&os.LinkError{Op: "rename", Err: syscall.Errno(3)},
	}
	for _, e := range notRetry {
		if isRetryableRenameError(e) {
			t.Fatalf("error %v should NOT be retryable", e)
		}
	}
}
