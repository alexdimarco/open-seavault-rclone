// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"os"
	"time"
)

// Durable rename with a Windows retry loop (design phase-a1-vault-core D5.1,
// P1-9 atomicwrite-rename-no-retry-windows).
//
// On Windows a concurrent reader — a sync client, an antivirus scanner, another
// open handle — makes os.Rename fail transiently with ERROR_SHARING_VIOLATION,
// ERROR_ACCESS_DENIED or ERROR_LOCK_VIOLATION; the write is safe to retry after
// a short backoff. On every other OS a failed rename is returned immediately:
// POSIX rename(2) replaces the destination atomically and does not raise those
// transient sharing errors, so isRetryableRenameError reports false there and
// this loop runs exactly one attempt — i.e. plain os.Rename (rename_other.go).
//
// renameFn, renameSleep and renameRetryable are package vars so a portable test
// can drive the retry loop on any OS: it injects a renameFn that returns a fake
// sharing violation for the first N-1 attempts, a renameSleep that records the
// backoff without waiting, and a renameRetryable that recognises the fake error.
var (
	renameFn        = os.Rename
	removeFn        = os.Remove
	renameSleep     = time.Sleep
	renameRetryable = isRetryableRenameError
)

const (
	renameAttempts     = 10
	renameBackoffStart = 25 * time.Millisecond
	renameBackoffCap   = 400 * time.Millisecond
)

func renameWithRetry(oldpath, newpath string) error {
	backoff := renameBackoffStart
	var err error
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if err = renameFn(oldpath, newpath); err == nil {
			return nil
		}
		if !renameRetryable(err) {
			return err
		}
		if attempt == renameAttempts-1 {
			break
		}
		renameSleep(backoff)
		if backoff *= 2; backoff > renameBackoffCap {
			backoff = renameBackoffCap
		}
	}
	return err
}

// removeWithRetry deletes a file with the same Windows sharing-violation retry
// as renameWithRetry (design D5.1/D4.4): Compact removes superseded manifests and
// sweeps orphaned temp files, and on Windows a concurrent reader (sync client,
// antivirus) can make os.Remove fail transiently with the same errno set. An
// already-absent file is success, so Compact is idempotent and crash-safe. On
// non-Windows OSes renameRetryable reports false and this is one os.Remove.
func removeWithRetry(path string) error {
	backoff := renameBackoffStart
	var err error
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if err = removeFn(path); err == nil || os.IsNotExist(err) {
			return nil
		}
		if !renameRetryable(err) {
			return err
		}
		if attempt == renameAttempts-1 {
			break
		}
		renameSleep(backoff)
		if backoff *= 2; backoff > renameBackoffCap {
			backoff = renameBackoffCap
		}
	}
	return err
}
