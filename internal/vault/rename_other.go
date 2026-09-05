// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !windows

package vault

// isRetryableRenameError reports whether a failed rename should be retried.
// POSIX rename(2) does not raise the transient sharing-violation errors that
// Windows does, so no rename error is worth retrying here: renameWithRetry runs
// a single attempt and behaves as plain os.Rename (design D5.1).
func isRetryableRenameError(err error) bool { return false }
