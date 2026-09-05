// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !linux && !darwin && !windows

package keychain

// Check returns an unsupported status for platforms without a keychain implementation.
func Check() Status {
	return Status{Backend: "unsupported", Summary: "Keychain unavailable", Detail: "SeaVault does not support OS keychain storage on this platform.", Missing: []string{"supported OS keychain backend"}}
}
