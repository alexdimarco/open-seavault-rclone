// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build darwin

package keychain

import "os/exec"

// Check returns the macOS Keychain dependency state without reading any vault secret.
func Check() Status {
	st := Status{Backend: "macOS Keychain"}
	if _, err := exec.LookPath("security"); err != nil {
		st.Summary = "Keychain unavailable"
		st.Detail = "The macOS security command was not found. SeaVault cannot use Keychain from this environment."
		st.Missing = append(st.Missing, "security")
		return st
	}
	st.Available = true
	st.Summary = "Keychain available"
	st.Detail = "The macOS security command was detected."
	return st
}
