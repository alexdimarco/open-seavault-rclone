// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build linux

package keychain

import (
	"os"
	"os/exec"
)

// Check returns the Linux Secret Service dependency state without reading any vault secret.
func Check() Status {
	st := Status{Backend: "Linux Secret Service"}
	if _, err := exec.LookPath("secret-tool"); err != nil {
		st.Summary = "Keychain unavailable"
		st.Detail = "Install libsecret-tools so SeaVault can use secret-tool for OS keychain access."
		st.Missing = append(st.Missing, "secret-tool")
		return st
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		st.Summary = "Keychain may be unavailable"
		st.Detail = "secret-tool is installed, but DBUS_SESSION_BUS_ADDRESS is not set. Start a desktop session with a DBus user bus, or install and enable dbus-user-session plus a keyring such as gnome-keyring or KWallet."
		st.Missing = append(st.Missing, "DBUS_SESSION_BUS_ADDRESS")
		return st
	}
	st.Available = true
	st.Summary = "Keychain available"
	st.Detail = "secret-tool and the DBus session bus were detected."
	return st
}
