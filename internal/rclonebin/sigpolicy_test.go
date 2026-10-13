// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import "testing"

// An EMPTY signature mode (what an unset CLI flag now passes) must resolve to the
// policy file's mode, and an explicit mode must still win.
func TestSignatureModeEmptyResolvesToPolicy(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	pol := DefaultPolicy()
	pol.SignatureMode = "required"
	if err := SavePolicy(pol); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ in, want string }{
		{"", "required"},
		{"   ", "required"},
		{"optional", "optional"},
		{"REQUIRED", "required"},
		{"skip", "skip"},
	}
	for _, r := range rows {
		if got := signatureMode(r.in); got != r.want {
			t.Errorf("signatureMode(%q) = %q, want %q", r.in, got, r.want)
		}
	}
}
