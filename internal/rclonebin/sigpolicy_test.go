// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import "testing"

// signatureMode resolves what a caller asked for against policy.json:
//   - an empty request takes the policy's mode;
//   - a policy of "required" is a FLOOR: no request (CLI flag, GUI select) can
//     weaken it to optional or skip;
//   - an unknown mode, in a request or in the policy file, fails CLOSED to
//     "required" (a typo such as "requird" used to behave as optional).
func TestSignatureModeResolution(t *testing.T) {
	rows := []struct {
		name   string
		policy string
		in     string
		want   string
	}{
		{"required policy, empty request", "required", "", "required"},
		{"required policy, blank request", "required", "   ", "required"},
		{"required policy cannot be weakened to optional", "required", "optional", "required"},
		{"required policy cannot be weakened to skip", "required", "skip", "required"},
		{"required policy, upper-case request", "required", "REQUIRED", "required"},
		{"optional policy, empty request", "optional", "", "optional"},
		{"optional policy, request can tighten", "optional", "required", "required"},
		{"optional policy, request may skip", "optional", "skip", "skip"},
		{"optional policy, typo in request fails closed", "optional", "requird", "required"},
		{"no policy mode set, empty request", "", "", "optional"},
		{"typo in the policy file fails closed", "requird", "", "required"},
		{"typo in the policy file, explicit skip still closed", "requird", "skip", "required"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
			pol := DefaultPolicy()
			pol.SignatureMode = r.policy
			if err := SavePolicy(pol); err != nil {
				t.Fatal(err)
			}
			// LoadPolicy defaults an empty mode to "optional" itself; the row above
			// ("no policy mode set") pins that the end result is still optional.
			if got := signatureMode(r.in); got != r.want {
				t.Errorf("policy=%q signatureMode(%q) = %q, want %q", r.policy, r.in, got, r.want)
			}
		})
	}
}
