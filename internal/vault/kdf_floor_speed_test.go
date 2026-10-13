// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import "testing"

// Package-wide: rewraps in this suite use the tiny FastKDFConfigForTests, and
// raiseToFloor would lift every one to the production floor (scrypt 32768x8,
// ~32 MiB), which took the -race run of this package from ~23 s to ~400 s. Switch
// the floor off for the suite and have the tests that are ABOUT the floor switch
// it back on with requireRewrapFloor.
func init() { enforceRewrapFloor = false }

// requireRewrapFloor turns the production rewrap floor on for one test.
func requireRewrapFloor(t *testing.T) {
	t.Helper()
	enforceRewrapFloor = true
	t.Cleanup(func() { enforceRewrapFloor = false })
}

// Guards the guard: if the production default ever becomes false, or the switch is
// left off by mistake, the floor tests below would pass vacuously.
func TestRewrapFloorSwitchDefaultsOnInProduction(t *testing.T) {
	requireRewrapFloor(t)
	if !enforceRewrapFloor {
		t.Fatal("requireRewrapFloor did not enable the floor")
	}
	weak := FastKDFConfigForTests()
	weak.Salt = "AAAA"
	got, err := raiseToFloor(weak)
	if err != nil {
		t.Fatal(err)
	}
	n, nerr := NormalizeKDFConfig(got, true)
	if nerr != nil || ValidateKDFStrength(n) != nil {
		t.Fatalf("with the switch on a weak config must be raised to the floor: %v / %v", nerr, ValidateKDFStrength(n))
	}
}
