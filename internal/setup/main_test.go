// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"os"
	"testing"
)

// TestMain isolates the profile/keychain app-data store for the whole setup
// test package. Plan.Validate now reads the profile store (a side-effect-free
// collision check, profile-collision-orphan), so every test that reaches
// Validate — directly or through Execute — must resolve against a controlled,
// empty store rather than the developer's or CI runner's real one. Tests that
// need their OWN store still override SEAVAULT_APP_HOME with t.Setenv; that
// override restores to this shared temp dir afterwards. Nothing here writes to
// the store, so the shared default stays empty and no test collides with
// another.
func TestMain(m *testing.M) {
	if _, set := os.LookupEnv("SEAVAULT_APP_HOME"); !set {
		dir, err := os.MkdirTemp("", "setup-pkg-apphome-")
		if err != nil {
			panic(err)
		}
		if err := os.Setenv("SEAVAULT_APP_HOME", dir); err != nil {
			panic(err)
		}
		code := m.Run()
		_ = os.RemoveAll(dir)
		os.Exit(code)
	}
	os.Exit(m.Run())
}
