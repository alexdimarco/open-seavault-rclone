// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"os"
	"testing"
)

// TestMain isolates the app-data directory for the whole vault test package.
//
// Open now resolves a device id from appdir.DataDir (design D4.1, the vector
// clock's writer key), and the freshness anchor / gc-seen stores live there too.
// Without isolation those would land in the developer's (and CI's) real home on
// every vault open. Redirecting SEAVAULT_APP_HOME to a throwaway dir keeps the
// package hermetic; individual tests that need a fresh device or a distinct
// anchor still override it with t.Setenv, which restores this default afterwards.
func TestMain(m *testing.M) {
	os.Exit(runWithIsolatedAppHome(m))
}

func runWithIsolatedAppHome(m *testing.M) int {
	if _, set := os.LookupEnv("SEAVAULT_APP_HOME"); !set {
		dir, err := os.MkdirTemp("", "seavault-vault-test-home-")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		if err := os.Setenv("SEAVAULT_APP_HOME", dir); err != nil {
			panic(err)
		}
	}
	return m.Run()
}
