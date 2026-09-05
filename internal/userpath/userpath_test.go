// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package userpath

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAbsExpandsHome(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
		t.Setenv("HOMEDRIVE", "")
		t.Setenv("HOMEPATH", "")
	} else {
		t.Setenv("HOME", home)
	}
	got, err := Abs("~/Nextcloud/seavault")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Nextcloud", "seavault")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestValidateSlashUserPathGivesClearError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only path shape")
	}
	err := ValidateCreatableVaultPath("/user/alex/Nextcloud/seavault")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "/Users/<name>") || !strings.Contains(msg, "/home/<name>") {
		t.Fatalf("unexpected error: %s", msg)
	}
}

func TestValidateAllowsPathBelowExistingParent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Nextcloud", "seavault")
	if err := ValidateCreatableVaultPath(root); err != nil {
		t.Fatal(err)
	}
}
