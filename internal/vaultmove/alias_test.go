// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vaultmove

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// Move compared source and destination as path STRINGS, so any other spelling of
// the same directory slipped past the "same path" and "inside source" checks;
// with Replace, prepareDestination then RemoveAll'd the destination - the
// source vault itself.

func newAliasVault(t *testing.T) (root, src string) {
	t.Helper()
	root = t.TempDir()
	src = filepath.Join(root, "Vault")
	if err := vault.Create(src, "passphrase", vault.DefaultChunkParams()); err != nil {
		t.Fatal(err)
	}
	return root, src
}

func requireVaultIntact(t *testing.T, src string) {
	t.Helper()
	if _, err := vault.ReadConfig(src); err != nil {
		t.Fatalf("the source vault was destroyed or damaged: %v", err)
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
}

func TestMoveReplaceRefusesSymlinkToSource(t *testing.T) {
	root, src := newAliasVault(t)
	link := filepath.Join(root, "link")
	symlinkOrSkip(t, src, link)

	for _, replace := range []bool{false, true} {
		if _, err := Move(src, link, Options{Replace: replace}); err == nil {
			t.Fatalf("Move to a symlink of the source (replace=%v) must fail", replace)
		}
		requireVaultIntact(t, src)
	}
}

func TestMoveReplaceRefusesDestinationThroughSymlinkedParent(t *testing.T) {
	root, src := newAliasVault(t)
	alias := filepath.Join(t.TempDir(), "alias")
	symlinkOrSkip(t, root, alias)

	// alias/Vault is the source reached through a symlinked parent.
	if _, err := Move(src, filepath.Join(alias, "Vault"), Options{Replace: true}); err == nil {
		t.Fatal("Move onto the source via a symlinked parent must fail")
	}
	requireVaultIntact(t, src)
}

func TestMoveRefusesDestinationInsideSourceViaSymlink(t *testing.T) {
	root, src := newAliasVault(t)
	link := filepath.Join(root, "link")
	symlinkOrSkip(t, src, link)

	if _, err := Move(src, filepath.Join(link, "child"), Options{}); err == nil {
		t.Fatal("a destination inside the source, spelled through a symlink, must fail")
	}
	requireVaultIntact(t, src)
}

func TestMoveReplaceRefusesCaseVariantOfSource(t *testing.T) {
	root, src := newAliasVault(t)
	variant := filepath.Join(root, strings.ToLower(filepath.Base(src)))
	if _, err := os.Stat(variant); err != nil {
		t.Skip("filesystem is case-sensitive; a case variant is a different directory here")
	}
	for _, replace := range []bool{false, true} {
		if _, err := Move(src, variant, Options{Replace: replace}); err == nil {
			t.Fatalf("Move onto a case variant of the source (replace=%v) must fail", replace)
		}
		requireVaultIntact(t, src)
	}
}
