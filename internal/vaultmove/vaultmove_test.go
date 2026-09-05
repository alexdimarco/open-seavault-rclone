// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vaultmove

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

func TestMoveProfileMovesVaultAndUpdatesProfilesAndRemotes(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", filepath.Join(t.TempDir(), "app"))
	root := t.TempDir()
	src := filepath.Join(root, "old-vault")
	dst := filepath.Join(root, "new-vault")
	if err := vault.Create(src, "passphrase", vault.DefaultChunkParams()); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(src, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "a.txt")
	if err := os.WriteFile(plain, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutPath(plain, "docs/a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Add("work", src); err != nil {
		t.Fatal(err)
	}
	if _, err := remotes.Add(remotes.DefaultProfile("remote-work", src, filepath.Join(root, "remote"), "local")); err != nil {
		t.Fatal(err)
	}

	res, err := MoveProfile("work", dst, Options{UpdateRemoteProfiles: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moved {
		t.Fatalf("expected move result: %+v", res)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source still exists or unexpected stat error: %v", err)
	}
	if _, err := vault.ReadConfig(dst); err != nil {
		t.Fatalf("destination is not a vault: %v", err)
	}
	entry, ok, err := profile.Resolve("work")
	if err != nil || !ok {
		t.Fatalf("profile not found: ok=%v err=%v", ok, err)
	}
	if filepath.Clean(entry.VaultPath) != filepath.Clean(dst) {
		t.Fatalf("profile path not updated: %s", entry.VaultPath)
	}
	rp, ok, err := remotes.Get("remote-work")
	if err != nil || !ok {
		t.Fatalf("remote not found: ok=%v err=%v", ok, err)
	}
	if filepath.Clean(rp.Vault) != filepath.Clean(dst) {
		t.Fatalf("remote path not updated: %s", rp.Vault)
	}
	v2, err := vault.Open(dst, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(root, "out.txt")
	if err := v2.GetPath("docs/a.txt", outPath); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Fatalf("unexpected content %q", out)
	}
}

func TestMoveRejectsDestinationInsideSource(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "vault")
	if err := vault.Create(src, "passphrase", vault.DefaultChunkParams()); err != nil {
		t.Fatal(err)
	}
	_, err := Move(src, filepath.Join(src, "child"), Options{})
	if err == nil {
		t.Fatal("expected nested destination error")
	}
}
