// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncput

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

func newTestVault(t *testing.T) *vault.Vault {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	if err := vault.CreateWithOptions(root, "passphrase", vault.CreateOptions{Chunk: vault.DefaultChunkParams(), KDF: vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: 16, ScryptR: 1, ScryptP: 1}}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(root, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAutoFallsBackToNativeWhenRsyncMissing(t *testing.T) {
	v := newTestVault(t)
	src := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(src, []byte("native fallback"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := PutPath(context.Background(), v, src, "docs/source.txt", Options{Method: MethodAuto, RsyncBinary: "definitely-not-rsync-seavault-test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != MethodNative {
		t.Fatalf("expected native fallback, got %q", res.Method)
	}
	paths, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "content/docs/source.txt" {
		t.Fatalf("unexpected paths: %#v", paths)
	}
}

func TestRsyncPutFolder(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not available")
	}
	v := newTestVault(t)
	srcRoot := filepath.Join(t.TempDir(), "source folder")
	if err := os.MkdirAll(filepath.Join(srcRoot, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "nested", "file.txt"), []byte("rsync folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := PutPath(context.Background(), v, srcRoot, "archive", Options{Method: MethodRsync})
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != MethodRsync || len(res.Results) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	paths, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "content/archive/nested/file.txt" {
		t.Fatalf("unexpected paths: %#v", paths)
	}
}

func TestRejectMetadataSource(t *testing.T) {
	v := newTestVault(t)
	src := filepath.Join(v.Root, vault.MetadataDirName, "vault.json")
	// The guard must hold for every method and must not depend on an rsync
	// binary being installed (the CI image has none): strip PATH so a lookup
	// would fail, then expect the metadata rejection, not a lookup error.
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))
	for _, method := range []string{MethodRsync, MethodSystemRsync, MethodManagedRsync, MethodAuto, MethodNative} {
		_, err := PutPath(context.Background(), v, src, "bad/vault.json", Options{Method: method})
		if err == nil || !strings.Contains(err.Error(), ".seavault") {
			t.Fatalf("method %s: expected metadata rejection, got %v", method, err)
		}
	}
	if entries, _ := v.List(); len(entries) != 0 {
		t.Fatalf("metadata source must never be ingested; vault lists %v", entries)
	}
}

// the advisory warning for a foreign metadata-named source
// directory must survive the rsyncput.PutPath wrapper, not be dropped between
// vault.PutPathReport and the Result the CLI prints. The vault layer already
// emits the warning (vault.TestForeignMetadataDirImportedWithWarning); this
// tombstone pins the wrapper so `seavault put` never reports silent success for
// an imported second-vault SeaVaultData / legacy.seavault backup tree. Uses the
// native method so it does not depend on an rsync binary (CI images have none).
func TestForeignMetadataWarningSurvivesPutWrapper(t *testing.T) {
	v := newTestVault(t)
	src := filepath.Join(t.TempDir(), "backup-tree")
	foreign := filepath.Join(src, "SeaVaultData")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "inner.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := PutPath(context.Background(), v, src, "restored", Options{Method: MethodNative})
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "imported as plain content") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the warning must reach the put Result, got Warnings=%#v", res.Warnings)
	}
	//  also promises the file IS imported (never a silent skip): the warning
	// must accompany a real, reachable import, not a refusal.
	paths, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	imported := false
	for _, p := range paths {
		if strings.HasSuffix(p, "restored/SeaVaultData/inner.txt") {
			imported = true
		}
	}
	if !imported {
		t.Fatalf("the foreign metadata dir's file must be imported as plain content; got %#v", paths)
	}
}
