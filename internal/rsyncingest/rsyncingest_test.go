// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncingest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

func fakeRsync(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake rsync script is POSIX-only")
	}
	bin := filepath.Join(t.TempDir(), "rsync")
	script := `#!/usr/bin/env sh
set -eu
if [ "${1:-}" = "--version" ]; then echo 'rsync  version 3.4.1'; exit 0; fi
src=''
dst=''
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    *) src="$dst"; dst="$arg" ;;
  esac
done
if [ -z "$src" ] || [ -z "$dst" ]; then echo 'missing source/destination' >&2; exit 2; fi
mkdir -p "$dst"
case "$src" in
  */) cp -R "$src". "$dst"/ ;;
  *) cp "$src" "$dst"/ ;;
esac
echo "fake rsync copied $src to $dst"
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestPutPathUsesRsyncStagingForDirectory(t *testing.T) {
	rsync := fakeRsync(t)
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	if err := vault.CreateWithOptions(vaultPath, "password", vault.CreateOptions{KDF: vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: 16, ScryptR: 1, ScryptP: 1}}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(vaultPath, "password")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("bravo"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := PutPath(context.Background(), v, src, "", Options{Mode: ModeRsync, RsyncPath: rsync, PreserveRootOnEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Report.UsedRsync || !strings.Contains(strings.Join(res.Report.Command, " "), "rsync") {
		t.Fatalf("expected rsync report, got %#v", res.Report)
	}
	paths, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(paths, "\n")
	if !strings.Contains(got, "content/source/a.txt") || !strings.Contains(got, "content/source/sub/b.txt") {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func TestInvalidModeReturnsError(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	if err := vault.CreateWithOptions(vaultPath, "password", vault.CreateOptions{KDF: vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: 16, ScryptR: 1, ScryptP: 1}}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(vaultPath, "password")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "a.txt")
	if err := os.WriteFile(src, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = PutPath(context.Background(), v, src, "a.txt", Options{Mode: "surprise"})
	if err == nil || !strings.Contains(err.Error(), "unsupported ingest mode") {
		t.Fatalf("expected unsupported mode error, got %v", err)
	}
}

func TestAutoFallsBackToDirectWhenRsyncMissing(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault")
	if err := vault.CreateWithOptions(vaultPath, "password", vault.CreateOptions{KDF: vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: 16, ScryptR: 1, ScryptP: 1}}); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(vaultPath, "password")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "a.txt")
	if err := os.WriteFile(src, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing-rsync")
	t.Setenv("PATH", filepath.Join(root, "empty-path"))
	res, err := PutPath(context.Background(), v, src, "a.txt", Options{Mode: ModeAuto, RsyncPath: missing})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.UsedRsync || !strings.Contains(res.Report.Warning, "direct ingestion fallback") {
		t.Fatalf("expected direct fallback warning, got %#v", res.Report)
	}
	paths, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "content/a.txt" {
		t.Fatalf("unexpected paths: %v", paths)
	}
}
