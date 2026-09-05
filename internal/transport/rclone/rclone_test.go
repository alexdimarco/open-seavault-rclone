// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclone

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

type fakeRunner struct{ args [][]string }

func (f *fakeRunner) Run(ctx context.Context, args []string) (string, error) {
	f.args = append(f.args, append([]string(nil), args...))
	return "ok", nil
}

func (f *fakeRunner) Path() string { return "/managed/rclone" }

func TestDryRunPushUsesCopyOnly(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	vaultRoot := t.TempDir()
	meta := filepath.Join(vaultRoot, vault.MetadataDirName)
	for _, d := range []string{filepath.Join(meta, "objects", "chunks"), filepath.Join(meta, "manifests")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(meta, vault.ConfigFileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := remotes.DefaultProfile("remote", vaultRoot, "remote:bucket/path", "s3")
	r := &fakeRunner{}
	b := NewWithRunner(p, r)
	res, err := b.DryRunPush(context.Background())
	if err != nil {
		t.Fatalf("DryRunPush failed: %v", err)
	}
	if !res.DryRun || !res.OK {
		t.Fatalf("unexpected result: %+v", res)
	}
	joined := flatten(r.args)
	if strings.Contains(joined, " sync ") {
		t.Fatalf("dry-run push must not use rclone sync: %s", joined)
	}
	if !strings.Contains(joined, "copy") || !strings.Contains(joined, "--dry-run") {
		t.Fatalf("expected copy with --dry-run: %s", joined)
	}
	if !strings.Contains(joined, vault.MetadataDirName) {
		t.Fatalf("expected remote.seavault path: %s", joined)
	}
}

func flatten(args [][]string) string {
	var parts []string
	for _, a := range args {
		parts = append(parts, strings.Join(a, " "))
	}
	return strings.Join(parts, " | ")
}
