// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclone

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/transport"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

var errCatNotFound = errors.New("directory not found")

func transportOpts() transport.Options { return transport.Options{} }

// scriptedRunner records args and returns a canned response for `cat` (the
// remote vault.json read the identity guard performs) while behaving like the
// plain fake for everything else.
type scriptedRunner struct {
	args   [][]string
	catOut string
	catErr error
}

func (r *scriptedRunner) Run(ctx context.Context, args []string) (string, error) {
	r.args = append(r.args, append([]string(nil), args...))
	if len(args) > 0 && args[0] == "cat" {
		return r.catOut, r.catErr
	}
	return "ok", nil
}
func (r *scriptedRunner) Path() string { return "/managed/rclone" }

func newLocalVaultWithID(t *testing.T, id string) string {
	t.Helper()
	root := t.TempDir()
	meta := filepath.Join(root, vault.MetadataDirName)
	for _, d := range []string{filepath.Join(meta, "objects", "chunks"), filepath.Join(meta, "manifests")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(meta, vault.ConfigFileName), []byte(`{"vaultId":"`+id+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func issuedCopy(args [][]string) bool {
	for _, a := range args {
		for _, tok := range a {
			if tok == "copy" {
				return true
			}
		}
	}
	return false
}

// A push to a remote that already holds a DIFFERENT vault's vault.json must be
// refused BEFORE any copy runs, so the foreign vault's wrapped keys are never
// overwritten.
func TestPushRefusedWhenRemoteHoldsDifferentVault(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	root := newLocalVaultWithID(t, "LOCAL-AAA")
	r := &scriptedRunner{catOut: `{"vaultId":"REMOTE-BBB","wrappedKeys":"c2VjcmV0"}`}
	b := NewWithRunner(remotes.DefaultProfile("remote", root, "remote:bucket", "s3"), r)

	res, err := b.Push(context.Background(), transportOpts())
	if err == nil {
		t.Fatal("push onto a different remote vault must fail")
	}
	if res.OK {
		t.Fatalf("result must not be OK: %+v", res)
	}
	if issuedCopy(r.args) {
		t.Fatalf("no copy may run once the guard refuses: %v", r.args)
	}
	if !strings.Contains(res.Error, "REMOTE-BBB") || !strings.Contains(res.Error, "LOCAL-AAA") {
		t.Fatalf("error must name both vault ids: %q", res.Error)
	}
}

func TestPullRefusedWhenRemoteHoldsDifferentVault(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	root := newLocalVaultWithID(t, "LOCAL-AAA")
	r := &scriptedRunner{catOut: `{"vaultId":"REMOTE-BBB"}`}
	b := NewWithRunner(remotes.DefaultProfile("remote", root, "remote:bucket", "s3"), r)

	_, err := b.Pull(context.Background(), transportOpts())
	if err == nil {
		t.Fatal("pull from a different remote vault must fail")
	}
	if issuedCopy(r.args) {
		t.Fatalf("no copy may run once the guard refuses: %v", r.args)
	}
}

// Same vault id: the sync proceeds and the copy sequence runs.
func TestPushProceedsWhenRemoteMatches(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	root := newLocalVaultWithID(t, "LOCAL-AAA")
	r := &scriptedRunner{catOut: `{"vaultId":"LOCAL-AAA"}`}
	b := NewWithRunner(remotes.DefaultProfile("remote", root, "remote:bucket", "s3"), r)

	res, err := b.Push(context.Background(), transportOpts())
	if err != nil {
		t.Fatalf("matching vault must push: %v", err)
	}
	if !res.OK || !issuedCopy(r.args) {
		t.Fatalf("expected a successful copy push: ok=%v args=%v", res.OK, r.args)
	}
}

// First push: the remote has no vault.json yet (cat errors), so the guard must
// let the push proceed rather than block the very first upload.
func TestPushProceedsWhenRemoteHasNoConfigYet(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	root := newLocalVaultWithID(t, "LOCAL-AAA")
	r := &scriptedRunner{catErr: errCatNotFound}
	b := NewWithRunner(remotes.DefaultProfile("remote", root, "remote:bucket", "s3"), r)

	res, err := b.Push(context.Background(), transportOpts())
	if err != nil {
		t.Fatalf("first push (no remote config) must proceed: %v", err)
	}
	if !res.OK || !issuedCopy(r.args) {
		t.Fatalf("expected the first push to copy: ok=%v args=%v", res.OK, r.args)
	}
}
