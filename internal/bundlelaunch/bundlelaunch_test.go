// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package bundlelaunch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestActiveAndFinderLaunch (M1 / §2.1 / I-M3): every branch of the darwin-only
// bundle-launch detection, driven off a Mac through injected goos / env /
// executable-path values. Each row asserts; an empty table would fail the row
// count guard below.
func TestActiveAndFinderLaunch(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvBundleLaunch {
				return v
			}
			return ""
		}
	}
	const macExec = "/Applications/open-seavault-rclone.app/Contents/MacOS/open-seavault-rclone"
	const plainExec = "/usr/local/bin/seavault"

	rows := []struct {
		name       string
		goos       string
		env        string
		exec       string
		argv       []string
		wantActive bool
		wantFinder bool
	}{
		{"darwin env, no args", "darwin", "1", plainExec, nil, true, true},
		{"darwin exec-path, no args", "darwin", "", macExec, []string{}, true, true},
		{"darwin env, only -psn_ arg", "darwin", "1", plainExec, []string{"-psn_0_12345"}, true, true},
		{"darwin exec-path, only -psn_ arg", "darwin", "", macExec, []string{"-psn_0_98765"}, true, true},
		{"darwin env, but a real arg", "darwin", "1", plainExec, []string{"list"}, true, false},
		{"darwin env, -psn_ plus a real arg", "darwin", "1", plainExec, []string{"-psn_0_1", "list"}, true, false},
		{"darwin, neither env nor path, no args", "darwin", "", plainExec, nil, false, false},
		{"linux env ignored, no args", "linux", "1", plainExec, nil, false, false},
		{"linux exec-path ignored", "linux", "", macExec, nil, false, false},
		{"windows env ignored", "windows", "1", plainExec, nil, false, false},
	}
	seen := 0
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			seen++
			if got := Active(r.goos, env(r.env), r.exec); got != r.wantActive {
				t.Fatalf("Active(%q, env=%q, %q) = %v, want %v", r.goos, r.env, r.exec, got, r.wantActive)
			}
			if got := FinderLaunch(r.goos, env(r.env), r.exec, r.argv); got != r.wantFinder {
				t.Fatalf("FinderLaunch(%q, env=%q, %q, %v) = %v, want %v", r.goos, r.env, r.exec, r.argv, got, r.wantFinder)
			}
		})
	}
	if seen != len(rows) {
		t.Fatalf("ran %d rows, expected %d (the table must not be vacuous)", seen, len(rows))
	}
}

// TestOnlyFinderArgs pins the argument gate directly.
func TestOnlyFinderArgs(t *testing.T) {
	rows := []struct {
		argv []string
		want bool
	}{
		{nil, true},
		{[]string{}, true},
		{[]string{"-psn_0_12345"}, true},
		{[]string{"list"}, false},
		{[]string{"gui"}, false},
		{[]string{"-psn_0_1", "-psn_0_2"}, false},
		{[]string{"-psn_0_1", "list"}, false},
	}
	for _, r := range rows {
		if got := OnlyFinderArgs(r.argv); got != r.want {
			t.Fatalf("OnlyFinderArgs(%v) = %v, want %v", r.argv, got, r.want)
		}
	}
}

// TestLockRoundTrip (M10 support): a written lock reads back byte-for-byte with
// 0600 permissions; a missing file errors; RemoveLock is idempotent.
func TestLockRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "gui.lock")

	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(tok))
	}
	if err := WriteLock(path, Lock{Token: tok, Port: 8787}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("lock perm = %o, want 600", perm)
	}
	got, err := ReadLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != tok || got.Port != 8787 {
		t.Fatalf("read lock = %+v, want token match and port 8787", got)
	}

	if _, err := ReadLock(filepath.Join(dir, "absent.lock")); err == nil {
		t.Fatal("ReadLock of a missing file must error")
	}
	if err := RemoveLock(path); err != nil {
		t.Fatal(err)
	}
	if err := RemoveLock(path); err != nil {
		t.Fatalf("RemoveLock must be idempotent on an already-removed file: %v", err)
	}
}

// TestLogSinkCapAndRotation (M2 / I-M8 support): the sink writes 0600, caps the
// file, rotates ONCE to path+".1", and a nil sink writes nothing.
func TestLogSinkCapAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "gui.log")

	// A small cap forces a rotation on the second write.
	sink := NewLogSink(path, 40)
	if err := sink.Writeln("launch: http://127.0.0.1:8787/?launch=SECRET"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("log perm = %o, want 600", perm)
	}
	if err := sink.Writeln("grace-exit: no browser page connected; exiting"); err != nil {
		t.Fatal(err)
	}
	// The first line rotated out to gui.log.1; the current file holds the second.
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("expected a rotated file gui.log.1: %v", err)
	}
	if !strings.Contains(string(rotated), "launch:") {
		t.Fatal("the rotated file must hold the first (launch) line")
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cur), "grace-exit:") {
		t.Fatal("the current file must hold the second (grace-exit) line after rotation")
	}
	if strings.Contains(string(cur), "launch:") {
		t.Fatal("the current file must NOT still hold the pre-rotation line")
	}

	// A nil sink is a no-op: no panic, no file.
	var nilSink *LogSink
	if err := nilSink.Writeln("must-not-write"); err != nil {
		t.Fatalf("nil sink Writeln must be a no-op: %v", err)
	}
	if nilSink.Path() != "" {
		t.Fatal("nil sink Path must be empty")
	}
}
