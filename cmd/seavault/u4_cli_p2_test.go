// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnknownSubcommandExitsTwo (U4 CLI-1, I-P1 behaviour row): an UNKNOWN
// subcommand of any command group is a usage error and exits 2 — the SAME code an
// unknown top-level command yields. Before U4 an unknown top-level exited 2 while
// an unknown subcommand exited 1 (the U2 CLI-1 friction row). The table covers a
// dispatchGroup group per code path plus app-config, whose leaf handler dispatches
// its own sub-actions; every row asserts, and a known bare group is included as a
// control so the row proves 2 is specific to the unknown case, not a blanket
// change (a bare group still exits 0, CLI 6).
func TestUnknownSubcommandExitsTwo(t *testing.T) {
	unknown := []struct {
		name string
		argv []string
	}{
		{"rclone", []string{"rclone", "frobnicate"}},
		{"remote", []string{"remote", "frobnicate"}},
		{"profile", []string{"profile", "frobnicate"}},
		{"keychain", []string{"keychain", "frobnicate"}},
		{"vault", []string{"vault", "frobnicate"}},
		{"password", []string{"password", "frobnicate"}},
		{"recovery", []string{"recovery", "frobnicate"}},
		{"rsync", []string{"rsync", "frobnicate"}},
		{"ssh-key", []string{"ssh-key", "frobnicate"}},
		{"tls", []string{"tls", "frobnicate"}},
		{"app-config", []string{"app-config", "frobnicate"}},
	}
	if len(unknown) == 0 {
		t.Fatal("the unknown-subcommand table is empty; the test would be vacuous")
	}
	for _, tc := range unknown {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCode(t, tc.argv...); got != 2 {
				t.Fatalf("run(%v) exit = %d, want 2 (an unknown subcommand is a usage error)", tc.argv, got)
			}
		})
	}
	// Control: a bare group verb still exits 0 (CLI 6), so exit 2 is specific to the
	// unknown subcommand and not a blanket usage-error change.
	if got := runCode(t, "rclone"); got != 0 {
		t.Fatalf("bare group `rclone` exit = %d, want 0 (a bare group prints help and exits 0)", got)
	}
}

// TestKeychainDeleteReportPlainNoEntryAndDebug (U4 DOCS-1): `keychain delete`
// composes an operator line via keychainDeleteReport. A missing entry (the service
// answered, no entry) reports "no keychain entry for <vault>" plainly and is NOT an
// error, so nothing to delete exits 0; a genuine backend failure reports a plain
// summary and returns the raw backend text ONLY as the --debug detail, never in the
// plain line. Before U4 the delete dumped the raw backend error on a missing entry.
// Every row asserts, and every error row asserts the plain line does not leak the
// backend text (I-R2/I-S1: no backend/secret substring in the operator line).
func TestKeychainDeleteReportPlainNoEntryAndDebug(t *testing.T) {
	const label = "/vaults/photos"
	// Distinctive backend strings that must never appear in a plain operator line.
	lookupErr := errors.New("secret-tool: no such secret exists; exit status 1")
	backendErr := errors.New("Secret Service delete failed: exit status 1: org.freedesktop.Secret.Error")

	rows := []struct {
		name       string
		getErr     error
		reachable  bool
		delErr     error
		wantLine   string
		wantIsErr  bool
		wantRawSub string // substring the --debug detail must carry ("" = detail must be empty)
	}{
		{
			name:      "missing entry, service reachable",
			getErr:    lookupErr,
			reachable: true,
			wantLine:  "no keychain entry for " + label,
			wantIsErr: false,
		},
		{
			name:       "service unreachable",
			getErr:     backendErr,
			reachable:  false,
			wantLine:   "could not reach the OS keychain to delete the entry",
			wantIsErr:  true,
			wantRawSub: "org.freedesktop.Secret.Error",
		},
		{
			name:       "entry existed, delete failed",
			getErr:     nil,
			reachable:  true,
			delErr:     backendErr,
			wantLine:   "could not delete the OS keychain entry",
			wantIsErr:  true,
			wantRawSub: "org.freedesktop.Secret.Error",
		},
		{
			name:      "entry deleted",
			getErr:    nil,
			reachable: true,
			wantLine:  "OS keychain entry deleted",
			wantIsErr: false,
		},
	}
	if len(rows) == 0 {
		t.Fatal("the keychain-delete-report table is empty; the test would be vacuous")
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			line, isErr, raw := keychainDeleteReport(label, tc.getErr, tc.reachable, tc.delErr)
			if line != tc.wantLine {
				t.Fatalf("line = %q, want %q", line, tc.wantLine)
			}
			if isErr != tc.wantIsErr {
				t.Fatalf("isErr = %v, want %v", isErr, tc.wantIsErr)
			}
			if tc.wantRawSub == "" {
				if raw != "" {
					t.Fatalf("rawDetail = %q, want empty", raw)
				}
			} else if !strings.Contains(raw, tc.wantRawSub) {
				t.Fatalf("rawDetail = %q, want it to carry %q for --debug", raw, tc.wantRawSub)
			}
			// The plain operator line must never leak the raw backend error text —
			// that is the --debug-only detail (DOCS-1, I-R2).
			for _, leak := range []string{"secret-tool", "org.freedesktop", "exit status", "Secret Service delete failed"} {
				if strings.Contains(line, leak) {
					t.Fatalf("plain line %q leaks backend text %q; raw detail must be --debug-only", line, leak)
				}
			}
		})
	}
}

// TestInitAppliesLeftoversClassification (U4 CLI 4, I-P1 behaviour row): `init` on
// a directory that is non-empty but holds no vault (interrupted-setup leftovers)
// returns the same remove-and-retry remedy `setup` enforces, instead of a
// lower-level create failure. An EMPTY directory still initializes cleanly, so the
// classification is specific to leftovers and does not block a normal init.
func TestInitAppliesLeftoversClassification(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	// A password is set so a neutralized classification would proceed to create
	// (and fail differently) rather than block on the hidden prompt — the red is a
	// wrong message, never a hang.
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")

	// Leftovers directory: non-empty, no vault.json.
	leftovers := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(leftovers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leftovers, "half-written.chunk"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := captureRun(t, "init", leftovers)
	if code == 0 {
		t.Fatalf("init on a leftovers directory must fail; got exit 0\nstderr: %s", stderr)
	}
	lo := strings.ToLower(stderr)
	if !strings.Contains(lo, "leftover") || !strings.Contains(lo, "remove that directory and re-run") {
		t.Fatalf("init on a leftovers directory must name the remove-and-retry remedy; got:\n%s", stderr)
	}

	// Control: an EMPTY directory initializes cleanly (the classification does not
	// block a normal init).
	empty := filepath.Join(t.TempDir(), "fresh")
	_, stderr2, code2 := captureRun(t, "init", empty)
	if code2 != 0 {
		t.Fatalf("init on an empty directory must succeed; got exit %d\nstderr: %s", code2, stderr2)
	}
	if strings.Contains(strings.ToLower(stderr2), "leftover") {
		t.Fatalf("init on an empty directory must not mention leftovers; got:\n%s", stderr2)
	}
}
