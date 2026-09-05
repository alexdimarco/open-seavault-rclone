// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build darwin

package keychain

import (
	"errors"
	"strings"
	"testing"
)

// TestSetSendsCommandOnStdin is the darwin-only half of: Set exec's exactly
// ["security","-i"] and writes the add-generic-password command — carrying the
// account and secret — to stdin, so neither ever appears in argv (I5).
func TestSetSendsCommandOnStdin(t *testing.T) {
	orig := runSecurity
	defer func() { runSecurity = orig }()
	var gotArgs []string
	var gotStdin string
	runSecurity = func(stdin string, args ...string) ([]byte, error) {
		gotArgs = args
		gotStdin = stdin
		return nil, nil
	}
	if err := Set("vault-1", `p"w\x`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(gotArgs) != 1 || gotArgs[0] != "-i" {
		t.Fatalf("argv after program = %v, want [-i]", gotArgs)
	}
	if !strings.Contains(gotStdin, `-a "vault-1"`) {
		t.Errorf("stdin missing quoted account: %q", gotStdin)
	}
	if !strings.Contains(gotStdin, `-w "p\"w\\x"`) {
		t.Errorf("stdin missing quoted/escaped secret: %q", gotStdin)
	}
}

// TestSetRefusesControlCharBeforeExec proves the control-character refusal fires
// before any exec: runSecurity must not be reached.
func TestSetRefusesControlCharBeforeExec(t *testing.T) {
	orig := runSecurity
	defer func() { runSecurity = orig }()
	called := false
	runSecurity = func(stdin string, args ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	if err := Set("vault-1", "two\nlines"); !errors.Is(err, ErrSecretNotStorable) {
		t.Fatalf("Set with newline secret = %v, want ErrSecretNotStorable", err)
	}
	if called {
		t.Fatal("runSecurity was invoked for an unstorable secret")
	}
}

// TestSetErrorHidesCapturedOutput proves a failing exec never leaks the captured
// `security` output (which could hold a secret fragment) into the error text.
func TestSetErrorHidesCapturedOutput(t *testing.T) {
	orig := runSecurity
	defer func() { runSecurity = orig }()
	const leak = "SENSITIVE-CAPTURED-OUTPUT-hunter2"
	runSecurity = func(stdin string, args ...string) ([]byte, error) {
		return []byte(leak), errors.New("exit status 1")
	}
	err := Set("vault-1", "hunter2")
	if err == nil {
		t.Fatal("Set succeeded despite runSecurity error")
	}
	if strings.Contains(err.Error(), leak) {
		t.Fatalf("error text leaked captured output: %q", err.Error())
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error text leaked the secret: %q", err.Error())
	}
}
