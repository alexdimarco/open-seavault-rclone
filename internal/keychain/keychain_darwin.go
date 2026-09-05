// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build darwin

package keychain

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// runSecurity is the exec seam for the interactive keychain write. It runs
// `security <args>` with stdin fed from the given string and returns the
// combined output. A darwin-tagged test overrides it to assert the argv and the
// command written to stdin without touching the real login keychain. Its
// captured output is deliberately never woven into an error message (design
// D8.1) so a desynchronised command stream cannot echo a secret fragment into a
// log.
var runSecurity = func(stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command("security", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.Bytes(), err
}

func Get(account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", Service, "-a", account, "-w").Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("macOS Keychain lookup timed out; unlock the login keychain or enter the password manually")
	}
	if err != nil {
		return "", fmt.Errorf("macOS Keychain lookup failed: %w", err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

// Set stores the password without ever placing it in argv (design D8.1, I5): the
// add-generic-password command — with the secret in a `-w` argument — is written
// to `security -i` on stdin, and argv is exactly ["security","-i"]. A secret or
// account with a control byte is refused before any exec (the line-oriented
// interactive reader could otherwise desynchronise), and the error on failure is
// fixed text that never includes the captured `security` output.
func Set(account, secret string) error {
	if err := secretIsStorable(account, secret); err != nil {
		return err
	}
	if _, err := runSecurity(securityCommandLine(account, secret)+"\n", "-i"); err != nil {
		return fmt.Errorf("macOS Keychain store failed; the vault still opens with the password typed or via SEAVAULT_PASSWORD")
	}
	return nil
}

func Delete(account string) error {
	cmd := exec.Command("security", "delete-generic-password", "-s", Service, "-a", account)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("macOS Keychain delete failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
