// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"flag"
	"testing"
)

// `rclone install|update --signature` defaulted to "optional". The installer only
// consults policy.json's signatureMode when the mode is EMPTY, so the flag's own
// default silently overrode an administrator's "required" and a bad signature
// became a warning. An unset flag must stay empty so the policy decides.

func TestSignatureFlagUnsetDefersToPolicy(t *testing.T) {
	fs := flag.NewFlagSet("rclone install", flag.ContinueOnError)
	p := signatureFlag(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *p != "" {
		t.Fatalf("--signature unset = %q; it must stay empty so policy.json's signatureMode applies", *p)
	}

	// An explicit value is still honoured.
	fs = flag.NewFlagSet("rclone install", flag.ContinueOnError)
	p = signatureFlag(fs)
	if err := fs.Parse([]string{"--signature", "required"}); err != nil {
		t.Fatal(err)
	}
	if *p != "required" {
		t.Fatalf("explicit --signature required = %q", *p)
	}
}
