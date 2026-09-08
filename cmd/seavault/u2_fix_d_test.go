// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRecoveryGenerateHelpAdvertisesSaveFlag is the F-D docs-consistency guard for
// DOCS-1: the v0.19 README documents `seavault recovery generate --save PATH` (the
// standalone DRAFT recovery card). The --save flag is implemented in
// cmdRecoveryGenerate and works, but the documented claim is only honest if
// `recovery generate --help` actually advertises the flag — otherwise the
// "every command/flag appears in help" contract (C7 / ADM-6; friction DOCS-6)
// drifts silently. Assert the registry usage line and the rendered help both name
// --save so a future edit that drops it from the help is a RED, visible diff.
func TestRecoveryGenerateHelpAdvertisesSaveFlag(t *testing.T) {
	var row command
	found := false
	for _, c := range commands {
		if c.group == "recovery" && c.name == "generate" {
			row = c
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no `recovery generate` row in the command registry")
	}
	if !strings.Contains(row.usage, "--save") {
		t.Fatalf("`recovery generate` registry usage must advertise --save (documented in README v0.19); got %q", row.usage)
	}
	var buf bytes.Buffer
	renderCommandHelp(&buf, row)
	if out := buf.String(); !strings.Contains(out, "--save") {
		t.Fatalf("`recovery generate --help` must show --save; got:\n%s", out)
	}
}
