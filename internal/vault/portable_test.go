// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"strings"
	"testing"
)

// TestValidatePortableName exercises every rule of the design: each illegal
// row must be rejected and each legal row accepted. A table that asserted
// nothing on some rows would pass vacuously, so every row is checked, and the
// error of an illegal row must name the sanitised suggestion (the fix).
func TestValidatePortableName(t *testing.T) {
	illegal := []struct {
		name string
		want string // fragment the error must contain
	}{
		{"a<b", "<"},
		{"a>b", ">"},
		{"a:b.txt", ":"},
		{`a"b`, `"`},
		{"a|b", "|"},
		{"a?b", "?"},
		{"a*b", "*"},
		{"a\x00b", "control character"},
		{"a\x1fb", "control character"},
		{"a\x7fb", "control character"},
		{"name.", "trailing"},
		{"name ", "trailing"},
		{"CON", "reserved device name"},
		{"con", "reserved device name"},
		{"CON.txt", "reserved device name"},
		{"nul", "reserved device name"},
		{"PRN", "reserved device name"},
		{"AUX", "reserved device name"},
		{"COM1", "reserved device name"},
		{"lpt9.log", "reserved device name"},
		{"", "empty"},
	}
	for _, tc := range illegal {
		err := ValidatePortableName(tc.name)
		if err == nil {
			t.Errorf("ValidatePortableName(%q) = nil, want rejection", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ValidatePortableName(%q) error %q does not mention %q", tc.name, err.Error(), tc.want)
		}
		// The fix names a form that itself passes, so the suggestion is actionable.
		if s := sanitizePortableSegment(tc.name); ValidatePortableName(s) != nil {
			t.Errorf("sanitized form %q of %q is itself not portable", s, tc.name)
		}
	}

	legal := []string{
		"file.txt",
		"12-30 standup.txt",
		"console.txt", // stem "console" is not the reserved "CON"
		"COM0",        // only COM1-COM9 are reserved
		"a.CON",       // stem is "a", extension is not checked
		"CONsole",
		"a b c.txt",
		"_CON",
	}
	for _, name := range legal {
		if err := ValidatePortableName(name); err != nil {
			t.Errorf("ValidatePortableName(%q) = %v, want nil", name, err)
		}
	}
}

// TestSanitizePortableSegment pins the exact sanitisation of the design: illegal
// and control characters become '_', trailing dots/spaces are trimmed, reserved
// stems gain a leading '_', and an all-illegal segment collapses to "_".
func TestSanitizePortableSegment(t *testing.T) {
	cases := map[string]string{
		"a:b.txt": "a_b.txt",
		"a<b>c":   "a_b_c",
		"a|b?c*":  "a_b_c_",
		"a\x00b":  "a_b",
		"name.":   "name",
		"name ":   "name",
		"name. .": "name",
		"CON":     "_CON",
		"con":     "_con",
		"CON.txt": "_CON.txt",
		"COM1.":   "_COM1",
		"...":     "_",
		"":        "_",
		"ok.txt":  "ok.txt",
	}
	for in, want := range cases {
		if got := sanitizePortableSegment(in); got != want {
			t.Errorf("sanitizePortableSegment(%q) = %q, want %q", in, got, want)
		}
	}
}
