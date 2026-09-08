// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// singleDashFlag matches a short "-x" flag introduced by start-or-whitespace. It
// deliberately does NOT match a double-dash "--x" long flag (the char after the
// first dash is another dash, not a letter), so a usage line that spells every
// flag with "--" passes and one that regresses to "-x" fails (H1, ADM-6).
var singleDashFlag = regexp.MustCompile(`(^|[\s\[])-[A-Za-z]`)

// quotedToken pulls the double-quoted subcommand names out of a `case "a", "b":`
// line when H4 reconstructs a group's real dispatch set from source.
var quotedToken = regexp.MustCompile(`"([^"]+)"`)

// fullPath is the invocation prefix a leaf row's usage line must contain:
// "seavault <name>" for a top-level command, "seavault <group> <name>" for a
// subcommand.
func fullPath(c command) string {
	if c.group == "" {
		return "seavault " + c.name
	}
	return "seavault " + c.group + " " + c.name
}

// TestRegistryHelpRendersEveryRow is H1 (§3.1): iterate the command registry and
// assert every row's --help renders a non-empty synopsis and a double-dash usage
// line, and that every group's help lists each of its subcommands with a
// synopsis. The table is asserted on EVERY row; an empty table fails.
func TestRegistryHelpRendersEveryRow(t *testing.T) {
	if len(commands) == 0 {
		t.Fatal("command registry is empty; the table must list every dispatchable command")
	}

	sawDoubleDashFlag := false
	rows := 0
	for _, c := range commands {
		rows++
		if strings.TrimSpace(c.synopsis) == "" {
			t.Errorf("registry row %q (group %q) has an empty synopsis; every command needs a one-line description", c.name, c.group)
		}

		if len(groupChildren(c.name)) > 0 && c.group == "" {
			// Group parent: --help is the group listing, exercised below.
			continue
		}

		// Leaf command: its --help renders a usage line drawn from the row.
		if c.usage == "" {
			t.Errorf("leaf row %q (group %q) has an empty usage line", c.name, c.group)
			continue
		}
		var buf bytes.Buffer
		renderCommandHelp(&buf, c)
		out := buf.String()
		if !strings.Contains(out, c.synopsis) {
			t.Errorf("%s --help must render its synopsis; got:\n%s", fullPath(c), out)
		}
		if !strings.Contains(out, fullPath(c)) {
			t.Errorf("%s --help usage must name the command %q; got:\n%s", fullPath(c), fullPath(c), out)
		}
		if singleDashFlag.MatchString(c.usage) {
			t.Errorf("usage for %s uses a single-dash flag; flags must be double-dash (ADM-6): %q", fullPath(c), c.usage)
		}
		if strings.Contains(c.usage, "--") {
			sawDoubleDashFlag = true
		}
	}
	if rows != len(commands) {
		t.Fatalf("iterated %d rows but registry has %d", rows, len(commands))
	}
	if !sawDoubleDashFlag {
		t.Fatal("no registry usage line spells a flag with a double dash; the double-dash convention is not exercised")
	}

	// Every group's help lists each of its subcommands with the subcommand's
	// synopsis (asserted on every group and every child; a childless group fails).
	groups := []string{"profile", "vault", "password", "recovery", "keychain", "rclone", "rsync", "remote", "ssh-key"}
	for _, g := range groups {
		subs := groupChildren(g)
		if len(subs) == 0 {
			t.Fatalf("group %q has no subcommands in the registry", g)
		}
		var buf bytes.Buffer
		renderGroupHelp(&buf, g)
		out := buf.String()
		for _, sub := range subs {
			if !strings.Contains(out, sub.name) {
				t.Errorf("group help for %q must list subcommand %q; got:\n%s", g, sub.name, out)
			}
			if !strings.Contains(out, sub.synopsis) {
				t.Errorf("group help for %q must show subcommand %q's synopsis; got:\n%s", g, sub.name, out)
			}
		}
	}
}

// parseSwitchCases reconstructs a group leaf-dispatcher's real recognized
// subcommand set by reading its `case "..."` labels straight from main.go. This
// is the INDEPENDENT source of truth H4 compares the registry against, so a
// subcommand the code dispatches but the table forgot (or the reverse) is caught.
func parseSwitchCases(t *testing.T, funcHeader string) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, funcHeader) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("function header %q not found in main.go", funcHeader)
	}
	got := map[string]bool{}
	ended := false
	for i := start + 1; i < len(lines); i++ {
		ln := lines[i]
		if ln == "}" { // gofmt puts the closing brace of a top-level func at column 0
			ended = true
			break
		}
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "case ") && strings.HasSuffix(trimmed, ":") {
			for _, m := range quotedToken.FindAllStringSubmatch(trimmed, -1) {
				got[m[1]] = true
			}
		}
	}
	if !ended {
		t.Fatalf("did not find the closing brace of %q", funcHeader)
	}
	if len(got) == 0 {
		t.Fatalf("parsed no case labels from %q; the parser or the function shape changed", funcHeader)
	}
	return got
}

// registryGroupNames returns the recognized names of a group in the registry:
// every child row's name plus its aliases (dispatch honors both).
func registryGroupNames(group string) map[string]bool {
	got := map[string]bool{}
	for _, c := range groupChildren(group) {
		got[c.name] = true
		for _, a := range c.aliases {
			got[a] = true
		}
	}
	return got
}

// TestRegistryEqualsDispatchBothDirections is H4 (C3): the registry names equal
// the dispatchable names in BOTH directions, at the top level and inside every
// group. The four commands older usage() text omitted — rclone version / rclone
// path, remote sync / remote config — must be present, and dispatch must
// recognize each registered name and reject a bogus one.
func TestRegistryEqualsDispatchBothDirections(t *testing.T) {
	// Top level: the registry's top-level names and aliases equal the specified
	// command set (test = spec), both directions.
	wantTop := map[string]bool{
		"setup": true, "init": true, "put": true, "get": true, "export": true,
		"list": true, "remove": true, "rm": true, "verify": true, "gc": true,
		"compact": true, "stats": true, "serve": true, "gui": true,
		"app-config": true, "config": true, "move": true, "version": true,
		"profile": true, "vault": true, "password": true, "recovery": true,
		"keychain": true, "rclone": true, "rsync": true, "remote": true, "ssh-key": true,
	}
	gotTop := map[string]bool{}
	for _, c := range commands {
		if c.group != "" {
			continue
		}
		gotTop[c.name] = true
		for _, a := range c.aliases {
			gotTop[a] = true
		}
	}
	assertSetsEqual(t, "top-level", wantTop, gotTop)

	// Each group: the registry's recognized names equal the leaf dispatcher's
	// real `case` labels parsed from source.
	groups := map[string]string{
		"profile":  "func execProfile(args []string) error {",
		"vault":    "func execVault(args []string) error {",
		"password": "func execPassword(args []string) error {",
		"recovery": "func execRecovery(args []string) error {",
		"keychain": "func execKeychain(args []string) error {",
		"rclone":   "func execRclone(args []string) error {",
		"rsync":    "func execRsync(args []string) error {",
		"remote":   "func execRemote(args []string) error {",
		"ssh-key":  "func execSSHKey(args []string) error {",
	}
	for group, header := range groups {
		dispatchable := parseSwitchCases(t, header)
		registered := registryGroupNames(group)
		assertSetsEqual(t, group, dispatchable, registered)
	}

	// The C3 known-omission commands must be dispatch-recognized (not "unknown").
	omissions := []struct{ group, name string }{
		{"rclone", "version"}, {"rclone", "path"},
		{"remote", "sync"}, {"remote", "config"},
	}
	for _, o := range omissions {
		if _, ok := groupCommand(o.group, o.name); !ok {
			t.Errorf("C3: %q %q must be in the registry so dispatch recognizes it", o.group, o.name)
		}
	}

	// Recognition holds for every registered name; a bogus name is rejected.
	for _, c := range commands {
		if c.group == "" {
			if _, ok := topLevelCommand(c.name); !ok {
				t.Errorf("top-level %q is registered but topLevelCommand does not recognize it", c.name)
			}
			continue
		}
		if _, ok := groupCommand(c.group, c.name); !ok {
			t.Errorf("%s %q is registered but groupCommand does not recognize it", c.group, c.name)
		}
	}
	if _, ok := topLevelCommand("definitely-not-a-command"); ok {
		t.Error("topLevelCommand must reject an unregistered name")
	}
	if _, ok := groupCommand("rclone", "definitely-not-a-subcommand"); ok {
		t.Error("groupCommand must reject an unregistered subcommand")
	}
}

func assertSetsEqual(t *testing.T, label string, want, got map[string]bool) {
	t.Helper()
	for name := range want {
		if !got[name] {
			t.Errorf("%s: %q is dispatchable but missing from the registry", label, name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("%s: %q is in the registry but not dispatchable", label, name)
		}
	}
}

// runCode invokes run(argv) with stdout and stderr redirected so help/usage text
// does not clutter the test log, and returns the process exit code.
func runCode(t *testing.T, argv ...string) int {
	t.Helper()
	var code int
	_, _, _ = captureOutputs(t, func() error {
		code = run(argv)
		return nil
	})
	return code
}

// TestExitCodeContract is H5 (C7): an explicit --help or a bare group prints help
// and exits 0; an unknown subcommand or command exits non-zero. Every row of the
// table is asserted; each argv is help/bare/unknown/version only, so no real
// command handler (and no rclone/rsync binary) is ever invoked.
func TestExitCodeContract(t *testing.T) {
	zero := []struct {
		name string
		argv []string
	}{
		{"global --help", []string{"--help"}},
		{"global -h", []string{"-h"}},
		{"global help", []string{"help"}},
		{"version", []string{"version"}},
		{"bare group profile", []string{"profile"}},
		{"bare group rclone", []string{"rclone"}},
		{"bare group remote", []string{"remote"}},
		{"bare group ssh-key", []string{"ssh-key"}},
		{"group --help", []string{"rclone", "--help"}},
		{"subcommand --help", []string{"rclone", "status", "--help"}},
		{"subcommand --help (omission)", []string{"remote", "sync", "--help"}},
	}
	for _, tc := range zero {
		if got := runCode(t, tc.argv...); got != 0 {
			t.Errorf("%s: run(%v) exit = %d, want 0 (explicit help / bare group exits 0)", tc.name, tc.argv, got)
		}
	}

	nonZero := []struct {
		name string
		argv []string
		want int
	}{
		{"no args", []string{}, 2},
		{"unknown top-level", []string{"definitely-not-a-command"}, 2},
		{"unknown rclone subcommand", []string{"rclone", "frobnicate"}, 1},
		{"unknown remote subcommand", []string{"remote", "frobnicate"}, 1},
		{"unknown profile subcommand", []string{"profile", "frobnicate"}, 1},
	}
	for _, tc := range nonZero {
		got := runCode(t, tc.argv...)
		if got == 0 {
			t.Errorf("%s: run(%v) exit = 0, want non-zero", tc.name, tc.argv)
		}
		if got != tc.want {
			t.Errorf("%s: run(%v) exit = %d, want %d", tc.name, tc.argv, got, tc.want)
		}
	}
}
