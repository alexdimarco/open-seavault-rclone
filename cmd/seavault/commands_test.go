// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"bytes"
	"os"
	"reflect"
	"regexp"
	"runtime"
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

// groupWiringRe matches a group's one-line dispatch wiring in the package source
// — `func cmdX(args []string) error { return dispatchGroup("<group>", execX, args) }`
// — capturing the group name (1) and its leaf-dispatcher function name (2). This
// is exactly the machinery main() reaches through (run → the group parent's
// handler → dispatchGroup → execX), parsed straight from source so H4 derives the
// dispatch side with no hardcoded group/command list.
var groupWiringRe = regexp.MustCompile(`func\s+\w+\(args \[\]string\) error\s*\{\s*return dispatchGroup\("([^"]+)",\s*(\w+),\s*args\)\s*\}`)

// execDefRe matches a leaf-dispatcher definition — `func exec…(args []string) error {`
// — capturing its name (1). H4 uses it to prove every exec dispatcher the package
// defines is actually wired into dispatch (and therefore reachable from a registry
// row): a stray exec function nothing dispatches is an unregistered handler.
var execDefRe = regexp.MustCompile(`func\s+(exec\w+)\(args \[\]string\) error\s*\{`)

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

// readPackageSource returns every non-test .go file in the cmd/seavault package
// concatenated, so H4 parses the dispatch machinery from the WHOLE package (not
// just main.go) and cannot be fooled by moving a dispatcher into another file.
func readPackageSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var b strings.Builder
	files := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		b.Write(src)
		b.WriteString("\n")
		files++
	}
	if files == 0 {
		t.Fatal("found no non-test .go sources in the package; the source parser is misconfigured")
	}
	return b.String()
}

// handlerFuncName resolves a registry row's handler value back to the name of the
// function it points at (e.g. cmdSetup), via reflection over the compiled func
// value. H4 uses it to prove a registered top-level command's handler is a real,
// defined function — i.e. that a reachable handler actually exists behind it.
func handlerFuncName(h func(args []string) error) string {
	if h == nil {
		return ""
	}
	f := runtime.FuncForPC(reflect.ValueOf(h).Pointer())
	if f == nil {
		return ""
	}
	full := f.Name() // ".../cmd/seavault.cmdSetup"
	if i := strings.LastIndex(full, "."); i >= 0 {
		return full[i+1:]
	}
	return full
}

// TestRegistryEqualsDispatchBothDirections is H4 (C3): the command registry and
// the dispatch machinery agree in BOTH directions, with NO hardcoded command or
// group list — the registry side is read from the commands.go table (the in-memory
// `commands` slice and its helpers) and the dispatch side is PARSED from the
// package source (the `func cmdX(...) { return dispatchGroup("g", execX, args) }`
// wirings run() reaches through, plus each execX's real `case` labels). It goes
// red when a registered command has no reachable handler, or a reachable handler
// (an unregistered group, a stray exec dispatcher, or a case the table forgot) is
// not registered. The four commands older usage() text omitted — rclone version /
// rclone path, remote sync / remote config — must be present and dispatched.
func TestRegistryEqualsDispatchBothDirections(t *testing.T) {
	src := readPackageSource(t)

	// ---- Dispatch side, parsed from source (no hardcoded group/command list). ----
	// group -> its leaf dispatcher, straight from the dispatchGroup wirings.
	groupToExec := map[string]string{}
	for _, m := range groupWiringRe.FindAllStringSubmatch(src, -1) {
		groupToExec[m[1]] = m[2]
	}
	if len(groupToExec) == 0 {
		t.Fatal("parsed no group dispatch wirings from source; the parser or the dispatchGroup pattern changed")
	}
	// Every exec leaf dispatcher DEFINED in the package.
	definedExecs := map[string]bool{}
	for _, m := range execDefRe.FindAllStringSubmatch(src, -1) {
		definedExecs[m[1]] = true
	}
	if len(definedExecs) == 0 {
		t.Fatal("parsed no exec dispatcher definitions from source; the parser changed")
	}
	// Every exec dispatcher the package defines must be wired into dispatch (and so
	// reachable from a registry row); every wiring must name a defined function. A
	// stray exec function nothing dispatches is an unregistered reachable handler.
	wired := map[string]bool{}
	for _, execFn := range groupToExec {
		wired[execFn] = true
	}
	for fn := range definedExecs {
		if !wired[fn] {
			t.Errorf("exec dispatcher %q is defined in the package but no group wires it via dispatchGroup; a reachable handler must be registered", fn)
		}
	}
	for _, fn := range groupToExec {
		if !definedExecs[fn] {
			t.Errorf("a dispatchGroup wiring names exec dispatcher %q but no such function is defined in the package", fn)
		}
	}

	// ---- Registry side, from the commands.go table (no hardcoded list). ----
	// A group parent is a top-level row (group == "") that has child rows.
	registryGroups := map[string]bool{}
	for _, c := range commands {
		if c.group == "" && len(groupChildren(c.name)) > 0 {
			registryGroups[c.name] = true
		}
	}
	if len(registryGroups) == 0 {
		t.Fatal("the registry lists no group parents; the table is malformed")
	}

	// ---- Group set: dispatched groups == registered group parents, both ways. ----
	dispatchGroupSet := map[string]bool{}
	for g := range groupToExec {
		dispatchGroupSet[g] = true
	}
	// want = dispatch side, got = registry side: loop 1 catches a dispatched group
	// the registry forgot; loop 2 catches a registered group nothing dispatches.
	assertSetsEqual(t, "group set", dispatchGroupSet, registryGroups)

	// ---- Per group: dispatchable case labels == registered names+aliases. ----
	for g, execFn := range groupToExec {
		dispatchable := parseSwitchCases(t, "func "+execFn+"(args []string) error {")
		registered := registryGroupNames(g)
		if len(registered) == 0 {
			t.Errorf("group %q dispatches %d subcommand(s) but the registry lists none", g, len(dispatchable))
		}
		assertSetsEqual(t, g, dispatchable, registered)
	}

	// ---- Top level: every registered top-level leaf has a reachable handler. ----
	// run() dispatches top-level rows straight from the table, so a leaf is
	// reachable exactly when its handler is a real, defined function. Group parents
	// are covered by the group-set/per-group checks above; subcommand rows have no
	// own handler.
	topLevelLeaves := 0
	for _, c := range commands {
		if c.group != "" || len(groupChildren(c.name)) > 0 {
			continue
		}
		topLevelLeaves++
		if c.handler == nil {
			t.Errorf("top-level command %q has a nil handler; it is registered but unreachable", c.name)
			continue
		}
		fn := handlerFuncName(c.handler)
		if fn == "" {
			t.Errorf("top-level command %q: could not resolve its handler function name", c.name)
			continue
		}
		if !strings.Contains(src, "func "+fn+"(") {
			t.Errorf("top-level command %q dispatches to %q, which is not defined in the package source (no reachable handler)", c.name, fn)
		}
	}
	if topLevelLeaves == 0 {
		t.Fatal("the registry lists no top-level leaf commands; the table is malformed")
	}

	// ---- Recognition holds for every registered name; a bogus name is rejected. ----
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

	// ---- The C3 known-omission commands must be registered AND dispatched. ----
	for _, o := range []struct{ group, name string }{
		{"rclone", "version"}, {"rclone", "path"},
		{"remote", "sync"}, {"remote", "config"},
	} {
		if _, ok := groupCommand(o.group, o.name); !ok {
			t.Errorf("C3: %q %q must be in the registry so dispatch recognizes it", o.group, o.name)
		}
		execFn, ok := groupToExec[o.group]
		if !ok {
			t.Errorf("C3: group %q has no dispatch wiring", o.group)
			continue
		}
		if !parseSwitchCases(t, "func "+execFn+"(args []string) error {")[o.name] {
			t.Errorf("C3: %q %q is registered but %s does not dispatch it", o.group, o.name, execFn)
		}
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
