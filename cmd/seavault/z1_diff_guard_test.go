// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestZ1NoPreU2TestEditedOrDeleted (matrix Z1, I-U1/I-U8): the U2 branch must ADD
// tests, never weaken the pre-U2 suite. This guard diffs the whole working tree
// against the branch base (merge-base with main) and fails if any *_test.go file
// is Modified, Deleted, or Renamed — an edited or removed pre-U2 test. New test
// files (status Added) are exactly what a feature branch should carry, so the
// guard also asserts at least one *_test.go was Added, so it can never pass
// vacuously on an empty diff.
//
// It is a repository-integrity check, not a unit test, so it needs git and the
// base ref; when neither `main` nor `origin/main` resolves (a detached/shallow
// checkout that dropped the base), it SKIPS rather than fails spuriously — a
// visible skip, never a green vacuous pass.
func TestZ1NoPreU2TestEditedOrDeleted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available; cannot run the Z1 diff guard")
	}
	root, err := gitOutput(t, ".", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Skipf("not a git checkout; cannot run the Z1 diff guard: %v", err)
	}
	root = strings.TrimSpace(root)

	base := ""
	for _, ref := range []string{"main", "origin/main"} {
		if out, err := gitOutput(t, root, "merge-base", "HEAD", ref); err == nil {
			base = strings.TrimSpace(out)
			break
		}
	}
	if base == "" {
		t.Skip("could not resolve the branch base (main / origin/main); cannot run the Z1 diff guard")
	}

	// Whole working tree (committed branch changes + uncommitted edits) vs base.
	diff, err := gitOutput(t, root, "diff", "--name-status", "-M", base)
	if err != nil {
		t.Fatalf("git diff against base %s failed: %v", base, err)
	}
	lines := strings.Split(strings.TrimSpace(diff), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		t.Fatalf("the branch shows no changes against its base %s; the guard would be vacuous", base)
	}

	addedTests := 0
	var offenders []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		status := fields[0]
		// A rename prints "R<score>\told\tnew"; check both paths.
		paths := fields[1:]
		touchesTest := false
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				touchesTest = true
			}
		}
		if !touchesTest {
			continue
		}
		switch {
		case status == "A":
			addedTests++
		case strings.HasPrefix(status, "M") || strings.HasPrefix(status, "D") || strings.HasPrefix(status, "R"):
			offenders = append(offenders, line)
		}
	}

	if len(offenders) != 0 {
		t.Fatalf("pre-U2 tests must not be edited, deleted, or renamed (I-U1/I-U8); offending diff rows:\n%s", strings.Join(offenders, "\n"))
	}
	if addedTests == 0 {
		t.Fatalf("expected the U2 branch to ADD at least one *_test.go against base %s; found none (the guard would be vacuous)", base)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
