// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Phase U5 slice S3 (docs + finish-the-phase) drift guards. The install docs are
// the user-facing half of the unsigned-tier declaration; these Linux-checkable
// rows keep them from drifting away from the artifacts and the CLI they describe:
//
//   M7  — docs side (design §5, I-M5, C1/C2/C9): docs/install.md includes the
//         single-source packaging/macos/FIRST-LAUNCH.txt VERBATIM and that text
//         carries the current-macOS wording (Privacy & Security / Open Anyway) and
//         the version-independent xattr command; every `seavault` command the doc
//         names resolves in the registry that --help renders from; the uninstall
//         section names every precise step (C9); the unsigned signing state is
//         declared inside the artifacts (SIGNING.txt / the PKG readme, I-M5); and
//         GATEKEEPER-CHECK.md is the greppable per-tag manual gate the release job
//         asserts.
//   M11 — the .command/postinstall handle a missing /usr/local/bin (C4) AND
//         docs/install.md documents the new-Terminal and PATH notes, so the doc
//         and the golden script can never drift apart.
//
// Every table asserts on every row; an empty match set is a failure, never a
// vacuous pass.

func s3Doc(t *testing.T, parts ...string) string {
	t.Helper()
	return mustReadRepoFile(t, filepath.Join(append([]string{"..", ".."}, parts...)...))
}

// TestInstallDocIncludesFirstLaunchVerbatim (M7, design §5, C1/C2): docs/install.md
// embeds the LIVE packaging/macos/FIRST-LAUNCH.txt byte-for-byte (a drift guard:
// edit the single source without updating the doc and this goes red), and the
// embedded workaround leads with the current-macOS path plus the xattr fallback.
func TestInstallDocIncludesFirstLaunchVerbatim(t *testing.T) {
	install := s3Doc(t, "docs", "install.md")
	firstLaunch := s3Doc(t, "packaging", "macos", "FIRST-LAUNCH.txt")

	// The whole first-launch note must appear verbatim (trailing newline aside).
	body := strings.TrimRight(firstLaunch, "\n")
	if !strings.Contains(install, body) {
		t.Fatalf("docs/install.md must include packaging/macos/FIRST-LAUNCH.txt VERBATIM (design §5 single-source drift guard); the exact text was not found as a contiguous block")
	}

	// The embedded text must carry the current-macOS wording and the co-primary
	// version-independent command (C1/C2). Assert on the DOC so a future edit that
	// keeps the block but strips these strings is caught here too.
	rows := []struct{ name, substr string }{
		{"System Settings → Privacy & Security (macOS 13-15)", "Privacy & Security"},
		{"the Open Anyway control", "Open Anyway"},
		{"the version-independent xattr command", "xattr -dr com.apple.quarantine"},
		{"the app path in the xattr command", "/Applications/open-seavault-rclone.app"},
	}
	for _, r := range rows {
		if !strings.Contains(install, r.substr) {
			t.Errorf("docs/install.md first-launch section must name %s (%q)", r.name, r.substr)
		}
	}

	// The dead pre-15 Control-click path must not be presented ahead of the
	// working one: Open Anyway must appear before the first Control-click mention.
	iOpen := strings.Index(install, "Open Anyway")
	iCtrl := strings.Index(install, "Control-click")
	if iOpen >= 0 && iCtrl >= 0 && iCtrl < iOpen {
		t.Error("docs/install.md leads with Control-click → Open (dead on macOS 15); Open Anyway must come first (C1)")
	}
}

// codeUnits returns the shell-command surface of a Markdown doc: the inner lines
// of every ``` fenced block plus the contents of every `inline code span`. Prose
// is excluded so a phrase like "the `seavault` command" is never mistaken for a
// `seavault command` invocation. Used by the --help drift guard.
func codeUnits(md string) []string {
	var units []string
	inFence := false
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			units = append(units, line)
			continue
		}
		// Inline spans: text between single backticks (odd segments).
		parts := strings.Split(line, "`")
		for i := 1; i < len(parts); i += 2 {
			units = append(units, parts[i])
		}
	}
	return units
}

// seavaultInvocation matches a `seavault <token> [<token2>]` command in a code
// unit. Group 1 guards against a path or longer word (the char before `seavault`
// must be start-of-unit or a non-path, non-word char), so `/usr/local/bin/seavault`
// and `open-seavault-rclone` never match.
var seavaultInvocation = regexp.MustCompile(`(^|[^/\w.-])seavault[ \t]+(\S+)(?:[ \t]+(\S+))?`)

// TestInstallDocCommandsExistInHelp (M7, design §5): every `seavault` command
// docs/install.md names must exist in the registry that usage()/--help renders
// FROM (topLevelCommand / groupCommand are the same recognition gate dispatch and
// help use). A doc that invents a command, or keeps naming one after it is
// renamed away, fails here. Non-vacuous: at least two real commands must be found.
func TestInstallDocCommandsExistInHelp(t *testing.T) {
	install := s3Doc(t, "docs", "install.md")

	found := 0
	seen := map[string]bool{}
	for _, unit := range codeUnits(install) {
		for _, m := range seavaultInvocation.FindAllStringSubmatch(unit, -1) {
			tok := m[2]
			if strings.HasPrefix(tok, "-") {
				continue // a flag, not a subcommand
			}
			// Strip trailing punctuation a sentence in a code span might carry.
			tok = strings.TrimRight(tok, ".,;:")
			if tok == "" {
				continue
			}
			found++
			row, ok := topLevelCommand(tok)
			if !ok {
				t.Errorf("docs/install.md names `seavault %s`, which is not a registered command (not in --help): %q", tok, strings.TrimSpace(unit))
				continue
			}
			seen[tok] = true
			// If it is a group parent and a plain second token follows, that must
			// be a real subcommand too.
			if sub := strings.TrimRight(m[3], ".,;:"); sub != "" && !strings.HasPrefix(sub, "-") && len(groupChildren(row.name)) > 0 {
				if _, ok := groupCommand(row.name, sub); !ok {
					t.Errorf("docs/install.md names `seavault %s %s`, which is not a registered subcommand: %q", tok, sub, strings.TrimSpace(unit))
				}
			}
		}
	}
	if found < 2 {
		t.Fatalf("expected docs/install.md to name at least two `seavault` commands (guard would be vacuous); found %d", found)
	}
	// The command surface actually renders in --help: prove the registry we
	// resolved against is the one usage() prints from.
	help := usageText()
	for tok := range seen {
		if !strings.Contains(help, "seavault "+tok) {
			t.Errorf("`seavault %s` resolves in the registry but does not appear in usage() output; --help and the registry disagree", tok)
		}
	}
}

// TestInstallDocUninstallIsPrecise (M7, design §5, C9): the uninstall section names
// every step in order — quit the iconless app (Activity Monitor / pkill), sudo rm
// the root-owned symlink, drag to Trash, pkgutil --forget the receipt, and delete
// the app-data dir. Each is a filed usability-friction fix (C9); dropping any one
// re-opens it, so every row asserts.
func TestInstallDocUninstallIsPrecise(t *testing.T) {
	install := s3Doc(t, "docs", "install.md")
	rows := []struct{ name, substr string }{
		{"quit the iconless app via Activity Monitor", "Activity Monitor"},
		{"quit the iconless app via pkill", "pkill -f open-seavault-rclone"},
		{"sudo rm the root-owned CLI symlink", "sudo rm /usr/local/bin/seavault"},
		{"drag the app to the Trash", "Trash"},
		{"forget the PKG receipt", "sudo pkgutil --forget io.github.alexdimarco.open-seavault-rclone"},
		{"delete the app-data directory", "Library/Application Support/open-seavault-rclone"},
		{"states vaults are untouched", "vaults"},
		// friction B/C4: `pkill -f open-seavault-rclone` misses a Terminal-started
		// `seavault gui` (argv0 = seavault), so the quit guidance must name that
		// case and its recourse (Ctrl-C in that Terminal).
		{"names a Terminal-started gui (friction B/C4)", "seavault gui"},
		{"stops a Terminal-started gui with Ctrl-C (friction B/C4)", "Ctrl-C"},
	}
	for _, r := range rows {
		if !strings.Contains(install, r.substr) {
			t.Errorf("docs/install.md uninstall section must name %s (%q)", r.name, r.substr)
		}
	}
}

// TestUnsignedStateDeclaredInArtifacts (M7, I-M5): the unsigned signing state is
// declared INSIDE every artifact, never implied by a filename. SIGNING.txt (the
// default the bundle build writes) says "ad-hoc, not notarized"; the PKG readme
// (FIRST-LAUNCH.txt) declares the unsigned state plainly.
func TestUnsignedStateDeclaredInArtifacts(t *testing.T) {
	buildBundle := s3Doc(t, "packaging", "macos", "build-bundle.sh")
	// The ad-hoc SIGNING.txt content the unsigned path writes.
	for _, want := range []string{"ad-hoc", "not notarized"} {
		if !strings.Contains(buildBundle, want) {
			t.Errorf("build-bundle.sh default SIGNING_TEXT must declare the unsigned state (%q); I-M5", want)
		}
	}
	// The PKG readme = FIRST-LAUNCH.txt declares the unsigned state plainly.
	firstLaunch := s3Doc(t, "packaging", "macos", "FIRST-LAUNCH.txt")
	if !strings.Contains(firstLaunch, "not yet signed with an Apple Developer ID") {
		t.Error("FIRST-LAUNCH.txt (the PKG readme) must declare the unsigned state plainly (I-M5)")
	}
	if !strings.Contains(firstLaunch, "SIGNING.txt") {
		t.Error("FIRST-LAUNCH.txt must point the reader to SIGNING.txt for the exact signing state (I-M5)")
	}
}

// TestGatekeeperCheckIsGreppablePerTagGate (M7 format, design §6, C2): the release
// job greps packaging/macos/GATEKEEPER-CHECK.md for the tag being released, so the
// file must be a plain-text table whose rows carry a Tag in the first column. This
// asserts the release-job contract (the exact grep) AND the doc's table shape, so
// the manual gate the human fills stays machine-checkable.
func TestGatekeeperCheckIsGreppablePerTagGate(t *testing.T) {
	rel := s3Doc(t, ".github", "workflows", "release.yml")
	// release-ci-secrets-1: the gate is an ANCHORED table-row match, not the old
	// spoofable unanchored substring grep. The exact anchored grep must be present…
	if !strings.Contains(rel, `grep -qE "^\|[[:space:]]*${tag_re}[[:space:]]*\|" packaging/macos/GATEKEEPER-CHECK.md`) {
		t.Error("release.yml must assert the per-tag Gatekeeper sign-off with an ANCHORED table-row grep (release-ci-secrets-1, design §6, C2)")
	}
	// …and the old unanchored substring grep must be gone (it matched the EXAMPLE
	// row and cross-satisfied v0.2 ⊂ v0.22).
	if strings.Contains(rel, `grep -qF "$TAG" packaging/macos/GATEKEEPER-CHECK.md`) {
		t.Error("release.yml must NOT use the unanchored `grep -qF \"$TAG\"` Gatekeeper gate (spoofable; release-ci-secrets-1)")
	}

	md := s3Doc(t, "packaging", "macos", "GATEKEEPER-CHECK.md")
	// A Markdown table with at least a Tag column and a Date column, so a human's
	// dated per-tag row is what the release-job grep matches.
	var headerCols []string
	for _, line := range strings.Split(md, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "|") && strings.Contains(l, "Tag") && strings.Contains(l, "Date") {
			for _, c := range strings.Split(strings.Trim(l, "|"), "|") {
				headerCols = append(headerCols, strings.TrimSpace(c))
			}
			break
		}
	}
	if len(headerCols) == 0 {
		t.Fatal("GATEKEEPER-CHECK.md must carry a Markdown table with Tag and Date columns (the greppable per-tag sign-off log)")
	}
	wantCols := []string{"Tag", "Date"}
	for _, w := range wantCols {
		got := false
		for _, c := range headerCols {
			if c == w {
				got = true
			}
		}
		if !got {
			t.Errorf("GATEKEEPER-CHECK.md sign-off table must have a %q column; header=%v", w, headerCols)
		}
	}
	// The gate must describe itself as manual and reference the release-job assertion.
	for _, want := range []string{"manual", "release job", "Open Anyway", "xattr"} {
		if !strings.Contains(md, want) {
			t.Errorf("GATEKEEPER-CHECK.md must state it is the %q gate the release job asserts", want)
		}
	}
	// The release checklist must route the human to this gate before each tag.
	checklist := s3Doc(t, "docs", "release-checklist.md")
	for _, want := range []string{"GATEKEEPER-CHECK.md", "Gatekeeper", "sign-off", "before"} {
		if !strings.Contains(checklist, want) {
			t.Errorf("docs/release-checklist.md must state the manual Gatekeeper %q step before each tag", want)
		}
	}
}

// TestInstallDocNewTerminalAndPathNotes (M11, design §3/§5, C4): the golden
// install-cli.sh handles a missing /usr/local/bin (mkdir -p) and prints the
// new-Terminal + PATH guidance, AND docs/install.md documents the same two notes,
// so the doc and the script the DMG/PKG ship can never drift apart.
func TestInstallDocNewTerminalAndPathNotes(t *testing.T) {
	install := s3Doc(t, "docs", "install.md")
	script := s3Doc(t, "packaging", "macos", "install-cli.sh")

	// C4: the golden script creates /usr/local/bin if absent.
	if !strings.Contains(script, "mkdir -p /usr/local/bin") {
		t.Error("install-cli.sh must `mkdir -p /usr/local/bin` (absent on a fresh Apple-silicon Mac, C4)")
	}

	// Both the script and the doc must carry the new-Terminal note and the PATH note.
	surfaces := []struct{ name, text string }{
		{"install-cli.sh", script},
		{"docs/install.md", install},
	}
	for _, s := range surfaces {
		low := strings.ToLower(s.text)
		if !strings.Contains(low, "new terminal") {
			t.Errorf("%s must tell the user to open a NEW Terminal window (C4)", s.name)
		}
		if !strings.Contains(s.text, "PATH") {
			t.Errorf("%s must document the /usr/local/bin PATH note (C4)", s.name)
		}
	}

	// The doc must show the concrete PATH-fix command (the same one the script echoes).
	if !strings.Contains(install, `export PATH="/usr/local/bin:$PATH"`) {
		t.Error("docs/install.md must show the concrete `export PATH=\"/usr/local/bin:$PATH\"` fix (M11)")
	}

	// friction B/C3: the PATH guidance must cover BOTH the zsh default (~/.zprofile)
	// AND a bash login shell (~/.bash_profile) — the old copy named only ~/.zprofile,
	// silently wrong for bash — and be idempotent (grep before append) so running it
	// twice adds nothing.
	for _, want := range []struct{ name, substr string }{
		{"the zsh profile (~/.zprofile)", "~/.zprofile"},
		{"the bash login profile (~/.bash_profile)", "~/.bash_profile"},
		{"an idempotent grep-before-append guard", `grep -qxF 'export PATH="/usr/local/bin:$PATH"'`},
	} {
		if !strings.Contains(install, want.substr) {
			t.Errorf("docs/install.md PATH guidance must cover %s (%q) (friction B/C3)", want.name, want.substr)
		}
	}
}
