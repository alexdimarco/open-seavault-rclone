// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Phase U5 slice S2 (packaging + jobs) Linux-side guards. The packaging rows
// themselves (M3, M4, M6, M8) run on a real macOS runner through
// packaging/macos/verify-bundle.sh; the rows here assert the Linux-checkable
// invariants: the golden CLI-install script is minimal and byte-identical across
// the DMG .command and the PKG postinstall sources (M5's golden, design §3/I-M4),
// the workflow files declare the packaging job and its guards (M12, design §4/§9
// C5), and the single-source FIRST-LAUNCH text carries the current-macOS
// Gatekeeper wording the release body prepends (M9, design §5/I-M5/C3).

func s2Read(t *testing.T, parts ...string) string {
	t.Helper()
	return mustReadRepoFile(t, filepath.Join(append([]string{"..", ".."}, parts...)...))
}

// TestInstallCliGoldenIsMinimal (M5, I-M4, C4): the golden install-cli.sh ensures
// /usr/local/bin exists and creates exactly one symlink, and does nothing else —
// no network, no other writes. Asserted on every forbidden token so the "nothing
// else" claim can never pass vacuously.
func TestInstallCliGoldenIsMinimal(t *testing.T) {
	golden := s2Read(t, "packaging", "macos", "install-cli.sh")

	// The two load-bearing actions must be present.
	must := []struct{ name, substr string }{
		{"mkdir -p of /usr/local/bin (C4: absent on a fresh Apple-silicon Mac)", "mkdir -p /usr/local/bin"},
		{"the /usr/local/bin/seavault symlink", "ln -sf"},
		{"the symlink target is /usr/local/bin/seavault", "/usr/local/bin/seavault"},
		{"the symlink source is the bundle binary", "/Contents/MacOS/open-seavault-rclone"},
	}
	for _, m := range must {
		if !strings.Contains(golden, m.substr) {
			t.Errorf("install-cli.sh must contain %s (%q)", m.name, m.substr)
		}
	}

	// "Nothing else": no network, no fetches, no other privileged writes. Every
	// forbidden token is asserted absent so the golden cannot quietly grow a leg.
	forbidden := []string{
		"curl", "wget", "nc ", "ncat", "scp", "sftp", "ssh ",
		"http://", "https://", "ftp://",
		"rm -rf", "chown", "chmod 777",
		"launchctl", "defaults write", "pkgutil --forget",
	}
	for _, f := range forbidden {
		if strings.Contains(golden, f) {
			t.Errorf("install-cli.sh must do nothing beyond mkdir+symlink; forbidden token present: %q", f)
		}
	}

	// The only two filesystem-mutating verbs allowed are mkdir and ln. Any other
	// write verb as a COMMAND (first token of a command segment) is a smell. We
	// tokenize on command separators so a word like "add" inside an echo is not a
	// false "dd".
	badVerbs := map[string]bool{"cp": true, "mv": true, "tee": true, "install": true, "dd": true, "rsync": true}
	segSplit := regexp.MustCompile(`[;&|(){}]|&&|\|\|`)
	for _, line := range strings.Split(golden, "\n") {
		code := line
		if i := strings.Index(code, "#"); i >= 0 {
			code = code[:i]
		}
		for _, seg := range segSplit.Split(code, -1) {
			fields := strings.Fields(seg)
			if len(fields) == 0 {
				continue
			}
			first := fields[0]
			// Skip a leading VAR=... assignment prefix.
			for len(fields) > 1 && strings.Contains(first, "=") && !strings.ContainsAny(first, "/\"'") {
				fields = fields[1:]
				first = fields[0]
			}
			if badVerbs[first] {
				t.Errorf("install-cli.sh must not run %q as a command (mkdir + symlink only): %q", first, line)
			}
		}
	}
}

// TestInstallCliByteIdenticalAcrossSources (M5's golden, design §3): the DMG
// .command and the PKG postinstall are the SAME file. The build scripts must ship
// packaging/macos/install-cli.sh VERBATIM (a plain copy, never a sed/awk rewrite)
// to both destinations, so the two installer entry points can never drift.
func TestInstallCliByteIdenticalAcrossSources(t *testing.T) {
	dmg := s2Read(t, "packaging", "macos", "build-dmg.sh")
	pkg := s2Read(t, "packaging", "macos", "build-pkg.sh")

	// Each build script copies install-cli.sh verbatim to its installer entry
	// point (the .command / the postinstall). We assert the reference plus the
	// absence of any transform on it.
	cases := []struct {
		name, script, dest string
	}{
		{"DMG .command", dmg, "Install command-line tool.command"},
		{"PKG postinstall", pkg, "postinstall"},
	}
	for _, c := range cases {
		if !strings.Contains(c.script, "install-cli.sh") {
			t.Errorf("%s build script must source packaging/macos/install-cli.sh (byte-identical golden)", c.name)
		}
		if !strings.Contains(c.script, c.dest) {
			t.Errorf("%s build script must write the golden to %q", c.name, c.dest)
		}
		// A verbatim copy: the script must `cp` the golden install-cli.sh source
		// (referenced via the INSTALL_CLI_SRC var whose default is install-cli.sh)
		// and must not rewrite it with sed/awk (which would break byte-identity).
		cpRe := regexp.MustCompile(`cp\s+[^\n]*INSTALL_CLI_SRC`)
		if !cpRe.MatchString(c.script) {
			t.Errorf("%s build script must `cp` the install-cli.sh golden verbatim (found no plain copy of $INSTALL_CLI_SRC)", c.name)
		}
		for _, transform := range []string{"sed", "awk", "perl", "> \"$", "envsubst"} {
			// Only flag a transform that operates on install-cli.sh on the same line.
			for _, line := range strings.Split(c.script, "\n") {
				if strings.Contains(line, "install-cli.sh") && strings.Contains(line, transform) {
					t.Errorf("%s must not transform install-cli.sh (byte-identity); offending line: %q", c.name, strings.TrimSpace(line))
				}
			}
		}
	}
}

// ghGlobToRegexp converts a GitHub Actions path glob to a regexp: `**` matches
// across separators, `*` within a path segment. Used to prove the ci-macos path
// scope excludes doc-only commits (M12) without a YAML dependency.
func ghGlobToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\', '?':
			b.WriteByte('\\')
			b.WriteByte(glob[i])
		default:
			b.WriteByte(glob[i])
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// extractYAMLList returns the indented list items under a `key:` mapping in a
// (small, trusted, self-authored) YAML block. It reads until dedent. Good enough
// for the fixed-shape workflow files this repo owns.
func extractYAMLList(yaml, key string) []string {
	lines := strings.Split(yaml, "\n")
	var out []string
	inList := false
	keyIndent := -1
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if !inList {
			if strings.HasPrefix(trimmed, key+":") {
				inList = true
				keyIndent = indent
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		if indent <= keyIndent {
			break // dedented out of the list
		}
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(trimmed[2:])
			item = strings.Trim(item, `'"`)
			// Drop a trailing inline comment.
			if i := strings.Index(item, " #"); i >= 0 {
				item = strings.TrimSpace(item[:i])
			}
			out = append(out, item)
		}
	}
	return out
}

// TestCiMacosWorkflowGuards (M12, design §4 C5): ci-macos.yml declares concurrency
// cancel-in-progress, a 30-minute timeout, and a scoped path filter, runs on
// macos-latest, and is explicitly labeled self-consistency (NOT proving I-M1). A
// doc-only commit must not trigger it: no path glob may match a doc file.
func TestCiMacosWorkflowGuards(t *testing.T) {
	ci := s2Read(t, ".github", "workflows", "ci-macos.yml")

	must := []struct{ name, substr string }{
		{"cancel-in-progress", "cancel-in-progress: true"},
		{"a bounded 30-minute timeout", "timeout-minutes: 30"},
		{"runs on a real macOS runner", "runs-on: macos-latest"},
		{"push trigger", "push:"},
		{"path scoping under push", "paths:"},
		{"assembles the bundle", "build-bundle.sh"},
		{"runs the shared verifier", "verify-bundle.sh"},
		{"labeled self-consistency, not I-M1", "self-consistency"},
		{"states it does NOT prove I-M1", "does NOT prove I-M1"},
	}
	for _, m := range must {
		if !strings.Contains(ci, m.substr) {
			t.Errorf("ci-macos.yml must declare %s (%q)", m.name, m.substr)
		}
	}

	// It must run on push to main AND to feature branches.
	branches := extractYAMLList(ci, "branches")
	haveMain, haveFeature := false, false
	for _, b := range branches {
		if b == "main" || b == "master" {
			haveMain = true
		}
		if strings.HasPrefix(b, "feature/") || b == "feature/**" || strings.Contains(b, "feature") {
			haveFeature = true
		}
	}
	if len(branches) == 0 {
		t.Error("ci-macos.yml push.branches must be a non-empty list (main + feature branches)")
	}
	if !haveMain {
		t.Errorf("ci-macos.yml must run on push to main; branches=%v", branches)
	}
	if !haveFeature {
		t.Errorf("ci-macos.yml must run on push to feature branches; branches=%v", branches)
	}

	// The path scope must include the packaging inputs and MUST NOT match a
	// doc-only commit — the whole point of C5.
	paths := extractYAMLList(ci, "paths")
	if len(paths) == 0 {
		t.Fatal("ci-macos.yml push.paths must be a non-empty scoped list (C5)")
	}
	// Packaging inputs must be in scope (so it is not vacuously scoped to nothing).
	packagingProbes := []string{
		"packaging/macos/build-bundle.sh",
		"packaging/macos/verify-bundle.sh",
		"cmd/seavault/main.go",
		"internal/webui/assets/svlogo/icon.png",
		".github/workflows/ci-macos.yml",
	}
	for _, probe := range packagingProbes {
		matched := false
		for _, p := range paths {
			if ghGlobToRegexp(p).MatchString(probe) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("ci-macos.yml path scope must cover the packaging input %q; paths=%v", probe, paths)
		}
	}
	// Doc-only commits must NOT trigger it.
	docProbes := []string{"README.md", "SECURITY.md", "DESIGN.md", "docs/install.md", "docs/design-u5-macos-bundle.md"}
	for _, probe := range docProbes {
		for _, p := range paths {
			if ghGlobToRegexp(p).MatchString(probe) {
				t.Errorf("ci-macos.yml path scope must NOT match the doc-only file %q (a doc commit must skip it, C5); pattern %q matched", probe, p)
			}
		}
	}
}

// TestReleaseWorkflowMacosJob (M12/M9/M3/M4 declarations, design §4): the release
// workflow's first job uploads the two darwin binaries as artifacts, and a second
// macos job downloads them, assembles/verifies/packages, branches ad-hoc vs
// Developer-ID signing, bounds and logs notarization, prepends the first-launch
// note to the Release body, appends the DMG/PKG hashes, and never echoes secrets.
func TestReleaseWorkflowMacosJob(t *testing.T) {
	rel := s2Read(t, ".github", "workflows", "release.yml")

	must := []struct{ name, substr string }{
		{"first job uploads the darwin binaries as artifacts", "upload-artifact"},
		{"a macos job on a real runner", "runs-on: macos-latest"},
		{"the macos job needs the first job", "needs:"},
		{"the macos job downloads the darwin artifacts", "download-artifact"},
		{"assembles the bundle", "build-bundle.sh"},
		{"runs the shared verifier", "verify-bundle.sh"},
		{"builds the DMG", "build-dmg.sh"},
		{"builds the PKG", "build-pkg.sh"},
		{"ad-hoc signs when the Developer ID is absent", "codesign --force --deep -s -"},
		{"Developer-ID cert secret gate", "MACOS_DEVELOPER_ID_P12"},
		{"submits for notarization", "notarytool submit"},
		{"waits for the notarization result under the job's control", "--wait"},
		{"fetches the notary log on non-Accepted (C6)", "notarytool log"},
		{"prepends the first-launch note to the Release body (C3, M9)", "FIRST-LAUNCH.txt"},
		{"edits the release notes", "gh release edit"},
		{"appends the hashes to SHA256SUMS.txt", "SHA256SUMS.txt"},
		{"asserts the Gatekeeper sign-off for the tag (C2)", "GATEKEEPER-CHECK.md"},
		{"masks secrets so they never echo (I-M2)", "add-mask"},
	}
	for _, m := range must {
		if !strings.Contains(rel, m.substr) {
			t.Errorf("release.yml must declare: %s (%q)", m.name, m.substr)
		}
	}

	// The macos job must depend on the linux build job (needs:), so it cannot run
	// against binaries the first job did not produce (I-M1 / C8).
	if !strings.Contains(rel, "macos:") {
		t.Error("release.yml must define a `macos:` job (design §4)")
	}
}

// TestFirstLaunchTextIsCurrentMacOS (M9 support, design §5, C1/C2; friction A/C2,
// B/C1, A/C5, A/C6): the single FIRST-LAUNCH source names the path that works on
// the shipping macOS first (Privacy & Security → Open Anyway) with an OPEN-ENDED
// version floor ("macOS 13 Ventura and later"), never a closed enumeration that
// silently goes stale — the fix for friction A/C2, where the frozen "…, 15 Sequoia"
// list stopped two majors short of the shipping macOS 26 Tahoe. It keeps xattr as a
// co-primary reliable path (and says the app must already be in /Applications),
// demotes Control-click → Open to a macOS 11–12 note, covers the .pkg (and that a
// PKG install usually carries no quarantine, A/C6), names the Sequoia-and-later
// second confirmation dialog, tells the user the blocked-.command recourse (B/C1),
// and states the quit-on-close / no-Dock-icon facts (A/C5). Every row asserts so
// the copy can never silently regress to the pre-15 dead path or re-freeze the list.
func TestFirstLaunchTextIsCurrentMacOS(t *testing.T) {
	txt := s2Read(t, "packaging", "macos", "FIRST-LAUNCH.txt")

	rows := []struct{ name, substr string }{
		{"declares the unsigned state plainly", "not yet signed with an Apple Developer ID"},
		{"names System Settings → Privacy & Security (macOS 13+)", "Privacy & Security"},
		{"the Open Anyway control", "Open Anyway"},
		{"the version-independent xattr command (co-primary)", "xattr -dr com.apple.quarantine"},
		{"the app path in the xattr command", "/Applications/open-seavault-rclone.app"},
		{"Control-click demoted to a macOS 11-12 note", "11"},
		{"Control-click wording present but scoped to 11-12", "Control-click"},
		{"covers the installer package", ".pkg"},
		{"an OPEN-ENDED version floor, not a frozen enumeration (friction A/C2)", "Ventura and later"},
		{"names the Sequoia-and-later second confirmation dialog (friction A/C2 III)", "Sequoia and later"},
		{"tells the user the xattr command targets the app in /Applications (friction A/C2 III)", "into /Applications first"},
		{"documents the blocked-.command recourse (friction B/C1)", `"Install command-line tool.command"`},
		{"notes a PKG install usually carries no quarantine (friction A/C6)", "no quarantine flag"},
		{"states the no-Dock-icon fact (friction A/C5)", "no Dock icon"},
		{"states the quit-on-close fact (friction A/C5)", "quits on its own when you"},
	}
	for _, r := range rows {
		if !strings.Contains(txt, r.substr) {
			t.Errorf("FIRST-LAUNCH.txt must %s (%q)", r.name, r.substr)
		}
	}

	// friction A/C2: the primary "Open Anyway" path must NOT re-freeze into a closed
	// version list. The old copy read "macOS 13 Ventura, 14 Sonoma, 15 Sequoia:",
	// stale the day it shipped; that exact enumeration must never come back.
	if strings.Contains(txt, "14 Sonoma, 15 Sequoia") {
		t.Error("FIRST-LAUNCH.txt path 1 must be open-ended (\"macOS 13 Ventura and later\"), not the frozen \"13 Ventura, 14 Sonoma, 15 Sequoia\" enumeration that stops short of the shipping macOS (friction A/C2)")
	}

	// The dead pre-15 instruction must not be presented as the PRIMARY path: the
	// Privacy & Security / Open Anyway wording must appear BEFORE the first
	// Control-click mention (which is only the 11-12 fallback).
	iOpenAnyway := strings.Index(txt, "Open Anyway")
	iControlClick := strings.Index(txt, "Control-click")
	if iOpenAnyway >= 0 && iControlClick >= 0 && iControlClick < iOpenAnyway {
		t.Error("FIRST-LAUNCH.txt leads with Control-click → Open (dead on macOS 15); Open Anyway must come first (C1)")
	}
}

// TestGatekeeperCheckTemplate (design §6 C2): the manual per-release sign-off file
// exists, explains it is a manual gate the release job asserts, and carries a
// dated table the human fills before each tag. The release job greps it for the
// current tag; here we assert the template's shape so that grep has something to
// match once a human signs off.
func TestGatekeeperCheckTemplate(t *testing.T) {
	md := s2Read(t, "packaging", "macos", "GATEKEEPER-CHECK.md")
	rows := []struct{ name, substr string }{
		{"names the manual gate", "manual"},
		{"references the release-job assertion", "release job"},
		{"a dated sign-off column", "Date"},
		{"a tag column the job greps", "Tag"},
		{"names the Open Anyway path being verified", "Open Anyway"},
		{"names the xattr path being verified", "xattr"},
	}
	for _, r := range rows {
		if !strings.Contains(md, r.substr) {
			t.Errorf("GATEKEEPER-CHECK.md must %s (%q)", r.name, r.substr)
		}
	}
}

// TestInfoPlistTemplate (design §2): the plist template carries the bundle
// identity, the agent (LSUIElement), the LSEnvironment bundle-launch flag, the
// 11.0 floor, and version placeholders the build script fills.
func TestInfoPlistTemplate(t *testing.T) {
	pl := s2Read(t, "packaging", "macos", "Info.plist.template")
	rows := []struct{ name, substr string }{
		{"the bundle identifier", "io.github.alexdimarco.open-seavault-rclone"},
		{"the executable name", "open-seavault-rclone"},
		{"LSUIElement (agent, no Dock icon)", "LSUIElement"},
		{"LSEnvironment", "LSEnvironment"},
		{"the bundle-launch env flag", "SEAVAULT_BUNDLE_LAUNCH"},
		{"the 11.0 minimum system version", "11.0"},
		{"a short-version placeholder", "__SHORT_VERSION__"},
		{"a bundle-version placeholder", "__BUNDLE_VERSION__"},
		{"the icon file", ".icns"},
	}
	for _, r := range rows {
		if !strings.Contains(pl, r.substr) {
			t.Errorf("Info.plist.template must contain %s (%q)", r.name, r.substr)
		}
	}
	// LSUIElement must be true (the agent has no window).
	if !strings.Contains(pl, "<key>LSUIElement</key>") {
		t.Error("Info.plist.template must set LSUIElement as a key")
	}
}
