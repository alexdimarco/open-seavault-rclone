// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Phase U5 FIXER B (packaging + workflows) regression guards. Each test binds a
// filed adversarial/friction finding to the exact workflow/script content that
// fixes it (a drift guard: revert the fix and the binding assertion goes red), and
// where the behaviour is executable on Linux it is ALSO exercised end-to-end so the
// assertion can never pass vacuously.

func fbRepoPath(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return p
}

// gatekeeperAnchoredMatch mirrors the release.yml gate: an ANCHORED table-row match
// whose Tag column equals the tag exactly, built by escaping every regex
// metacharacter in the tag. It runs the REAL grep so the semantics are proven, not
// asserted from memory. The workflow is bound to this by TestGatekeeperGate below,
// which asserts release.yml carries the identical grep string.
func gatekeeperAnchoredMatch(t *testing.T, file, tag string) bool {
	t.Helper()
	// tag_re="$(printf '%s' "$TAG" | sed 's/[^[:alnum:]]/\\&/g')"
	var b strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	pat := `^\|[[:space:]]*` + b.String() + `[[:space:]]*\|`
	cmd := exec.Command("grep", "-qE", pat, file)
	err := cmd.Run()
	return err == nil
}

// TestGatekeeperGate (release-ci-secrets-1, friction B/C5+C/C2): the Gatekeeper
// sign-off gate is an anchored per-tag ROW match (not a spoofable substring), it
// runs in the release job BEFORE gh release create, and the EXAMPLE row is deleted.
func TestGatekeeperGate(t *testing.T) {
	if _, err := exec.LookPath("grep"); err != nil {
		t.Skip("grep unavailable")
	}

	// Behavioural: seed a fixture with an example row + a real v0.22.0 row and prove
	// the anchored match rejects the spoofs the unanchored grep accepted.
	fix := filepath.Join(t.TempDir(), "gk.md")
	if err := os.WriteFile(fix, []byte(
		"| Tag | Date |\n|-----|------|\n"+
			"| v0.0.0-EXAMPLE | 2026-01-01 |\n"+
			"| v0.22.0 | 2026-09-09 |\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tag  string
		want bool
	}{
		{"v0.22.0", true},        // exact row present
		{"v0.0.0", false},        // must NOT be satisfied by v0.0.0-EXAMPLE
		{"v0.2", false},          // must NOT be satisfied by v0.22.0 (substring)
		{"v0.22", false},         // must NOT be satisfied by v0.22.0 (prefix)
		{"v0.0.0-EXAMPLE", true}, // literal example row (only if one exists)
		{"v0.23.0", false},       // no row
	}
	for _, c := range cases {
		if got := gatekeeperAnchoredMatch(t, fix, c.tag); got != c.want {
			t.Errorf("anchored gate(%q) = %v, want %v (release-ci-secrets-1)", c.tag, got, c.want)
		}
	}

	// Binding: release.yml must carry this exact anchored grep, and NOT the old
	// unanchored substring grep.
	rel := s3Doc(t, ".github", "workflows", "release.yml")
	if !strings.Contains(rel, `grep -qE "^\|[[:space:]]*${tag_re}[[:space:]]*\|" packaging/macos/GATEKEEPER-CHECK.md`) {
		t.Error("release.yml must use the anchored table-row Gatekeeper grep (release-ci-secrets-1)")
	}
	if strings.Contains(rel, `grep -qF "$TAG" packaging/macos/GATEKEEPER-CHECK.md`) {
		t.Error("release.yml must not use the unanchored `grep -qF \"$TAG\"` gate (spoofable, release-ci-secrets-1)")
	}
	if !strings.Contains(rel, `sed 's/[^[:alnum:]]/\\&/g'`) {
		t.Error("release.yml must escape regex metacharacters in the tag before the anchored grep (release-ci-secrets-1)")
	}

	// Position: the gate runs in the release job, BEFORE gh release create.
	idxGate := strings.Index(rel, "Assert the per-tag Gatekeeper sign-off exists BEFORE publishing")
	idxCreate := strings.Index(rel, "gh release create")
	idxMacos := strings.Index(rel, "\n  macos:")
	if idxGate < 0 || idxCreate < 0 || idxMacos < 0 {
		t.Fatalf("release.yml missing gate/create/macos anchors (gate=%d create=%d macos=%d)", idxGate, idxCreate, idxMacos)
	}
	if !(idxGate < idxCreate) {
		t.Error("the Gatekeeper gate must run BEFORE gh release create (release-ci-secrets-1, friction C/C2)")
	}
	if !(idxCreate < idxMacos) {
		t.Error("gh release create must be in the release job, before the macos job (release-ci-secrets-1)")
	}

	// The EXAMPLE row must be deleted from the sign-off log.
	mdText := s3Doc(t, "packaging", "macos", "GATEKEEPER-CHECK.md")
	for _, line := range strings.Split(mdText, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "| v0.0.0-EXAMPLE") {
			t.Error("GATEKEEPER-CHECK.md must not carry the v0.0.0-EXAMPLE sign-off row (release-ci-secrets-1)")
		}
	}
}

// TestReleaseBodyPrependIsIdempotent (release-ci-secrets-2): the release-body
// prepend is idempotent (a re-run does not stack a second note) and the M9
// self-check FAILS on a doubled body.
func TestReleaseBodyPrependIsIdempotent(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	rel := s3Doc(t, ".github", "workflows", "release.yml")

	// Binding: the prepend must guard on the body already beginning with the note,
	// and the M9 check must count occurrences and fail on more than one.
	bindings := []string{
		`case "$body" in`,
		`"$firstline"*)`,
		`grep -Fxc -- "$firstline"`,
	}
	for _, b := range bindings {
		if !strings.Contains(rel, b) {
			t.Errorf("release.yml prepend must contain %q for idempotency + doubled-body detection (release-ci-secrets-2)", b)
		}
	}
	if !strings.Contains(rel, `!= "1"`) {
		t.Error("release.yml M9 check must fail when the note count is not exactly 1 (release-ci-secrets-2)")
	}

	// Behavioural: the idempotent-prepend + M9-count algorithm the workflow uses.
	// Prepending N times yields the note exactly once; a forced doubled body fails.
	script := `
set -u
NOTE="$1"; BODY="$2"
firstline="$(head -1 "$NOTE")"
body="$(cat "$BODY")"
case "$body" in
  "$firstline"*) : ;;  # already prepended
  *) { cat "$NOTE"; echo; echo '---'; echo; printf '%s\n' "$body"; } > "$BODY.new"; mv "$BODY.new" "$BODY" ;;
esac
newbody="$(cat "$BODY")"
case "$newbody" in "$firstline"*) : ;; *) echo NOBEGIN; exit 2 ;; esac
count="$(printf '%s\n' "$newbody" | grep -Fxc -- "$firstline" || true)"
[ "${count:-0}" = "1" ] || { echo "DOUBLED:$count"; exit 3; }
echo OK
`
	dir := t.TempDir()
	note := filepath.Join(dir, "NOTE.txt")
	body := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(note, []byte("open-seavault-rclone — first launch on macOS\nl2\nl3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(body, []byte("Generated notes.\n- a change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func() (string, int) {
		cmd := exec.Command("sh", "-c", script, "sh", note, body)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run: %v", err)
		}
		return strings.TrimSpace(string(out)), code
	}
	for i := 0; i < 3; i++ {
		out, code := run()
		if code != 0 || out != "OK" {
			t.Fatalf("prepend run %d: out=%q code=%d, want OK/0 (idempotent, release-ci-secrets-2)", i, out, code)
		}
	}
	// Force a doubled body; the M9 count check must fail.
	nb, _ := os.ReadFile(body)
	doubled := append([]byte("open-seavault-rclone — first launch on macOS\nl2\nl3\n\n---\n\n"), nb...)
	if err := os.WriteFile(body, doubled, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run()
	if code == 0 || !strings.HasPrefix(out, "DOUBLED:") {
		t.Fatalf("doubled body must fail M9; got out=%q code=%d (release-ci-secrets-2)", out, code)
	}
}

// TestInstallCliMissingBinaryGuard (friction B/C1): running the golden
// install-cli.sh before the app exists prints the drag-the-app message and exits
// non-zero BEFORE any sudo re-exec.
func TestInstallCliMissingBinaryGuard(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	golden := fbRepoPath(t, "packaging", "macos", "install-cli.sh")
	if _, err := os.Stat("/Applications/open-seavault-rclone.app/Contents/MacOS/open-seavault-rclone"); err == nil {
		t.Skip("the bundle binary exists on this host; cannot exercise the missing-binary guard")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sudo-was-called")
	fakeSudo := filepath.Join(dir, "sudo")
	// A fake sudo that RECORDS its invocation and exits (never re-execs, so a
	// neutralized guard cannot loop). With the guard present it is never reached.
	if err := os.WriteFile(fakeSudo, []byte("#!/bin/sh\n: > \""+sentinel+"\"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", golden)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("install-cli.sh must exit non-zero when the bundle binary is missing (friction B/C1); output:\n%s", out)
	}
	if !strings.Contains(string(out), "Drag open-seavault-rclone.app into /Applications first, then run this again.") {
		t.Fatalf("install-cli.sh must print the drag-the-app message (friction B/C1); got:\n%s", out)
	}
	if _, e := os.Stat(sentinel); e == nil {
		t.Fatal("the binary-exists guard must fire BEFORE the sudo re-exec (friction B/C1)")
	}
}

// TestInstallCliSymlinkHardening (installer-scripts-1): the golden removes any
// pre-existing entry, uses ln -sfn (no deref of a symlink-to-dir), and verifies
// readlink. The binding assertions catch a revert; the executable mechanism proves
// the attack the finding describes is actually defeated.
func TestInstallCliSymlinkHardening(t *testing.T) {
	golden := s2Read(t, "packaging", "macos", "install-cli.sh")
	for _, tok := range []string{"ln -sfn", "rm -f /usr/local/bin/seavault", "readlink /usr/local/bin/seavault"} {
		if !strings.Contains(golden, tok) {
			t.Errorf("install-cli.sh must contain %q (installer-scripts-1)", tok)
		}
	}
	// A verify-or-fail branch must be present.
	if !strings.Contains(golden, "Install failed:") {
		t.Error("install-cli.sh must fail loudly when readlink does not equal the intended target (installer-scripts-1)")
	}

	if _, err := exec.LookPath("ln"); err != nil {
		t.Skip("ln unavailable")
	}
	// Mechanism: pre-plant seavault -> attacker_dir, then run the golden's hardened
	// sequence; the link must end up pointing at the real bin, and nothing may be
	// dropped inside attacker_dir. (A plain `ln -sf` would deref and drop a link in
	// attacker_dir — the exact defect installer-scripts-1 reports.)
	dir := t.TempDir()
	attacker := filepath.Join(dir, "attacker")
	realDir := filepath.Join(dir, "real")
	if err := os.MkdirAll(attacker, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(realDir, "open-seavault-rclone")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "seavault")
	if err := os.Symlink(attacker, target); err != nil {
		t.Fatal(err)
	}
	sh := "set -eu\n" +
		"rm -f \"$1\"\n" +
		"ln -sfn \"$2\" \"$1\"\n" +
		"got=\"$(readlink \"$1\" || true)\"\n" +
		"[ \"$got\" = \"$2\" ] || { echo BADLINK; exit 1; }\n"
	cmd := exec.Command("sh", "-c", sh, "sh", target, bin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hardened symlink sequence failed: %v\n%s", err, out)
	}
	got, err := os.Readlink(target)
	if err != nil || got != bin {
		t.Fatalf("target must point at the real bin, got %q err=%v (installer-scripts-1)", got, err)
	}
	entries, _ := os.ReadDir(attacker)
	if len(entries) != 0 {
		t.Fatalf("no link may be dropped inside the pre-existing symlink target dir; found %d entries (installer-scripts-1)", len(entries))
	}
}

// TestVerifyBundleChecksDmgCommandGolden (installer-scripts-2): verify-bundle.sh
// cmp -s's the golden install-cli.sh against BOTH the PKG postinstall and the DMG
// .command, so the DMG entry point cannot silently drift.
func TestVerifyBundleChecksDmgCommandGolden(t *testing.T) {
	v := s2Read(t, "packaging", "macos", "verify-bundle.sh")
	// At least two byte-identity checks against the golden (PKG postinstall + DMG .command).
	n := strings.Count(v, `cmp -s "$INSTALL_CLI_SRC"`)
	if n < 2 {
		t.Errorf("verify-bundle.sh must cmp -s the golden against BOTH the postinstall and the DMG .command; found %d cmp checks (installer-scripts-2)", n)
	}
	// The DMG .command comparison specifically.
	if !strings.Contains(v, `cmp -s "$INSTALL_CLI_SRC" "$MP/Install command-line tool.command"`) {
		t.Error("verify-bundle.sh must byte-compare the DMG .command to the golden install-cli.sh (installer-scripts-2)")
	}
}

// TestFirstLaunchNoteTierGated (installer-scripts-3): a signed-tier note (no
// Gatekeeper workaround, no macOS version list) exists and the release job
// substitutes it for the unsigned note on the notarized path across the app, DMG,
// PKG readme, and release body.
func TestFirstLaunchNoteTierGated(t *testing.T) {
	signed := s2Read(t, "packaging", "macos", "FIRST-LAUNCH-SIGNED.txt")
	// Declares the signed/notarized state; opens normally; points at SIGNING.txt.
	for _, want := range []string{"signed with an Apple Developer ID", "notarized", "SIGNING.txt"} {
		if !strings.Contains(signed, want) {
			t.Errorf("FIRST-LAUNCH-SIGNED.txt must declare the signed tier (%q) (installer-scripts-3)", want)
		}
	}
	// No workaround (the whole point of the signed tier) and no closed macOS list.
	for _, forbidden := range []string{"Open Anyway", "xattr", "Control-click", "Privacy & Security", "Ventura", "Sonoma", "Sequoia", "not yet signed"} {
		if strings.Contains(signed, forbidden) {
			t.Errorf("FIRST-LAUNCH-SIGNED.txt must NOT carry the unsigned-tier workaround/version text (%q) (installer-scripts-3)", forbidden)
		}
	}

	rel := s3Doc(t, ".github", "workflows", "release.yml")
	// Tier selection: signed note on the devid path, unsigned note otherwise.
	if !strings.Contains(rel, `NOTE_SRC="packaging/macos/FIRST-LAUNCH-SIGNED.txt"`) {
		t.Error("release.yml must select the signed-tier note on the notarized path (installer-scripts-3)")
	}
	if !strings.Contains(rel, `NOTE_SRC="packaging/macos/FIRST-LAUNCH.txt"`) {
		t.Error("release.yml must select the unsigned note on the ad-hoc path (installer-scripts-3)")
	}
	// The note source is threaded into the app/DMG/PKG builds and the release body.
	if strings.Count(rel, `FIRST_LAUNCH_SRC="$NOTE_SRC"`) < 3 {
		t.Errorf("release.yml must pass the tier note to build-bundle/build-dmg/build-pkg on the notarized path (installer-scripts-3); found %d", strings.Count(rel, `FIRST_LAUNCH_SRC="$NOTE_SRC"`))
	}
	if !strings.Contains(rel, `cat "$NOTE_SRC"`) {
		t.Error("release.yml must prepend the tier-selected NOTE_SRC to the release body (installer-scripts-3)")
	}
}

// TestSigningTextSingleSourced (friction C/C3): the ad-hoc SIGNING.txt text is
// single-sourced from build-bundle.sh's default; neither workflow re-authors it on
// the ad-hoc path (only the Developer-ID override sets SIGNING_TEXT).
func TestSigningTextSingleSourced(t *testing.T) {
	bundle := s2Read(t, "packaging", "macos", "build-bundle.sh")
	if !strings.Contains(bundle, `SIGNING_TEXT="${SIGNING_TEXT:-ad-hoc signed, not notarized}"`) {
		t.Error("build-bundle.sh must be the single source of the ad-hoc SIGNING.txt text (friction C/C3)")
	}
	ci := s2Read(t, ".github", "workflows", "ci-macos.yml")
	if strings.Contains(ci, "SIGNING_TEXT=") {
		t.Error("ci-macos.yml must pass NO SIGNING_TEXT (single-sourced from build-bundle.sh, friction C/C3)")
	}
	rel := s3Doc(t, ".github", "workflows", "release.yml")
	if strings.Contains(rel, `SIGNING_TEXT="ad-hoc`) {
		t.Error("release.yml must not author the ad-hoc SIGNING text; only the Developer-ID override sets SIGNING_TEXT (friction C/C3)")
	}
}

// TestWorkflowsInjectLinkerVersion (version injection, friction C/C4/C6): both
// workflows build with -X main.version=<value> — the tag without its leading v on a
// release, 0.0.0-ci-<sha> on a non-tag ci build.
func TestWorkflowsInjectLinkerVersion(t *testing.T) {
	rel := s3Doc(t, ".github", "workflows", "release.yml")
	if !strings.Contains(rel, `-X main.version=${BUILD_VERSION}`) {
		t.Error("release.yml go build must inject -X main.version (version injection)")
	}
	if !strings.Contains(rel, `BUILD_VERSION="${VERSION#v}"`) {
		t.Error("release.yml must derive the injected version as the tag without its leading v (version injection)")
	}
	ci := s2Read(t, ".github", "workflows", "ci-macos.yml")
	if !strings.Contains(ci, `-X main.version=${BUILD_VERSION}`) {
		t.Error("ci-macos.yml go build must inject -X main.version (version injection)")
	}
	if !strings.Contains(ci, `BUILD_VERSION="0.0.0-ci-${GITHUB_SHA:0:7}"`) {
		t.Error("ci-macos.yml must derive the injected version as 0.0.0-ci-<sha> on a non-tag build (version injection)")
	}
	// The plain -s -w with no -X must be gone from every build line.
	for _, wf := range []struct{ name, txt string }{{"release.yml", rel}, {"ci-macos.yml", ci}} {
		for _, line := range strings.Split(wf.txt, "\n") {
			if strings.Contains(line, "go build") && strings.Contains(line, "-ldflags") && !strings.Contains(line, "main.version") {
				t.Errorf("%s go build line still has no version injection: %q", wf.name, strings.TrimSpace(line))
			}
		}
	}
}

// TestCiMacosPathsCoverSmokePackages (release-ci-secrets-3): the ci-macos path scope
// covers internal/bundlelaunch and internal/webui (the code the M8 smoke exercises),
// while doc-only files still do not trigger it.
func TestCiMacosPathsCoverSmokePackages(t *testing.T) {
	ci := s2Read(t, ".github", "workflows", "ci-macos.yml")
	paths := extractYAMLList(ci, "paths")
	if len(paths) == 0 {
		t.Fatal("ci-macos.yml paths must be a non-empty list")
	}
	matchAny := func(probe string) bool {
		for _, p := range paths {
			if ghGlobToRegexp(p).MatchString(probe) {
				return true
			}
		}
		return false
	}
	for _, probe := range []string{
		"internal/bundlelaunch/lock.go",
		"internal/bundlelaunch/relaunch.go",
		"internal/webui/server.go",
		"internal/webui/heartbeat.go",
	} {
		if !matchAny(probe) {
			t.Errorf("ci-macos.yml path scope must cover the M8-smoke input %q (release-ci-secrets-3); paths=%v", probe, paths)
		}
	}
	// A doc-only commit must still be excluded.
	for _, probe := range []string{"README.md", "docs/install.md", "SECURITY.md"} {
		if matchAny(probe) {
			t.Errorf("ci-macos.yml must NOT trigger on doc-only %q (C5)", probe)
		}
	}
}

// TestPartialSigningSecretsFailClosed (release-ci-secrets-4, friction C/C1): partial
// signing secrets fail the job (naming the missing ones) rather than silently
// degrading to the unsigned tier; all-present is the signed tier; none-present is
// ad-hoc.
func TestPartialSigningSecretsFailClosed(t *testing.T) {
	rel := s3Doc(t, ".github", "workflows", "release.yml")
	// Binding: the fail-closed decision must be present.
	for _, b := range []string{
		`req_names="MACOS_DEVELOPER_ID_P12 MACOS_DEVELOPER_ID_P12_PASSWORD APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID APPLE_NOTARY_KEY_P8"`,
		"refusing to ship a silently-unsigned release",
		"missing required signing secrets:",
	} {
		if !strings.Contains(rel, b) {
			t.Errorf("release.yml must fail closed on partial signing secrets: missing %q (release-ci-secrets-4)", b)
		}
	}

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	// Behavioural: the exact fail-closed decision the workflow uses. Prints
	// SIGNED / ADHOC / (exit 1) and names the missing secrets on a partial config.
	decide := `
req_names="MACOS_DEVELOPER_ID_P12 MACOS_DEVELOPER_ID_P12_PASSWORD APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID APPLE_NOTARY_KEY_P8"
present=0; total=0; missing=""
for n in $req_names; do
  total=$((total+1)); eval "v=\${$n:-}"
  if [ -n "$v" ]; then present=$((present+1)); else missing="$missing $n"; fi
done
opt_present=0
[ -n "${MACOS_INSTALLER_ID_P12:-}" ] && opt_present=1
[ -n "${MACOS_INSTALLER_ID_P12_PASSWORD:-}" ] && opt_present=1
if [ "$present" -eq "$total" ]; then echo SIGNED; exit 0
elif [ "$present" -gt 0 ] || [ "$opt_present" -eq 1 ]; then echo "PARTIAL missing:$missing" >&2; exit 1
fi
echo ADHOC; exit 0
`
	allFive := []string{
		"MACOS_DEVELOPER_ID_P12=x", "MACOS_DEVELOPER_ID_P12_PASSWORD=x",
		"APPLE_NOTARY_KEY_ID=x", "APPLE_NOTARY_ISSUER_ID=x", "APPLE_NOTARY_KEY_P8=x",
	}
	run := func(env []string) (string, string, int) {
		cmd := exec.Command("sh", "-c", decide)
		cmd.Env = env
		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run decide: %v", err)
		}
		return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), code
	}

	// None present -> ad-hoc, exit 0.
	if out, _, code := run([]string{}); out != "ADHOC" || code != 0 {
		t.Errorf("no signing secrets -> ADHOC/0, got %q/%d (release-ci-secrets-4)", out, code)
	}
	// All five present -> signed, exit 0.
	if out, _, code := run(allFive); out != "SIGNED" || code != 0 {
		t.Errorf("all signing secrets -> SIGNED/0, got %q/%d (release-ci-secrets-4)", out, code)
	}
	// Only the p12 present -> fail closed, exit 1, naming the missing notary secrets.
	if _, serr, code := run([]string{"MACOS_DEVELOPER_ID_P12=x"}); code != 1 || !strings.Contains(serr, "APPLE_NOTARY_KEY_P8") {
		t.Errorf("partial secrets must fail closed naming what's missing; stderr=%q code=%d (release-ci-secrets-4)", serr, code)
	}
	// Only the (optional) installer cert present, no required -> also fail closed.
	if _, _, code := run([]string{"MACOS_INSTALLER_ID_P12=x"}); code != 1 {
		t.Errorf("a lone installer cert with no Developer-ID/notary secrets must fail closed; code=%d (release-ci-secrets-4)", code)
	}
}

// TestPkgNotarizeGatedOnInstallerSign (release-ci-secrets-4): the PKG is notarized
// only when it was productsigned with a Developer ID Installer cert; otherwise it
// ships un-notarized rather than aborting the release on an Invalid notarization.
func TestPkgNotarizeGatedOnInstallerSign(t *testing.T) {
	rel := s3Doc(t, ".github", "workflows", "release.yml")
	// productsign sets pkg_signed=1…
	iSet := strings.Index(rel, "pkg_signed=1")
	iGate := strings.Index(rel, `if [ "$pkg_signed" = "1" ]; then`)
	iNotarizePkg := strings.Index(rel, `notarize "$PKG"`)
	if iSet < 0 || iGate < 0 || iNotarizePkg < 0 {
		t.Fatalf("release.yml must gate PKG notarization on productsign (set=%d gate=%d notarize=%d) (release-ci-secrets-4)", iSet, iGate, iNotarizePkg)
	}
	// …and the only notarize "$PKG" call is inside the pkg_signed gate.
	if !(iGate < iNotarizePkg) {
		t.Error("notarize \"$PKG\" must be guarded by the pkg_signed gate (release-ci-secrets-4)")
	}
	if strings.Count(rel, `notarize "$PKG"`) != 1 {
		t.Errorf("expected exactly one guarded notarize \"$PKG\"; found %d (release-ci-secrets-4)", strings.Count(rel, `notarize "$PKG"`))
	}
}
