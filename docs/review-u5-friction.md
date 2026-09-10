<!--
Friction review — Phase U5 (macOS bundle), process/friction-review.md
HOW CELLS WERE WALKED: no real Mac was available. Every cell was walked against
(a) the Linux-built binary `go build -o /tmp/sv-u5/seavault ./cmd/seavault`
(reports 0.21.0), driven through SEAVAULT_BUNDLE_LAUNCH=1 / SEAVAULT_APP_HOME /
--no-open / --bundle-grace where the darwin path is not OS-gated; (b) the
packaging/macos scripts, Info.plist.template, docs, and the U5 drift-guard tests
(all green); and (c) the two green ci-macos runs 34388861436 and 34391651537 on
image macos-26-arm64 (macOS 26.6.2 Tahoe), read via `gh run view --log`. GUI-only
seams — the Finder/Gatekeeper/installer dialogs, the DMG window rendering, the
real double-click relaunch through LaunchServices, the browser open — are headless
on the runner and were read from code/logs, never from a rendered UI; each such
cell says so. The Developer-ID + notarize branch of release.yml and the I-M1
byte-identity check are RELEASE-ONLY and have never executed (no signing secrets,
no tag) — verified by reading the YAML only.
ACTORS: A = macOS DMG hand-install user; B = Mac CLI user; C = new maintainer cold.
CELLS WALKED: 18 (3 actors x 6). FUNCTIONING: yes 8 / partial 10 / no 0.
FINDINGS: Type II 11, Type III 37.
VERDICT: SHIPPABLE_WITH_BACKLOG.
-->

# Phase U5 (macOS bundle) — friction review

**Verdict: SHIPPABLE_WITH_BACKLOG.** No cell fell to `functions=no`, and the golden
path (download DMG → drag to Applications → first launch via the workaround →
browser opens) completes: the version-independent `xattr` path 2 rescues the first
launch even where the GUI "Open Anyway" copy is stale, and the smoke proves the
server binds, writes the 0600 launch URL, answers 200 over loopback, and exits on
page-close. Friction beyond the accepted unsigned-state Type I is real but reducible
without weakening any control — 11 Type II items form the backlog below. This review
was walked with no real Mac (see header); the Gatekeeper/installer GUIs and the real
relaunch remain a per-release human sign-off (GATEKEEPER-CHECK.md), unperformed for
any real tag.

## Type II items that shape the verdict (backlog, none blocks the golden path)

1. **A/C2, C/C2 — FIRST-LAUNCH.txt version list is a frozen enumeration stopping at
   "15 Sequoia."** The shipping OS, and the very OS the green runner used, is macOS 26
   Tahoe. A Tahoe user does not see their version named in the "Open Anyway" path; only
   the "any version" xattr path 2 keeps first launch self-service. This is durability
   concern C1 from the pre-design review re-manifesting: the flow was fixed, the version
   set frozen already-stale at ship. **Fix:** open-ended header ("macOS 13 Ventura and
   later …"); assert the open-ended phrasing (or `sw_vers`) in the M7 drift guard instead
   of the literal "Sequoia," which currently passes green while naming a two-major-old OS.
2. **A/C3 — grace-exit with zero connected pages emits no user-visible signal.** In the
   failure mode the smoke is built around (browser blocked, no page connects), LSUIElement
   means no Dock icon, no window; the launch URL lands only in the 0600 gui.log; the agent
   runs invisibly until the grace kills it. **Fix:** on grace-exit with zero sessions, post
   a macOS user notification carrying the launch URL (stdout is discarded by LaunchServices).
3. **A/C3 — no Dock icon means the only running-state / stop surfaces are the browser tab
   or Activity Monitor/pkill.** Deliberate LSUIElement tradeoff; legibility cost is real
   for a non-technical user. **Fix:** launch notification + an in-tab "closing this tab
   quits the app" line.
4. **B/C1 — install-cli.sh symlinks unconditionally and reports false success.** `ln -sf
   "$BIN" /usr/local/bin/seavault` with no check that $BIN exists: a user who double-clicks
   the .command before dragging the app gets a dangling symlink AND `Installed: …` + exit 0
   (reproduced locally). Their next `seavault version` then fails no-such-file. **Fix:**
   `[ -x "$BIN" ] || { echo "Drag the app into /Applications first…" >&2; exit 1; }`.
5. **B/C1 — the DMG's Install command-line tool.command is itself quarantined**, so it hits
   the same Gatekeeper block as the app on macOS 13–15, but the Open-Anyway/Control-click
   workaround is documented only for "the app" and "the .pkg"; the .command is never named,
   so the documented primary CLI path can dead-end with no recourse. **Fix:** add "if macOS
   blocks the .command, Control-click → Open" to install.md and FIRST-LAUNCH.txt, or steer
   first-time CLI users to the PKG.
6. **B/C5, C/C2 — the manual Gatekeeper sign-off gate is a spoofable substring grep.**
   `grep -qF "$TAG" GATEKEEPER-CHECK.md` (release.yml:88) matches the tag anywhere: `v0.0.0`
   is satisfied by the shipped `v0.0.0-EXAMPLE` row, `v0.2` by a future `v0.22` row. The doc
   claims the gate "cannot be skipped silently." **Fix:** anchor to a table row
   (`grep -qE "^\| *${TAG//./\\.} *\|"`) and delete the example row before the first real tag.
7. **C/C2 — the same gate fires AFTER the GitHub Release is already published.** `gh release
   create` is in the release job (line 61); the grep is in the macos job that `needs:
   release` (line 88). A missing sign-off skips only the DMG/PKG attach and the note prepend
   — the Linux/Windows/raw-darwin tarballs are already live, contradicting the doc's "fails
   the release." **Fix:** move the grep into the release job before `gh release create`.
8. **C/C1 — partial signing secrets fail open to the unsigned tier silently.** `have_devid=1`
   needs all four of p12 + notary key/id/issuer (release.yml:112); set the cert but omit the
   notary key and the job takes the ad-hoc path, writes SIGNING.txt "ad-hoc … not notarized,"
   and verify-bundle passes with EXPECT_SPCTL=reject — a silently-unsigned release with some
   signing secrets present. **Fix:** if some-but-not-all signing secrets are present, fail
   (or masked-warn) rather than degrade.
9. **C/C3 — SIGNING.txt is not single-sourced.** "ad-hoc signed, not notarized" is authored
   three times (build-bundle.sh:34, release.yml:211, ci-macos.yml:56 variant) plus a fourth
   DevID string; the only guard checks build-bundle.sh alone, so release.yml can drift
   uncaught. **Fix:** make build-bundle.sh's default the single source; ad-hoc path passes no
   SIGNING_TEXT, only DevID overrides.
10. **C/C4, C/C6 — the compiled binary version (0.21.0) is out of step with the v0.22 phase
    everywhere else.** `const version = "0.21.0"` (main.go:54); the release build injects no
    `-X`, so the tarball name and Info.plist take GITHUB_REF_NAME while the binary reports an
    independent hand-maintained constant. A maintainer reading v0.22 docs runs 0.21.0 (the
    runner log confirms it on the real artifact). No test couples the const to the tag or
    README. **Fix:** inject via `-ldflags "-X main.version=${GITHUB_REF_NAME#v}"`, or bump the
    const now and add a guard against the newest README "What changed in vX.Y" heading.
11. **C/C6 — "bump the version" in the checklist names no file and does not flag the
    const↔tag↔plist independence.** Tag v0.22.0 while main.go reads 0.21.0 ships a plist that
    says 0.22.0 around a binary that reports 0.21.0 — today's branch state. **Fix:** name
    cmd/seavault/main.go:54 in the checklist and tie to the ldflags/guard fix above.

## Findings table

| Cell | Fn | Friction finding | Type | Fix / backlog |
|------|----|------------------|------|---------------|
| A/C1 DMG contents | partial | Bare UDZO of a staging folder: no background, no drag arrow, no icon positions; app is 4th of 5 sorted items | III | Style the DMG (create-dmg/AppleScript layout) with the app→Applications arrow + window bounds |
| A/C1 | partial | FIRST-LAUNCH.txt is a plain .txt among 5 items, nothing signals "open me first"; user hits the block before finding the fix beside it | III | Rename to "READ ME FIRST — first launch is blocked.txt" and/or surface the warning in DMG chrome |
| A/C1 | partial | "Install command-line tool.command" gives no hint it is optional/CLI-only | III | Group it lower, label "Optional: command-line tool" |
| A/C1 | partial | Verification scope: log only asserts the 5 items present, never ls's the mount or opens Finder; layout read from code | III | None — recorded for log-vs-code honesty |
| A/C2 first-launch text | partial | Version list frozen at Sequoia; Tahoe (the runner OS) absent from the Open-Anyway path | **II** | Open-ended "and later"; drift guard asserts phrasing not a version name |
| A/C2 | partial | M7 drift guard asserts literal "Sequoia" — freezes the stale set and passes green | III | Assert open-ended phrasing or drive off `sw_vers` |
| A/C2 | partial | xattr command assumes app already at /Applications; run before dragging = silent no-op | III | Prepend "after you've moved it to Applications, …" |
| A/C2 | partial | Open-Anyway copy omits Sequoia's final "click Open" dialog | III | Add "then open the app again; click Open in the final dialog" |
| A/C2 | partial | Verification scope: Gatekeeper dialog exercised nowhere; sign-off log holds only the example row | III | Human sign-off vs macOS 26 before tagging |
| A/C3 double-click | partial | LSUIElement: zero visible signal between double-click and the browser painting | III | Document, or post a launch notification |
| A/C3 | partial | Failure mode (no page connects): no signal at all; URL buried in 0600 gui.log until grace kills it | **II** | Notification carrying the launch URL on grace-exit |
| A/C3 | partial | No Dock icon ⇒ only running/stop surfaces are the tab or Activity Monitor/pkill | **II** | Launch notification + in-tab quit line |
| A/C3 | partial | Verification scope: smoke runs --no-open; browser-open + LSUIElement read from code | III | None — a notification would be assertable |
| A/C4 relaunch | partial | Real LaunchServices relaunch never exercised; single-instance path proven only by Linux unit tests injecting darwin | III | Add a second-invocation step to verify-bundle.sh on the runner |
| A/C4 | partial | Nothing the user sees distinguishes "reopened existing" from "started fresh" | III | Optional transient "reconnected" toast |
| A/C5 close-quits | partial | Quit-on-close stated only in install.md; absent from FIRST-LAUNCH.txt (the DMG text) and in-tab | III | One line in FIRST-LAUNCH.txt / in-tab footer |
| A/C5 | partial | 10s heartbeat vs 10s close-timeout: an OS-discarded tab can race a shutdown while the user believes the tab is open | III | Widen timeout margin (e.g. 30s vs 10s) and/or state a discarded tab needs relaunch |
| A/C5 | partial | Verification scope: the quit itself IS log-verified (I-M6); the "stated where seen" gap is doc-read | III | None |
| A/C6 PKG readme | yes | Readme pane's Control-click note is only visible after the user already bypassed Gatekeeper to open the .pkg | III | Ensure the .pkg Control-click note is on every external surface (release body prepend does this) |
| A/C6 | yes | Shared FIRST-LAUNCH.txt implies both paths meet the same wall; a .pkg app often has no quarantine and no prompt | III | Half a sentence: "installed via the .pkg, it usually opens without this step" |
| A/C6 | yes | Verification scope: build+install+golden symlink+version log-verified; readme pane + Control-click GUI not rendered | III | None — "yes" scoped to the headless mechanism |
| B/C1 CLI .command | partial | Unconditional symlink → dangling link + false "Installed"/exit 0 when app not yet dragged (reproduced) | **II** | Guard `[ -x "$BIN" ]` before symlink |
| B/C1 | partial | The .command is itself quarantined and Gatekeeper-blocked, but the workaround is documented only for the app/.pkg | **II** | Document Control-click → Open for the .command, or steer to the PKG |
| B/C1 | partial | `exec sudo` gives a bare Password: prompt with no reason line | III | Echo "creating the seavault command needs your login password …" first |
| B/C2 fresh Apple-silicon | yes | No friction: `mkdir -p` handles absent /usr/local/bin, proven on a real runner with the dir moved aside | III | Note the interactive .command path is covered by golden byte-identity, not an e2e double-click |
| B/C3 PATH guidance | yes | .zprofile targets zsh (correct default) but silently wrong for a bash login shell | III | Prefix "for the default zsh shell:" (update both surfaces; M11 keeps lockstep) |
| B/C3 | yes | Frames the PATH branch as the likely cause when a stale Terminal is far more common | III | Soften to "on the rare setup where /usr/local/bin is not on PATH …" |
| B/C3 | yes | `>> ~/.zprofile` not idempotent | III | Optional grep-guard or "run once" |
| B/C4 uninstall | yes | `pkill -f open-seavault-rclone` misses a terminal-launched `seavault gui` (argv0 = seavault) | III | Add "(a gui you started in Terminal — Ctrl-C there instead)" |
| B/C5 checklist | partial | Manual Gatekeeper sign-off enforced by a spoofable substring grep (v0.0.0 ← example row; v0.2 ← v0.22) | **II** | Anchor grep to a table row; delete the example row |
| B/C5 | partial | Step 1 hand-runs 2 of 6 cross-builds; the other 4 targets surface only after the tag | III | Loop the same six, or state it is a spot check |
| B/C5 | partial | Example row says "delete when a real tag is added" but nothing enforces removal | III | Tie to the anchored-grep fix |
| B/C6 Linux/Windows install | yes | Windows section is prose-only (no extraction/PATH/confirm examples); Linux gets copy-paste | III | Add a PowerShell block for parity |
| C/C1 release explainer | yes | Secret NAMES + the base64-encode requirement live only in release.yml; no maintainer doc states them; whole DevID branch never ran | III | Add an "Enabling signed builds" section naming the 7 secrets + base64 |
| C/C1 | yes | Partial signing secrets fail open to unsigned silently | **II** | All-or-nothing assertion before the have_devid branch |
| C/C1 | yes | DMG codesign `|| true` swallows failure; notarize/staple `|| true` similarly lossy | III | Drop `|| true` on the DMG codesign or log explicitly |
| C/C2 GATEKEEPER-CHECK | yes | Sign-off gate fires after `gh release create` — blocks packaging, not the already-shipped release | **II** | Move the grep into the release job before publish |
| C/C2 | yes | Fail-closed is a bare substring grep, not a row match | III | Anchor to a table row and say so |
| C/C2 | yes | FIRST-LAUNCH names 13–15 while the runner is macOS 26; example row is 15.x | III | Record the macOS major per sign-off; refresh the version list |
| C/C3 single-source | partial | SIGNING.txt triplicated across build-bundle.sh/release.yml/ci-macos.yml; guard checks only build-bundle.sh | **II** | Make build-bundle.sh the single source; only DevID overrides |
| C/C3 | partial | Workaround steps re-authored (not copied) in GATEKEEPER-CHECK.md + release-checklist.md, keyword-checked only | III | Point both at FIRST-LAUNCH.txt as authority, or add a parity assert |
| C/C4 STATUS/README | partial | Binary reports 0.21.0 while README changelog and STATUS are v0.22; no `-X`, no guard | **II** | Inject via ldflags or bump the const + add a guard |
| C/C4 | partial | Docs name a fixed artifact set; checklist claims drift guards "enforce both" but no test asserts artifact NAMES | III | Add a name-vs-release.yml guard, or soften the "enforce both" claim |
| C/C5 help-vs-docs | yes | Every documented seavault command resolves in --help and is guarded (sound) | III | None required |
| C/C5 | yes | `--bundle-grace` is real and tested but absent from `seavault gui --help` | III | Add `[--bundle-grace 60s]` to the gui usage string |
| C/C6 hand steps | partial | "Bump the version" names no file and hides the const↔tag↔plist independence | **II** | Name main.go:54 + ldflags/guard |
| C/C6 | partial | Enabling signed releases is entirely undocumented manual prep (~7 secrets, base64) | III | Document in release-checklist.md or SIGNING-SETUP.md |
| C/C6 | partial | Example Gatekeeper row's removal is never enforced or mentioned in the checklist | III | Checklist: replace the example row with the first real sign-off |

## What is solidly verified

The PKG path is end-to-end log-verified on a real runner (build → install → golden
postinstall byte-identity → `/usr/local/bin/seavault version`), including the fresh
Apple-silicon case with /usr/local/bin removed and restored. The single-instance
lock, bind-before-open, stale-lock handling, and /api/relaunch triple-gating
(loopback + endpoint-enabled + constant-time token) are unit-proven on Linux with
`bundleOSName="darwin"` injected. The 0600 rotate-once log sink, the loopback-only
session-less relaunch endpoint, and the I-M6 exit-on-page-close are all asserted
green (runs 34388861436, 34391651537). The unsigned-state Gatekeeper wall itself is
the accepted Type I of this phase; the xattr path 2 keeps first launch self-service
independent of macOS version.

## Fix-tranche addendum (post-review)

The 11 Type II items and the Type III rows they anchor were fixed in a three-fixer
tranche on `feature/u5-macos-bundle`. Each Type II maps to the commit that carries its
fix; the Type III rows fixed alongside them are listed with their owner.

| # | Type II item | fix commit | what landed |
|---|--------------|-----------|-------------|
| 1 | A/C2, C/C2 — FIRST-LAUNCH version list frozen at "15 Sequoia" | F-C (docs+final) | path 1 is now the open-ended "macOS 13 Ventura and later (including macOS 26 Tahoe)"; the M7 drift guard asserts the open-ended phrasing and forbids the old frozen enumeration, instead of matching the literal "Sequoia" |
| 2 | A/C3 — grace-exit emits no user-visible signal | F-A `c98b020` | a macOS user notification carrying the launch URL is posted on grace-exit with zero sessions |
| 3 | A/C3 — no running-state/stop surface | F-A `c98b020` | launch notification + an in-tab "closing this tab quits the app" hint (`internal/webui/quit_hint_u5_test.go`) |
| 4 | B/C1 — install-cli.sh symlinks unconditionally, false success | F-B `e319546` | `[ -x "$BIN" ]` guard before the symlink; a run before the app is in place now fails loudly |
| 5 | B/C1 — the `.command` is itself quarantined, undocumented | F-C (docs+final) | FIRST-LAUNCH.txt and install.md now document "if macOS blocks the .command, Control-click it → Open" |
| 6 | B/C5, C/C2 — spoofable substring sign-off grep | F-B `e319546` | anchored table-row grep; example row deleted (release-ci-secrets-1) |
| 7 | C/C2 — gate fires after `gh release create` | F-B `e319546` | the grep moved into the `release` job before publish; release-checklist.md (F-C) now states the before-publish timing |
| 8 | C/C1 — partial signing secrets fail open silently | F-B `e319546` | all-or-nothing assertion: some-but-not-all signing secrets fail rather than degrade to unsigned |
| 9 | C/C3 — SIGNING.txt not single-sourced | F-B `e319546` | build-bundle.sh's default is the single source; only the DevID path overrides |
| 10 | C/C4, C/C6 — binary version 0.21.0 out of step with v0.22 | F-A `c98b020` + F-B `e319546` (code), F-C (docs) | `var version` injected via `-ldflags -X main.version=${tag#v}`; release-checklist.md names the mechanism and the file, README's v0.22 note states the release version comes from the tag |
| 11 | C/C6 — "bump the version" names no file | F-C (docs+final) | release-checklist step 2 names `cmd/seavault/main.go`'s `var version` and the linker-flag injection, and drops the hand-edit instruction |

Type III rows fixed by F-C alongside the above: the Sequoia-and-later second confirmation
dialog and the "app must already be in /Applications" xattr note (A/C2); quit-on-close and
the no-Dock-icon fact stated in FIRST-LAUNCH.txt (A/C5); the PATH notes now cover zsh
(`~/.zprofile`) and bash (`~/.bash_profile`) and are idempotent (grep before append) (B/C3);
the uninstall quit guidance distinguishes the bundle agent from a Terminal-started `seavault
gui` (Ctrl-C) (B/C4); and the shared FIRST-LAUNCH note now says a `.pkg`-installed app usually
carries no quarantine (A/C6). The GATEKEEPER-CHECK.md sign-off row format is documented in
prose with an example (`vX.Y.Z`, indented) that structurally cannot satisfy the anchored gate.

**Post-tranche verdict:** SHIPPABLE — the backlog Type II items are cleared, the golden path
is unchanged and still completes, and no control was weakened. The Gatekeeper GUI dialog and
the real LaunchServices relaunch remain a per-release human sign-off (`GATEKEEPER-CHECK.md`),
still unperformed for any real tag by construction.
