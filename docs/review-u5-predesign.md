# Pre-code design review — Phase U5 (macOS bundle, unsigned tier)

- **Reviewed:** `docs/design-u5-macos-bundle.md` (Revision 1, "pre-code design, awaiting the 10-lens review")
- **Repository / branch:** `open-seavault-rclone`, `feature/u5-macos-bundle` (base = `main` at the v0.21.0 merge `b5446a7`)
- **Process:** assurance-kit `process/design-review.md` — 10-lens pre-code design review (lens sweep → skeptic → rescue → synthesis)
- **Synthesis model:** claude-opus-4-8
- **Date:** 2026-09-09

## Verdict: GO_WITH_CONDITIONS

Nothing survived as a NO_GO blocker. The one blocker raised (`usability-friction-1`, the macOS 15 Sequoia dead-end workaround) is a **confirmed** defect — the authoritative fact that Sequoia removed the Control-click→Open bypass is not refutable, and the design plainly makes that dead path primary (§5) — but it is a documentation-copy defect with zero coupling to the bundle/installer/release-job architecture. The rescue pass saved it through the design's own single-source workaround-text propagation (§5) and its per-release re-check invariant (§6). It folds into Conditions 1 and 2 below.

Every other surviving finding is dischargeable by a concrete, testable revision applied to the design before build. None requires a new subsystem; the bundle, LSUIElement agent, universal binary, DMG/PKG/postinstall, and the conditional sign/verify/smoke release pipeline all stand.

## Conditions (all must be applied as a design revision before build)

| n | Condition | Addresses |
|---|---|---|
| 1 | **Rewrite the Gatekeeper workaround for the current macOS.** Replace the §5 body (replicated to `FIRST-LAUNCH.txt`, `SIGNING.txt`, the DMG pane, the PKG readme, and `docs/install.md` via the design's existing single-source mechanism) so the path that works on the shipping release leads: "Open it once — it will be blocked — then System Settings → Privacy & Security → scroll to Security → click 'Open Anyway' → confirm." Demote "Control-click → Open" to a macOS 11–12 note. Promote the version-independent `xattr -dr com.apple.quarantine …` to a co-primary reliable path. State the OS version each path applies to. | usability-friction-1, purpose-threat-fit-3, durability-1, security-adversarial-7, honesty-of-claims-3 |
| 2 | **Fix the §6 conditional invariant and the M7 drift guard.** Change §6 from "matches macOS 11–15" to name the version-keyed GUI flows plus the `xattr` command. Change M7 to assert the "Open Anyway"/"Privacy & Security" text AND `xattr`; drop the bare right-click→Open as primary. Relabel the per-release re-check a manual gate with a dated human sign-off. | usability-friction-2, honesty-of-claims-3, durability-1 |
| 3 | **Surface the unsigned state on the GitHub Release page.** The `macos` job prepends the Gatekeeper note to the Release body; add a test row asserting the release notes carry it. | purpose-threat-fit-2 |
| 4 | **Make the CLI symlink robust on a fresh Apple-Silicon Mac.** Relax I-M4 to allow `mkdir -p /usr/local/bin` + one symlink (or target a guaranteed dir); add a test row with `/usr/local/bin` removed; handle/document PATH visibility. | usability-friction-3 |
| 5 | **Guard `ci-macos.yml`:** add `concurrency`+cancel, `timeout-minutes`, `on.push.paths` scoping, and bounded retries on `hdiutil detach`/`installer`. | dependency-cost-1 |
| 6 | **Make notarization failure observable/bounded:** fetch+upload `notarytool log <id>` on non-Accepted, split transient retry from fail-fast rejection, set a step timeout. | failure-recoverability-4 |
| 7 | **Define "the app log" for headless bundle launch:** write grace-exit line + launch URL to a file under the darwin data dir (or os_log); M2 asserts the FILE, not stdout. | integration-seams-5 |
| 8 | **Resolve I-M1 vs §4's second build and M3's push-time vacuity:** download the ubuntu darwin binaries and lipo those (or pin identical Go toolchain); mark M3 tarball-equality release-only, push-time row labeled as NOT proving I-M1. | honesty-of-claims-2 |
| 9 | **Specify uninstall precisely:** quit the iconless app, `sudo rm` the root-owned symlink, `pkgutil --forget`, drag to Trash, delete the data dir. | usability-friction-6 |
| 10 | **Handle re-launch of the running iconless app:** detect a serving instance before opening a browser (probe/lockfile) or bind-first-then-open; document how to tell it is running. | usability-friction-5 |
| 11 | **Provide a Retina-complete icon source or state the 512 cap.** | integration-seams-7 |

## Per-lens findings

| ID | Severity | Disposition | One-line |
|---|---|---|---|
| purpose-threat-fit-1 | note | refuted | Unsigned .pkg dead weight — refuted: `.command` symlinks and does nothing else (I-M4). |
| purpose-threat-fit-2 | note | confirmed | Unsigned state not declared on the Release page (`--generate-notes` only). → C3 |
| purpose-threat-fit-3 | condition | confirmed | Design certifies the 15-broken workaround as "matches 11–15". → C1 |
| focus-proportionality-1..5 | — | refuted | Dead code / redundant PKG / CI cost / duplicated prose / grace polish — all refuted. |
| usability-friction-1 | blocker | rescued | Right-click→Open dead on macOS 15; Privacy & Security never mentioned. → C1, C2 |
| usability-friction-2 | condition | confirmed | §6 invariant false for 15; M7 cements the wrong instruction. → C2 |
| usability-friction-3 | condition | confirmed | `/usr/local/bin` absent on fresh Apple Silicon; I-M4 forbids the `mkdir`. → C4 |
| usability-friction-4 | note | refuted | The `.command` itself quarantined — refuted: PKG installs both. |
| usability-friction-5 | note | confirmed | Re-launch opens a broken tab; 2nd process dies on bind conflict. → C10 |
| usability-friction-6 | note | confirmed | Uninstall under-specified (sudo symlink, PKG receipt, no quit). → C9 |
| durability-1 | condition | confirmed | Primary workaround broken on the current+forward OS. → C1, C2 |
| durability-2..6 | — | refuted | mkdir / floating runner / grace / codesign-deep / quit — all refuted. |
| integration-seams-1..4,6 | — | refuted | Symlink path / needs-job / seam / bundle-detect / toolchain — all refuted. |
| integration-seams-5 | note | confirmed | I-M6 grace-exit "one line to the app log" has no file sink. → C7 |
| integration-seams-7 | note | confirmed | 512 source cannot fill 512@2x (1024); soft on Retina. → C11 |
| security-adversarial-1..6 | — | refuted | Symlink safety / xattr integrity / ad-hoc authenticity / secret channels / spoofed env / runtime quarantine — all refuted. |
| security-adversarial-7 | condition | confirmed | Wrong 15 workaround funnels users to the wholesale `xattr` strip. → C1 |
| failure-recoverability-1..3,5,6 | — | refuted | Symlink / silent surface / SHA256SUMS / build coupling / grace race — all refuted. |
| failure-recoverability-4 | note | confirmed | Notarization: no timeout/retry, never fetches reject log. → C6 |
| migration-coexistence-1..4 | — | refuted | Bare seavault / pre-existing symlink / held port / lossy config — all refuted. |
| dependency-cost-1 | condition | confirmed | ci-macos.yml: no path filter/concurrency/timeout on flaky packaging. → C5 |
| dependency-cost-2..5 | — | refuted | Triple notary / cert expiry / 4 artifacts / drifting runner — all refuted. |
| honesty-of-claims-1,4,5,6 | — | refuted | Hash-equality / DevID vacuity / M1 OS / browser-suppression — all refuted. |
| honesty-of-claims-2 | note | confirmed | I-M1 "no separate build path" contradicted by §4; M3 vacuous on push. → C8 |
| honesty-of-claims-3 | condition | confirmed | Workaround + §6 wrong for 15; M7 passes while the fix is broken. → C1, C2 |

## Refuted findings (with refuting quotes)

- **purpose-threat-fit-1** — "`Install command-line tool.command` … it does nothing else, I-M4."
- **focus-proportionality-1** — "the job **verifies before upload**: `plutil -lint`, `lipo -info` … `codesign --verify --deep --strict`, `spctl --assess` … a real smoke: run the bundle binary `--version`" (design:85-89).
- **focus-proportionality-2** — "a DMG (drag to Applications) and a `.pkg` (installs the app and the `seavault` command)".
- **focus-proportionality-3** — "a `ci-macos.yml` that runs the same assembly and M3–M8 on every push to main".
- **focus-proportionality-4** — "the workaround text matches macOS 11–15 and is re-checked per release on the runner's macOS."
- **focus-proportionality-5** — `if !enabled || !seen || timeout <= 0 || sessions > 0 {` (server.go:602; `seen` set only on a real heartbeat, 619/640).
- **usability-friction-4** — "a `.pkg` (installs the app and the `seavault` command)".
- **durability-2** — I-M4 "create one symlink and nothing else: no network, no other writes" (design:120-121).
- **durability-3** — §8 "runs the same assembly and M3–M8 on every push"; §4 "the expectation is asserted, never hidden"; §6 version-dependent label.
- **durability-4** — "`gui` also exits if no page connects within a grace period (60 s, `--bundle-grace` override)".
- **durability-5** — "MacOS/open-seavault-rclone the universal (amd64 + arm64, `lipo -create`) release binary".
- **durability-6** — server.go:606 shutdown-on-timeout; I-M6 "never leaves an invisible lingering process".
- **integration-seams-1** — "A Terminal user typing `seavault` with no arguments still gets usage (I-M3)."
- **integration-seams-2** — "A second job `macos` … needing the existing verify step to have passed".
- **integration-seams-3** — "S1 … Linux-testable with the env var and an injected executable path".
- **integration-seams-4** — "`SEAVAULT_BUNDLE_LAUNCH=1` … OR the executable path contains `/Contents/MacOS/`".
- **integration-seams-6** — I-M1 "no separate build path" (toolchain residual carried in C8).
- **security-adversarial-1** — I-M4 "create one symlink and nothing else … no privilege beyond the symlink."
- **security-adversarial-2** — "macOS will say the app cannot be opened because Apple cannot check it for malicious software."
- **security-adversarial-3** — I-M5 + SIGNING.txt "ad-hoc signed, not notarized".
- **security-adversarial-4** — "Secrets never appear in logs (the job masks them …, I-M2)."
- **security-adversarial-5** — "A Terminal user typing `seavault` with no arguments still gets usage (I-M3)."
- **security-adversarial-6** — rclonebin fetch() plain Go HTTP GET sets no quarantine xattr; §3 DMG holds no runtime binary.
- **failure-recoverability-1** — I-M4 "create one symlink and nothing else" (fresh-Mac gap in C4).
- **failure-recoverability-2** — openBrowser surfaced via printLaunchGuidance (main.go:1683-1687).
- **failure-recoverability-3** — "the job **verifies before upload** … install the PKG on the runner and run `/usr/local/bin/seavault --version`."
- **failure-recoverability-5** — I-M1 "same universal build … no separate build path" (residual in C8).
- **failure-recoverability-6** — "`gui` also exits if no page connects within a grace period".
- **migration-coexistence-1** — "still gets usage (I-M3)."
- **migration-coexistence-2** — I-M4 "create one symlink and nothing else".
- **migration-coexistence-3** — main.go:2270-2271 printLaunchGuidance / net.Listen with `listenErrorHint`.
- **migration-coexistence-4** — §3/I-M4 "create one symlink and nothing else".
- **dependency-cost-2** — "`notarytool submit --wait` on a zip of the app, `stapler staple`" (single submission).
- **dependency-cost-3** — "switch on the day the certificate secrets exist" + ad-hoc tier when absent.
- **dependency-cost-4** — M5 "`installer -pkg … -target /` then `/usr/local/bin/seavault --version`".
- **dependency-cost-5** — "a `ci-macos.yml` that runs the same assembly and M3–M8 on every push".
- **honesty-of-claims-1** — I-M1 build identity (residual in C8).
- **honesty-of-claims-4** — "the expectation is asserted, never hidden".
- **honesty-of-claims-5** — "S1 … Linux-testable with the env var and an injected executable path".
- **honesty-of-claims-6** — same S1 seam suppresses the browser in the test.

## Rescue outcome

- **usability-friction-1 (blocker) — SAVED.** Confirmed, not refutable: macOS 15 removed the Control-click→Open bypass and §5 makes that dead path primary. But the defect lives entirely in copy, not mechanism — the bundle, LSUIElement agent, universal binary, DMG/PKG/postinstall, and sign/verify/smoke pipeline are untouched. The named change rides the design's own hooks: §5's single-source workaround text (correct once, flows everywhere), §6's per-release re-check (the standing place to keep Apple-controlled text current), and flipping M7's drift guard. Folded into Conditions 1 and 2.
- **Honest residuals** (carried, not papered over): (a) a headless runner cannot exercise the GUI Gatekeeper dialog, so M7 verifies the reliable path (`xattr` + the "Open Anyway" wording) is present; GUI-copy correctness rests on the §6 per-release **human** re-check, relabeled a manual gate by Condition 2; (b) the `xattr` one-liner worked on every version, so promoting it to co-primary removes any total-lockout scenario.

## What the build must prove (conditions → test matrix)

| Condition | Row(s) that must change / be added |
|---|---|
| C1, C2 | Revise M7 to assert the "Privacy & Security"/"Open Anyway" wording AND `xattr` across install.md + all artifact sinks; Control-click only inside a macOS 11–12 note; mark the GUI re-check a manual per-release sign-off. |
| C3 | New row: assert the GitHub Release body contains the unsigned/Gatekeeper note. |
| C4 | Revise M5: run the golden postinstall/`.command` with `/usr/local/bin` removed (or assert `mkdir -p`); update the I-M4 golden expectation. |
| C5 | Assert (or reviewer-gate) `concurrency.cancel-in-progress`, `timeout-minutes`, `on.push.paths`, and retries in `ci-macos.yml`. |
| C6 | Revise M4/signing smoke (release-only): assert the `notarytool log` capture path and step timeout exist. |
| C7 | Revise M2: assert the grace-exit line + launch URL appear in the on-disk app-log file, not just stdout. |
| C8 | Split M3 into a release-only tarball-equality row (proving I-M1) and a push-time self-consistency row labeled as NOT proving I-M1; record the Go toolchain in both jobs. |
| C9 | Extend M7 docs guard: uninstall section names quitting the app, `sudo rm`, `pkgutil --forget`, drag-to-Trash, and the data dir. |
| C10 | New app-side row (S1): a second bundle instance re-opens the running link or surfaces a legible failure — never a rotated-secret tab. |
| C11 | Revise M3's icon check: assert `icon_512x512@2x.png` from a ≥1024 master, or assert the design records the 512-cap for the unsigned tier. |

---
*Filed by the synthesis agent of the assurance-kit 10-lens pre-code design review. The design must be revised to satisfy Conditions 1–11 (a revision, not new subsystems) before Phase U5 enters build.*
