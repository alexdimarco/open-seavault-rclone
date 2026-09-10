# Adversarial review — Phase U5 (macOS .app bundle, DMG/PKG, signed-release CI)

WHAT: An adversarial review of the BUILT Phase U5 on branch `feature/u5-macos-bundle`
against the design contract in `docs/design-u5-macos-bundle.md` (Revision 2, BUILT;
invariants I-M1..I-M8) and its pre-code review `docs/review-u5-predesign.md`. Scope:
`internal/bundlelaunch`, `cmd/seavault`, `internal/webui` (`/api/relaunch`),
`packaging/macos/`, `.github/workflows/release.yml`, `.github/workflows/ci-macos.yml`,
`docs/install.md`, `docs/release-checklist.md`, and the README Install + v0.22 sections.

PROCESS: Reviewer agents built the real binary on Linux and drove the bundle-launch
behaviour through `SEAVAULT_BUNDLE_LAUNCH=1`, a throwaway `SEAVAULT_APP_HOME`, and
`--no-open` / `--bundle-grace`; the installer and CI logic were exercised with the exact
golden shell commands and by reading the green macOS runs. Each high/medium claim was run
past a skeptic pass that reproduced it end-to-end (throwaway Go tests added, run, removed;
tree reconfirmed clean) or established it against the golden shell on Linux. LOW-severity
finder notes were carried through as reported and were NOT re-run through the skeptic in
this lean pass — they are code-inspection findings. The real user home, the real keychain,
and `main` were never touched; every process started was killed by PID.

MODEL: claude-opus-4-8

## Counts

- Found (raw confirmed claims carried into synthesis): 10
- Confirmed (after dedupe): 9
- Refuted: 1

`relaunch-redirect-1` and `relaunch-lock-log-1` describe the SAME defect — the
single-instance relaunch client authenticates itself TO the running instance with the
lock token but never authenticates the RESPONDER. Merged into `relaunch-lock-log-1`.

## Confirmed findings

| id | sev | title | repro (abridged) | fix |
|----|-----|-------|------------------|-----|
| relaunch-lock-log-1 | high | Second bundle launch trusts ANY loopback responder on the lock's port; a squatting listener redirects the launch to an attacker URL (I-M7) | Throwaway repro test: attacker http.Server returns `{launchURL: http://attacker.example/phish?launch=EVIL}` ignoring the token; stale lock names the attacker port; occupy the victim addr; `cmdGUI` opened exactly the attacker URL. No `signal.Notify` anywhere, so the documented quit leaves the stale lock. | Authenticate the responder (HMAC over launchURL, verified before openBrowser); validate URL is loopback http/https on the expected port; SIGINT/SIGTERM handler runs RemoveLock; remove stale lock after a failed relaunch. |
| release-ci-secrets-1 | high | Gatekeeper fail-closed sign-off gate is an unanchored substring grep, satisfied by the file's own EXAMPLE row | `grep -qF v0.0.0 GATEKEEPER-CHECK.md` PASSES — matches the EXAMPLE row the file labels "not a real sign-off". Real rows later cross-satisfy (`v0.22` ⊂ `v0.22.0`). | Anchored per-column exact-tag match excluding the EXAMPLE row; delete the EXAMPLE row. |
| installer-scripts-1 | medium | Golden `ln -sf` (no -n) dereferences a pre-existing seavault symlink-to-dir: root-owned write into an attacker dir, false "Installed" (I-M4) | Pre-plant `seavault -> attacker_dir`, run golden `ln -sf` → seavault STILL → attacker_dir, a root link dropped inside it, script prints "Installed". Homebrew Intel `/usr/local/bin` is user-writable. | `ln -sfn`; optionally `rm -f` first and verify `readlink` equals the target. |
| installer-scripts-2 | medium | DMG `.command` byte-identity to the golden is never verified — I-M4/M5 coverage exists only for the PKG postinstall | verify-bundle.sh diffs only the PKG postinstall (`cmp` line 211); the DMG block checks the `.command` for PRESENCE only. | Add `cmp -s` of golden vs the DMG `.command` in the M6 block. |
| release-ci-secrets-2 | medium | Release-body first-launch prepend is non-idempotent; a macos-job re-run duplicates the note | Simulated shell: two prepends → 2 copies of the note; the M9 self-check still passes on the doubled body. | Skip when the body already begins with firstline, or strip a leading FIRST-LAUNCH block before re-prepending. |
| release-ci-secrets-4 | medium | Dev ID Installer cert optional but the PKG is notarized unconditionally, so app-cert-only config aborts the release | have_devid ignores the Installer cert; build-pkg.sh never productsigns; `notarize "$PKG"` on an unsigned pkg → Invalid → set -e aborts before upload/prepend, half-populated release. | Add the Installer cert to have_devid, or notarize the PKG only when productsigned. |
| relaunch-silent-1 | medium | A second bundle launch that can't reach a running instance dies with no window and NO log line — contradicts I-M8 | Occupy addr, no lock file, `cmdGUI(--addr <busy>)` → returns bind error, gui.log never created (Writeln never reached on this path). | Write the exit reason to the sink before returning the bind error; optionally an osascript notification. |
| installer-scripts-3 | low | FIRST-LAUNCH "not yet signed / xattr override" baked into every artifact + release body with no signing-tier guard (I-M5) | build-bundle.sh/build-dmg.sh/release.yml copy the note with no `if:`; on the Dev-ID path SIGNING.txt says "notarized" while the note + body say "not yet signed". | Tier-gate the note off have_devid so SIGNING.txt, the note, and the release body agree. |
| release-ci-secrets-3 | low | ci-macos `paths` omits `internal/webui/**` and `internal/bundlelaunch/**` — the exact code the M8 smoke exercises | The M8 smoke reads the launch URL from bundlelaunch's sink and POSTs the webui heartbeat handler; a push touching only those files matches no `paths` entry, so ci-macos does not run. | Add `internal/bundlelaunch/**` and `internal/webui/**` to the paths list. |

## Refuted findings

| id | title | why refuted |
|----|-------|-------------|
| stale-lock-signal-1 | gui installs no signal handler, so the documented quit leaves a stale single-instance lock at the fixed port | Mechanism confirmed — `main.go:2447` `defer func() { _ = bundlelaunch.RemoveLock(lockPath) }()` is the sole cleanup and `grep -rn 'signal.Notify\|os/signal' cmd/ internal/` is empty, and design §67 states "a stale lock (no live listener) is ignored ... (I-M7)". But a stale lock is BENIGN on its own: I-M7 tolerates it and the bind-fail path handles it (`TestBindConflictWithStaleLockErrors`). It is the *enabling precondition* for `relaunch-lock-log-1`, folded into that finding's threat model, not an independent defect. |

## Fix-tranche ordering

**Tranche 1 — the relaunch trust boundary (do first; exploitable today with a co-resident principal).**
(1) `relaunch-lock-log-1` — responder HMAC auth (load-bearing) + URL validation + SIGINT/SIGTERM RemoveLock + stale-lock removal, with a permanent regression test.
(2) `relaunch-silent-1` — write the bind-fail exit reason to the sink; same code path, I-M7/I-M8 correctness.

**Tranche 2 — the release gate that can ship unsigned/unattested (before any real tag).**
(3) `release-ci-secrets-1` — anchor the Gatekeeper grep, delete the EXAMPLE row.

**Tranche 3 — installer + verify integrity (I-M4/M5).**
(4) `installer-scripts-1` — `ln -sfn` + readlink verify. (5) `installer-scripts-2` — DMG `.command` byte-compare.

**Tranche 4 — signed-tier release plumbing (latent until Developer-ID secrets land).**
(6) `release-ci-secrets-4` — gate have_devid on the Installer cert or make PKG notarization conditional. (7) `installer-scripts-3` — tier-gate the FIRST-LAUNCH note; both driven off have_devid.

**Tranche 5 — CI coverage completeness (low).**
(8) `release-ci-secrets-2` — idempotent prepend. (9) `release-ci-secrets-3` — add the two internal dirs to the ci-macos paths filter.

## Fix-tranche addendum (post-review)

The confirmed findings were fixed in a three-fixer tranche on `feature/u5-macos-bundle`.
Each maps to the commit that carries its fix and its regression test:

| id | sev | fix commit | what landed |
|----|-----|-----------|-------------|
| relaunch-lock-log-1 | high | F-A `c98b020` | responder HMAC auth over the launchURL verified before openBrowser; loopback/port/scheme validation; SIGINT/SIGTERM RemoveLock; stale-lock removal after a failed relaunch (regression tests `internal/bundlelaunch/relaunch_auth_test.go`, `internal/webui/relaunch_mac_u5_test.go`) |
| relaunch-silent-1 | medium | F-A `c98b020` | the bind-fail path writes its exit reason to the 0600 `gui.log` sink before returning the error (I-M8), and posts a user notification |
| release-ci-secrets-1 | high | F-B `e319546` | the Gatekeeper gate is an ANCHORED per-tag table-row grep (`^\|…tag…\|`) moved into the `release` job BEFORE `gh release create`; the `v0.0.0-EXAMPLE` row deleted (u5_fix_b/u5_s3_docs guards) |
| installer-scripts-1 | medium | F-B `e319546` | golden symlink uses `ln -sfn` with a `readlink` verify; the `.command`/postinstall no longer dereference a pre-planted symlink-to-dir |
| installer-scripts-2 | medium | F-B `e319546` | `verify-bundle.sh` now `cmp`s the DMG `.command` byte-for-byte against the golden, matching the PKG-postinstall coverage |
| release-ci-secrets-4 | medium | F-B `e319546` | `have_devid` accounts for the Installer cert; the PKG is notarized only when productsigned, so an app-cert-only config no longer aborts the release |
| release-ci-secrets-2 | medium | F-B `e319546` | the release-body first-launch prepend is idempotent (guards on the body already beginning with the note); a macos re-run no longer doubles it |
| installer-scripts-3 | low | F-B `e319546` | the FIRST-LAUNCH note is tier-gated off `have_devid` (`FIRST-LAUNCH-SIGNED.txt` on the Developer-ID path) so SIGNING.txt, the note, and the Release body agree |
| release-ci-secrets-3 | low | F-B `e319546` | `internal/bundlelaunch/**` and `internal/webui/**` added to the `ci-macos.yml` paths filter so the M8 smoke's inputs trigger it |

The refuted finding (`stale-lock-signal-1`) stays refuted: its enabling precondition is
folded into `relaunch-lock-log-1`, whose fix also installs the SIGINT/SIGTERM cleanup, so
the documented quit no longer leaves a stale lock.

**Post-tranche verdict:** all 9 confirmed findings fixed, each red-first with a permanent
regression test; the unfiltered `go test -race -count=1 ./...` suite is green on Linux and
the `ci-macos.yml` run on the pushed branch is green. No finding deferred.
