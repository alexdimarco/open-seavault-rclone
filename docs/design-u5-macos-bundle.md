# Design — Phase U5: a proper macOS bundle (unsigned tier), installers, and install docs

STATUS: BUILT + REVIEWED + FIX-TRANCHE — Revision 2 (the 11 conditions of the pre-code review, `docs/review-u5-predesign.md`, GO_WITH_CONDITIONS; 55 judged / 40 refuted / 1 blocker rescued) is applied below and in §9 and built across three slices. Slice commits: S1 `f5a82e1` (app-side bundle-launch — Finder-launch default M1, grace timeout + 0600 file log sink M2, single-instance relaunch M10), S2 `8c4bd67` + `7f19625` (packaging assets, the release `macos` job and `ci-macos.yml`, `verify-bundle.sh`, and the M8 file-sink smoke lock), and S3 `ed04264` (docs + finish-the-phase: `docs/install.md`, the README Install and v0.22 changelog sections, `docs/release-checklist.md`, the M7 docs drift guards + M11, and the final verification set). The macOS packaging rows (M3–M6, M8) run on a real `macos-latest` runner via `ci-macos.yml` on the pushed branch; the release-only rows (I-M1 tarball identity, notarization) run in the tagged release job.

The BUILT phase was then reviewed and fixed. The filed reviews are `docs/review-u5-adversarial.md` (9 confirmed / 1 refuted) and `docs/review-u5-friction.md` (Type II 11 / Type III 37, verdict SHIPPABLE_WITH_BACKLOG); their confirmed findings and Type II/III rows were fixed in a three-fixer tranche: **F-A `c98b020`** (relaunch responder HMAC auth + URL validation + SIGINT/SIGTERM lock cleanup, bundle bind-fail exit-logging, launch/grace notifications, linker version), **F-B `e319546`** (anchored per-tag Gatekeeper gate moved before publish, fail-closed/all-or-nothing signing, tier-gated FIRST-LAUNCH note, idempotent release-body prepend, `ln -sfn` + guarded installer, DMG `.command` byte-compare, `-X main.version` injection, ci-macos paths), and **F-C** (this docs + final commit: the open-ended FIRST-LAUNCH/GATEKEEPER/install wording, the M7 drift guard, `docs/release-checklist.md`, README, and the per-finding fix→commit addenda at the foot of both review files). Each finding maps to its fix commit in those addenda.

## 1. Goal and scope

The macOS release is a raw binary in a tarball. It works, but it does not present as an installed
program: nothing appears in Applications or Launchpad, a double-click shows a terminal printing
usage, and the first launch hits Gatekeeper with no guidance. U5 ships the pieces in the right
places **without waiting for an Apple Developer ID**, declares the unsigned state and its manual
workaround plainly everywhere a user will meet it, and wires code signing and notarization so they
switch on the day the certificate secrets exist.

**In scope:** an `open-seavault-rclone.app` bundle around a universal binary; a Finder-launch
default; a bundle-launch grace timeout; a DMG (drag to Applications) and a `.pkg` (installs the
app and the `seavault` command); a macOS job in the release workflow that builds, ad-hoc signs,
verifies, smoke-tests, and (when secrets are present) Developer-ID signs, notarizes and staples;
`docs/install.md` for all platforms with the macOS first-launch workaround first; a README Install
section; the v0.22 changelog.
**Out of scope:** a native window (the interface stays the browser), a Homebrew tap (next), the
Windows MSI/Authenticode analog (later), any change to what the binary does once running.

## 2. The bundle

```
open-seavault-rclone.app/
  Contents/
    Info.plist            CFBundleIdentifier io.github.alexdimarco.open-seavault-rclone
                          CFBundleName/DisplayName "open-seavault-rclone"; CFBundleVersion and
                          CFBundleShortVersionString from the release tag; CFBundleExecutable
                          open-seavault-rclone; CFBundleIconFile; LSMinimumSystemVersion 11.0;
                          LSUIElement true (the browser is the interface — no bouncing Dock icon
                          for a process with no window); LSEnvironment SEAVAULT_BUNDLE_LAUNCH=1
    MacOS/open-seavault-rclone   the universal (amd64 + arm64, `lipo -create`) release binary —
                          byte-identical to the binaries in the two darwin tarballs (I-M1)
    Resources/open-seavault-rclone.icns   generated on the macOS runner from the 512×512
                          internal/webui/assets/svlogo/icon.png via sips + iconutil. The
                          source caps at 512 px, so the 1024-px Retina slot is omitted and
                          the largest icon is soft on Retina displays — accepted for the
                          unsigned tier; a 1024-px or vector master is a later asset (C11)
    Resources/FIRST-LAUNCH.txt            the Gatekeeper note (§5), also shown in the DMG
    Resources/SIGNING.txt                 "ad-hoc signed, not notarized" or "Developer ID
                          <team>, notarized <date>" — written by the release job (I-M5)
```

### 2.1 Finder-launch default (app-side, small)

In `main()`, before dispatch: on darwin, when there are no arguments (or only the legacy
`-psn_…` argument) AND the process is a bundle launch — `SEAVAULT_BUNDLE_LAUNCH=1` in the
environment (set by `LSEnvironment`) OR the executable path contains `/Contents/MacOS/` — run
`gui` with its defaults (open the browser, exit when the page closes). A Terminal user typing
`seavault` with no arguments still gets usage (I-M3): neither condition holds there.

### 2.2 Bundle-launch grace timeout, single instance, and a real log sink (app-side, small)

`gui` already exits when the browser page stops sending heartbeats, but if the browser never
opens (blocked, misconfigured) a background process with no Dock icon would linger. On a bundle
launch, `gui` also exits if no page connects within a grace period (60 s, `--bundle-grace`
override) (I-M6). Terminal `gui` is unchanged.

**Single instance (C10).** A Dock-iconless app invites a second double-click. On a bundle
launch, `gui` binds its port FIRST and opens the browser only after a successful bind (today the
browser is opened before `net.Listen`); if the bind fails because an instance is already serving,
it asks that instance for its current launch link over loopback (a tiny authenticated
`/api/relaunch` that only a process holding the app-data lock file's token can call) and opens
THAT link instead of starting a second server, then exits. The lock file lives under the darwin
data dir; a stale lock (no live listener) is ignored. Terminal `gui` keeps today's behaviour
(port in use is an error) (I-M7).

**Log sink (C7).** LaunchServices discards a bundle's stdout, so on a bundle launch the launch
URL, the grace-exit line, and the relaunch line are written to
`~/Library/Application Support/open-seavault-rclone/logs/gui.log` (0600, size-capped, rotated
once) in addition to stdout; Terminal launches are unchanged (I-M8).

## 3. Installers

- **DMG** `open-seavault-rclone_vX.Y.Z_macos_universal.dmg`: the `.app`, an `Applications` symlink,
  `FIRST-LAUNCH.txt`, `SIGNING.txt`, and `Install command-line tool.command` (a double-clickable
  script that ensures `/usr/local/bin` exists (`mkdir -p`, absent on a fresh Apple-silicon Mac)
  and symlinks `/usr/local/bin/seavault` → the bundle binary, asking for the password via `sudo`
  in Terminal; it does nothing else, I-M4, C4). The script and `install.md` tell the user to open
  a new Terminal window, and how to add `/usr/local/bin` to `PATH` for shells that lack it.
- **PKG** `open-seavault-rclone_vX.Y.Z_macos_universal.pkg` (`pkgbuild` + `productbuild`,
  install location `/Applications`, a `postinstall` that does exactly the same `mkdir -p` +
  symlink, I-M4). Distribution XML shows the first-launch note as the installer's readme pane.
- Both names are stable regardless of signing state; the signing state is declared inside
  (`SIGNING.txt`, the installer readme), never hidden or implied by a filename (I-M5).

## 4. The release job

A second job `macos` (runs-on `macos-latest`) in `.github/workflows/release.yml`, needing the
existing verify-and-build job to have passed: it **downloads the two darwin binaries that job
produced** (uploaded as workflow artifacts) rather than compiling again, so "no separate build
path" is literally true (C8, I-M1); `lipo -create` them, assemble the bundle, generate the
`.icns`, write the plist with the tag version, then **sign**:

- Secrets present (`MACOS_DEVELOPER_ID_P12`, `MACOS_DEVELOPER_ID_P12_PASSWORD`,
  `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`, `APPLE_NOTARY_KEY_P8`): import the certificate
  into a temporary keychain, `codesign --force --deep --options runtime --timestamp -s "Developer ID
  Application: …"`, `notarytool submit --wait` on a zip of the app, `stapler staple`, build DMG and
  PKG, sign the PKG with the Developer ID Installer certificate if present, notarize and staple
  those too; `SIGNING.txt` records the team and date.
- Secrets absent: `codesign --force --deep -s -` (ad-hoc, so the universal binary is a valid
  signed object on Apple silicon), build DMG and PKG unsigned, `SIGNING.txt` says so.
- In both cases the job **verifies before upload**: `plutil -lint`, `lipo -info` shows both
  architectures, `codesign --verify --deep --strict`, `spctl --assess --type execute` recorded
  as expected (rejected when ad-hoc, accepted when notarized — the expectation is asserted, never
  hidden), a real smoke: run the bundle binary `--version`, run it as a bundle launch with the
  browser suppressed and confirm the launch URL answers, mount the DMG and check its contents,
  expand the PKG and check the postinstall does only the symlink, install the PKG on the runner
  and run `/usr/local/bin/seavault --version`.
- Uploads: the DMG, the PKG, and their SHA256 lines appended to `SHA256SUMS.txt`. The two darwin
  tarballs stay for scripts. **The release body carries the first-launch/Gatekeeper note (C3)**:
  the job prepends `FIRST-LAUNCH.txt` to the generated release notes (`gh release edit --notes`),
  so the declaration is present where a user clicks the `.dmg`, not only inside artifacts they
  have not opened.
- **Notarization is observable and bounded (C6):** `notarytool submit --wait` runs under an
  explicit step timeout; on any result other than Accepted the job runs `notarytool log
  <submission-id>`, prints it, and uploads it as a job artifact; a transient failure (network,
  service) is retried with bounded backoff, a rejection fails fast with the log.
- Secrets never appear in logs (the job masks them and never echoes the keychain password or the
  notary key, I-M2).
- **`ci-macos.yml` is cheap and stable (C5):** `concurrency: { group: ci-macos-${{ github.ref }},
  cancel-in-progress: true }`, `timeout-minutes: 30`, `on.push.paths` scoped to the packaging and
  app inputs (the workflow files, `cmd/seavault`, `internal/webui/assets/svlogo`, the packaging
  scripts and plist template) so doc-only commits skip it, and `hdiutil detach` / `installer`
  wrapped in bounded retries.

## 5. Docs: the workaround, front and center

`docs/install.md` (new, linked from a new README **Install** section): macOS first — download the
DMG, drag to Applications, then the workaround **written for the macOS that ships today (C1)**,
kept in ONE source file (`packaging/macos/FIRST-LAUNCH.txt`) that the release job copies into
the DMG, the PKG readme pane, `SIGNING.txt`'s companion note, and that `install.md` includes
verbatim (drift-guarded):

> **This build is not yet signed with an Apple Developer ID, so macOS will refuse to open it the
> first time.** Two ways to allow it, once:
> 1. **macOS 13 Ventura and later (including macOS 26 Tahoe):** open the app once (it will be
>    blocked), then open **System Settings → Privacy & Security**, scroll to *Security*, click
>    **Open Anyway** next to open-seavault-rclone, and confirm with Touch ID or your password. On
>    macOS 15 Sequoia and later, click through the extra confirmation dialog that follows.
> 2. **Any version, in Terminal (drag the app into /Applications first):**
>    `xattr -dr com.apple.quarantine /Applications/open-seavault-rclone.app`
>
> If the DMG's `Install command-line tool.command` is itself blocked, Control-click it → Open. On
> macOS 11–12 only, Control-click the app → Open → Open also works. For the installer package:
> Control-click the .pkg → Open (all versions) — though a `.pkg`-installed app usually carries no
> quarantine and opens with no prompt. Once open, the interface is the browser (no Dock icon, an
> agent) and the app quits when the page closes.

The header is **open-ended by version floor, never a closed enumeration** (durability condition
C1; friction A/C2): "macOS 13 Ventura and later" does not go stale when a new major ships, as the
frozen "…, 15 Sequoia" list did the day macOS 26 Tahoe shipped. The M7 drift guard asserts the
open-ended phrasing (and forbids the old frozen list), not a version name.

Then the command-line tool (the `.command` or the PKG; open a new Terminal; `PATH` note), what
launching does (the browser opens; there is no Dock icon; the app quits when the page closes or
after 60 s if no page connects; a second double-click re-opens the running instance), where data
and the log live, and **uninstall, precisely (C9)**: quit the running app first (it has no Dock
icon — use Activity Monitor or `pkill -f open-seavault-rclone`), `sudo rm /usr/local/bin/seavault`
(the symlink is root-owned when the PKG or the `.command` created it), drag
`/Applications/open-seavault-rclone.app` to the Trash, `sudo pkgutil --forget
io.github.alexdimarco.open-seavault-rclone` if the PKG was used, and delete
`~/Library/Application Support/open-seavault-rclone` to remove app data (vaults live where the
user put them and are untouched). Then Linux (tarball, where to put it) and Windows (zip and the
SmartScreen "More info → Run anyway" note, since the same unsigned state applies). A sentence
states that signed and notarized builds will remove the macOS step once a Developer ID is in
place.

## 6. Security invariants (proven by §7 unless labeled)

- **I-M1** The bundle executable is `lipo` of the exact darwin binaries the Linux release job
  built and uploaded (downloaded as artifacts, never recompiled): after `lipo -thin` each slice
  is byte-identical to the corresponding tarball binary (C8).
- **I-M2** No certificate password, notary key, or keychain password is ever printed; the job
  runs with secrets masked and the temporary keychain deleted after use.
- **I-M3** The Finder-launch default changes nothing for Terminal use: `seavault` with no
  arguments in a shell prints usage exactly as before.
- **I-M4** The installer scripts (DMG `.command`, PKG `postinstall`) ensure `/usr/local/bin`
  exists and create one symlink, and nothing else: no network, no other writes, no privilege
  beyond that (C4).
- **I-M5** The signing state is declared inside every artifact, in the docs, and in the GitHub
  Release body; an unsigned build is never presented as signed; asset names do not encode
  signing state (C3).
- **I-M6** A bundle launch never leaves an invisible lingering process: it exits when the page
  closes or when no page connects within the grace period.
- **I-M7** A bundle launch binds its port before opening a browser and never starts a second
  server: a second launch re-opens the running instance's current link and exits (C10).
- **I-M8** On a bundle launch the launch URL and every exit reason are written to a real file
  sink under the app-data dir, not only to a stdout LaunchServices discards (C7).
- **Conditional (labeled, C2):** Gatekeeper behaviour is Apple's and version-dependent. The
  workaround text names two GUI flows by an OPEN-ENDED version floor — System Settings → Privacy
  & Security → Open Anyway (macOS 13 Ventura and later, the current path) and Control-click → Open
  (only the older macOS 11–12) — plus the version-independent `xattr` command. The version floor is
  never a closed enumeration (C1/friction A/C2), so it does not go stale when a new macOS major
  ships. A headless runner cannot exercise the GUI dialog, so the per-release check of
  the workaround against the current macOS is a **manual gate**: a dated human sign-off recorded
  in `packaging/macos/GATEKEEPER-CHECK.md` before each tag.

## 7. Test matrix (red-first; every row asserts; the macOS rows run on the release runner and in a CI job on `macos-latest`)

| ID | Proves | How |
|---|---|---|
| M1 | §2.1, I-M3 | on darwin, with `SEAVAULT_BUNDLE_LAUNCH=1` (or an executable path under `/Contents/MacOS/`) and no args → `gui` is dispatched (browser suppressed in the test); with neither → usage; on other OSes the env var is ignored |
| M2 | §2.2, I-M6, I-M8 | a bundle launch with no page connecting exits within the grace period and the FILE `logs/gui.log` contains the launch URL and the grace-exit line (stdout capture is not the proof, C7); a connected page keeps it alive; Terminal `gui` has no grace exit and writes no file |
| M3 | §2, I-M1 | RELEASE job only (C8): `lipo -info` lists x86_64 and arm64 and each `lipo -thin` slice is byte-identical to the downloaded tarball binary; `plutil -lint` passes; the icns exists. The push-time `ci-macos.yml` job assembles from a fresh local build and runs the same structural checks, explicitly labeled "self-consistency, does NOT prove I-M1" |
| M4 | §4 signing | ad-hoc: `codesign --verify --deep --strict` passes and `spctl --assess` is recorded as rejected; with secrets: accepted and stapled — the row asserts whichever expectation matches the secrets present and never passes vacuously |
| M5 | §3, I-M4 | `pkgutil --expand`: the postinstall equals the golden `mkdir -p /usr/local/bin` + symlink script; `installer -pkg … -target /` on a runner with `/usr/local/bin` REMOVED first, then `/usr/local/bin/seavault --version` prints the version (C4); the DMG `.command` equals the same golden logic |
| M6 | §3 | `hdiutil attach`: the DMG holds the app, the Applications link, `FIRST-LAUNCH.txt`, `SIGNING.txt`, and the `.command`; detach (bounded retries) |
| M7 | §5, I-M5, C2 | `SIGNING.txt` and the PKG readme say "ad-hoc, not notarized" for the unsigned path; `docs/install.md` includes `packaging/macos/FIRST-LAUNCH.txt` verbatim and that text contains "Privacy & Security", "Open Anyway", and the `xattr -dr com.apple.quarantine` command; every command the doc names exists in `--help`; `GATEKEEPER-CHECK.md` carries a dated sign-off for the current tag (release job asserts presence; the human writes it) |
| M8 | smoke | run the bundle binary as a bundle launch with the browser suppressed; the launch URL from `logs/gui.log` answers over loopback; the process exits after the page-close heartbeat stops |
| M9 | I-M5, C3 | after publish, `gh release view` shows the release body begins with the first-launch note |
| M10 | I-M7, C10 | with an instance serving, a second bundle launch re-opens the running instance's current link (captured via the suppressed-browser seam) and exits without binding; the port is bound before the browser-open seam fires; a stale lock file is ignored; Terminal `gui` on a busy port still errors |
| M11 | §3, C4 | the `.command` and postinstall handle a missing `/usr/local/bin`; `install.md` documents the new-Terminal and `PATH` notes (drift guard) |
| M12 | C5 | `ci-macos.yml` declares concurrency cancel-in-progress, a 30-minute timeout, and path scoping; a doc-only commit does not trigger it (asserted by inspecting the workflow file in a Linux test) |
| Z1 | discipline | no pre-U5 test edited except via the exemption list; the unfiltered race suite green on Linux; the macOS CI job green |

## 8. Build order

S1 (app-side: Finder-launch default + grace timeout + tests M1/M2, Linux-testable with the env var
and an injected executable path) → S2 (release workflow `macos` job: bundle assembly, icns, plist,
conditional signing, DMG/PKG, verification and smoke — plus a `ci-macos.yml` that runs the same
assembly and M3–M8 on every push to main so the packaging is exercised before a tag) → S3 (docs:
install.md, README Install, FIRST-LAUNCH/SIGNING text, changelog v0.22, drift guard). Each slice:
builder, independent verifier, one fix cycle; the final verifier confirms the packaging job ran
green on a macOS runner (a pushed branch build), not only that the YAML parses.

## 9. Revision 2 — how each review condition was applied

| Cond | Applied as |
|---|---|
| C1 | §5 workaround rewritten with an OPEN-ENDED version floor (macOS 13 Ventura and later, Privacy & Security → Open Anyway) with `xattr` co-primary and Control-click → Open demoted to the older 11–12; one source file `packaging/macos/FIRST-LAUNCH.txt` propagated everywhere. The fix tranche (friction A/C2) made the header open-ended after the frozen "…, 15 Sequoia" list shipped already two majors behind macOS 26 Tahoe |
| C2 | §6 conditional names the flows by an open-ended version floor + the version-independent command; the per-release Gatekeeper check is a manual, dated sign-off in `GATEKEEPER-CHECK.md`; M7 asserts the open-ended phrasing (forbidding the old frozen list), the Open Anyway/xattr text, and the sign-off's presence |
| C3 | §4 the release body carries the first-launch note; I-M5; M9 |
| C4 | §3 scripts `mkdir -p /usr/local/bin` then symlink; I-M4 relaxed accordingly; PATH/new-Terminal notes; M5 runs with the dir removed; M11 |
| C5 | §4 `ci-macos.yml` concurrency cancel-in-progress, 30-min timeout, path scoping, bounded retries; M12 |
| C6 | §4 notarization under a step timeout; `notarytool log` printed and uploaded on non-Accepted; transient retry vs fail-fast rejection |
| C7 | §2.2 a real file sink `logs/gui.log` for bundle launches; I-M8; M2 asserts the file |
| C8 | §4 the macOS job downloads the Linux-built darwin binaries and lipos those; I-M1 = per-slice byte identity; M3 release-only, the push-time job labeled self-consistency |
| C9 | §5 uninstall precisely: quit the Dock-iconless app (Activity Monitor / pkill), `sudo rm` the symlink, Trash the app, `pkgutil --forget`, delete app data |
| C10 | §2.2 bind before browser-open; single-instance via an app-data lock + an authenticated relaunch call; I-M7; M10 |
| C11 | §2 the 512-px icon cap stated; a 1024/vector master is a later asset |
