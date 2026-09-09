# Design — Phase U5: a proper macOS bundle (unsigned tier), installers, and install docs

STATUS: pre-code design, awaiting the 10-lens review. Revision 1.

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
                          internal/webui/assets/svlogo/icon.png via sips + iconutil
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

### 2.2 Bundle-launch grace timeout (app-side, small)

`gui` already exits when the browser page stops sending heartbeats, but if the browser never
opens (blocked, misconfigured) a background process with no Dock icon would linger. On a bundle
launch, `gui` also exits if no page connects within a grace period (60 s, `--bundle-grace`
override), logging one line to the app log (I-M6). Terminal `gui` is unchanged.

## 3. Installers

- **DMG** `open-seavault-rclone_vX.Y.Z_macos_universal.dmg`: the `.app`, an `Applications` symlink,
  `FIRST-LAUNCH.txt`, `SIGNING.txt`, and `Install command-line tool.command` (a double-clickable
  script that symlinks `/usr/local/bin/seavault` → the bundle binary, asking for the password via
  `sudo` in Terminal; it does nothing else, I-M4).
- **PKG** `open-seavault-rclone_vX.Y.Z_macos_universal.pkg` (`pkgbuild` + `productbuild`,
  install location `/Applications`, a `postinstall` that only creates the same symlink, I-M4).
  Distribution XML shows the first-launch note as the installer's readme pane.
- Both names are stable regardless of signing state; the signing state is declared inside
  (`SIGNING.txt`, the installer readme), never hidden or implied by a filename (I-M5).

## 4. The release job

A second job `macos` (runs-on `macos-latest`) in `.github/workflows/release.yml`, needing the
existing verify step to have passed: build both darwin binaries with the same flags as the Linux
job, `lipo -create`, assemble the bundle, generate the `.icns`, write the plist with the tag
version, then **sign**:

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
  tarballs stay for scripts.
- Secrets never appear in logs (the job masks them and never echoes the keychain password or the
  notary key, I-M2).

## 5. Docs: the workaround, front and center

`docs/install.md` (new, linked from a new README **Install** section): macOS first — download the
DMG, drag to Applications, then **"macOS will say the app cannot be opened because Apple cannot
check it for malicious software. This build is not yet signed with an Apple Developer ID. To open
it: right-click (or Control-click) the app → Open → Open. You only need to do this once. Or, in
Terminal: `xattr -dr com.apple.quarantine /Applications/open-seavault-rclone.app`."** — the same
text in `FIRST-LAUNCH.txt`, the DMG, and the PKG readme pane; the PKG gets its own line
("right-click the .pkg → Open"). Then the command-line tool, what launching does (the browser
opens; the app quits when the page closes), where data lives, how to uninstall (drag to Trash,
remove the symlink, the app-data path). Then Linux (tarball, where to put it) and Windows (zip
and the SmartScreen "More info → Run anyway" note, since the same unsigned state applies). A
sentence states that signed and notarized builds will remove the macOS step once a Developer ID
is in place.

## 6. Security invariants (proven by §7 unless labeled)

- **I-M1** The bundle executable is the same universal build of the same sources as the released
  tarball binaries (same flags, same commit); no separate build path.
- **I-M2** No certificate password, notary key, or keychain password is ever printed; the job
  runs with secrets masked and the temporary keychain deleted after use.
- **I-M3** The Finder-launch default changes nothing for Terminal use: `seavault` with no
  arguments in a shell prints usage exactly as before.
- **I-M4** The installer scripts (DMG `.command`, PKG `postinstall`) create one symlink and
  nothing else: no network, no other writes, no privilege beyond the symlink.
- **I-M5** The signing state is declared inside every artifact and in the docs; an unsigned
  build is never presented as signed; asset names do not encode signing state.
- **I-M6** A bundle launch never leaves an invisible lingering process: it exits when the page
  closes or when no page connects within the grace period.
- **Conditional (labeled):** Gatekeeper behaviour is Apple's and version-dependent; the
  workaround text matches macOS 11–15 and is re-checked per release on the runner's macOS.

## 7. Test matrix (red-first; every row asserts; the macOS rows run on the release runner and in a CI job on `macos-latest`)

| ID | Proves | How |
|---|---|---|
| M1 | §2.1, I-M3 | on darwin, with `SEAVAULT_BUNDLE_LAUNCH=1` (or an executable path under `/Contents/MacOS/`) and no args → `gui` is dispatched (browser suppressed in the test); with neither → usage; on other OSes the env var is ignored |
| M2 | §2.2, I-M6 | a bundle launch with no page connecting exits within the grace period with the log line; a connected page keeps it alive; Terminal `gui` has no grace exit |
| M3 | §2, I-M1 | on the runner: `lipo -info` lists x86_64 and arm64; the bundle binary's hash equals the tarball binaries' per-arch hashes after `lipo -thin`; `plutil -lint` passes; the icns exists |
| M4 | §4 signing | ad-hoc: `codesign --verify --deep --strict` passes and `spctl --assess` is recorded as rejected; with secrets: accepted and stapled (job-gated) |
| M5 | §3, I-M4 | `pkgutil --expand`: the postinstall contains exactly the symlink logic (a golden file); `installer -pkg … -target /` then `/usr/local/bin/seavault --version` prints the version; the DMG `.command` is the same golden logic |
| M6 | §3 | `hdiutil attach`: the DMG holds the app, the Applications link, `FIRST-LAUNCH.txt`, `SIGNING.txt`, and the `.command`; detach |
| M7 | §5, I-M5 | `SIGNING.txt` and the PKG readme say "ad-hoc, not notarized" for the unsigned path; `docs/install.md` contains the right-click → Open and `xattr` workaround and every command it names exists in `--help` (drift guard) |
| M8 | smoke | run the bundle binary as a bundle launch with the browser suppressed; the printed launch URL answers over loopback; the process exits after the page-close heartbeat stops |
| Z1 | discipline | no pre-U5 test edited except via the exemption list; the unfiltered race suite green on Linux; the macOS CI job green |

## 8. Build order

S1 (app-side: Finder-launch default + grace timeout + tests M1/M2, Linux-testable with the env var
and an injected executable path) → S2 (release workflow `macos` job: bundle assembly, icns, plist,
conditional signing, DMG/PKG, verification and smoke — plus a `ci-macos.yml` that runs the same
assembly and M3–M8 on every push to main so the packaging is exercised before a tag) → S3 (docs:
install.md, README Install, FIRST-LAUNCH/SIGNING text, changelog v0.22, drift guard). Each slice:
builder, independent verifier, one fix cycle; the final verifier confirms the packaging job ran
green on a macOS runner (a pushed branch build), not only that the YAML parses.
