# Release checklist

Follow this before pushing a release tag. The macOS packaging is exercised on every
push by `ci-macos.yml`; this checklist covers the human gates the automation cannot
perform, and the order of operations for cutting a tag.

## Before tagging

1. **Green CI.** The unfiltered race suite (`make test` / `go test -race ./...`) is
   green on Linux, and the latest `ci-macos.yml` run on the branch you are releasing
   is green. Both cross-builds are clean:

   ```sh
   GOOS=windows GOARCH=amd64 go build ./cmd/seavault
   GOOS=darwin  GOARCH=arm64 go build ./cmd/seavault
   ```

2. **Version and changelog.** Bump the version, and add a "What changed in vX.Y" entry
   to `README.md`.

3. **Manual Gatekeeper sign-off (macOS, required every tag).** Gatekeeper's
   first-launch behaviour is Apple's and version-dependent, and a headless CI runner
   cannot exercise the GUI dialog, so this is a **manual gate**. On a Mac running the
   current macOS release, with a freshly downloaded (quarantined) build:

   - Verify the `packaging/macos/FIRST-LAUNCH.txt` workaround still matches the
     shipping macOS (System Settings &rarr; Privacy & Security &rarr; **Open Anyway**;
     the `xattr -dr com.apple.quarantine` fallback; the `.pkg` via Control-click &rarr;
     Open). If any path no longer matches, fix `FIRST-LAUNCH.txt` &mdash; the single
     source that flows into the DMG, the PKG readme, `docs/install.md`, and the Release
     body &mdash; **before** tagging.
   - Record a dated sign-off row for the tag in
     [`packaging/macos/GATEKEEPER-CHECK.md`](../packaging/macos/GATEKEEPER-CHECK.md).

   The release job asserts that a row for the tag being released exists in that file
   and fails the release if it is missing, so this gate cannot be skipped silently.
   The job cannot check the GUI copy for correctness &mdash; that is what your sign-off
   attests.

4. **Docs match reality.** `docs/install.md` names the current artifact set and every
   `seavault` command it mentions still exists (the doc drift guards in
   `cmd/seavault` enforce both, but re-read the macOS section after any packaging
   change).

## Cutting the tag

5. Push the tag. The release workflow builds the per-platform archives, then the
   `macos` job downloads the darwin binaries, assembles and verifies the bundle, ad-hoc
   (or Developer-ID) signs, notarizes when secrets are present, builds the DMG and PKG,
   appends their hashes to `SHA256SUMS.txt`, and prepends `FIRST-LAUNCH.txt` to the
   Release body.

6. **After publish**, confirm the GitHub Release body opens with the first-launch note,
   and that the DMG, PKG, and `SHA256SUMS.txt` are attached.
