# Release checklist

Follow this before pushing a release tag. The macOS packaging is exercised on every
push by `ci-macos.yml`; this checklist covers the human gates the automation cannot
perform, and the order of operations for cutting a tag.

## Before tagging

1. **Green CI.** The unfiltered race suite (`make test` / `go test -race ./...`) is
   green on Linux, and the latest `ci-macos.yml` run on the branch you are releasing
   is green. All six release cross-builds are clean — the same six targets the release
   workflow ships (linux and darwin amd64/arm64, windows amd64/arm64), not only a spot
   check:

   ```sh
   for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
     GOOS="${t%/*}" GOARCH="${t#*/}" go build ./cmd/seavault || echo "FAILED: $t"
   done
   ```

2. **Version and changelog.** Add a "What changed in vX.Y" entry to `README.md`. You do
   **not** hand-edit a version number in the source: the version the shipped binary
   reports is `var version` in `cmd/seavault/main.go`, and the release workflow injects
   the tag into it at link time with
   `go build -ldflags "-X main.version=${GITHUB_REF_NAME#v}"`. The dev tree keeps a
   `-dev` default so a locally built binary is never mistaken for a released one; the
   released binary's version therefore comes from the git tag you push, not from that
   line. Pick the tag (`vX.Y.Z`) so it matches the README changelog heading.

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
     [`packaging/macos/GATEKEEPER-CHECK.md`](../packaging/macos/GATEKEEPER-CHECK.md),
     following the row format that file documents.

   The `release` job runs this check **before it publishes the GitHub Release** — the
   anchored per-tag row grep sits ahead of `gh release create`, so a missing sign-off
   fails the whole release before anything is published, not merely the DMG/PKG attach.
   The match is an anchored table row whose Tag column equals the tag exactly (a loose
   substring would be spoofable), so the gate cannot be skipped silently. The job cannot
   check the GUI copy for correctness &mdash; that is what your sign-off attests.

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
