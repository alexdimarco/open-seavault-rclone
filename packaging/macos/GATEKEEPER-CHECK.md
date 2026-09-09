# Gatekeeper workaround sign-off (manual per-release gate)

Gatekeeper's first-launch behaviour is Apple's and version-dependent, and a
headless CI runner cannot exercise the GUI dialog (design §6, C2). So before each
release tag a human must verify, on the macOS that ships today, that the
`FIRST-LAUNCH.txt` workaround still works, and record it here.

Before it publishes the GitHub Release, the release job asserts that a sign-off
row for the tag being released exists in the table below. The match is an ANCHORED
table row whose Tag column equals the tag EXACTLY (not a loose substring: a
substring grep is spoofable — an example row, or `v0.2` inside `v0.22`). It does
**not** and cannot check the GUI copy for correctness — that is what your sign-off
attests. A missing row fails the job before anything is published, so this gate
cannot be skipped silently.

## What to verify before signing off

On a Mac running the current macOS release, with a freshly downloaded (quarantined)
DMG for the candidate tag:

1. **macOS 13-15 path:** open the app once (blocked), then
   System Settings -> Privacy & Security -> Security -> **Open Anyway** -> confirm.
   The app launches.
2. **xattr path (any version):**
   `xattr -dr com.apple.quarantine /Applications/open-seavault-rclone.app`, then
   open the app. It launches.
3. The `.pkg` opens via Control-click -> Open.

If any path no longer matches the shipping macOS, fix `FIRST-LAUNCH.txt` (the single
source) BEFORE tagging, then sign off.

## Sign-off log

Add one row per release tag. Keep newest at the top.

| Tag | macOS version checked | Date | Signed off by | Result |
|-----|-----------------------|------|---------------|--------|
