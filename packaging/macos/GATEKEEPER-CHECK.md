# Gatekeeper workaround sign-off (manual per-release gate)

Gatekeeper's first-launch behaviour is Apple's and version-dependent, and a
headless CI runner cannot exercise the GUI dialog (design §6, C2). So before each
release tag a human must verify, on the macOS that ships today, that the
`FIRST-LAUNCH.txt` workaround still works, and record it here.

The release job asserts that a row for the tag being released exists in the table
below (it greps this file for the tag). It does **not** and cannot check the GUI
copy for correctness — that is what your sign-off attests. The job fails the
release if no row names the tag, so this gate cannot be skipped silently.

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
| v0.0.0-EXAMPLE | 15.x Sequoia | 2026-01-01 | (example row — not a real sign-off) | Open Anyway + xattr verified; delete when a real tag is added |
