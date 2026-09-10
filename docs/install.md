# Installing open-seavault-rclone

open-seavault-rclone ships as a desktop build for macOS and as plain archives for
Linux and Windows. Every build is listed on the project's [GitHub Releases](https://github.com/alexdimarco/open-seavault-rclone/releases)
page. The file names below use `vX.Y.Z` for the release tag you are installing.

The desktop builds are not yet code-signed (see [About signing](#about-signing)), so
macOS and Windows each show a one-time warning the first time you open them. Both are
documented below, front and center, because you will meet them before anything else.

## macOS

Download `open-seavault-rclone_vX.Y.Z_macos_universal.dmg` from the Releases page,
open it, and drag **open-seavault-rclone** onto the **Applications** shortcut in the
same window. (A `.pkg` installer is published too — see
[The command-line tool](#the-command-line-tool-seavault) — which drops the same app
in Applications and installs the CLI in one step.)

### First launch (Gatekeeper)

This is the one-time step to allow an unsigned build. It is reproduced verbatim from
`FIRST-LAUNCH.txt`, the single source that also ships inside the DMG, in the `.pkg`
readme pane, and at the top of the GitHub Release description — so it reads the same
wherever you meet it:

```text
open-seavault-rclone — first launch on macOS

This build is not yet signed with an Apple Developer ID, so macOS will refuse to
open it the first time. Two ways to allow it, once:

  1. macOS 13 Ventura and later (including macOS 26 Tahoe):
     open the app once (it will be blocked), then open
     System Settings -> Privacy & Security, scroll to Security, click
     "Open Anyway" next to open-seavault-rclone, and confirm with Touch ID or
     your password. On macOS 15 Sequoia and later, macOS shows one more
     confirmation dialog right after that — click "Open Anyway" (or "Open") in it
     to finish.

  2. Any version, in Terminal (drag the app into /Applications first — this
     command targets it there):
     xattr -dr com.apple.quarantine /Applications/open-seavault-rclone.app

If you double-click "Install command-line tool.command" from the DMG and macOS
blocks it too, Control-click it -> Open -> Open to run it that once.

On macOS 11-12 only, Control-click the app -> Open -> Open also works. For the
installer package: Control-click the .pkg -> Open (all versions). An app installed
from the .pkg usually carries no quarantine flag, so it often opens with no
first-launch prompt at all.

Once it opens, the interface is your web browser: there is no separate window and
no Dock icon (the app runs as a macOS agent), and it quits on its own when you
close the browser tab.

Signed and notarized builds will remove this step once an Apple Developer ID is
in place. This artifact's exact signing state is recorded in SIGNING.txt.
```

### The command-line tool (`seavault`)

The app is enough to open vaults from Finder, but the `seavault` command adds
scripting and the full CLI. Two ways to install it:

- **From the DMG:** double-click **Install command-line tool.command**. It asks for
  your password once (in Terminal, through `sudo`) and symlinks
  `/usr/local/bin/seavault` to the binary inside the app. It creates `/usr/local/bin`
  if it is missing (a fresh Apple-silicon Mac has no such directory) and does nothing
  else — no network, no other writes. The `.command` is unsigned like the app, so
  macOS may block it on first run too; if it does, **Control-click it → Open → Open**
  to run it that once.
- **From the PKG:** download `open-seavault-rclone_vX.Y.Z_macos_universal.pkg` and run
  it. It installs the app into `/Applications` and its `postinstall` makes the same
  `/usr/local/bin/seavault` symlink for you. An app installed this way usually carries
  no quarantine flag, so it typically opens without the first-launch step above.

**Open a new Terminal window afterward** so the shell picks up the new command — a
Terminal that was already open will not see it (a stale Terminal is the usual reason
`seavault` seems missing). On the rare setup where `/usr/local/bin` is genuinely not
on your `PATH`, add it to your login shell's profile and open a new Terminal again.
Use the file for your shell — `~/.zprofile` for **zsh** (the macOS default) or
`~/.bash_profile` for **bash**. These are idempotent (they check before appending, so
running them twice adds nothing):

```sh
# zsh (macOS default):
grep -qxF 'export PATH="/usr/local/bin:$PATH"' ~/.zprofile 2>/dev/null || \
  echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zprofile

# bash login shell (if that is your shell instead):
grep -qxF 'export PATH="/usr/local/bin:$PATH"' ~/.bash_profile 2>/dev/null || \
  echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile
```

Confirm the install with `seavault version`.

### What launching does

Double-clicking the app (or running `seavault gui`) opens the interface **in your web
browser** — there is no separate application window, and no bouncing Dock icon,
because the app runs as a macOS agent. It quits on its own when you close the browser
tab, or after 60 seconds if no page ever connects (for example if the browser was
blocked). Double-clicking the app a second time does **not** start a second copy: it
re-opens the tab for the instance already running.

### Where your data and the log live

- App data (this device's config, saved profiles, the single-instance lock):
  `~/Library/Application Support/open-seavault-rclone`
- The bundle-launch log: `~/Library/Application Support/open-seavault-rclone/logs/gui.log`
  — owner-readable only (`0600`). LaunchServices discards a double-clicked app's
  console output, so the launch URL and every exit reason are written to this file
  instead of the terminal.
- Your **vaults** live wherever you created them (inside a cloud-sync folder, on an
  external drive, and so on) and are never stored inside the app-data directory.

### Uninstall

Reverse the install in order. Your vaults are untouched by every step below.

1. **Quit the running app first.** A bundle launch (double-click) runs as an agent with
   no Dock icon, so quit it in **Activity Monitor** (search for `open-seavault-rclone`
   and stop it) or in Terminal:

   ```sh
   pkill -f open-seavault-rclone
   ```

   That matches the bundle agent. If instead you started the GUI yourself in a Terminal
   with `seavault gui`, its process is named `seavault` (not `open-seavault-rclone`), so
   `pkill` above will not catch it — press **Ctrl-C** in that Terminal to stop it.

2. **Remove the CLI symlink.** It is root-owned when the PKG or the `.command`
   created it, so use `sudo`:

   ```sh
   sudo rm /usr/local/bin/seavault
   ```

3. **Drag `open-seavault-rclone.app`** from `/Applications` to the Trash.

4. **Forget the package receipt** — only if you installed with the `.pkg`:

   ```sh
   sudo pkgutil --forget io.github.alexdimarco.open-seavault-rclone
   ```

5. **Delete the app data** to remove this device's config and the log:

   ```sh
   rm -rf ~/Library/Application\ Support/open-seavault-rclone
   ```

   This removes app data only; your vaults live where you put them and are not
   deleted here. Remove a vault by deleting its own folder.

## Linux

There is no Gatekeeper step on Linux. Download
`open-seavault-rclone_vX.Y.Z_linux_amd64.tar.gz` (or `_linux_arm64` on ARM), unpack
it, and put the `seavault` binary somewhere on your `PATH`:

```sh
tar -xzf open-seavault-rclone_vX.Y.Z_linux_amd64.tar.gz
sudo install open-seavault-rclone_vX.Y.Z_linux_amd64/seavault /usr/local/bin/seavault
seavault version
```

Then run `seavault setup` to create your first vault, or `seavault gui` for the
browser interface.

## Windows

Download `open-seavault-rclone_vX.Y.Z_windows_amd64.zip` (or `_windows_arm64`), unzip
it, and put `seavault.exe` somewhere on your `PATH`.

This build is **not yet code-signed with an Authenticode certificate**, so the first
time you run it Microsoft Defender **SmartScreen** may show "Windows protected your
PC". Click **More info**, then **Run anyway** to allow it — the same unsigned state
the macOS note above describes. Then run `seavault setup` to begin.

## About signing

These desktop builds are shipped unsigned for now. Once an Apple Developer ID (macOS)
and an Authenticode certificate (Windows) are in place, the release pipeline signs and
notarizes automatically, the artifact names stay exactly the same, and both the macOS
"Open Anyway" / `xattr` step and the Windows SmartScreen step disappear. Every macOS
artifact records its own exact signing state inside it, in `SIGNING.txt`.
