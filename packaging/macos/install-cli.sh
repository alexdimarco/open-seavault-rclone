#!/bin/sh
# open-seavault-rclone — install the command-line tool  (design §3, I-M4, C4).
#
# GOLDEN SCRIPT. This exact file is shipped byte-for-byte as BOTH the DMG's
# "Install command-line tool.command" and the .pkg postinstall (M5's golden).
# packaging/macos/build-dmg.sh and build-pkg.sh copy it verbatim; nothing rewrites
# it, so the two installer entry points can never drift.
#
# It does one thing: ensure /usr/local/bin exists and symlink
# /usr/local/bin/seavault to the bundled binary. No network, no other writes, no
# privilege beyond creating that one directory and that one symlink.
set -eu

APP="/Applications/open-seavault-rclone.app"
BIN="$APP/Contents/MacOS/open-seavault-rclone"

# friction B/C1: the bundle binary must exist and be executable before we do
# anything. A user who double-clicks this .command BEFORE dragging the app into
# /Applications would otherwise get a dangling symlink and a false "Installed".
# Check first, before the sudo re-exec, so the fix (drag the app) costs no
# password prompt.
if [ ! -x "$BIN" ]; then
	echo "Drag open-seavault-rclone.app into /Applications first, then run this again." >&2
	exit 1
fi

# /usr/local/bin is root-owned, and absent on a fresh Apple-silicon Mac (C4). The
# .pkg postinstall already runs as root; the DMG .command is double-clicked as the
# user, so re-exec once under sudo (a password prompt in Terminal) to obtain
# exactly the privilege the mkdir + symlink below need, and nothing more.
if [ "$(id -u)" -ne 0 ]; then
	exec sudo /bin/sh "$0" "$@"
fi

mkdir -p /usr/local/bin
# installer-scripts-1 (I-M4): remove any pre-existing /usr/local/bin/seavault
# FIRST, then ln -sfn (never dereference a pre-existing symlink-to-directory — a
# plain `ln -sf` would drop the new link INSIDE that directory, a root-owned write
# into an attacker-controlled target on a user-writable /usr/local/bin). Then
# verify readlink points exactly where we intended, or fail loudly.
rm -f /usr/local/bin/seavault
ln -sfn "$BIN" /usr/local/bin/seavault
got="$(readlink /usr/local/bin/seavault || true)"
if [ "$got" != "$BIN" ]; then
	echo "Install failed: /usr/local/bin/seavault points at '$got', expected '$BIN'." >&2
	exit 1
fi

echo "Installed: /usr/local/bin/seavault -> $BIN"
echo "Open a NEW Terminal window so seavault is on your PATH."
echo "If your shell still cannot find it, add /usr/local/bin to your PATH:"
echo '  echo '\''export PATH="/usr/local/bin:$PATH"'\'' >> ~/.zprofile'
