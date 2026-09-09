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

# /usr/local/bin is root-owned, and absent on a fresh Apple-silicon Mac (C4). The
# .pkg postinstall already runs as root; the DMG .command is double-clicked as the
# user, so re-exec once under sudo (a password prompt in Terminal) to obtain
# exactly the privilege the mkdir + symlink below need, and nothing more.
if [ "$(id -u)" -ne 0 ]; then
	exec sudo /bin/sh "$0" "$@"
fi

mkdir -p /usr/local/bin
ln -sf "$BIN" /usr/local/bin/seavault

echo "Installed: /usr/local/bin/seavault -> $BIN"
echo "Open a NEW Terminal window so seavault is on your PATH."
echo "If your shell still cannot find it, add /usr/local/bin to your PATH:"
echo '  echo '\''export PATH="/usr/local/bin:$PATH"'\'' >> ~/.zprofile'
