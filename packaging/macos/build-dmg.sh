#!/usr/bin/env bash
# build-dmg.sh — a drag-to-Applications DMG holding the .app, an Applications
# symlink, the first-launch/signing texts, and the golden CLI-install .command
# (design §3). Runs on macOS (needs hdiutil).
#
# Usage:
#   build-dmg.sh <app-path> <version> <out.dmg>
#
# Env:
#   FIRST_LAUNCH_SRC  first-launch text (default: packaging/macos/FIRST-LAUNCH.txt)
#   INSTALL_CLI_SRC   golden CLI-install script (default: packaging/macos/install-cli.sh)
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: build-dmg.sh <app-path> <version> <out.dmg>" >&2
	exit 2
fi

APP="$1"
VERSION="$2"
OUT_DMG="$3"

HERE="$(cd "$(dirname "$0")" && pwd)"
FIRST_LAUNCH_SRC="${FIRST_LAUNCH_SRC:-$HERE/FIRST-LAUNCH.txt}"
INSTALL_CLI_SRC="${INSTALL_CLI_SRC:-$HERE/install-cli.sh}"

[ -d "$APP" ] || { echo "missing app: $APP" >&2; exit 1; }

STAGE="$(mktemp -d)/dmgroot"
mkdir -p "$STAGE"

cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
cp "$FIRST_LAUNCH_SRC" "$STAGE/FIRST-LAUNCH.txt"
cp "$APP/Contents/Resources/SIGNING.txt" "$STAGE/SIGNING.txt"

# The CLI-install entry point is the golden install-cli.sh copied VERBATIM (M5's
# byte-identity golden — the .pkg postinstall is the same file). No rewrite.
cp "$INSTALL_CLI_SRC" "$STAGE/Install command-line tool.command"
chmod +x "$STAGE/Install command-line tool.command"

rm -f "$OUT_DMG"
hdiutil create \
	-volname "open-seavault-rclone" \
	-srcfolder "$STAGE" \
	-fs HFS+ \
	-format UDZO \
	-ov \
	"$OUT_DMG"

echo "built DMG: $OUT_DMG"
