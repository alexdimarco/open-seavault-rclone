#!/usr/bin/env bash
# build-pkg.sh — a flat installer .pkg that drops the .app in /Applications and,
# via a postinstall, symlinks the seavault CLI (design §3). The first-launch note
# is the installer's readme pane. Runs on macOS (needs pkgbuild, productbuild).
#
# Usage:
#   build-pkg.sh <app-path> <version> <out.pkg>
#
# Env:
#   FIRST_LAUNCH_SRC  first-launch text (default: packaging/macos/FIRST-LAUNCH.txt)
#   INSTALL_CLI_SRC   golden CLI-install script (default: packaging/macos/install-cli.sh)
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: build-pkg.sh <app-path> <version> <out.pkg>" >&2
	exit 2
fi

APP="$1"
VERSION="$2"
OUT_PKG="$3"

HERE="$(cd "$(dirname "$0")" && pwd)"
FIRST_LAUNCH_SRC="${FIRST_LAUNCH_SRC:-$HERE/FIRST-LAUNCH.txt}"
INSTALL_CLI_SRC="${INSTALL_CLI_SRC:-$HERE/install-cli.sh}"
IDENTIFIER="io.github.alexdimarco.open-seavault-rclone"

SHORT_VERSION="${VERSION#v}"
SHORT_VERSION="${SHORT_VERSION%%-*}"
[ -n "$SHORT_VERSION" ] || SHORT_VERSION="0.0.0"

[ -d "$APP" ] || { echo "missing app: $APP" >&2; exit 1; }

WORK="$(mktemp -d)"
PKGROOT="$WORK/root"
SCRIPTS="$WORK/scripts"
RES="$WORK/resources"
COMP="$WORK/component"
mkdir -p "$PKGROOT" "$SCRIPTS" "$RES" "$COMP"

# The payload: the .app, installed into /Applications.
cp -R "$APP" "$PKGROOT/"

# The postinstall IS the golden install-cli.sh, copied VERBATIM (M5's byte-identity
# golden — the DMG .command is the same file). No rewrite; it runs as root here so
# its sudo self-re-exec is skipped and it just mkdir+symlinks.
cp "$INSTALL_CLI_SRC" "$SCRIPTS/postinstall"
chmod +x "$SCRIPTS/postinstall"

# The readme pane text (design §3).
cp "$FIRST_LAUNCH_SRC" "$RES/FIRST-LAUNCH.txt"

pkgbuild \
	--root "$PKGROOT" \
	--scripts "$SCRIPTS" \
	--identifier "$IDENTIFIER" \
	--version "$SHORT_VERSION" \
	--install-location /Applications \
	"$COMP/component.pkg"

cat > "$WORK/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>open-seavault-rclone</title>
    <readme file="FIRST-LAUNCH.txt"/>
    <options customize="never" require-scripts="true" hostArchitectures="x86_64,arm64"/>
    <choices-outline>
        <line choice="default">
            <line choice="$IDENTIFIER"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$IDENTIFIER" visible="false">
        <pkg-ref id="$IDENTIFIER"/>
    </choice>
    <pkg-ref id="$IDENTIFIER" version="$SHORT_VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
XML

rm -f "$OUT_PKG"
productbuild \
	--distribution "$WORK/distribution.xml" \
	--resources "$RES" \
	--package-path "$COMP" \
	"$OUT_PKG"

echo "built PKG: $OUT_PKG"
