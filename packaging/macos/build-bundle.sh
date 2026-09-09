#!/usr/bin/env bash
# build-bundle.sh — assemble open-seavault-rclone.app from two darwin binaries
# (design §2, §4). Runs on macOS (needs lipo, sips, iconutil, plutil).
#
# Usage:
#   build-bundle.sh <amd64-binary> <arm64-binary> <version> <out-dir>
#
# Env:
#   ICON_SRC          PNG icon source (default: internal/webui/assets/svlogo/icon.png)
#   FIRST_LAUNCH_SRC  first-launch text (default: packaging/macos/FIRST-LAUNCH.txt)
#   PLIST_TEMPLATE    Info.plist template (default: packaging/macos/Info.plist.template)
#   SIGNING_TEXT      one line written verbatim to Contents/Resources/SIGNING.txt
#                     (default: the ad-hoc, not-notarized declaration)
#
# It assembles and writes SIGNING.txt; it does NOT sign (the workflow signs after,
# so codesign runs over the finished bundle) — design §4.
set -euo pipefail

if [ "$#" -ne 4 ]; then
	echo "usage: build-bundle.sh <amd64-binary> <arm64-binary> <version> <out-dir>" >&2
	exit 2
fi

AMD64_BIN="$1"
ARM64_BIN="$2"
VERSION="$3"
OUT_DIR="$4"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
ICON_SRC="${ICON_SRC:-$REPO_ROOT/internal/webui/assets/svlogo/icon.png}"
FIRST_LAUNCH_SRC="${FIRST_LAUNCH_SRC:-$HERE/FIRST-LAUNCH.txt}"
PLIST_TEMPLATE="${PLIST_TEMPLATE:-$HERE/Info.plist.template}"
SIGNING_TEXT="${SIGNING_TEXT:-ad-hoc signed, not notarized}"

# CFBundleShortVersionString / CFBundleVersion want a bare dotted number; strip a
# leading v and anything past the first pre-release/build separator.
SHORT_VERSION="${VERSION#v}"
SHORT_VERSION="${SHORT_VERSION%%-*}"
[ -n "$SHORT_VERSION" ] || SHORT_VERSION="0.0.0"
BUNDLE_VERSION="$SHORT_VERSION"

for f in "$AMD64_BIN" "$ARM64_BIN" "$ICON_SRC" "$FIRST_LAUNCH_SRC" "$PLIST_TEMPLATE"; do
	[ -f "$f" ] || { echo "missing input: $f" >&2; exit 1; }
done

APP="$OUT_DIR/open-seavault-rclone.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# The universal executable: lipo the two darwin slices (design §2, I-M1). The
# workflow provides the exact binaries the linux release job built and uploaded.
lipo -create "$AMD64_BIN" "$ARM64_BIN" -output "$APP/Contents/MacOS/open-seavault-rclone"
chmod +x "$APP/Contents/MacOS/open-seavault-rclone"

# Info.plist from the template, with the tag version filled in.
sed -e "s/__SHORT_VERSION__/$SHORT_VERSION/g" \
    -e "s/__BUNDLE_VERSION__/$BUNDLE_VERSION/g" \
    "$PLIST_TEMPLATE" > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist"

# The icns: sips-resize the 512px source into an .iconset, then iconutil. The
# source caps at 512px, so the 1024px (512x512@2x) Retina slot is OMITTED
# (design §2, C11) — the largest icon is soft on Retina; accepted for this tier.
ICONSET="$(mktemp -d)/open-seavault-rclone.iconset"
mkdir -p "$ICONSET"
gen() { sips -z "$1" "$1" "$ICON_SRC" --out "$ICONSET/$2" >/dev/null; }
gen 16   icon_16x16.png
gen 32   icon_16x16@2x.png
gen 32   icon_32x32.png
gen 64   icon_32x32@2x.png
gen 128  icon_128x128.png
gen 256  icon_128x128@2x.png
gen 256  icon_256x256.png
gen 512  icon_256x256@2x.png
gen 512  icon_512x512.png
# icon_512x512@2x.png (1024) intentionally omitted — source is 512px (C11).
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/open-seavault-rclone.icns"

# The first-launch note (shown in the DMG and copied around by the workflow).
cp "$FIRST_LAUNCH_SRC" "$APP/Contents/Resources/FIRST-LAUNCH.txt"

# SIGNING.txt records the signing state INSIDE the artifact (design §2/§4, I-M5).
printf '%s\n' "$SIGNING_TEXT" > "$APP/Contents/Resources/SIGNING.txt"

echo "assembled: $APP  (version $SHORT_VERSION)"
