#!/usr/bin/env bash
# verify-bundle.sh — verify a (already-signed) open-seavault-rclone.app and its
# installers on a real macOS runner before upload (design §4, §7). Every check is
# fail-closed and asserts non-vacuously.
#
# Rows: M3 (plist/lipo/icns [+ release-only byte-identity, I-M1]), M4
# (codesign + spctl against the expected state), M6 (DMG contents), M8 (bundle
# launch smoke), M5 (PKG postinstall == golden, install with /usr/local/bin
# removed). The push-time ci-macos job runs this in MODE=selfcheck and the byte
# identity check is skipped and LABELED self-consistency (does NOT prove I-M1).
#
# Env (required):
#   APP            path to open-seavault-rclone.app (already codesigned)
# Env (optional):
#   DMG            path to the .dmg  -> runs M6
#   PKG            path to the .pkg  -> runs M5
#   MODE           release | selfcheck   (default selfcheck)
#   EXPECT_SPCTL   reject | accept       (default reject; the expectation is asserted)
#   SRC_AMD64      darwin/amd64 binary   (MODE=release: proves I-M1 byte identity)
#   SRC_ARM64      darwin/arm64 binary   (MODE=release: proves I-M1 byte identity)
#   INSTALL_CLI_SRC golden CLI-install script (default packaging/macos/install-cli.sh)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
APP="${APP:?APP must point at the .app bundle}"
MODE="${MODE:-selfcheck}"
EXPECT_SPCTL="${EXPECT_SPCTL:-reject}"
INSTALL_CLI_SRC="${INSTALL_CLI_SRC:-$HERE/install-cli.sh}"
BIN="$APP/Contents/MacOS/open-seavault-rclone"

fail() { echo "VERIFY FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

free_port() {
	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
	else
		# Fallback: probe from a high base until a bind fails to connect.
		local p
		for p in $(seq 49200 49260); do
			if ! nc -z 127.0.0.1 "$p" >/dev/null 2>&1; then echo "$p"; return; fi
		done
		echo 49999
	fi
}

echo "== verify-bundle.sh  MODE=$MODE  EXPECT_SPCTL=$EXPECT_SPCTL =="
[ -d "$APP" ] || fail "no .app at $APP"
[ -x "$BIN" ] || fail "no executable at $BIN"

# ---- M3: structure ---------------------------------------------------------
echo "-- M3: bundle structure"
plutil -lint "$APP/Contents/Info.plist" >/dev/null || fail "plutil -lint failed"
ok "plutil -lint"

ARCHS="$(lipo -info "$BIN")"
echo "$ARCHS" | grep -q 'x86_64' || fail "lipo -info missing x86_64: $ARCHS"
echo "$ARCHS" | grep -q 'arm64'  || fail "lipo -info missing arm64: $ARCHS"
ok "lipo -info lists x86_64 and arm64"

ICNS="$APP/Contents/Resources/open-seavault-rclone.icns"
[ -f "$ICNS" ] || fail "missing icns $ICNS"
[ -s "$ICNS" ] || fail "icns is empty"
ok "icns present"

[ -f "$APP/Contents/Resources/SIGNING.txt" ] || fail "missing SIGNING.txt"
[ -f "$APP/Contents/Resources/FIRST-LAUNCH.txt" ] || fail "missing FIRST-LAUNCH.txt"
ok "SIGNING.txt and FIRST-LAUNCH.txt present"

if [ "$MODE" = "release" ]; then
	: "${SRC_AMD64:?release mode needs SRC_AMD64 for byte identity}"
	: "${SRC_ARM64:?release mode needs SRC_ARM64 for byte identity}"
	TMP_ID="$(mktemp -d)"
	lipo "$BIN" -thin x86_64 -output "$TMP_ID/amd64"
	lipo "$BIN" -thin arm64  -output "$TMP_ID/arm64"
	got_amd="$(shasum -a 256 "$TMP_ID/amd64" | awk '{print $1}')"
	want_amd="$(shasum -a 256 "$SRC_AMD64"   | awk '{print $1}')"
	got_arm="$(shasum -a 256 "$TMP_ID/arm64" | awk '{print $1}')"
	want_arm="$(shasum -a 256 "$SRC_ARM64"   | awk '{print $1}')"
	[ "$got_amd" = "$want_amd" ] || fail "I-M1: amd64 slice differs from the released darwin binary"
	[ "$got_arm" = "$want_arm" ] || fail "I-M1: arm64 slice differs from the released darwin binary"
	ok "I-M1: each lipo -thin slice is byte-identical to the released darwin binary"
else
	echo "  self-consistency: MODE=selfcheck assembles from a fresh local build; the"
	echo "  byte-identity of the slices to the released tarball binaries is NOT checked"
	echo "  here — this run does NOT prove I-M1 (design §7, M3; that is release-only)."
fi

# ---- M4: signing -----------------------------------------------------------
echo "-- M4: signing state"
codesign --verify --deep --strict --verbose=2 "$APP" || fail "codesign --verify --deep --strict failed"
ok "codesign --verify --deep --strict"

set +e
spctl --assess --type execute --verbose=4 "$APP" 2>/tmp/spctl.out
spctl_rc=$?
set -e
echo "  spctl said: $(cat /tmp/spctl.out 2>/dev/null | tr '\n' ' ')"
case "$EXPECT_SPCTL" in
	reject)
		[ "$spctl_rc" -ne 0 ] || fail "M4: expected spctl to REJECT the ad-hoc bundle, but it accepted (rc=0)"
		ok "spctl assess is rejected, as expected for the ad-hoc tier"
		;;
	accept)
		[ "$spctl_rc" -eq 0 ] || fail "M4: expected spctl to ACCEPT the notarized bundle, but it rejected (rc=$spctl_rc)"
		ok "spctl assess is accepted, as expected for the notarized tier"
		;;
	*)
		fail "EXPECT_SPCTL must be reject|accept, got $EXPECT_SPCTL"
		;;
esac

# ---- M8: bundle launch smoke ----------------------------------------------
echo "-- M8: bundle launch smoke (browser suppressed)"
VER="$("$BIN" version)"
[ -n "$VER" ] || fail "M8: the bundle binary printed no version"
ok "bundle binary version: $VER"

SMOKE_HOME="$(mktemp -d)"
PORT="$(free_port)"
LOG="$SMOKE_HOME/data/logs/gui.log"
# Default --exit-on-browser-close (armed) so the page-close heartbeat governs the
# exit; --bundle-grace is a wide safety net (90s) that must NOT be what exits the
# process — the assertion below bounds the exit far below it.
SEAVAULT_APP_HOME="$SMOKE_HOME" SEAVAULT_BUNDLE_LAUNCH=1 \
	"$BIN" gui --no-open --bundle-grace 90s \
	--addr "127.0.0.1:$PORT" >"$SMOKE_HOME/stdout.txt" 2>&1 &
SMOKE_PID=$!

# Recover the launch URL from the durable FILE sink (design §2.2, C7/I-M8):
# LaunchServices discards a bundle's stdout, so gui.log is where the launch link a
# second double-click needs actually lives. We read the URL from the file, never
# from stdout, and we never echo the URL itself (redacting it from diagnostics).
URL=""
for _ in $(seq 1 100); do
	if [ -f "$LOG" ] && grep -q '^launch: ' "$LOG"; then
		URL="$(sed -n 's/^launch: //p' "$LOG" | head -1)"
		break
	fi
	sleep 0.2
done
[ -n "$URL" ] || { grep -v 'launch=' "$SMOKE_HOME/stdout.txt" >&2 2>/dev/null || true; kill "$SMOKE_PID" 2>/dev/null || true; fail "M8: no launch line in the file log $LOG"; }
case "$URL" in
	*"/?launch="*) ok "launch URL recovered from the 0600 file sink" ;;
	*) kill "$SMOKE_PID" 2>/dev/null || true; fail "M8: launch line has no launch secret URL" ;;
esac
# The durable file sink must be 0600 (I-M8): the launch secret's persistent home is
# owner-only. (stdout also carries the guidance line, but LaunchServices discards a
# bundle's stdout — the file is the durable sink and the one that must be locked.)
perm="$(stat -f '%Lp' "$LOG" 2>/dev/null || stat -c '%a' "$LOG")"
[ "$perm" = "600" ] || { kill "$SMOKE_PID" 2>/dev/null || true; fail "M8: gui.log perm=$perm, want 600 (I-M8)"; }
ok "the durable launch-URL sink gui.log is 0600 (I-M8)"

# The launch URL answers over loopback (redeeming saves the session cookie).
code="$(curl -sSL -c "$SMOKE_HOME/jar" -b "$SMOKE_HOME/jar" -o /dev/null -w '%{http_code}' "$URL" || echo 000)"
[ "$code" = "200" ] || { kill "$SMOKE_PID" 2>/dev/null || true; fail "M8: launch URL did not answer 200 over loopback (got $code)"; }
kill -0 "$SMOKE_PID" 2>/dev/null || fail "M8: the launch exited immediately after answering; it must stay up for a connected page"
ok "launch URL answers 200 over loopback and the process stays up"

# A page connects: two heartbeats mark it connected; the process must stay alive.
curl -s -b "$SMOKE_HOME/jar" -X POST -o /dev/null "http://127.0.0.1:$PORT/api/browser-heartbeat" || true
sleep 2
curl -s -b "$SMOKE_HOME/jar" -X POST -o /dev/null "http://127.0.0.1:$PORT/api/browser-heartbeat" || true
kill -0 "$SMOKE_PID" 2>/dev/null || fail "M8: the process died while the page was heartbeating"
ok "the process stays alive while the page heartbeats"

# The page stops (heartbeats cease). The process must exit after the page-close
# heartbeat stops (design M8, I-M6) — well before the 90s grace safety net, so the
# heartbeat-stop path (not grace) is what is proven.
exited=0
for _ in $(seq 1 40); do
	if ! kill -0 "$SMOKE_PID" 2>/dev/null; then exited=1; break; fi
	sleep 1
done
wait "$SMOKE_PID" 2>/dev/null || true
[ "$exited" = "1" ] || { kill "$SMOKE_PID" 2>/dev/null || true; fail "M8/I-M6: the bundle launch did not exit after the page-close heartbeat stopped"; }
ok "bundle launch exited after the page-close heartbeat stopped (no lingering agent, I-M6)"

# ---- M6: DMG ---------------------------------------------------------------
if [ -n "${DMG:-}" ]; then
	echo "-- M6: DMG contents"
	[ -f "$DMG" ] || fail "no DMG at $DMG"
	MP="$(mktemp -d)/mnt"; mkdir -p "$MP"
	hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MP" >/dev/null || fail "hdiutil attach failed"
	dmg_ok=1
	[ -d "$MP/open-seavault-rclone.app" ] || { echo "  missing .app in DMG" >&2; dmg_ok=0; }
	[ -L "$MP/Applications" ] || { echo "  missing Applications symlink in DMG" >&2; dmg_ok=0; }
	[ -f "$MP/FIRST-LAUNCH.txt" ] || { echo "  missing FIRST-LAUNCH.txt in DMG" >&2; dmg_ok=0; }
	[ -f "$MP/SIGNING.txt" ] || { echo "  missing SIGNING.txt in DMG" >&2; dmg_ok=0; }
	[ -f "$MP/Install command-line tool.command" ] || { echo "  missing .command in DMG" >&2; dmg_ok=0; }
	# Detach with bounded retries (C5): a just-mounted image can be busy.
	detached=0
	for _ in $(seq 1 5); do
		if hdiutil detach "$MP" >/dev/null 2>&1; then detached=1; break; fi
		sleep 2
	done
	[ "$detached" = "1" ] || hdiutil detach "$MP" -force >/dev/null 2>&1 || true
	[ "$dmg_ok" = "1" ] || fail "M6: DMG contents incomplete"
	[ "$detached" = "1" ] || fail "M6: could not detach the DMG after retries"
	ok "DMG holds the app, Applications link, FIRST-LAUNCH.txt, SIGNING.txt, .command; detached"
fi

# ---- M5: PKG ---------------------------------------------------------------
if [ -n "${PKG:-}" ]; then
	echo "-- M5: PKG postinstall == golden, and install with /usr/local/bin removed"
	[ -f "$PKG" ] || fail "no PKG at $PKG"
	EXP="$(mktemp -d)/pkg"
	pkgutil --expand-full "$PKG" "$EXP" >/dev/null || fail "pkgutil --expand-full failed"
	POSTINSTALL="$(find "$EXP" -type f -name postinstall | head -1)"
	[ -n "$POSTINSTALL" ] || fail "M5: no postinstall found in the expanded PKG"
	cmp -s "$INSTALL_CLI_SRC" "$POSTINSTALL" || fail "M5: PKG postinstall is not byte-identical to the golden install-cli.sh"
	ok "PKG postinstall is byte-identical to the golden install-cli.sh"

	# C4: prove the golden mkdir -p handles a fresh Apple-silicon Mac where
	# /usr/local/bin does not exist. Move it ASIDE (not destroy) so the dir is
	# genuinely absent when the postinstall runs, then restore it afterwards — the
	# release job needs the tools that live there (gh, shasum) in later steps.
	BK="$(mktemp -d)/usr-local-bin-backup"
	if [ -e /usr/local/bin ]; then sudo mv /usr/local/bin "$BK"; fi
	[ -e /usr/local/bin ] && fail "M5: /usr/local/bin should be absent before install"
	installed=0
	for _ in $(seq 1 3); do
		if sudo installer -pkg "$PKG" -target / >/tmp/installer.out 2>&1; then installed=1; break; fi
		echo "  installer transient failure, retrying..." >&2; sleep 3
	done
	if [ "$installed" != "1" ]; then
		# Restore before failing so we do not leave the runner without its tools.
		if [ -e "$BK" ]; then sudo mkdir -p /usr/local/bin && sudo cp -a "$BK/." /usr/local/bin/ 2>/dev/null || true; fi
		cat /tmp/installer.out >&2 || true
		fail "M5: installer -pkg failed after retries"
	fi
	[ -L /usr/local/bin/seavault ] || { [ -e "$BK" ] && sudo cp -a "$BK/." /usr/local/bin/ 2>/dev/null || true; fail "M5: postinstall did not create the /usr/local/bin/seavault symlink"; }
	CLIVER="$(/usr/local/bin/seavault version)"
	# Restore the pre-existing /usr/local/bin contents alongside the new symlink.
	if [ -e "$BK" ]; then sudo cp -a "$BK/." /usr/local/bin/ 2>/dev/null || true; fi
	[ -n "$CLIVER" ] || fail "M5: installed /usr/local/bin/seavault printed no version"
	ok "installed /usr/local/bin/seavault version: $CLIVER (with /usr/local/bin absent at install time, then restored)"
fi

echo "== verify-bundle.sh: all checks passed (MODE=$MODE) =="
