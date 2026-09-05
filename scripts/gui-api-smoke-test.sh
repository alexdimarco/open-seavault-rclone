#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
export SEAVAULT_APP_HOME="$WORK/app-home"
mkdir -p "$SEAVAULT_APP_HOME"
ADDR="127.0.0.1:18787"
URL="http://$ADDR"
LOG="$WORK/gui.log"
JAR="$WORK/cookies"
VAULT="$WORK/cloud-sync/seavault"
PASSWORD='gui-smoke-password'

cleanup() {
  if [[ -n "${PID:-}" ]]; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

"$BIN" gui --no-open --addr "$ADDR" >"$LOG" 2>&1 &
PID=$!

# A bare GET / is 403 by design: the GUI serves only through a per-launch link
# (http://ADDR/?launch=<secret>) whose secret is printed to the log and rotates
# each launch. Read the secret from the log, redeem the launch link (it 302s to
# the app and sets the session cookie in the jar), and take the CSRF data-token
# from the redeemed page. Retry until the listener is up and the token appears.
TOKEN=""
for _ in $(seq 1 100); do
  # The || true keeps a not-yet-written log (fast startup, grep finds nothing)
  # from tripping set -e/pipefail and aborting the whole script silently.
  SECRET="$(grep -o 'launch=[A-Za-z0-9_-]*' "$LOG" 2>/dev/null | head -n 1 | cut -d= -f2 || true)"
  if [[ -n "$SECRET" ]]; then
    HTML="$(curl -fsS -L -c "$JAR" -b "$JAR" "$URL/?launch=$SECRET" 2>/dev/null || true)"
    TOKEN="$(printf '%s' "$HTML" | sed -n 's/.*data-token="\([^"]*\)".*/\1/p' | head -n 1)"
    [[ -n "$TOKEN" ]] && break
  fi
  sleep 0.1
done
if [[ -z "$TOKEN" ]]; then
  echo "could not extract GUI token" >&2
  cat "$LOG" >&2
  exit 1
fi

post_json() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -b "$JAR" -c "$JAR" \
    -H 'Content-Type: application/json' \
    -H "X-SeaVault-Token: $TOKEN" \
    -d "$body" \
    "$URL$path"
}

mkdir -p "$(dirname "$VAULT")"
post_json /api/init "{\"vaultPath\":\"$VAULT\",\"password\":\"$PASSWORD\",\"kdf\":\"argon2id\",\"argon2Time\":2,\"argon2MemoryKiB\":19456,\"argon2Parallelism\":1}" | grep -q '"opened":true'
curl -fsS -b "$JAR" -H "X-SeaVault-Token: $TOKEN" "$URL/api/status" | grep -q '"open":true'
CLOSE_RESP="$(post_json /api/close '{}')"
printf '%s' "$CLOSE_RESP" | grep -q '"ok":true'
NEW_TOKEN="$(printf '%s' "$CLOSE_RESP" | sed -n 's/.*"browserToken":"\([^"]*\)".*/\1/p' | head -n 1)"
if [[ -n "$NEW_TOKEN" ]]; then
  TOKEN="$NEW_TOKEN"
fi
post_json /api/open "{\"vaultPath\":\"$VAULT\",\"password\":\"$PASSWORD\",\"profile\":\"ignored-old-form-field\",\"kdf\":\"argon2id\",\"savePassword\":false,\"useKeychain\":false}" | grep -q '"opened":true'
curl -fsS -b "$JAR" -H "X-SeaVault-Token: $TOKEN" "$URL/api/status" | grep -q '"open":true'

SRC_DIR="$WORK/gui-source"
mkdir -p "$SRC_DIR/nested"
printf 'gui rsync path upload\n' > "$SRC_DIR/nested/upload.txt"
UPLOAD_BODY=$(printf '{"sourcePath":"%s","virtualPath":"gui-folder","method":"auto"}' "$SRC_DIR")
post_json /api/upload-path "$UPLOAD_BODY" | grep -q '"results"'
curl -fsS -b "$JAR" -H "X-SeaVault-Token: $TOKEN" "$URL/api/files" | grep -q '"path":"content/gui-folder/nested/upload.txt"'
EXPORT_DIR="$WORK/gui-export"
post_json /api/export "{\"virtualPath\":\"gui-folder\",\"destPath\":\"$EXPORT_DIR\",\"overwrite\":\"fail\",\"dryRun\":true}" | grep -q '"files":1'
post_json /api/export "{\"virtualPath\":\"gui-folder\",\"destPath\":\"$EXPORT_DIR\",\"overwrite\":\"fail\"}" | grep -q '"exported":1'
grep -q 'gui rsync path upload' "$EXPORT_DIR/nested/upload.txt"

echo 'GUI API smoke test passed'
