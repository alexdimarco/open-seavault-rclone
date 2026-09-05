#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
export SEAVAULT_APP_HOME="$WORK/app-home"
mkdir -p "$SEAVAULT_APP_HOME"
ADDR="127.0.0.1:18878"
URL="http://$ADDR"
LOG="$WORK/webdav.log"
VAULT="$WORK/cloud-sync/seavault"
PASSWORD='webdav-smoke-password'

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

JAR="$WORK/cookies"

# A bare GET / is 403 by design (Phase 0): the GUI serves only through the
# per-launch link printed to the log. Redeem it into the cookie jar and take the
# CSRF data-token from the served page. The WebDAV path uses a DISTINCT token
# that /api/webdav reports once a vault is open (Phase 0 P1-14), never the CSRF
# token, and export-zip uses a single-use ticket.
TOKEN=""
for _ in $(seq 1 100); do
  SECRET="$(grep -o 'launch=[A-Za-z0-9_-]*' "$LOG" 2>/dev/null | head -n 1 | cut -d= -f2 || true)"
  if [[ -n "$SECRET" ]]; then
    HTML="$(curl -fsS -L -c "$JAR" -b "$JAR" "$URL/?launch=$SECRET" 2>/dev/null || true)"
    TOKEN="$(printf '%s' "$HTML" | sed -n 's/.*data-token="\([^"]*\)".*/\1/p' | head -n 1)"
    [[ -n "$TOKEN" ]] && break
  fi
  sleep 0.1
done
if [[ -z "$TOKEN" ]]; then
  echo "could not redeem the GUI launch link / extract the CSRF token" >&2
  cat "$LOG" >&2
  exit 1
fi

post_json() {
  local path="$1"
  local body="$2"
  curl -fsS -b "$JAR" \
    -H 'Content-Type: application/json' \
    -H "X-SeaVault-Token: $TOKEN" \
    -d "$body" \
    "$URL$path"
}

mkdir -p "$(dirname "$VAULT")"
post_json /api/init "{\"vaultPath\":\"$VAULT\",\"password\":\"$PASSWORD\",\"kdf\":\"argon2id\",\"argon2Time\":2,\"argon2MemoryKiB\":19456,\"argon2Parallelism\":1}" | grep -q '"opened":true'

# The WebDAV mount token is distinct from the CSRF token; read it from the status.
DAV="$(curl -fsS -b "$JAR" "$URL/api/webdav" | sed -n 's/.*"url":"\(\/dav\/[^"]*\)".*/\1/p' | head -n 1)"
if [[ -z "$DAV" ]]; then
  echo "could not read the WebDAV URL from /api/webdav" >&2
  exit 1
fi
if [[ "$DAV" == "/dav/$TOKEN/" ]]; then
  echo 'the WebDAV URL must not reuse the CSRF token' >&2
  exit 1
fi
dav() {
  local method="$1"
  local path="$2"
  shift 2
  curl -fsS -b "$JAR" -X "$method" -H "X-SeaVault-Token: $TOKEN" "$@" "$URL$DAV$path"
}

printf 'webdav smoke\n' > "$WORK/a.txt"
dav PUT docs/a.txt -T "$WORK/a.txt" >/dev/null
dav PROPFIND "" -H 'Depth: 1' | grep -q '/content/'
dav PROPFIND docs/ -H 'Depth: 1' | grep -q 'a.txt'
dav GET docs/a.txt | grep -q 'webdav smoke'
dav COPY docs/a.txt -H "Destination: ${DAV}docs/b.txt" >/dev/null
dav MOVE docs/b.txt -H "Destination: ${DAV}docs/c.txt" >/dev/null
dav GET docs/c.txt | grep -q 'webdav smoke'
# Range GET (Phase 0 P1-2) and Overwrite: F (P1-3)
dav GET docs/c.txt -H 'Range: bytes=0-5' -o "$WORK/range.bin" -D "$WORK/range.hdr" >/dev/null
grep -q '206' "$WORK/range.hdr"
[[ "$(cat "$WORK/range.bin")" == "webdav" ]]
if dav COPY docs/a.txt -H "Destination: ${DAV}docs/c.txt" -H 'Overwrite: F' >/dev/null 2>&1; then
  echo 'expected COPY with Overwrite: F onto an existing file to fail' >&2
  exit 1
fi
# export-zip uses a single-use ticket (Phase 0 P1-14)
TICKET="$(post_json /api/export-zip/ticket '{"path":"docs"}' | sed -n 's/.*"ticket":"\([^"]*\)".*/\1/p' | head -n 1)"
[[ -n "$TICKET" ]]
curl -fsS -b "$JAR" "$URL/api/export-zip?ticket=$TICKET" >/dev/null
if curl -fsS -b "$JAR" "$URL/api/export-zip?ticket=$TICKET" >/dev/null 2>&1; then
  echo 'expected a consumed export ticket to be refused' >&2
  exit 1
fi
if curl -fsS -b "$JAR" "$URL/api/export-zip?path=docs&token=$TOKEN" >/dev/null 2>&1; then
  echo 'expected the old ?token= export form to be refused' >&2
  exit 1
fi
dav DELETE docs/c.txt >/dev/null

if dav PUT .seavault/bad -d bad >/dev/null 2>&1; then
  echo 'expected .seavault PUT to fail' >&2
  exit 1
fi
if dav PUT SeaVaultData/bad -d bad >/dev/null 2>&1; then
  echo 'expected SeaVaultData PUT to fail' >&2
  exit 1
fi
# The CSRF token must not open the WebDAV path (Phase 0 P1-14)
if curl -fsS -b "$JAR" -X PROPFIND -H 'Depth: 1' "$URL/dav/$TOKEN/" >/dev/null 2>&1; then
  echo 'expected /dav/<csrf-token>/ to be refused' >&2
  exit 1
fi
post_json /api/webdav '{"readOnly":true}' | grep -q '"readOnly":true'
if dav PUT readonly.txt -d bad >/dev/null 2>&1; then
  echo 'expected readonly PUT to fail' >&2
  exit 1
fi

echo 'WebDAV file manager smoke test passed'
