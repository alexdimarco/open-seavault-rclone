#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
if ! command -v rsync >/dev/null 2>&1; then
  echo 'rsync not available; skipping rsync put smoke test'
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export SEAVAULT_PASSWORD='rsync-put-smoke-password'
VAULT="$WORK/cloud-sync/SeaVault"
SRC="$WORK/source-folder"
OUT="$WORK/out"

mkdir -p "$SRC/nested" "$(dirname "$VAULT")"
printf 'alpha\n' > "$SRC/root.txt"
printf 'nested beta\n' > "$SRC/nested/beta.txt"

"$BIN" init -kdf argon2id -argon2-time 2 -argon2-memory 19456 -argon2-parallelism 1 "$VAULT" >/dev/null
"$BIN" put --method rsync "$VAULT" "$SRC" archive >/dev/null
"$BIN" list "$VAULT" | grep -q '^content/archive/root.txt$'
"$BIN" list "$VAULT" | grep -q '^content/archive/nested/beta.txt$'
"$BIN" get "$VAULT" archive "$OUT" >/dev/null
cmp "$SRC/root.txt" "$OUT/root.txt"
cmp "$SRC/nested/beta.txt" "$OUT/nested/beta.txt"
"$BIN" verify "$VAULT" >/dev/null

echo 'rsync put smoke test passed'
