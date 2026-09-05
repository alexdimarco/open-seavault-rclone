#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export SEAVAULT_PASSWORD='rsync-ingest-smoke-password'
VAULT="$WORK/vault"
SRC="$WORK/source-folder"
OUT="$WORK/out"

mkdir -p "$SRC/sub"
printf 'alpha\n' > "$SRC/a.txt"
printf 'bravo\n' > "$SRC/sub/b.txt"

"$BIN" init -kdf argon2id -argon2-time 2 -argon2-memory 19456 -argon2-parallelism 1 "$VAULT" >/dev/null
"$BIN" rsync status >/dev/null
"$BIN" put --method rsync "$VAULT" "$SRC" archive >/dev/null
"$BIN" list "$VAULT" | grep -q '^content/archive/a.txt$'
"$BIN" list "$VAULT" | grep -q '^content/archive/sub/b.txt$'
"$BIN" get "$VAULT" archive "$OUT" >/dev/null
cmp "$SRC/a.txt" "$OUT/a.txt"
cmp "$SRC/sub/b.txt" "$OUT/sub/b.txt"

if find "$VAULT/SeaVaultData" -type f -name '*.txt' | grep -q .; then
  echo 'plaintext unexpectedly present in SeaVaultData' >&2
  exit 1
fi

echo 'rsync ingest smoke test passed'
