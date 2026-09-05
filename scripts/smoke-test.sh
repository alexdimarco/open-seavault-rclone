#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export SEAVAULT_PASSWORD='smoke-test-password'
VAULT="$WORK/cloud-sync/SeaVault"
SRC="$WORK/source.txt"
OUT="$WORK/out.txt"

mkdir -p "$(dirname "$VAULT")"
printf 'hello encrypted cloud storage\n' > "$SRC"

"$BIN" init -kdf argon2id -argon2-time 2 -argon2-memory 19456 -argon2-parallelism 1 "$VAULT" >/dev/null
"$BIN" put "$VAULT" "$SRC" docs/source.txt >/dev/null
"$BIN" list "$VAULT" | grep -q '^content/docs/source.txt$'
"$BIN" get "$VAULT" docs/source.txt "$OUT" >/dev/null
cmp "$SRC" "$OUT"
EXPORT_DIR="$WORK/export"
"$BIN" export --dry-run "$VAULT" . "$EXPORT_DIR" >/dev/null
"$BIN" export "$VAULT" docs "$EXPORT_DIR" >/dev/null
cmp "$SRC" "$EXPORT_DIR/source.txt"
"$BIN" verify "$VAULT" >/dev/null
"$BIN" stats "$VAULT" >/dev/null
"$BIN" remove "$VAULT" docs/source.txt >/dev/null
# A bare `gc` is a dry run; with the removed file's chunk now unreferenced it must
# report candidates and exit 3 ("action required", not an error), so a scripted
# caller detects that nothing was reclaimed without --confirm (friction II-2).
set +e
"$BIN" gc "$VAULT" >/dev/null
GC_RC=$?
set -e
[ "$GC_RC" -eq 3 ] || { echo "expected bare gc dry run to exit 3, got $GC_RC" >&2; exit 1; }
"$BIN" compact "$VAULT" >/dev/null
"$BIN" gc --confirm "$VAULT" >/dev/null

echo 'smoke test passed'
