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

# T8 (design section 7): the non-interactive first-run wizard, end to end against
# the real binary. `setup --preset local` reads the password from SEAVAULT_PASSWORD,
# creates a vault and registers a profile; a put/get round-trip through that
# profile proves the wizard's output is a working vault. A private app-home keeps
# the profile out of the developer's real store.
export SEAVAULT_APP_HOME="$WORK/app-home"
SETUP_VAULT="$WORK/setup-vault/MyVault"
SETUP_OUT="$WORK/setup-out.txt"
"$BIN" setup --preset local --vault "$SETUP_VAULT" --no-keychain --profile smokeprofile >/dev/null
"$BIN" put smokeprofile "$SRC" docs/source.txt >/dev/null
"$BIN" list smokeprofile | grep -q '^content/docs/source.txt$'
"$BIN" get smokeprofile docs/source.txt "$SETUP_OUT" >/dev/null
cmp "$SRC" "$SETUP_OUT"

# ADM-5: a --preset run whose --vault already holds a matching vault is an
# idempotent no-op — a provisioning loop can re-run the SAME command and it must
# exit 0 (reporting the existing vault) rather than failing on "already exists".
RERUN_OUT="$("$BIN" setup --preset local --vault "$SETUP_VAULT" --no-keychain --profile smokeprofile)"
echo "$RERUN_OUT" | grep -q 'already exists' || {
	echo "expected the idempotent re-run to report the existing vault" >&2; exit 1; }

# ADM-1: --preset --json emits the machine-readable result (never a secret). Parse
# it with python3 or jq when either is available, else assert the shape textually.
JSON_VAULT="$WORK/json-vault/MyVault"
JSON_OUT="$("$BIN" setup --preset local --vault "$JSON_VAULT" --no-keychain --profile jsonprofile --json)"
if printf '%s' "$JSON_OUT" | grep -q "$SEAVAULT_PASSWORD"; then
	echo "the --json output must never carry the password" >&2; exit 1
fi
if command -v python3 >/dev/null 2>&1; then
	printf '%s' "$JSON_OUT" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["profile"]=="jsonprofile", d
assert d["cloud"]=="local", d
assert d["vaultID"], d
assert d["recoveryCreated"] is False, d
'
elif command -v jq >/dev/null 2>&1; then
	[ "$(printf '%s' "$JSON_OUT" | jq -r .profile)" = "jsonprofile" ] || {
		echo "jq: --json profile mismatch" >&2; exit 1; }
	[ "$(printf '%s' "$JSON_OUT" | jq -r .cloud)" = "local" ] || {
		echo "jq: --json cloud mismatch" >&2; exit 1; }
else
	printf '%s' "$JSON_OUT" | grep -q '"profile": "jsonprofile"' || {
		echo "--json output missing the profile field" >&2; exit 1; }
fi

echo 'smoke test passed'
