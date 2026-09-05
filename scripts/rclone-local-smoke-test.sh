#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export SEAVAULT_APP_HOME="$WORK/app-home"
export SEAVAULT_PASSWORD='rclone-smoke-password'

FAKE="$WORK/rclone"
cat > "$FAKE" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
shift || true
strip_flags() {
  local out=()
  while (($#)); do
    case "$1" in
      --config|--log-format|--transfers|--checkers|--stats|--bwlimit)
        shift 2 ;;
      --progress|--fast-list|--dry-run|--size-only|--one-way)
        shift ;;
      *) out+=("$1"); shift ;;
    esac
  done
  printf '%s\0' "${out[@]}"
}
case "$cmd" in
  version)
    echo 'rclone v1.74.0'
    ;;
  mkdir)
    mapfile -d '' args < <(strip_flags "$@")
    mkdir -p "${args[0]}"
    ;;
  lsf)
    mapfile -d '' args < <(strip_flags "$@")
    test -d "${args[0]}" && find "${args[0]}" -maxdepth 1 -mindepth 1 -printf '%f\n' || true
    ;;
  copy)
    dry=0
    for a in "$@"; do [[ "$a" == "--dry-run" ]] && dry=1; done
    mapfile -d '' args < <(strip_flags "$@")
    src="${args[0]}"; dst="${args[1]}"
    if [[ "$dry" == "1" ]]; then echo "would copy $src to $dst"; exit 0; fi
    mkdir -p "$dst"
    if [[ -d "$src" ]]; then cp -R "$src"/. "$dst"/; else cp "$src" "$dst"/; fi
    echo "copied $src to $dst"
    ;;
  check)
    mapfile -d '' args < <(strip_flags "$@")
    diff -qr "${args[0]}" "${args[1]}" >/dev/null
    echo 'check OK'
    ;;
  *)
    echo "unsupported fake rclone command: $cmd" >&2
    exit 2
    ;;
esac
SH
chmod 700 "$FAKE"

VAULT="$WORK/vault"
REMOTE="$WORK/remote"
VAULT2="$WORK/pulled"
SRC="$WORK/source.txt"
OUT="$WORK/out.txt"
printf 'rclone transport smoke\n' > "$SRC"

"$BIN" rclone install --from-binary "$FAKE" --signature skip >/dev/null
"$BIN" rclone verify-runtime >/dev/null
"$BIN" init -kdf argon2id -argon2-time 2 -argon2-memory 19456 -argon2-parallelism 1 "$VAULT" >/dev/null
"$BIN" put "$VAULT" "$SRC" docs/source.txt >/dev/null
"$BIN" remote add --backend local rclone-local "$VAULT" "$REMOTE" >/dev/null
"$BIN" remote dry-run rclone-local >/dev/null
"$BIN" remote push rclone-local >/dev/null
test -f "$REMOTE/SeaVaultData/vault.json"
"$BIN" remote check rclone-local >/dev/null
"$BIN" remote add --backend local pulled "$VAULT2" "$REMOTE" >/dev/null
"$BIN" remote pull pulled >/dev/null
"$BIN" list "$VAULT2" | grep -q '^content/docs/source.txt$'
"$BIN" get "$VAULT2" docs/source.txt "$OUT" >/dev/null
cmp "$SRC" "$OUT"

echo 'rclone local smoke test passed'
