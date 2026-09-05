# Validation checklist

## Functional

- `go test ./...` passes.
- `go build ./cmd/seavault` succeeds.
- `scripts/smoke-test.sh` can initialize, put, list, get, verify, stats, remove, and garbage-collect a test vault.
- `seavault gui` opens the browser UI and can upload/download a file.
- `seavault serve` accepts basic WebDAV `PUT`, `GET`, `DELETE`, and `PROPFIND` requests.

## Storage

- The configured vault path is inside the desired sync-client directory.
- No plaintext file contents appear under `.seavault`.
- New vaults create `objects/chunks` and `manifests` sharded trees.
- Re-uploading identical content does not increase the encrypted chunk-object count.

## Security

- Wrong password fails to unlock the vault.
- Tampering with an encrypted chunk causes `verify` to fail.
- Tampering with an encrypted manifest causes manifest decryption/authentication failure.
- CLI password prompts do not echo input.
- OS keychain storage can be enabled and disabled per vault.

## Password, recovery, and format sealing (A2)

- `seavault password change VAULT` rotates the password: the old password no
  longer unlocks (on this client and a v0.16 peer), the new one does, a file put
  before the change still decrypts (no chunk rewrite), and `formatEpoch` increments.
- After a `password change`, replacing `vault.json` with the pre-change copy is
  detected: an interactive open warns and proceeds only with `--accept-rollback`,
  and a keychain/non-interactive open (`SEAVAULT_PASSWORD`, keychain, or `serve`)
  hard-refuses without `--accept-rollback`.
- Editing any MAC-covered field of `vault.json` (VaultID, chunk params, KDF cost,
  a wrap ciphertext) makes a subsequent open fail its integrity check; an
  untampered vault opens; a wrong password still reports a wrong password.
- `seavault recovery generate VAULT` shows a one-time phrase and requires a correct
  read-back before writing anything; a wrong read-back aborts with no entry added.
- `seavault recovery redeem VAULT` unlocks with the phrase, sets a new password,
  and consumes the redeemed entry so the phrase alone no longer opens the vault;
  `recovery revoke` removes a listed entry.
- `seavault vault seal-format VAULT` prints the device signal (or the explicit
  no-inventory warning), requires confirmation or `--yes`, and bumps the on-disk
  `version` to 3 and `minReader` to 3. A v0.16 build then refuses the vault
  ("unsupported vault version 3"); a build supporting only format 2 is fenced with
  a "needs a newer version" error; this build still opens it.
- `seavault vault unseal-format VAULT` restores `version` 2 / `minReader` 2 and
  re-admits both a v0.16 build and a format-2 build.

## Sync conflict handling

- A duplicate manifest for the same virtual path is preserved as a conflict copy.
- An older duplicate manifest does not override a newer live manifest.
- A delete tombstone suppresses a live copy at or below its `deletedGeneration`
  (a stale version the deleter had already seen) but keeps a live copy above it —
  a concurrent edit the deleter never saw — as a `*.conflict-*` copy; a tombstone
  from an older client with no `deletedGeneration` keeps every live copy.
- Reads and reloads write nothing to the metadata dir; `compact` (CLI) or the
  GUI's Reclaim space materialises the deferred conflict copies and sweeps
  temp-file orphans; a second run is a no-op.
- User-facing conflict names are visible through `list`, GUI, and WebDAV.

## Garbage collection (two-phase, fenced)

- `seavault gc VAULT` is a dry run: it prints candidate chunk ids and total bytes
  and writes nothing (no intents created, no chunks removed).
- `seavault gc --confirm VAULT` writes one intent per unreferenced chunk under
  `gc-intents/` and removes nothing on the first run.
- A second `--confirm` run before the fence elapses still removes nothing.
- With the fence elapsed (recorded intent time, device first-seen time, and chunk
  mtime all older than `--fence`), `--confirm` removes the chunk and then its
  intent files.
- A chunk re-referenced between runs has its intent cancelled instead of being
  collected.
- `verify` lists pending intents with their age.
- A `.tmp-*` orphan older than the fence in `objects/chunks` or `manifests` is
  swept by `compact`; a young one is kept.

## Rclone transport

- `seavault rclone install --from-binary <known-rclone>` records a managed runtime outside the vault.
- `seavault rclone verify-runtime` detects binary hash mismatches.
- `seavault rclone status --check-update` reports installed and latest runtime status.
- `seavault remote add` saves profiles outside the vault.
- `seavault remote dry-run` uses copy-safe rclone commands and does not call destructive sync.
- `seavault remote push` transfers only `.seavault` objects.
- `seavault remote pull` can populate a second vault directory from the encrypted remote copy.
- `scripts/rclone-local-smoke-test.sh` passes without external cloud credentials.
- Rclone config redaction removes tokens, secrets, passwords, and key material from support output.
- SSH private keys are stored in app configuration, not in `.seavault`.

## Manual OS drills (pending)

These exercise OS-specific code that CI only cross-builds and vets on Linux; run
them on a real host once the per-OS runners exist. Status: **pending**.

- **Windows share-deny rename retry.** Hold a share-deny lock on a chunk file
  (open it with `FILE_SHARE_NONE`, e.g. via another process) during a `put`, and
  confirm the write's atomic rename succeeds via `renameWithRetry` rather than
  failing on the first `ERROR_SHARING_VIOLATION`.
- **Windows mintty passphrase refusal.** Run a password prompt under a real mintty
  pty (Git Bash / MSYS2 terminal); the read must refuse with "this terminal
  cannot hide typed input" rather than echo the password.
- **Windows PowerShell passphrase.** Run the same prompt under PowerShell /
  Windows Terminal; typed input must not echo, and the console mode must be
  restored afterwards.
- **macOS keychain write.** Confirm `seavault` stores a password with the OS
  keychain via `security -i` (no secret in the process argument list), and that a
  password containing a control character is refused with `ErrSecretNotStorable`
  while the vault still opens with the typed password.

## Compliance evidence to collect

- Runtime version and SHA256 hash.
- Runtime source URL or offline artifact provenance.
- Remote profile target type and provider region.
- Confirmation that plaintext files are not present in the remote target.
- Rclone transfer logs with secrets redacted.
- Data-residency and support-access evidence for the chosen provider.
- Key rotation and lost-device revocation procedure.
