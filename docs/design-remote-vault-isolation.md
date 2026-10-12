# Design: one remote folder per vault (remote vault isolation)

Status: PROPOSED, awaiting design review (CLAUDE.md: remote config is security-sensitive).
No code is written until this note is approved.

## Problem

`seavault setup --preset rclone --remote X` hard-codes the remote path as `X:`
(`cmd/seavault/main.go:371`). `joinRemote` turns that into `X:/SeaVaultData`
(`internal/transport/rclone/rclone.go:290-297`). Every vault set up against the
same remote therefore shares ONE remote folder, and nothing checks which vault a
remote `vault.json` belongs to.

`push` copies `vault.json` to the remote (`rclone.go:197`); `pull` copies the
remote folder over the local one (`rclone.go:201-206`). `vault.json` holds the
wrapped keys, so overwriting it makes the other vault unopenable.

### Example (today)

1. `seavault setup --preset rclone --remote nas --vault ~/Taxes`
2. `seavault setup --preset rclone --remote nas --vault ~/Photos`
3. Push Taxes: `nas:/SeaVaultData/vault.json` = Taxes' keys.
4. Push Photos: that file is replaced with Photos' keys. Taxes' chunks are
   still there but its wrapped keys are gone from the remote.
5. Pull Taxes: the remote folder is copied over `~/Taxes/SeaVaultData`, so Taxes'
   local `vault.json` is replaced by Photos' and Taxes will not open.

A related gap: `remotes.Add` updates a profile in place by name
(`remotes.go:188-196`), so setup silently repoints an existing remote profile.
Vault profiles already refuse this (rule C3); remote profiles do not.

## Proposal

### 1. Identity check (the safety net; no layout change)

Before ANY push or pull, read the remote `vault.json` (if present) and compare its
`vaultId` to the local vault's.

| Remote state | Push | Pull |
|---|---|---|
| no `vault.json` | allowed (first push) | refuse: nothing to pull |
| same `vaultId` | allowed | allowed |
| different `vaultId` | REFUSE, name both IDs | REFUSE, name both IDs |

`vaultId` is plaintext and unauthenticated, so this is a guard against honest
mistakes, not against a hostile server (a hostile server can already delete
everything; SECURITY.md covers that). Pull additionally keeps the existing
config-tag and rollback checks that run on the next open.

### 2. Per-vault remote subfolder for NEW setups

`--preset rclone` sets the remote path to `X:seavault/<profile-name>` instead of
`X:`. Example: `nas:seavault/Taxes` and `nas:seavault/Photos` can never collide.
Existing profiles keep whatever path they were saved with; nothing is migrated
automatically, because moving a remote folder is its own risky operation.

### 3. Setup collision check

`setup` refuses when a remote profile with the same name already points at a
DIFFERENT remote path or vault (same behaviour as vault profiles today), and the
idempotent re-run reports success only when the remote is also registered and
passes its probe (this also fixes the "re-run says OK though the cloud step never
worked" finding).

## Options considered

- Identity check only: smallest, protects existing users, but new users can still
  point two vaults at one folder and just get refusals.
- Subfolder only: prevents new collisions, does nothing for existing shared
  folders. Rejected as the only fix.
- Both (recommended): the check protects every existing setup; the subfolder
  stops new ones from ever hitting it.

## Tests (prove-fail first)

- two vaults, one fake remote: second push refused and the first vault's remote
  `vault.json` byte-identical afterwards; pull of the wrong vault refused and the
  local `vault.json` untouched.
- same vault push/pull still works.
- setup of a second vault on the same remote lands in a different folder.
- setup re-run after a failed remote step does NOT report success.

## Open questions for review

1. Subfolder name: `seavault/<profile>` or `seavault/<vaultId>`? The profile name
   is readable; the vault ID is stable if the profile is renamed.
2. Should an existing shared remote folder trigger a one-time warning at open?
3. Refuse versus offer `--force` on an identity mismatch? Recommended: refuse,
   with no override flag.
