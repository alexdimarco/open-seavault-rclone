# SeaVault Fast

SeaVault Fast is a cross-platform prototype for client-side encrypted storage. It stores plaintext only on the local client, splits files into Seafile-style content-defined chunks, encrypts chunks and sharded manifests, and transports only the encrypted `.seavault` repository.

This repository is a working MVP, not an audited production replacement for Cryptomator.



## License

open-seavault-rclone is free software, licensed under the **GNU General Public License, version 3 or later** (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for the full text. Copyright (C) 2026 Crescendum.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You are free to use, study, modify, and redistribute it under the terms of the GPL.

Vendored and bundled third-party components keep their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The GPL does not grant trademark rights: the **SeaVault** and **Crescendum** names, logos, icons, favicons, wordmarks, and visual identity remain reserved &mdash; see [TRADEMARKS.md](TRADEMARKS.md).

## What changed in v0.17 (Phase A2 config-and-key layer)

Phase A2 adds a config-and-key layer to the vault format without re-keying any manifest or rewriting any chunk. Every addition is an additive `omitempty` field on a `Version = 2` config, so the vault stays **openable by a v0.16 client throughout the grace release** — the format grows while the on-the-wire `Version` stays 2. The one deliberate, operator-triggered boundary is `seavault vault seal-format`.

- **Password rotation.** `seavault password change VAULT` rewraps the master key under a new password (fresh salt and nonce) without touching any chunk or manifest, so every file put before the change still decrypts. The retired password stops opening the vault on both this client and a v0.16 peer; the legacy wrap is kept current under the new password so a v0.16 device keeps unlocking through the grace release. If the vault's password is in the OS keychain it is updated to the new secret. The GUI exposes this under a **Password & recovery** panel.
- **Recovery key.** `seavault recovery generate VAULT` mints a one-time recovery phrase (shown once, never stored) with a mandatory read-back before it is committed; `seavault recovery redeem VAULT` unlocks with the phrase and, in one transaction, sets a new password **and** consumes the redeemed entry so a leaked phrase cannot keep opening the vault; `seavault recovery revoke`/`list` manage entries.
- **Config integrity + freshness.** `vault.json` now carries a `configTag` (an HMAC over the config under a master-derived key) so a server that edits the VaultID, chunk parameters, KDF cost, or the wrapped-key set is caught as tampering once the vault is unlocked. A device-local, never-synced freshness anchor additionally catches a **rolled-back** config (an old `vault.json` replayed after a password change): any unlock refuses and prints how to proceed &mdash; re-run with `--accept-rollback` if you deliberately restored from an older backup, otherwise treat it as a possible attack and do not enter a retired password. See [SECURITY.md](SECURITY.md) for the exact guarantees and residuals.
- **Causal reconciliation.** File and manifest records carry an additive per-device vector clock. Two devices that edit concurrently now both survive (one canonical, the rest as `*.conflict-*`), a delete that causally dominates an edit deletes cleanly, and a delete concurrent with an edit keeps both — a strict improvement over the v0.16 generation-only rule, which A2 keeps as the fallback for records a v0.16 peer wrote (they carry no clock).
- **`seavault vault seal-format VAULT`.** The operator's explicit end of the grace release: it bumps `Version` to 3 and raises `minReader` to 3 in one signed rewrite, after an interactive confirmation (or `--yes`). Once sealed, SeaVault 0.16 and older can **no longer open the vault** (they refuse on their own version fence) and A2 clients below format 3 are fenced with a typed error. Before sealing, the command prints whatever device inventory it has (a device-local, never-synced list of readers it has seen) or, when it has none, an explicit warning that it cannot see your other devices — so confirm every device is upgraded first. `seavault vault unseal-format VAULT` reverses it (restoring `Version` 2 / `minReader` 2) as long as no later phase has re-keyed the manifests.
- **Grace-release guidance.** Roll A2 out by upgrading **every** device before sealing. During the grace release you can still downgrade a device to v0.16 (the legacy wrap stays populated and current, so it keeps unlocking), which makes backing out a bad release possible; sealing is the one-way step. Take a full-vault backup before migrating. While the fleet is mixed, config-tamper protection holds only on A2 devices, and a v0.16 peer's garbage collection can still delete a chunk an A2 device keeps live via a causal conflict copy — both stated in [SECURITY.md](SECURITY.md). Complete the upgrade and `seal-format` before relying on A2's causal conflict preservation.

## What changed in v0.16 (Phase A1 vault-core hardening)

Phase A1 hardens the vault core without changing the on-disk format: a vault a v0.15 client created opens unchanged, and everything this version writes into it stays readable by v0.15. The one deliberate boundary is the new metadata directory name for vaults this version **creates**.

- **New vaults use a visible `SeaVaultData` directory.** Older vaults keep their hidden `.seavault` directory and open transparently; both names are recognised. A vault this version creates is **not** located by SeaVault 0.15.0 or older on another device (that client fails to find a vault — a `no such file` error on `.seavault/vault.json` — rather than corrupting anything), so upgrade every device before creating new vaults in a shared folder. See [docs/local-sync-location.md](docs/local-sync-location.md).
- **`seavault gc` is a dry run by default.** `seavault gc VAULT` prints the candidate chunks and bytes and writes nothing (and exits 3 when it would reclaim something, so scripted callers notice the missing `--confirm`); `seavault gc --confirm VAULT` runs the two-phase, time-fenced deletion (synced intent, then removal once the fence — default `72h`, `--fence` to change — has elapsed by the deleting device's clock and its device-local first-seen record). `verify` lists pending intents so a delete in flight is visible. Pending intents are informational; a delete completes on a later `gc --confirm` once the fence elapses; to stop one, put the content back or run `gc --confirm` on a device that references it. See [SECURITY.md](SECURITY.md) (Garbage-collection fence) for the accepted residuals.
- **`seavault compact`.** A new command (and the GUI's **Reclaim space** button, `POST /api/compact`) materialises deferred sync-conflict copies, removes superseded manifests, and sweeps `.tmp-*` orphans. Reads and reloads write nothing to the metadata directory.
- **A concurrent edit is never lost to a concurrent delete.** Delete tombstones now record the generation they superseded (`deletedGeneration`): a live copy above that generation — an edit the deleter never saw — survives as a `*.conflict-*` copy instead of being suppressed.
- **Portable-name policy.** New paths must be restorable on Windows: a segment with `<>:"|?*`, a control character, a trailing dot/space, or a Windows reserved stem (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) is refused at creation on every OS. Existing files with such names still read, overwrite, and export; export sanitises the illegal segment (e.g. `a:b.txt` -> `a_b.txt`) and never lets a colon reach the output path.
- **KDF floors and stronger defaults.** New vaults reject weak parameters at creation (Argon2id `m>=19456,t>=2` or `m>=65536,t>=1`; scrypt `N>=32768,r>=8`; PBKDF2 `iterations>=600000`); the default is Argon2id `t=3, m=64 MiB, p=4` (RFC 9106). Existing vaults keep their stored parameters.
- **Secret hygiene.** The macOS keychain write feeds `security -i` on stdin (no secret in the process argument list); a secret with a control character is refused. The Windows hidden prompt refuses a mintty/Cygwin pty that would echo and names the safe alternatives. See [SECURITY.md](SECURITY.md).

## What changed in v0.15 (Phase 0 loopback hardening)

Phase 0 hardens the local loopback surface (`seavault serve` and `seavault gui`). It changes no on-disk vault format — existing vaults open unchanged — but it changes the local HTTP contract in ways that break unattended scripts written for v0.14 and earlier.

### Breaking changes for scripts

- **`serve` now requires a WebDAV credential.** `seavault serve` previously accepted unauthenticated loopback requests; it now returns `401 Unauthorized` (with `WWW-Authenticate: Basic`) to any request that carries no valid HTTP Basic credential. Scripts must supply one — precedence is `--password-file PATH` > `SEAVAULT_SERVE_PASSWORD` > a freshly generated 32-character password printed once on start. There is no `--no-auth`.
- **A bare GUI URL is now `403`.** `http://127.0.0.1:8787/` no longer opens the app. The GUI is reachable only through the per-launch launch link (`http://127.0.0.1:8787/?launch=<secret>`) that `seavault gui` prints and opens on every start; the secret rotates each launch, so bookmarks to the bare address (or to a previous `?launch=` link) break by design. With `--no-open`, copy the printed link. Relaunching is the way to get a fresh link back.
- **The GUI WebDAV path uses a separate token.** The in-GUI endpoint is `/dav/<davToken>/`, where `davToken` is a distinct per-session WebDAV token — no longer the GUI's CSRF/session token, which is never placed in a `/dav/` URL. The token rotates when the vault closes or the GUI restarts. When a GUI password is set, `/dav/` additionally requires the GUI login cookie, so the copied URL then works only inside the browser tab; native clients (Finder/Explorer/rclone) must use `seavault serve`.
- **Export ZIP uses a ticket flow.** Downloading a folder as ZIP is now `POST /api/export-zip/ticket` (session + CSRF header) to obtain a single-use ticket, then `GET /api/export-zip?ticket=<t>`. The old `GET /api/export-zip?token=<csrf>` form is removed. The in-app file manager does this automatically; only direct API callers are affected.
- **Host allowlist (`--allow-host`).** Every request to `serve` and the GUI must carry a `Host` header naming a loopback address, `localhost`, or an explicit `--allow-host NAME` value (repeatable), or it is answered `403` with no DNS lookup (DNS-rebinding defence). Off-loopback deployments (`--insecure-bind`) must pass `--allow-host` for every name **or IP literal** clients connect as; an unspecified bind (`0.0.0.0`/`::`) is never added to the allowlist automatically.
- **`gui` no longer terminates other seavault processes.** Starting `seavault gui` used to kill every process named `seavault`, silently taking down a running `seavault serve` (a Finder/rclone mount). It no longer does; a second GUI on the same `--addr` now surfaces a normal bind-in-use error instead. A scoped single-instance lock is deferred to Phase B.

See [docs/webdav-file-manager.md](docs/webdav-file-manager.md), [docs/gui-launch-link.md](docs/gui-launch-link.md), and [SECURITY.md](SECURITY.md).

## What changed in v0.14

- Added a protected `content/` workspace for all user files and folders. New vaults create `content/` automatically.
- Added automatic migration on vault open for older vaults that stored user files at the virtual root. Legacy paths such as `docs/a.txt` are moved to `content/docs/a.txt` and old root-level manifests receive tombstones.
- Kept path compatibility for common commands: `seavault get vault docs/a.txt out.txt` resolves to `content/docs/a.txt` after migration.
- Made `content/` non-deletable and blocked moves, deletes, and writes to reserved internal paths such as `.seavault` and `.seavault-dir`.
- Implemented persistent encrypted directory markers so WebDAV `MKCOL` creates folders that remain visible even while empty.
- Hardened the WebDAV/file-manager path layer with constant-time session token checks, no-store decrypted responses, root normalization, folder-drop recursion where browsers support it, and clearer fallback messaging for unsupported folder drops.


## What changed in v0.13

- Added an integrated browser-based WebDAV file manager at `/files/`.
- Mounted the local WebDAV endpoint inside the GUI server at `/dav/<session-token>/`, so the GUI file manager does not depend on Finder, Windows Explorer, GNOME Files, KDE Dolphin, davfs2, WinFsp, macFUSE, or FUSE.
- WebDAV exposes only the unlocked virtual plaintext vault view. It never exposes raw `.seavault` chunks, manifests, tombstones, or internal metadata.
- Added WebDAV file-manager operations: browse folders, upload files, upload folders, drag-and-drop upload, create folder, download file, download folder as ZIP through the export workflow, rename/move, copy, delete, and copy local WebDAV URL.
- Added WebDAV session-token protection, token rotation on vault close, localhost same-origin access, no-store headers for decrypted responses, read-only/read-write mode, and path traversal/.seavault blocking.
- Kept the old virtual path list as an advanced raw file list for troubleshooting.

## What changed in v0.12

- Added move-vault-location support in the GUI and CLI.
- Added `seavault move` for moving any vault path or saved profile to a new local location.
- Added `seavault profile move` for moving a saved vault and updating its saved location.
- The GUI now includes a Move vault location panel with source selection, destination path, remote-profile update, and destination replace controls.
- Saved keychain passwords continue to work after a move because keychain entries are tied to the vault ID, not the folder path.
- Matching remote profiles can be updated automatically after a move.

## What changed in v0.11

- Added optional app-managed rsync runtime support. SeaVault now has managed tool controls for both rclone and rsync.
- Kept native Go ingest as the default dependency-free local import path.
- Added put methods: `native`, `managed-rsync`, `system-rsync`, `rsync`, and `auto`.
- `auto` now tries managed rsync first, then system rsync, then native import.
- Added CLI commands for managed rsync status, install/register, source update check, update, rollback, verification, and path discovery.
- Added GUI controls to register an existing rsync binary, install an offline SeaVault rsync runtime archive, check latest upstream source release, update, and rollback.
- Added runtime manifest tracking for managed rsync: version, source version, source URL, binary path, SHA256, install time, previous runtime, and runtime verification status.
- Added documentation for managed rsync, source/provenance handling, and native-vs-rsync ingest choices.

## What changed in v0.9

- Improved the GUI upload panel guidance for browser folder uploads. The virtual path help now states that browser folder selection already includes the selected folder name.
- Added visible selected-file and selected-folder summaries because browser file inputs often show only truncated names.
- Added a duplicate-folder warning when the virtual path ends with the same name as the selected browser folder.
- Prefilled the rsync binary override with the detected or usual rsync path for the current OS.
- Renamed the local path action to `Import local path` and added clearer messages when no local path is typed. This advanced path remains useful for very large local folders because browsers cannot expose a selected folder's real disk path.
- Extended rsync status output with OS, default hint, and candidate paths.

## What changed in v0.8

- Added saved-vault selection in the GUI with a dropdown for multiple vault locations.
- Added a right-side saved-vault status list with per-vault status bars, active-vault highlighting, keychain availability, and missing/error indicators.
- Added GUI support to save a vault location and optionally store its password in the OS keychain.
- Added CLI `seavault profile save --save-password NAME VAULT_DIR` and `seavault profile list --status`.
- Moved profile storage onto the shared SeaVault app configuration directory so tests and enterprise deployments can isolate app state with `SEAVAULT_APP_HOME`.

## What changed in v0.7

- Reworked the GUI into a responsive two-column desktop layout with the result/progress panel on the right.
- Added tablet and phone breakpoints, full-width controls, horizontally scrollable tables, and cross-browser colour/focus fallbacks.
- Added browser capability messaging for folder upload and core browser APIs.
- Added a GUI responsive-layout test and documentation in `docs/gui-responsive-layout.md`.

## What changed in v0.6

- Fixed large browser folder upload reliability by sending selected files in smaller batches with progress and cancel support.
- Added GUI bulk export for selected virtual folders/files and the entire vault.
- Added export dry-run counts, overwrite policy, local destination folder support, and optional ZIP export.
- Added `seavault export` for CLI bulk export with dry-run, ZIP, and overwrite controls.
- Moved the main GUI result/progress window to a right-side panel with clearer human-readable messages.
- Added GUI and API rsync status checks.
- Added rsync-assisted archive ingest for CLI `put` and GUI local path uploads.
- Added browser folder upload support in the GUI.
- Added rclone as the primary remote transport backend.
- Added an app-managed rclone runtime; users do not need system rclone.
- Added CLI commands for rclone runtime status, install, update, rollback, path, version, and verification.
- Added remote repository profiles for local and rclone targets.
- Added GUI panels for rclone runtime management, remote profiles, transfer actions, and SSH key management.
- Added safe copy-first remote operations: dry-run, push, pull, test, and check.
- Kept destructive `rclone sync` out of the default GUI flow.
- Added basic SSH key generation/import/list/public-key workflows for rclone SFTP profiles.
- Added tests for rclone runtime registration, profile storage, redaction, SSH keys, and rclone command construction.

## Encrypted sync location

The vault path is the encrypted local storage location. Put it inside a folder watched by a desktop sync client when using local-sync mode:

```bash
seavault init --profile nextcloud "~/Nextcloud/seavault"
seavault put --method auto nextcloud ./report.pdf reports/report.pdf
seavault put --method rsync nextcloud ./project-folder projects/project-folder
seavault list nextcloud            # shows content/reports/report.pdf and content/projects/...
seavault get nextcloud reports/report.pdf ./recovered/report.pdf
seavault export nextcloud . ~/Desktop/seavault-export
```

The provider sees only `.seavault/vault.json`, encrypted chunk objects, encrypted manifests, and tombstones. Plaintext files stay outside the vault unless explicitly exported/downloaded. User-visible paths live under the protected `content/` workspace in the virtual vault.

## Rsync-assisted archive ingest

The `put` command now defaults to `--method auto`, which tries the app-managed rsync runtime when installed and verified, then system rsync, then native Go ingest. Native Go ingest remains the dependency-free default in the GUI and the safest fallback. Use `--method managed-rsync` to require the managed runtime, `--method system-rsync` or `--method rsync` to require a system binary, or `--method native` to bypass rsync staging.

```bash
# Try managed rsync, then system rsync, then native Go import
seavault put --method auto nextcloud ./folder archive/folder

# Dependency-free local import
seavault put --method native nextcloud ./folder archive/folder

# Require the app-managed rsync runtime
seavault put --method managed-rsync nextcloud ./folder archive/folder

# Require system rsync and optionally override the binary path
seavault put --method system-rsync --rsync /usr/bin/rsync nextcloud ./folder archive/folder
```

Rsync is used only as a local staging/enumeration helper for ingest. It does not write plaintext into `.seavault`; the app encrypts staged files into content-defined chunks and encrypted manifests. The temporary staging directory is deleted after ingest unless debugging options are added in development builds.

The GUI now has two folder options:

- Browser folder upload, using the browser-provided relative file paths where supported. The selected folder name is already included in those relative paths. For example, selecting a folder named `Articles` and entering `Archive` stores files under `Archive/Articles/...`; entering `Articles` stores files under `Articles/Articles/...`.
- Local path ingest, where the local GUI server reads a typed file or folder path from this computer and uses rsync-assisted ingest. This is advanced but not redundant: browsers intentionally do not reveal the real local disk path of a selected folder, so local path ingest is the safer option for very large folders or scripted desktop workflows.

The GUI shows a selected-file or selected-folder summary below each picker and warns when the virtual path appears to duplicate the selected folder name.



## Built-in WebDAV file manager

Run the GUI:

```bash
seavault gui
```

Then open the Files section or browse directly to:

```text
http://127.0.0.1:8787/files/
```

The file manager is an in-app WebDAV client. It talks to the local same-origin WebDAV endpoint and does not require an operating-system WebDAV client or mount helper. The default endpoint is available only while a vault is unlocked:

```text
http://127.0.0.1:8787/dav/<session-token>/
```

The `/dav/` token is a distinct per-GUI-session WebDAV token (separate from the GUI's CSRF token, which is never placed in a `/dav/` URL). It is rotated when the vault is closed or the GUI restarts. Every request must carry a `Host` header naming a loopback address, `localhost`, or an explicit `--allow-host` value, or it is rejected with `403`; every response carries `Referrer-Policy: no-referrer`. Decrypted file responses include no-store headers. The endpoint blocks path traversal, `.seavault` internals, reserved `.seavault-dir` markers, and deletion of the protected `content/` workspace. Range (`bytes=`) requests are served as `206 Partial Content`. Use read-only mode when you want browse/download access without PUT, DELETE, MKCOL, MOVE, or COPY writes.

For native WebDAV clients (rclone, Finder) use `seavault serve`, which exposes the same virtual view over HTTP Basic authentication instead of a URL token. Windows Explorer's WebClient refuses Basic over plain HTTP unless `BasicAuthLevel=2`; the supported Windows drive path is the Phase B rclone/WinFsp mount. See [docs/webdav-file-manager.md](docs/webdav-file-manager.md).

Supported file-manager operations:

- browse folders through WebDAV `PROPFIND`
- download files through `GET`
- upload files and browser-selected folders through `PUT`
- create folders through `MKCOL`
- delete through `DELETE`
- rename/move through `MOVE`
- copy through `COPY`
- export selected folders as ZIP through the existing local export workflow

The encrypted vault storage remains unchanged. The cloud provider still sees only `.seavault` encrypted data. The WebDAV file manager exposes plaintext only inside the authenticated local browser session after the vault is unlocked.

## Move vault location

A vault can be moved to a new local folder without changing the vault ID or re-encrypting data. This is useful when moving the encrypted vault from one sync-client folder to another, for example from `~/SeaVault/research` to `~/Nextcloud/research-seavault`.

```bash
# Move a saved vault profile and update matching remote profiles
seavault profile move work-cloud ~/Nextcloud/seavault-work

# Move any vault path or profile, and update a named saved location
seavault move --profile work-cloud ~/SeaVault/work ~/Nextcloud/seavault-work

# Replace an existing empty or disposable destination
seavault profile move --replace work-cloud ~/Nextcloud/seavault-work
```

The move operation moves the entire encrypted vault folder, including `.seavault`. It rejects destinations inside the source vault to avoid recursive moves. If the move crosses filesystems, SeaVault falls back to a copy-then-remove workflow.

Keychain entries do not need to be rewritten because they are stored by vault ID. If the GUI moves the active open vault and a keychain password is available, it attempts to reopen the vault automatically at the new location. Otherwise, the vault is safely closed and can be reopened from the new location.

## Bulk export

The CLI and GUI can export a virtual folder, a single virtual file, or the entire vault. Export decrypts plaintext to a destination you choose, so do not export into `.seavault`.

```bash
# Plan an export without writing plaintext
seavault export --dry-run nextcloud . ~/Desktop/seavault-export

# Export the entire vault
seavault export nextcloud . ~/Desktop/seavault-export

# Export one virtual folder
seavault export --overwrite skip nextcloud projects/site ~/Desktop/site-export

# Export one virtual folder as ZIP
seavault export --zip nextcloud projects/site ~/Desktop
```

Overwrite policies are `fail`, `skip`, and `replace`. The GUI exposes the same controls with progress and cancel support.

## Managed rsync runtime

Managed rsync is optional. The app works without rsync because native Go ingest remains available. Managed rsync is useful when you want predictable local staging behaviour without asking users to install rsync manually. It is not the remote cloud transport; rclone remains the primary remote transport.

```bash
# Show managed/system rsync status and recommended ingest mode
seavault rsync status --check-update

# Register an existing verified rsync binary into SeaVault's managed runtime
seavault rsync install --from-binary /usr/bin/rsync

# Install an enterprise-built SeaVault rsync runtime archive
seavault rsync install --offline-archive ./seavault-rsync-3.4.2-linux-amd64.zip

# Update, rollback, verify, and show active path
seavault rsync check-update
seavault rsync update --offline-archive ./seavault-rsync-3.4.2-linux-amd64.zip
seavault rsync rollback
seavault rsync verify-runtime
seavault rsync path
```

Runtime locations:

| OS | Location |
|---|---|
| Linux | `~/.local/share/seavault/rsync` |
| macOS | `~/Library/Application Support/SeaVault/rsync` |
| Windows | `%LOCALAPPDATA%\SeaVault\rsync` |

Rsync upstream is source-first. SeaVault therefore supports a source-direct provenance model: track the upstream rsync source release, verify or register an enterprise-built runtime artifact, record the binary hash, and retain the previous version for rollback. A direct binary update channel should be operated by the project or an enterprise administrator, not by downloading arbitrary third-party rsync binaries.

## Rclone transport model

Rclone is the app-managed transport runtime, not the encryption layer. Rclone never receives plaintext user files; it only copies the vault's metadata directory (`<vault>/.seavault` or, for a v0.16 vault, `<vault>/SeaVaultData`; the transport resolves whichever the vault uses).

Safe defaults:

```text
push:    rclone copy local .seavault objects/manifests/tombstones to remote
pull:    rclone copy remote .seavault to local
check:   rclone check local .seavault and remote .seavault
sync:    not exposed as a default GUI action
```

## Managed rclone runtime

Install or register a managed rclone runtime:

```bash
# Online install, latest stable
seavault rclone install

# Offline/controlled registration from an existing binary
seavault rclone install --from-binary /usr/local/bin/rclone --signature skip

# Status, update, rollback, and verification
seavault rclone status --check-update
seavault rclone update
seavault rclone rollback
seavault rclone verify-runtime
seavault rclone path
```

Runtime locations:

| OS | Location |
|---|---|
| Linux | `~/.local/share/seavault/rclone` |
| macOS | `~/Library/Application Support/SeaVault/rclone` |
| Windows | `%LOCALAPPDATA%\SeaVault\rclone` |

Online installs download official rclone artifacts, verify SHA256SUMS, extract only the executable, run `rclone version`, and record the binary hash. GPG signature verification is supported when `gpg` is available; use `--signature required` where signature verification must be mandatory.

## Remote profiles

```bash
# Local folder target
seavault remote add --type local --backend local local-backup ~/SeaVault/research ~/Backup/SeaVault/research

# Rclone target
seavault remote add --backend b2 research-b2 ~/SeaVault/research b2ca:seavault/research

# Operations
seavault remote list
seavault remote test research-b2
seavault remote dry-run research-b2
seavault remote push research-b2
seavault remote pull research-b2
seavault remote check research-b2
```

Remote profile configuration is stored outside the vault. Rclone config is stored under app config, not inside `.seavault`.

## GUI

```bash
seavault gui
```

The GUI listens on `127.0.0.1:8787` by default. It provides vault create/open/upload/download/delete/verify workflows, batched browser folder upload, rsync-assisted local path ingest, bulk export, optional ZIP export, profile management, managed rsync and rclone runtime controls, remote repository profiles, transfer actions, and SSH key management.

`seavault gui` serves the app only through a per-launch launch link (`http://127.0.0.1:8787/?launch=<secret>`) and opens it automatically. A bare `http://127.0.0.1:8787/` no longer shows the app, and the launch secret rotates each launch, so bookmarks break by design. With `--no-open`, copy the printed launch link into the browser. `--allow-host NAME` (repeatable) adds an accepted `Host` header value; every request whose `Host` is not a loopback address, `localhost`, or an `--allow-host` value is rejected with `403` to block DNS-rebinding pages. See [docs/gui-launch-link.md](docs/gui-launch-link.md).

The desktop layout keeps the result/progress panel on the right. Narrower tablet and phone layouts collapse to one column so controls remain readable and tables do not force horizontal page scrolling. Browser folder upload is capability-detected; when a browser does not expose folder selection, use local path ingest for directory imports.

Do not bind the GUI to a public or shared network interface.

## CLI overview

```bash
seavault init [flags] VAULT_DIR
seavault put [--method auto|native|managed-rsync|system-rsync|rsync] [flags] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]
seavault get [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH
seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP
seavault rsync status|install|check-update|update|rollback|verify-runtime|path
seavault list [flags] VAULT_DIR_OR_PROFILE
seavault remove [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH
seavault verify [flags] VAULT_DIR_OR_PROFILE
seavault gc [--confirm] [--fence 72h] [--json] VAULT_DIR_OR_PROFILE
seavault compact VAULT_DIR_OR_PROFILE
seavault stats [flags] VAULT_DIR_OR_PROFILE
seavault serve [--addr 127.0.0.1:8765] [--user seavault] [--password-file PATH] [--quiet-credentials] [--allow-host NAME] [--drop-os-junk] [--no-keychain] [--insecure-bind] VAULT_DIR_OR_PROFILE
seavault gui [--addr 127.0.0.1:8787] [--no-open] [--allow-host NAME] [--exit-on-browser-close] [--insecure-bind] [VAULT_DIR_OR_PROFILE]
seavault rclone status|install|check-update|update|rollback|version|path|verify-runtime
seavault remote add|list|show|delete|test|dry-run|push|pull|check|config
seavault ssh-key generate|import|list|public
```

Vault passwords are resolved in this order: `SEAVAULT_PASSWORD`, OS keychain, then hidden prompt.

`seavault gc` without `--confirm` is a dry run. When it finds chunks it would reclaim, it writes a one-line advisory to stderr and exits with code **3** ("action required", distinct from the code-1 failure exit), so a scripted caller that omitted `--confirm` can detect from the exit status that nothing was reclaimed. A dry run with nothing to do exits 0 silently; `gc --json` prints the report and exits 0 regardless. Values passed to `--fence` below the 1h minimum are clamped to 1h with a stderr notice.

`seavault serve` requires a separate WebDAV Basic-auth credential (it is not the vault password). Its password source precedence is `--password-file` > `SEAVAULT_SERVE_PASSWORD` > a freshly generated 32-character password printed once on start. `--quiet-credentials` suppresses the print and requires one of the two explicit sources. `--no-keychain` skips the OS keychain when resolving the vault password. `--allow-host NAME` (repeatable, also on `gui`) adds a `Host` header value accepted besides loopback/`localhost`; it is required for off-loopback (`--insecure-bind`) deployments. See [docs/webdav-file-manager.md](docs/webdav-file-manager.md).

`seavault gui` serves the app only through the per-launch launch link it prints and opens (see the GUI section above). `--exit-on-browser-close` defaults to **true**: the GUI stops itself about 10 seconds after the browser page stops sending heartbeats (for example, when the tab is closed). Pass `--exit-on-browser-close=false` to keep a headless or scripted GUI server running after the browser disconnects. `--insecure-bind` (also on `serve`) permits binding to a non-loopback address and exposes decrypted content; it is not recommended.

## Storage model

The metadata directory is `SeaVaultData` for vaults created by v0.16 and later, or `.seavault` for legacy vaults created by v0.15 and earlier; both names are recognised on open, put, export, and transport.

```text
VAULT_DIR/
  SeaVaultData/            # or .seavault for a legacy vault
    vault.json
    objects/chunks/xx/<object-id>.chunk
    manifests/xx/<manifest-id>.manifest
    tombstones/
```

Files are split with content-defined chunking. Each plaintext chunk gets a keyed object ID, is encrypted with AES-256-GCM, and is stored once. Each virtual file path has an encrypted manifest that references ordered chunks.

## Build and test

```bash
go test ./...
go vet ./...
go build -o bin/seavault ./cmd/seavault
./scripts/smoke-test.sh ./bin/seavault
./scripts/gui-api-smoke-test.sh ./bin/seavault
./scripts/rsync-put-smoke-test.sh ./bin/seavault
```

GUI layout checks are covered by `go test ./internal/webui`. See `docs/gui-responsive-layout.md` for the static responsive-layout validation checklist and optional browser-render checks.

Cross-compile examples:

```bash
GOOS=linux GOARCH=amd64 go build -o dist/seavault-linux-amd64 ./cmd/seavault
GOOS=darwin GOARCH=arm64 go build -o dist/seavault-darwin-arm64 ./cmd/seavault
GOOS=windows GOARCH=amd64 go build -o dist/seavault-windows-amd64.exe ./cmd/seavault
```

## Current limitations

- Not independently audited.
- GUI is browser-based rather than a native toolkit GUI.
- Linux keychain support requires a Secret Service provider and `secret-tool`.
- GPG signature verification for rclone downloads depends on a locally available `gpg` binary.
- SSH key passphrase storage, host-key pinning UI, and SSH-agent GUI integration are still production-hardening items.
- Managed rsync is optional. `--method auto` falls back to native ingest when managed/system rsync is unavailable; strict rsync modes require either a verified managed runtime or a system binary.
- Native mount integrations are not included; `serve` provides a minimal WebDAV-compatible local endpoint.
- Multi-device concurrent edits are preserved as conflict copies, but the app does not merge application-level document contents.
- Password rotation, recovery keys, signed release pipelines, installer packages, and full admin policy enforcement are still future work.

## Security boundary

SeaVault protects file contents and virtual paths before the vault is synchronized. It does not hide total vault size, approximate object count, object churn, sync timing, or the existence of the vault from the cloud provider.
