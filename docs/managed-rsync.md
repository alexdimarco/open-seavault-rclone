# Managed rsync runtime

SeaVault can manage its own rsync runtime for local path ingest, similar to the managed rclone runtime. This is optional. The application must still work without rsync by using native Go ingest.

## Intended use

Managed rsync is a local ingest helper only:

```text
local source file or folder
  -> optional managed/system rsync staging
  -> native SeaVault chunking and encryption
  -> encrypted .seavault repository
  -> rclone/local transport
```

Rsync does not encrypt files and does not transport plaintext to cloud storage. It is never required for browser uploads.

## Ingest modes

| Mode | Behaviour |
|---|---|
| `native` | Walk and import files directly in Go. No external dependency. Recommended default. |
| `managed-rsync` | Require the app-managed rsync runtime. Fails if not installed or not verified. |
| `system-rsync` | Require a system rsync binary from PATH or `--rsync`. |
| `rsync` | Backwards-compatible alias for `system-rsync`. |
| `auto` | Try managed rsync, then system rsync, then native Go ingest. |

## CLI

```bash
seavault rsync status --check-update
seavault rsync install --from-binary /usr/bin/rsync
seavault rsync install --offline-archive ./seavault-rsync-3.4.2-linux-amd64.zip
seavault rsync update --offline-archive ./seavault-rsync-3.4.2-linux-amd64.zip
seavault rsync rollback
seavault rsync verify-runtime
seavault rsync path
```

## Runtime directories

| OS | Directory |
|---|---|
| Linux | `~/.local/share/seavault/rsync` |
| macOS | `~/Library/Application Support/SeaVault/rsync` |
| Windows | `%LOCALAPPDATA%\SeaVault\rsync` |

## Source provenance

Official rsync distribution is source-first. A practical cross-platform managed runtime should be built by the SeaVault project or by an enterprise administrator:

```text
official rsync source tarball
  -> verify upstream signature outside or inside release pipeline
  -> build per OS/architecture
  -> publish SeaVault runtime ZIP + SHA256SUMS + signature
  -> SeaVault app installs verified runtime
```

The app records the upstream source URL, source version, runtime hash, install time, and previous version for rollback.

## Windows note

Windows rsync runtimes often require support DLLs. Offline runtime ZIP archives should include `rsync.exe` plus any required DLLs in the same archive. SeaVault extracts and retains the full archive contents.
