# Rsync-backed archive ingestion

SeaVault can now use rsync as the staging mechanism before data is chunked and encrypted into the vault.

The flow is:

```text
source file or folder
  -> rsync staging directory
  -> content-defined chunking
  -> encrypted chunk objects
  -> encrypted sharded manifests
  -> <vault>/.seavault
```

Rsync never writes directly into the encrypted object store and never transfers plaintext to a remote service during `put`. It only stages local input into a temporary local directory so the vault can import a stable filesystem view. The temporary staging directory is deleted after the import completes.

## CLI

Default behaviour uses `auto`: rsync is used when available; direct ingestion is used only when rsync cannot be found.

```bash
seavault put ~/Nextcloud/seavault ./report.pdf reports/report.pdf
seavault put --ingest rsync ~/Nextcloud/seavault ./research-folder research
seavault put --ingest direct ~/Nextcloud/seavault ./research-folder research
seavault put --rsync-bin /usr/local/bin/rsync ~/Nextcloud/seavault ./research-folder research
seavault rsync status
```

Modes:

| Mode | Behaviour |
|---|---|
| `auto` | Use rsync when available, otherwise direct ingestion fallback. |
| `rsync` | Require rsync and fail if it is unavailable. |
| `direct` | Bypass rsync and ingest directly from the source path. |

Use `SEAVAULT_RSYNC=/path/to/rsync` or `--rsync-bin /path/to/rsync` when rsync is not on `PATH`.

On Windows, rsync is not guaranteed to be present by default. `auto` mode falls back to direct ingestion if no compatible rsync executable is found; use `--rsync-bin` or `SEAVAULT_RSYNC` to point at a tested cwRsync, MSYS2, Cygwin, or enterprise-managed rsync binary.

## GUI

The Upload panel now supports:

- ordinary multi-file upload;
- folder upload through browser directory selection;
- `auto`, `rsync`, and `direct` ingest modes;
- an optional rsync binary path;
- an rsync status check.

Folder uploads preserve browser-provided relative paths. Chromium, Edge, and Safari expose folder selection through the `webkitdirectory` file input attribute. Firefox support may vary.

## Security notes

- Plaintext upload staging is local and temporary.
- Staged plaintext is deleted after import.
- Only encrypted vault objects remain under `.seavault`.
- Rsync is invoked with `exec.CommandContext` and argument arrays; shell command strings are not constructed.
- For remote transport, keep using the rclone remote backend. Rsync ingestion is for putting local files and folders into the encrypted archive, not for cloud replication.

## Validation

Run:

```bash
go test ./...
go vet ./...
go build -o bin/seavault ./cmd/seavault
./scripts/smoke-test.sh ./bin/seavault
./scripts/gui-api-smoke-test.sh ./bin/seavault
./scripts/rsync-ingest-smoke-test.sh ./bin/seavault
./scripts/rclone-local-smoke-test.sh ./bin/seavault
```
