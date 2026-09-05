# Bulk export

Bulk export decrypts files from an open vault to a local destination. It is intended for recovery, migration, offline review, and user-controlled exports.

## Supported exports

| Export | CLI | GUI |
|---|---|---|
| Single virtual file | `seavault export VAULT path/file.txt DEST_DIR` | Enter the virtual path and destination folder |
| Virtual folder | `seavault export VAULT projects/site DEST_DIR` | Enter the folder path and destination folder |
| Entire vault | `seavault export VAULT . DEST_DIR` | Click Export entire vault |
| Dry run | `--dry-run` | Dry-run selected export or dry-run entire vault |
| ZIP archive | `--zip` | Check Create ZIP archive |
| Overwrite control | `--overwrite fail|skip|replace` | Overwrite policy selector |

## CLI examples

```bash
# Count files and bytes without writing plaintext output
seavault export --dry-run work-cloud . ~/Desktop/seavault-export

# Export the entire vault
seavault export work-cloud . ~/Desktop/seavault-export

# Export one folder and skip files already present at the destination
seavault export --overwrite skip work-cloud projects/site ~/Desktop/site-export

# Export one folder as a ZIP archive
seavault export --zip work-cloud projects/site ~/Desktop
```

When ZIP export is enabled and the destination is a directory, the app creates `<folder-name>.zip` inside that directory. If the destination path ends in `.zip`, that exact ZIP path is used.

## GUI behaviour

The GUI has an Export plaintext from vault panel. It supports:

- selected virtual folder or file
- entire vault export
- destination local folder or ZIP path
- overwrite policy
- dry-run file count
- optional ZIP export
- progress indicator
- cancel button

The GUI result and progress output appears in the right-side panel.

## Safety notes

Do not export into the vault's `.seavault` directory. Exports are plaintext. The cloud provider or sync client can read exported files if the destination folder is synchronized.

Overwrite policy meanings:

| Policy | Meaning |
|---|---|
| `fail` | Stop if a destination file or ZIP already exists |
| `skip` | Leave existing output unchanged and continue |
| `replace` | Replace existing output |
