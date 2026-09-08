# Cloud provider notes

open-seavault-rclone can use either local sync-client folders or direct rclone remotes.

## Recommended modes

| Target | Recommended mode |
|---|---|
| Nextcloud Desktop | Local vault path inside the sync folder |
| OneDrive Desktop | Local vault path inside the sync folder |
| Dropbox Desktop | Local vault path inside the sync folder |
| Google Drive Desktop | Local vault path inside the sync folder |
| iCloud Drive | Local vault path inside the sync folder |
| Syncthing | Local vault path inside the sync folder |
| SFTP server | Rclone SFTP remote |
| S3-compatible object store | Rclone S3 remote |
| Backblaze B2 | Rclone B2 remote |
| Azure Blob | Rclone Azure Blob remote |
| WebDAV/Nextcloud direct | Rclone WebDAV remote |

## Rclone configuration

Use the GUI Remote Repositories section or import an existing rclone config:

```bash
seavault remote config create
seavault remote config import ~/.config/rclone/rclone.conf
seavault remote config export-redacted
seavault remote config validate
```

Provider credentials are stored outside the vault. Where possible, use OS keychain or provider-specific short-lived credentials.

## Placement caveats (per detected provider)

When the setup wizard offers to place a vault inside a detected sync-client folder,
it shows that provider's placement caveat inline (design
`docs/design-setup-wizard.md` §4). The common thread is on-demand / online-only file
eviction: a vault opens only when every encrypted chunk is actually on local disk, so
each caveat says how to keep the vault folder materialised. **Which providers are
detected depends on the OS:** Dropbox, OneDrive, Nextcloud and (marker-gated) Syncthing
on every platform; iCloud Drive and Google Drive only on macOS and Windows, which are the
only platforms with a consumer client for them.

The text below is a **verbatim mirror** of the caveat catalog, reproduced here so a reader
gets the wording without opening the source:

### Dropbox

Dropbox can keep files online-only (Smart Sync / Selective Sync). Right-click the vault folder and choose "Make available offline" so every encrypted chunk stays on disk; otherwise the vault may fail to open when you are offline.

### OneDrive

OneDrive's Files On-Demand can make the vault's chunks online-only placeholders. Right-click the vault folder and choose "Always keep on this device" so the encrypted data is present locally.

### iCloud Drive

iCloud Drive can offload local copies of files you have not opened recently to free space (macOS "Optimize Mac Storage"; on Windows the iCloud client streams files on demand). Keep the vault folder downloaded — turn Optimize Storage off or open the folder to re-download it on macOS, and "Always Keep on This Device" / Keep Downloaded on Windows — so its encrypted chunks are not evicted.

### Google Drive

Google Drive for desktop streams files by default instead of mirroring them. Set the vault folder to "Available offline" (or use Mirror mode) so the encrypted data stays on local disk.

### Nextcloud

Nextcloud's virtual-files (on-demand) mode can leave the vault's chunks online-only. Mark the vault folder "Make always available locally", and enable hidden-file sync if you are opening an older .seavault vault.

### Syncthing

Syncthing skips anything matched by a .stignore rule and keeps no server-side version history by default. Keep the vault folder outside every ignore pattern so all chunks propagate to your other devices.

### Source of truth

These strings are authored in code, in `internal/setup/providers.go`, as the one caveat
catalog (`Provider` → caveat text) consumed by the CLI wizard, the GUI stepper, and the
`internal/setup.DetectSyncFolders` detector — a caveat is written and updated in exactly
one place (review condition C7). The block above is a copy kept in step by a drift-guard
test (`TestDocsMirrorCaveatCatalog` in `internal/setup`), which fails the build if this
doc's text and the code catalog ever diverge, so the code stays authoritative while the
doc still carries the words. Box, pCloud and MEGA are intentionally absent from the
wizard's provider enum until each has a verified caveat.
