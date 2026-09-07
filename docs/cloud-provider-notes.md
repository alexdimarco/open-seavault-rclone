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

## Placement caveats (single source of truth)

The per-provider placement caveats the setup wizard shows inline (for example
OneDrive Files On-Demand, or iCloud "Optimize Storage" evicting local copies)
are authored in code, in `internal/setup/providers.go`, as the one caveat
catalog (`Provider` → caveat text). That table — not this document — is the
authoritative source consumed by the CLI wizard, the GUI stepper, and the
`internal/setup.DetectSyncFolders` detector, so a caveat is written and updated
in exactly one place (design `docs/design-setup-wizard.md` §4, review condition
C7). Box, pCloud and MEGA are intentionally absent from the wizard's provider
enum until each has a verified caveat.
