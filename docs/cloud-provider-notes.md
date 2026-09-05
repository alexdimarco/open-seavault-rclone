# Cloud provider notes

SeaVault can use either local sync-client folders or direct rclone remotes.

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
