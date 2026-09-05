# Rclone backend presets

Default transport settings are conservative and can be tuned per backend.

| Backend | transfers | checkers | fast-list | Notes |
|---|---:|---:|---|---|
| local | 8 | 16 | off | Local filesystem and mounted shares usually do not need provider listing acceleration |
| SFTP | 4 | 8 | off | Tune based on server CPU and SSH latency |
| S3-compatible | 8 | 16 | on | Good default for object stores |
| Backblaze B2 | 8 | 16 | on | Watch API class and rate limits |
| Azure Blob | 8 | 16 | on | Validate region and tenant controls |
| Google Drive | 4 | 8 | auto | Avoid aggressive API throttling |
| OneDrive | 4 | 8 | auto | Watch throttling and business tenant policy |
| Dropbox | 4 | 8 | auto | Watch API throttling |
| WebDAV/Nextcloud | 4 | 8 | off | Server implementation varies; increase slowly |

Compression remains off by default because encrypted chunks are high entropy.
