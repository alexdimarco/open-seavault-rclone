# Rclone transport

SeaVault Fast treats rclone as a transport runtime, not as the encryption layer. The app encrypts data first, stores encrypted chunks and manifests under the vault metadata directory (`.seavault` for a legacy v0.15 vault, or `SeaVaultData` for a v0.16 vault — the transport resolves whichever name the vault uses), and then asks rclone to copy that encrypted repository to a remote target.

## Transport boundary

Plaintext never enters rclone. The only source or destination passed to rclone is the vault metadata directory:

```text
<vault>/.seavault          # legacy vault
<vault>/SeaVaultData       # v0.16 vault
```

This preserves the vault security model while adding direct support for rclone targets such as local paths, SFTP, S3-compatible object stores, Backblaze B2, Azure Blob, Google Drive, OneDrive, Dropbox, WebDAV/Nextcloud, and other rclone backends.

## Default safety model

The default operation is `copy`, not `sync`. Copy-only transfer is safer for encrypted object repositories because it does not delete remote chunks just because the local side no longer references them. Deletion is handled by vault tombstones and retention-aware garbage collection.

Default push sequence:

```text
rclone mkdir <remote>/.seavault
rclone copy <vault>/.seavault/objects/chunks <remote>/.seavault/objects/chunks
rclone copy <vault>/.seavault/manifests <remote>/.seavault/manifests
rclone copy <vault>/.seavault/tombstones <remote>/.seavault/tombstones
rclone copy <vault>/.seavault/vault.json <remote>/.seavault
```

Default pull sequence:

```text
rclone copy <remote>/.seavault <vault>/.seavault
```

Default check sequence:

```text
rclone check <vault>/.seavault <remote>/.seavault --size-only --one-way
```

## CLI examples

```bash
# Register a managed runtime from an existing binary for offline testing.
seavault rclone install --from-binary /usr/local/bin/rclone --signature skip

# Show managed runtime status.
seavault rclone status --check-update

# Add a direct rclone remote profile.
seavault remote add --backend b2 research-b2 ~/SeaVault/research b2ca:seavault/research

# Add a local folder target using the same remote abstraction.
seavault remote add --type local --backend local research-local ~/SeaVault/research ~/Backup/SeaVault/research

# Run safe transport operations.
seavault remote test research-b2
seavault remote dry-run research-b2
seavault remote push research-b2
seavault remote pull research-b2
seavault remote check research-b2
```

## Performance notes

The speed target remains the Seafile-style storage model: content-defined chunks, stable immutable encrypted objects, and small encrypted manifest shards. Rclone does not need byte-range deltas when unchanged chunks are skipped entirely.

Recommended defaults:

| Setting | Default | Reason |
|---|---:|---|
| transfers | 8 | Enough parallelism for common cloud targets without being overly aggressive |
| checkers | 16 | Improves listing/comparison throughput |
| fast-list | auto/on in profile | Faster on many object stores, but may use more memory |
| compression | off | Encrypted chunks are high entropy and normally do not compress well |
| destructive sync | disabled | Prevents accidental remote object deletion |

## Backend notes

Use local-folder transport for desktop sync clients such as OneDrive Desktop, Dropbox Desktop, Nextcloud Desktop, iCloud Drive, Google Drive Desktop, Syncthing, SMB mounts, and removable drives.

Use rclone transport for direct cloud APIs and SFTP. For Canadian public-sector use, validate data residency, support access, logging, backups, and subprocessors separately from the encryption outcome.
