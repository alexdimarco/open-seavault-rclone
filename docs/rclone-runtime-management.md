# App-managed rclone runtime

SeaVault Fast manages its own rclone executable so users do not have to install rclone separately and so the GUI can report the active runtime version, hash, source, and rollback state.

## Runtime locations

The runtime is stored outside the vault:

| OS | Runtime root |
|---|---|
| Linux | `~/.local/share/seavault/rclone` |
| macOS | `~/Library/Application Support/SeaVault/rclone` |
| Windows | `%LOCALAPPDATA%\SeaVault\rclone` |

For tests and portable deployments, set:

```bash
SEAVAULT_APP_HOME=/path/to/app-home
```

## Manifest

The runtime manifest records:

```json
{
  "installedVersion": "v1.74.0",
  "binaryPath": ".../rclone/v1.74.0/rclone",
  "sha256": "...",
  "sourceUrl": "https://downloads.rclone.org/...",
  "releaseChannel": "stable",
  "previousVersion": "...",
  "signatureVerified": true,
  "checksumVerified": true
}
```

## Install modes

### Official download

The installer can download the official platform zip, download the corresponding `SHA256SUMS`, verify the archive hash, extract only the rclone executable, run `rclone version`, hash the installed binary, and write the runtime manifest.

GPG signature verification is supported when `gpg` is available. Signature mode can be:

| Mode | Behaviour |
|---|---|
| `optional` | Try GPG verification, but continue with enforced SHA256 verification if GPG is unavailable |
| `required` | Fail unless GPG verification succeeds |
| `skip` | Skip GPG verification; SHA256 verification still applies for online installs |

### Existing binary registration

For offline or enterprise-controlled deployments:

```bash
seavault rclone install --from-binary /path/to/rclone --signature skip
```

This copies the binary into the app-managed runtime directory, runs `rclone version`, records the version, and stores the binary hash.

### Offline archive

Offline archive support accepts a local rclone zip and optional SHA256SUMS file:

```bash
seavault rclone install \
  --offline-archive ./rclone-v1.74.0-linux-amd64.zip \
  --offline-sha256sums ./SHA256SUMS \
  --signature skip
```

## Update and rollback

```bash
seavault rclone check-update
seavault rclone update
seavault rclone rollback
seavault rclone verify-runtime
```

Updates are staged and verified before activation. The previous runtime path and hash are retained for rollback.

## Enterprise policy file

The policy file is designed for later administrative enforcement:

```json
{
  "allowUpdates": true,
  "allowedChannels": ["stable"],
  "pinnedVersion": "",
  "allowedDownloadHosts": ["downloads.rclone.org", "rclone.org"],
  "updateCheckIntervalHours": 24,
  "requireManualApproval": true,
  "signatureMode": "optional"
}
```

Security outcome: the app can prove which managed rclone binary it used and detect local runtime tampering by SHA256 hash.

Paper compliance still requires a documented update approval process, change log retention, endpoint inventory, and incident response ownership.
