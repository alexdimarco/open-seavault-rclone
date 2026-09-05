# Admin policy

The current repository includes policy file structures for managed rclone runtime control. Full enforcement is a production-hardening item.

Recommended enterprise defaults:

```json
{
  "allowUpdates": false,
  "allowedChannels": ["stable"],
  "pinnedVersion": "v1.74.0",
  "allowedDownloadHosts": ["downloads.rclone.org", "rclone.org"],
  "updateCheckIntervalHours": 168,
  "requireManualApproval": true,
  "signatureMode": "required"
}
```

Validation checklist:

1. Pin a tested rclone version for production workstations.
2. Validate the app-managed rclone SHA256 hash.
3. Disable beta channel unless explicitly approved.
4. Keep runtime updates out of active transfer windows.
5. Store the validation report with endpoint management records.
6. Keep rclone credentials outside the vault.
7. Verify remote storage region, backups, support access, and subprocessors.
