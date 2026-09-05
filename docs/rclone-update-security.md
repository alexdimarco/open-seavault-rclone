# Rclone update security

SeaVault's managed-rclone update process is designed to be auditable and reversible.

## Online update path

1. Resolve the official rclone release artifact for the current OS and architecture.
2. Download from the official rclone download host.
3. Download `SHA256SUMS` from the same release path.
4. Optionally verify the signed checksum file with `gpg` and the rclone KEYS file.
5. Verify the zip archive SHA256 hash.
6. Extract only the rclone executable.
7. Run `rclone version` from the staged binary.
8. Hash the installed binary.
9. Atomically write the runtime manifest.
10. Retain the previous binary path and hash for rollback.

## Current caveat

GPG verification depends on a locally available `gpg` executable. Use `--signature required` in managed enterprise builds where signature verification is mandatory. Use offline artifacts when outbound downloads are not allowed.
