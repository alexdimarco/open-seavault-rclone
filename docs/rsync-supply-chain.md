# Rsync supply chain model

SeaVault does not assume that official upstream rsync publishes a complete, ready-to-use binary matrix for every target platform. The managed runtime path supports controlled registration and offline runtime archives.

## Recommended production channel

1. Monitor upstream rsync source releases.
2. Verify upstream source signatures in CI or release engineering.
3. Build per-platform runtime archives.
4. Sign and publish archives and checksums.
5. Configure SeaVault clients to use the approved runtime base URL or distribute offline archives.
6. Retain previous runtimes for rollback.

## Runtime manifest

The managed rsync manifest records:

- installed version
- source version
- source URL
- runtime artifact URL or registered binary path
- binary path
- SHA256
- install time
- previous version and binary path
- update check time

## Security rules

- Do not download rsync from arbitrary third-party mirrors.
- Do not run rsync through a shell.
- Do not store plaintext in `.seavault`.
- Do not make rsync mandatory for vault operation.
- Prefer native ingest unless rsync staging is explicitly needed.
