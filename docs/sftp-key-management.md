# SFTP SSH key management

SeaVault Fast includes basic SSH key management for rclone SFTP profiles. SSH keys are stored in app configuration, never inside the encrypted vault.

## Managed key location

| OS | Key directory |
|---|---|
| Linux | `~/.config/seavault/ssh` |
| macOS | `~/Library/Application Support/SeaVault/ssh` |
| Windows | `%APPDATA%\SeaVault\ssh` |

## CLI

```bash
seavault ssh-key generate research-sftp
seavault ssh-key list
seavault ssh-key public research-sftp_ed25519
seavault ssh-key import imported-key ~/.ssh/id_ed25519
```

Generated keys are Ed25519 keys. The GUI can show the public key so it can be added to a remote server's `authorized_keys` file.

## Current scope

Implemented:

- Generate Ed25519 key pair.
- Import an existing key.
- List managed keys.
- Show public key.
- Show SHA256 public-key fingerprint.

Remaining production work:

- Encrypted private-key passphrases.
- OS-keychain storage for SSH private-key passphrases.
- SSH agent integration in the GUI.
- Host-key scanning and explicit host-key pinning UI.
- One-time remote bootstrap to append public keys to `authorized_keys`.

Security outcome: private keys are kept out of the vault and can be managed per workstation.

Paper compliance still requires access review, revocation procedure, lost-device procedure, and documented key rotation.
