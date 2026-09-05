# Move vault location

SeaVault can move an encrypted vault folder to a new local location and update saved vault profiles after the move.

## What moves

The move operation moves the full vault root folder, including:

```text
<vault>/.seavault/vault.json
<vault>/.seavault/objects/chunks/...
<vault>/.seavault/manifests/...
<vault>/.seavault/tombstones/...
```

Plaintext is not decrypted or rewritten during a move.

## CLI

```bash
# Move a saved vault profile
seavault profile move work-cloud ~/Nextcloud/seavault-work

# Move a path or profile and update a saved vault name
seavault move --profile work-cloud ~/SeaVault/work ~/Nextcloud/seavault-work

# Update matching remote profiles after the move, default true
seavault profile move --update-remotes=true work-cloud ~/Nextcloud/seavault-work

# Replace destination if it already exists
seavault profile move --replace work-cloud ~/Nextcloud/seavault-work
```

## GUI

Use the `Move vault location` panel:

1. Select a saved vault or use the active vault as the source.
2. Enter the new vault location.
3. Leave `Update matching remote profiles` enabled unless you want to update remote profiles manually.
4. Click `Move vault location`.

## Keychain behaviour

OS keychain entries are tied to the vault ID, not the path. Moving the vault does not require storing the password again. If the active vault is moved and a keychain password is available, the GUI attempts to reopen it automatically at the new location.

## Safety rules

- The source must contain a valid `.seavault/vault.json`.
- The destination cannot be inside the source vault.
- The destination cannot be a parent of the source vault.
- Existing non-empty destinations require `--replace` or the GUI replace checkbox.
- Remote profiles that point at the old path can be updated automatically.
