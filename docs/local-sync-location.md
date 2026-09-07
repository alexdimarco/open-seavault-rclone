# Local sync location configuration

The encrypted location is the vault directory passed to `seavault init`, `seavault gui`, or `seavault profile add`.

Paths can use `~`, `$HOME`, `${HOME}`, or `%USERPROFILE%`. The GUI and CLI expand these before creating/opening the vault.

## Recommended layout

```text
CloudSyncFolder/
  open-seavault-rclone/
    SeaVaultData/
      vault.json
      objects/chunks/...
      manifests/...
```

Point the sync client at `CloudSyncFolder` or at `CloudSyncFolder/open-seavault-rclone`. Do not place plaintext source files inside the metadata directory.

## Metadata directory name

Vaults created by v0.16 and later keep their encrypted data in a **visible**
directory named `SeaVaultData`. Older vaults created by v0.15 and earlier use the
hidden `.seavault` directory; both are opened transparently, and everything this
version writes into a `.seavault` vault stays readable by a 0.15 client.

The visible name exists because a hidden `.seavault` directory is easy for a sync
client to miss: some clients skip dotfiles by default. If you keep opening an
older `.seavault` vault, enable hidden-file synchronization in your client — for
example, in Nextcloud clear "Ignore hidden files" (Settings -> General), and for
other clients remove any `.*` entry from the ignore/exclude list.

One-way boundary: a vault this version **creates** (in `SeaVaultData`) is not
located by open-seavault-rclone 0.15.0 or older on another device — that client looks only for
`.seavault` and fails to find a vault (its actual message is a not-found error,
`open <root>/.seavault/vault.json: no such file or directory`, verified against the
0.15.0 build) rather than corrupting anything. Upgrade every device before
creating new vaults in a shared folder. A root that somehow holds both a
`SeaVaultData/vault.json` and a `.seavault/vault.json` is refused as ambiguous;
keep one and remove or rename the other.

## Profiles

Profiles are local aliases that avoid repeating long cloud-sync paths.

```bash
seavault profile add work-cloud "~/OneDrive - Example Org/open-seavault-rclone"
seavault put work-cloud ./budget.xlsx finance/budget.xlsx
```

Profile files are stored in the user configuration directory, not in the vault.

## Validation checklist

1. Create a vault inside the sync-client folder.
2. Put a test file into the vault.
3. Confirm the sync client uploads the metadata directory contents (`SeaVaultData` for a new vault, `.seavault` for a legacy one — with hidden-file sync enabled).
4. Confirm the cloud web UI shows encrypted-looking chunk and manifest files only.
5. Open the same vault on another device after sync completes.
6. Verify the vault on both devices.
7. Simulate a conflict by editing the same virtual file on two devices before sync reconciliation.
8. Confirm one version remains at the original path and the other appears as a `*.conflict-*` virtual file.
