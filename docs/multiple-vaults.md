# Multiple vaults and saved vault locations

SeaVault can keep a local list of saved vault locations. A saved vault location is an app profile with a name and a vault path. The password is never written to the profile file. When requested, the password is stored separately in the operating-system keychain under the vault ID from `.seavault/vault.json`.

## GUI workflow

1. Open `seavault gui`.
2. Create or open a vault.
3. Enter a saved vault name, for example `work-nextcloud`.
4. Select `Save password in OS keychain` if this device should remember the password.
5. Click `Save vault location/password`.

The vault then appears in the saved-vault dropdown and in the right-side status panel. The right panel shows whether each saved vault is open, ready, missing, or password-required, plus a progress/status bar for each saved vault.

## CLI workflow

Save a vault location only:

```bash
seavault profile add work-nextcloud ~/Nextcloud/seavault
```

Save a vault location and store its password in the OS keychain:

```bash
seavault profile save --save-password work-nextcloud ~/Nextcloud/seavault
```

List saved vaults:

```bash
seavault profile list
```

List saved vaults with status:

```bash
seavault profile list --status
```

Open or operate on a saved vault by name:

```bash
seavault list work-nextcloud
seavault put work-nextcloud ./report.pdf reports/report.pdf
seavault export work-nextcloud . ~/Desktop/seavault-export
```

## Storage locations

Profiles are stored in the SeaVault app configuration directory. Passwords are stored in the operating-system keychain. Neither profiles nor keychain credentials are stored inside the encrypted vault folder.
