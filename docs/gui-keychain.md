# GUI and keychain notes

## GUI

Run:

```bash
seavault gui
```

The GUI opens a local browser page. It supports vault creation, opening, profile use, upload, download, delete, stats, and verification.

`seavault gui` now serves the app only through a per-launch launch link
(`http://127.0.0.1:8787/?launch=<secret>`) and opens it for you; a bare
`http://127.0.0.1:8787/` no longer shows the app, and the launch secret rotates
each launch so bookmarks break by design. See [gui-launch-link.md](gui-launch-link.md).

Use `Create vault and open` for first-time setup. A newly created vault is opened immediately. If saving the profile or the OS keychain entry fails, the vault remains open and the warning is shown in the status panel.

For the vault path, prefer `~/Nextcloud/seavault` or one of the suggested local encrypted-folder buttons. Do not use `/user/name/...`; macOS uses `/Users/name/...` and Linux uses `/home/name/...`.

## Keychain

CLI:

```bash
seavault keychain store work-cloud
seavault keychain status work-cloud
seavault keychain delete work-cloud
```

- `keychain store` prompts for the vault password, verifies it actually opens the
  vault, then saves it in the OS keychain keyed by the vault ID. On success it
  prints `password stored in OS keychain`.
- `keychain status` does a **per-vault entry lookup** (`keychain.Get` for that
  vault's ID), not a dependency probe. When an entry is present it prints
  `OS keychain entry exists`; when there is no entry — or the keyring is locked, or
  the keychain backend is unavailable — it exits non-zero with the lookup error
  (for example `Secret Service lookup failed; install libsecret-tools or use
  SEAVAULT_PASSWORD`). It does **not** distinguish "no entry stored" from "keychain
  unavailable"; both surface as that error.
- `keychain delete` removes the stored entry for the vault ID.

To check whether the keychain **backend itself** is usable — independently of any
one vault's entry — use the dependencies report, not `keychain status`. That probe
is exposed through the GUI/API: the "Local dependencies" panel in the GUI and the
`GET /api/dependencies` endpoint report the keychain backend state (on Linux, for
example, whether `secret-tool` is installed and whether `DBUS_SESSION_BUS_ADDRESS`
is set), which is the diagnostic a `keychain status` entry lookup cannot give you.

When a command that resolves the vault password from the keychain (such as
`serve` or `gui`) tries the keychain and it errors, it now prints a one-line note
to **stderr** before falling back, instead of silently swallowing the error:

```text
OS keychain unavailable (<reason>); falling back to SEAVAULT_PASSWORD or the hidden prompt
```

GUI:

- Select `Save password in OS keychain` when creating or opening a vault.
- Use `Open using keychain` later without typing the vault password.

## Platform requirements

| Platform | Mechanism | Requirement |
| --- | --- | --- |
| macOS | Keychain | Built-in `security` command |
| Windows | Credential Manager | Native Win32 credential APIs |
| Linux | Secret Service | `secret-tool` and an unlocked desktop keyring |

Linux headless servers usually do not have a Secret Service session. Use `SEAVAULT_PASSWORD` or a deployment-specific secret manager for automation.
