# Built-in WebDAV file manager

open-seavault-rclone includes an in-app WebDAV client/file manager so users do not need Finder, Windows Explorer, GNOME Files, KDE Dolphin, davfs2, WinFsp, macFUSE, FUSE, or another operating-system WebDAV client for the default workflow.

## Model

open-seavault-rclone still stores encrypted data in the vault directory:

```text
<vault>/.seavault/vault.json
<vault>/.seavault/objects/chunks/...
<vault>/.seavault/manifests/...
<vault>/.seavault/tombstones/...
```

When a vault is unlocked, the GUI exposes a local virtual plaintext view:

```text
/files/                      built-in browser file manager
/dav/<session-token>/        local WebDAV endpoint
```

All user-created files and folders live under the protected `content/` workspace. The WebDAV root shows `content/`; file operations occur inside it. Older vaults that do not have this structure are migrated automatically when opened.

The WebDAV endpoint never exposes raw `.seavault` internals or internal `.seavault-dir` directory markers.

**With a GUI password set, the in-GUI `/dav/` URL is browser-only.** When you
configure a GUI login password, `/dav/` additionally requires the GUI login
session cookie, which Finder, Windows Explorer, and rclone cannot present. The
GUI's "Copy WebDAV URL" button then hands you a URL that works only inside the
logged-in browser tab, and the GUI surfaces a note saying so. For a native WebDAV
client while a GUI password is set, run `seavault serve` (below): it authenticates
with HTTP Basic instead of the login cookie. Without a GUI password, the copied
`/dav/<davToken>/` URL works in native clients because the path token is the
credential.

## Supported operations

| Operation | WebDAV method | Notes |
|---|---|---|
| Browse folders | `PROPFIND` | Used by the in-app file manager. |
| Download file | `GET` | Decrypted response has `Cache-Control: no-store`. |
| Upload file | `PUT` | Encrypts into the vault immediately. |
| Create folder | `MKCOL` | Creates an encrypted `.seavault-dir` directory marker hidden from users and exports. |
| Delete | `DELETE` | Uses vault removal/tombstone handling. |
| Rename/move | `MOVE` | Moves files or directory prefixes inside the virtual view. |
| Copy | `COPY` | Copies files or directory prefixes inside the virtual view. |
| Lock compatibility | `LOCK`/`UNLOCK` | Implemented as lightweight compatibility responses. |

## Security controls

- Every request must carry a `Host` header naming a loopback address, `localhost`,
  or an explicit `--allow-host` value; anything else is answered `403` with no DNS
  lookup. This blocks DNS-rebinding pages and cross-site posts from the browser.
- Every response carries `Referrer-Policy: no-referrer`.
- `/dav/` requires a distinct random per-GUI-session WebDAV token (separate from
  the GUI's CSRF token, so the CSRF secret is never placed in a `/dav/` URL).
- The WebDAV token rotates when the vault closes or the GUI restarts.
- WebDAV runs only when a vault is open.
- The default GUI bind address remains localhost.
- Decrypted WebDAV responses include no-store headers.
- Path traversal is rejected.
- Absolute virtual paths are rejected.
- `.seavault` and `.seavault-dir` are blocked anywhere in user-controlled virtual paths.
- The protected `content/` workspace cannot be deleted or moved.
- Read-only mode rejects `PUT`, `DELETE`, `MKCOL`, `MOVE`, and `COPY`.
- The app does not log vault passwords or WebDAV session tokens.

## `seavault serve` and native WebDAV clients

`seavault serve` exposes the same virtual plaintext view over a standalone
WebDAV-compatible endpoint (default `http://127.0.0.1:8765/`) for native clients
such as rclone or Finder. Unlike the GUI-mounted `/dav/`, this endpoint uses HTTP
**Basic authentication** rather than a URL token:

```bash
# Generated password, printed once on start. The full startup output is:
seavault serve ~/Nextcloud/seavault
#   serving local WebDAV-compatible vault at http://127.0.0.1:8765/
#   bind is local by default; do not expose this listener on an untrusted network
#   WebDAV credentials: seavault / <32-char-password>
#   URL: http://seavault:<password>@127.0.0.1:8765/
```

If stdout is a file or pipe rather than a terminal (a daemon with redirected
output), a fifth line warns that the generated credential is being written to a
log/redirect and points at the `--password-file` + `--quiet-credentials` form
below. A generated password persists in scrollback and in any redirected log, so
for non-interactive/daemon use supply your own password instead:

```bash
# Supply your own password from a file. Create the file readable only by you,
# then start with --quiet-credentials so nothing is printed:
umask 077
printf '%s' 'your-strong-password' > ./dav.pass
chmod 600 ./dav.pass
seavault serve --password-file ./dav.pass --quiet-credentials ~/Nextcloud/seavault
#   serving local WebDAV-compatible vault at http://127.0.0.1:8765/
#   bind is local by default; do not expose this listener on an untrusted network
```

To pass the password through the environment instead, keep it out of shell
history — do **not** use the inline `SEAVAULT_SERVE_PASSWORD=... seavault serve`
form, because the interactive shell records the whole command line (password
included) in its history file:

```bash
# Read it in interactively (nothing echoed, nothing stored in history):
read -rs SEAVAULT_SERVE_PASSWORD; export SEAVAULT_SERVE_PASSWORD
seavault serve --quiet-credentials ~/Nextcloud/seavault

# ...or source it from an env file readable only by you (e.g. a systemd
# EnvironmentFile), never a world-readable one:
chmod 600 ./seavault.env          # file contains: SEAVAULT_SERVE_PASSWORD=...
set -a; . ./seavault.env; set +a
seavault serve --quiet-credentials ~/Nextcloud/seavault
```

`--password-file` is the most robust of the three: it never touches shell history
and, unlike an env var, is not visible in `/proc/<pid>/environ` to other
same-user processes.

Password source precedence, first wins: `--password-file` (content, trailing
newline trimmed, must be non-empty) > `SEAVAULT_SERVE_PASSWORD` > a freshly
generated 24-byte base64url password (32 characters). `--user` sets the username
(default `seavault`). `--quiet-credentials` suppresses the printed password and is
an error unless a password source is present. There is no `--no-auth`.

`--allow-host NAME` (repeatable) adds a `Host` header value the endpoint accepts
besides loopback addresses and `localhost`. It is required for any off-loopback
deployment (`--insecure-bind`): a bind to `0.0.0.0`/`::` is never added to the
allowlist automatically, so pass `--allow-host` for every name or IP clients
connect as. `--drop-os-junk` makes the endpoint silently discard OS cruft
(`.DS_Store`, `._*`, `Thumbs.db`, `desktop.ini`, and friends) instead of storing
it.

### Windows WebClient limitation

The Windows WebClient (Explorer's "Map network drive") refuses HTTP Basic
authentication over plain `http://` unless the registry value
`HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\BasicAuthLevel` is set
to `2`. The supported Windows drive-mount path is the Phase B rclone/WinFsp mount,
not this redirector. rclone (`rclone mount`/`rclone serve` clients) and macOS
Finder authenticate Basic over loopback without any such change.

## GUI workflow

1. Run `seavault gui`.
2. Open or create a vault.
3. Open `/files/` or use the Files section in the main GUI.
4. Browse the folder tree or breadcrumb path.
5. Upload files, upload a folder, drag files onto the drop zone, create folders, rename, copy, delete, or download.
6. Use read-only mode when exposing the local endpoint for browsing only.

## Why not OS-mounted WebDAV by default

OS-mounted WebDAV depends on native components and varies by platform. This project keeps the default path dependency-free by using a browser-based WebDAV client. Optional OS mount helpers can be added later without changing the vault format.
