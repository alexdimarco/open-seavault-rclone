# GUI launch link

Starting with the Phase 0 loopback hardening, `seavault gui` no longer serves the
application from a bare `http://127.0.0.1:8787/`. A browser tab reaches the GUI
only after it redeems a per-launch **launch secret**, which mints the session
cookie every other page and API route requires.

## What you see on start

```bash
seavault gui
#   serving local GUI at http://127.0.0.1:8787/?launch=<launch-secret>
#   open this exact launch link; a bare http://127.0.0.1:8787/ no longer shows the app, and the launch secret rotates each launch, so bookmarks break by design
#   bind is local by default; do not expose this listener on an untrusted network
#   exit-on-browser-close enabled; the GUI will stop shortly after the browser page closes
#   If your browser did not open, copy the link above into your browser.
```

The `exit-on-browser-close` line appears only under the default (`--exit-on-browser-close=true`);
pass `--exit-on-browser-close=false` to keep the server running after the browser
disconnects and that line is omitted. If the browser could not be opened
automatically, an additional line names the failure and tells you to copy the link
yourself.

`seavault gui` opens that exact link for you (unless you pass `--no-open`). Opening
the link:

1. Redeems the launch secret in constant time.
2. Sets an `HttpOnly`, `SameSite=Strict` session cookie (`Secure` under https).
3. Redirects to `/?redeemed=1` so the secret leaves the address bar and does not
   linger in browser history or a `Referer` header.

The launch secret is a 256-bit random value and is multi-use for the lifetime of
the process, so you can open a second tab from the same printed link. It is never
placed in a `/dav/` URL or returned by any API response.

## Why bookmarks break by design

The launch secret is regenerated on every `seavault gui` start, so a bookmark to a
previous `?launch=...` link is stale after a restart. This is intentional: a stale
secret cannot mint a session, and there is nothing sensitive to leak from the
address bar. Bookmark the bare `http://127.0.0.1:8787/` if you like — it renders a
short static page telling you to run `seavault gui` and open the freshly printed
launch link.

If your browser is configured not to store cookies for `127.0.0.1`/`localhost`,
the redeemed page tells you so: allow cookies for that address, then re-open the
launch link.

## `--no-open` and recovering the launch link

The launch link is printed to the terminal on **every** `seavault gui` start, and
`seavault gui` opens it for you unless you pass `--no-open` (in which case you copy
the printed link into the browser yourself).

If you lose the terminal scrollback, the recovery is to **relaunch**
`seavault gui`: each start prints — and opens — a fresh launch link. Relaunching
rotates the launch secret, so any previous link stops working.

There is no `seavault gui url` subcommand today. A non-disruptive reprint of the
current link (without restarting the server or rotating the secret) is a planned
future item; until it ships, relaunching is the supported way to get a working
link back.

## Host allowlist

The GUI (and the `/dav/` endpoint mounted inside it) rejects any request whose
`Host` header is not a loopback address, `localhost`, or an explicit
`--allow-host NAME` value (repeatable), answering `403` with no DNS lookup. This
blocks DNS-rebinding pages and cross-site form posts from the browser. Off-loopback
deployments (`--insecure-bind`) must pass `--allow-host` for every name clients
connect as; an unspecified bind (`0.0.0.0`/`::`) is never added to the allowlist
automatically.
