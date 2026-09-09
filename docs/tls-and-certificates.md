# TLS and certificates for the GUI and WebDAV

This guide covers serving the open-seavault-rclone GUI and the `seavault serve`
WebDAV endpoint over HTTPS with a certificate other devices trust, so you can open
the vault from a phone, a laptop, or a file manager on another machine without a
browser trust prompt — and so Windows can map the drive at all.

The guided way to do everything below is:

```bash
seavault tls setup
```

The wizard asks who needs to connect, picks a certificate route, validates the
pair, proposes the Host allowlist, prints the exact `seavault gui` / `seavault
serve` command for your chosen address, and prints the renewal recipe. This
document is the reference behind that wizard: every route, every challenge, and
every failure it can hit.

---

## When you need this

**If only this computer uses the vault, you need nothing here.** The GUI serves
plain HTTP on `127.0.0.1` and `seavault serve` is plaintext on loopback — traffic
never leaves the machine, so there is nothing to encrypt on the wire. A user who
does nothing sees no change.

You need a certificate only when **another device** connects to this machine's GUI
or WebDAV endpoint over the network (a LAN, or better, a VPN such as Tailscale or
WireGuard). At that point the bytes leave the machine and must be encrypted, and
the remote client must be able to *trust* the certificate — which a self-signed
certificate cannot deliver cleanly, and which Windows WebDAV refuses outright.

---

## The trust problem

TLS does two jobs: it encrypts the connection, and it lets the client verify it is
talking to the machine it meant to reach. Encryption is easy — any certificate
does it. Verification is the hard part, and it is where self-signed certificates
fall down.

- **Self-signed** (the GUI's built-in `https` floor): encrypts, but no certificate
  authority vouches for it. Browsers show a full-page "Your connection is not
  private" warning; you can click through, but that first click-through is exactly
  when a machine-in-the-middle can substitute its own certificate — *clients that
  accept a self-signed prompt are MITM-able on first connect*. Windows Explorer's
  WebDAV client refuses a self-signed certificate with no override at all. macOS
  Finder and Linux clients usually refuse or require manual trust. Use self-signed
  only for a quick loopback test.
- **CA-issued** (Let's Encrypt, your corporate CA, Tailscale's ACME): a certificate
  authority the client already trusts signs a certificate that names your host. The
  client verifies the name and the signature and connects with no prompt. This is
  what you want for any real cross-device use.

`seavault tls status` tells you which kind you have: a self-signed pair is reported
with `self-signed: yes — clients will show a trust prompt; Windows WebDAV will
refuse this certificate`.

---

## Why DNS-01

The usual way to get a Let's Encrypt certificate (the HTTP-01 challenge) requires
the CA to reach your machine on port 80 from the public internet. A vault server on
a home LAN, behind NAT, or reachable only over a VPN has no such inbound port — and
you should not open one just to get a certificate.

The **DNS-01** challenge proves you control the domain by creating a temporary TXT
record in its DNS zone instead of answering on a port. That means:

- the machine never needs to be internet-reachable — it only needs to talk *out* to
  your DNS provider's API;
- it works behind NAT, on a VPN-only host, or on a laptop that moves networks;
- it is the only challenge that can issue a **wildcard** certificate (`*.example.com`).

Every route below except Tailscale uses DNS-01.

---

## Which route fits your situation?

Pick the row that matches you, then jump to that route. The one situation with no
public route is a home LAN with no domain and no VPN: a public CA cannot issue for a
name only your LAN resolves, so either stand up a small local CA (Route D) and install
its root on every client, or adopt a VPN that brings its own trusted name (Route A).

| Your situation | Route |
|---|---|
| Your devices are already on a **Tailscale** tailnet | **Route A — Tailscale.** No domain, DNS token, or open port needed; the tailnet name is issued for you. |
| You control a **public domain** and its DNS, and want **no root** on this machine | **Route B — Let's Encrypt with `lego`** (DNS-01). |
| You control a public domain, **root is available**, and you prefer distro packaging | **Route C — certbot** (DNS-01). |
| Your organization runs an **internal / corporate CA** (or you already hold a cert) | **Route D — your own CA.** Point the app at the files; install the CA root on every client. |
| **Home LAN, no public domain, no VPN** | **Route D with a local CA:** mint a leaf from a small internal CA (`mkcert`, `step-ca`, or `openssl`) and install *that* CA's root on every device — or adopt **Route A (Tailscale)** to get a trusted name without running a CA. A public CA (Routes B/C) cannot issue for a LAN-only name. Whichever you choose, you must also make the name resolve on the LAN — see [Making the certificate name resolve on the LAN](#making-the-certificate-name-resolve-on-the-lan). |

---

## Route A — Tailscale

If your devices are already on a [Tailscale](https://tailscale.com) tailnet, this is
the least work: Tailscale runs its own ACME and issues a certificate for your
machine's MagicDNS name (`your-host.your-tailnet.ts.net`).

1. **Enable HTTPS certificates in the tailnet admin console** at
   <https://login.tailscale.com/admin/dns> (turn on "MagicDNS" and "HTTPS
   Certificates"). This is a common dead end — `tailscale cert` fails until it is
   turned on.
2. Run `seavault tls setup`, choose **Tailscale**. The wizard reads your MagicDNS
   name from `tailscale status --json` and runs, into the app's `tls/` directory:

   ```bash
   tailscale cert --cert-file <tls-dir>/<name>.crt --key-file <tls-dir>/<name>.key <name>
   ```

   No secret is involved, so the wizard runs this one for you.
3. Start the servers with the printed commands, for example:

   ```bash
   seavault gui   --addr 0.0.0.0:8787 --allow-host your-host.your-tailnet.ts.net
   seavault serve --addr 0.0.0.0:8765 --tls --allow-host your-host.your-tailnet.ts.net VAULT
   ```

**Renewal.** Tailscale certificates are short-lived (~90 days). Re-run `tailscale
cert <name>` before expiry; the app reloads the renewed pair within 30 seconds with
no restart. Schedule it **about monthly, not daily** — `tailscale cert` re-issues a
fresh certificate on every run (it is not an idempotent renew), so a daily job wastes
issuances and can hit rate limits. See [Renewal and hot-reload](#renewal-and-hot-reload)
for the per-tool cadence and timer snippets.

---

## Route B — Let's Encrypt with lego (no root)

[lego](https://go-acme.github.io/lego/) is a single static binary that speaks ACME
and DNS-01 and needs no root. This is the recommended route when you control a real
domain and its DNS.

### Install lego (without root)

lego is a Go program you can install into your own `~/go/bin` with no privileges:

```bash
go install github.com/go-acme/lego/v4/cmd/lego@latest
```

(or download a release binary from <https://github.com/go-acme/lego/releases>). The
wizard prints this line first when it does not find `lego` on your `PATH`, and keeps
it visible while it waits for the certificate files to appear.

### Create a least-privilege provider token

DNS-01 needs an API credential for your DNS provider so lego can write the challenge
TXT record. **Scope it to the one zone and to DNS edits only** — never a global or
account-wide key. Put the token in the environment variable(s) lego expects for your
provider; the wizard and this app **never ask for and never store** the token — you
export it and run lego yourself.

| Provider | lego `--dns` code | certbot plugin | Token environment variable(s) | Least-privilege scope |
|---|---|---|---|---|
| Cloudflare | `cloudflare` | `dns-cloudflare` | `CF_DNS_API_TOKEN` | an API token scoped to Zone:DNS:Edit on the single zone (a scoped API token, NOT the Global API Key) |
| AWS Route 53 | `route53` | `dns-route53` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | IAM credentials limited to route53:ChangeResourceRecordSets on the one hosted zone plus route53:GetChange and route53:ListHostedZonesByName |
| DigitalOcean | `digitalocean` | `dns-digitalocean` | `DO_AUTH_TOKEN` | a personal access token with write scope for DNS only |
| Google Cloud DNS | `gcloud` | `dns-google` | `GCE_PROJECT`, `GCE_SERVICE_ACCOUNT_FILE` | a service account with the DNS Administrator role scoped to the project, exported to a JSON key file |

For a provider not listed, see the [lego DNS provider
docs](https://go-acme.github.io/lego/dns/) for its `--dns` code and environment
variables. This table is the same one the wizard shows.

### Issue the certificate

Export the token(s), then run (the wizard prints this exact line with your domain
filled in):

```bash
export CF_DNS_API_TOKEN=...            # your provider's variable(s)
lego --path <tls-dir> --email you@example.com --dns cloudflare --domains vault.example.com run
```

The files land under `<tls-dir>/certificates/` as `<domain>.crt` and `<domain>.key`.
Point the app at them:

```bash
seavault tls use --cert <tls-dir>/certificates/vault.example.com.crt \
                 --key  <tls-dir>/certificates/vault.example.com.key \
                 --allow-host vault.example.com
```

### The usual challenges

- **Propagation delay.** After lego writes the TXT record, public DNS may take a few
  minutes to reflect it. If issuance fails immediately, wait and retry.
- **CAA records.** A `CAA` record on the domain that names a different CA will block
  Let's Encrypt from issuing. Add or fix the `CAA` record (or remove it) for the CA
  you use.
- **Rate limits.** Let's Encrypt caps certificates per domain per week. While testing,
  add `--server https://acme-staging-v02.api.letsencrypt.org/directory` to hit the
  staging CA (its certificates are untrusted but do not count against the limit).

### Renewal

Re-run lego with `renew` (same domain and the same environment variables):

```bash
lego --path <tls-dir> --email you@example.com --dns cloudflare --domains vault.example.com renew
```

Automate it with a timer — see [Renewal and hot-reload](#renewal-and-hot-reload).

---

## Route C — certbot

[certbot](https://certbot.eff.org) is the reference ACME client, packaged by most
distributions. It **needs root** to run and stores certificates under
`/etc/letsencrypt/`. Each DNS provider needs its own plugin package:

```bash
# Debian/Ubuntu
sudo apt install certbot python3-certbot-dns-cloudflare
# Fedora
sudo dnf install certbot certbot-dns-cloudflare
# macOS
brew install certbot
```

Issue (as root, with the provider token exported):

```bash
sudo -E certbot certonly --non-interactive --agree-tos --email you@example.com \
     --dns-cloudflare --domains vault.example.com
```

certbot writes `fullchain.pem` and `privkey.pem` under
`/etc/letsencrypt/live/vault.example.com/`. Reference them in place — do not copy
them into the vault:

```bash
seavault tls use --cert /etc/letsencrypt/live/vault.example.com/fullchain.pem \
                 --key  /etc/letsencrypt/live/vault.example.com/privkey.pem \
                 --allow-host vault.example.com
```

Renew all certbot certificates with `sudo certbot renew`. The certbot plugin column
in the [provider table](#create-a-least-privilege-provider-token) names the package
for each provider (`dns-cloudflare`, `dns-route53`, `dns-digitalocean`, `dns-google`).

---

## Route D — your own CA (corporate / internal PKI)

If your organization runs an internal certificate authority, or you already obtained
a certificate from another ACME client, point the app at the files directly:

```bash
seavault tls use --cert /path/to/leaf-and-chain.pem --key /path/to/private.key \
                 --allow-host vault.corp.example
```

- **Chain order matters.** The `--cert` PEM must be the **leaf certificate first**,
  followed by any **intermediate** certificates, in order up toward the root. Do not
  include the root itself. A missing intermediate is the most common cause of "unable
  to verify the first certificate" on clients that do not cache your intermediates.
- **Client trust.** Every device that connects must trust your CA's root. Install the
  internal root certificate into each client's system or browser trust store; without
  it, clients report "unknown authority" even though the chain is otherwise correct.
- The files are **referenced in place, never copied** — keep the private key readable
  only by you (`chmod 600`).

---

## Windows WebDAV specifics

Windows Explorer's built-in WebDAV client (the "Map network drive" / WebClient
service) is the strictest client and the main reason to get a real certificate:

- **It refuses self-signed certificates** with no override. Only a certificate
  chaining to a trusted root works.
- **Basic authentication is only allowed over HTTPS.** The WebClient service's
  default `BasicAuthLevel` (registry value
  `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\BasicAuthLevel`)
  permits Basic auth over SSL/TLS but not over plain HTTP. Serving `seavault serve`
  over a trusted HTTPS certificate is exactly what makes the Windows drive mount work
  without lowering that setting.
- **`FileSizeLimitInBytes`.** The WebClient caps a single transfer (default ~50 MB).
  Raise the registry value
  `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\FileSizeLimitInBytes`
  (max `4294967295`, ~4 GB) and restart the WebClient service for larger files.
- **Start the WebClient service first.** The Map-network-drive path goes through the
  WebClient (WebDAV Redirector) service, which is **Manual / trigger-started** by
  default. Start it, and set it to start automatically so the drive reconnects at
  logon:

  ```bat
  net start WebClient
  sc config WebClient start= auto
  ```

  (The space after `start=` is required by `sc`.) If `net start WebClient` reports the
  service is disabled, enable it in `services.msc` first.
- **Map the drive** once the certificate is trusted (chains to a root the machine
  trusts), the name resolves to the server (see
  [Making the certificate name resolve on the LAN](#making-the-certificate-name-resolve-on-the-lan)),
  and `seavault serve --tls` is running. Use the UNC form Microsoft documents for a
  WebDAV drive:

  ```bat
  net use Z: \\vault.example.com@SSL@8765\ /user:seavault *
  ```

  `@SSL` selects HTTPS; `@8765` is the port (omit `@port` for 443); the trailing `\`
  names the WebDAV root; the trailing `*` prompts for the password. The plain URL form
  (`net use Z: https://vault.example.com:8765/ /user:seavault *`) also works on current
  Windows builds, but the `\\host@SSL@port\` UNC form is the one Microsoft documents and
  is the most portable across builds. Connect by the **name**, never a bare IP — the
  certificate is valid for the name, and Windows WebDAV refuses a name mismatch.

---

## macOS Finder and Linux clients

- **macOS Finder**: Finder → Go → Connect to Server (`⌘K`), then
  `https://vault.example.com:8765/`, and enter the `seavault serve` user and
  password. Finder trusts any certificate in the system keychain; a self-signed pair
  prompts once and can be trusted manually, but a CA-issued certificate connects
  cleanly.
- **Linux GIO (GNOME Files / Nautilus)**: "Other Locations" → Connect to Server with
  `davs://vault.example.com:8765/`. GIO uses the system trust store (`ca-certificates`);
  install your internal root there for Route D.
- **Linux davfs2** (kernel mount): add the endpoint to `/etc/davfs2/secrets` and
  `mount -t davfs https://vault.example.com:8765/ /mnt/vault`. davfs2 verifies against
  `/etc/ssl/certs`; for an internal CA, add the root there.

In every case, connect to a **name the certificate is valid for** (a DNS SAN), not to
a bare IP address, or verification fails with a name mismatch.

---

## Making the certificate name resolve on the LAN

Your certificate is valid for a **name** (a DNS SAN such as `vault.example.com`), not
for a bare IP address. Every client must connect to that name, and the name must
resolve to the server's LAN IP **on each device**. **Connecting by bare IP cannot
work with a name-only certificate** — the client verifies the name against the SAN and
fails with `NET::ERR_CERT_COMMON_NAME_INVALID` (and Windows WebDAV refuses the mount
outright). A Tailscale certificate (Route A) needs none of this — MagicDNS resolves the
tailnet name on every device automatically. On a plain LAN with no internal DNS, make
the name resolve one of two ways:

**Option 1 — a router / local-DNS A record (best for more than a couple of devices).**
Add an `A` record mapping the certificate name to the server's LAN IP in your router's
DNS or your local DNS server (for example, a Pi-hole or `dnsmasq` entry
`address=/vault.example.com/192.168.1.10`). Every device on the LAN then resolves the
name with no per-device setup.

**Option 2 — a `hosts` file entry on each client (no DNS server needed).** Add one line
mapping the name to the server's LAN IP on every device that connects. Use the server's
actual LAN IP — the same address you pass to `seavault ... --addr` (find it with
`ip addr` on Linux, `ifconfig` on macOS, or `ipconfig` on Windows):

- **Windows** — edit `C:\Windows\System32\drivers\etc\hosts` in an **Administrator**
  editor, add the line, then flush the cache:

  ```text
  192.168.1.10   vault.example.com
  ```

  ```bat
  ipconfig /flushdns
  ```
- **macOS** — edit `/etc/hosts` with `sudo`, add the same line, then flush:

  ```bash
  sudo sh -c 'echo "192.168.1.10   vault.example.com" >> /etc/hosts'
  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
  ```
- **Linux** — edit `/etc/hosts` with `sudo` and add the same line (no flush needed on
  most distributions):

  ```bash
  sudo sh -c 'echo "192.168.1.10   vault.example.com" >> /etc/hosts'
  ```

Whichever option you use, keep typing the **name** in every URL and mount command; the
`hosts`/DNS entry only makes that name reach the server — it does not make a bare-IP
URL verify.

---

## Reaching a headless host from a phone

The GUI authenticates only through the rotating **launch link** —
`https://<name>:<port>/?launch=<secret>` — that `seavault gui` prints to the **host
terminal** on every start. There is no separate username/password login page for the
GUI, and the launch secret **rotates on every start**, so a phone needs that exact URL
from the start you will actually connect to. WebDAV (`seavault serve`) uses Basic auth
instead and needs no launch link — this note is about the GUI.

Get the current launch link onto the phone one of these ways:

- **As text.** Copy the whole `https://<name>:<port>/?launch=<secret>` line and send it
  to yourself (a message or email, or a clipboard-sharing tool), then open it in the
  phone's browser.
- **As a QR code.** Turn the URL into a QR code and scan it with the phone camera. On
  the host, `qrencode` prints a scannable code right in the terminal:

  ```bash
  qrencode -t ANSI "https://vault.example.com:8787/?launch=<secret>"
  ```

  (install `qrencode` from your package manager), or paste the URL into any offline QR
  generator. Because the secret rotates each launch, generate the code **after** the
  `seavault gui` start you will use; a stale link will not open.

For either path the name in the URL must resolve on the phone (see
[Making the certificate name resolve on the LAN](#making-the-certificate-name-resolve-on-the-lan);
on Tailscale, MagicDNS handles it) and the phone must trust the certificate — a
CA-issued one just works, while an internal-CA root (Route D) must be installed in the
phone's trust store first.

---

## The Host allowlist

open-seavault-rclone rejects any request whose `Host` header is not a loopback
address, `localhost`, or an explicitly allowed name — this is the DNS-rebinding
guard, and it stays authoritative. When you serve to other devices under a real
name, that name must be on the allowlist, or every request is refused with `403`.

- The wizard proposes the certificate's concrete DNS SANs as the allowlist and you
  confirm them; `tls use --allow-host NAME` (repeatable) sets them non-interactively;
  they are stored in the app config as `tls.allowHosts`.
- **Exact names only — no wildcards.** The allowlist matches host names exactly. A
  wildcard SAN like `*.corp.example` is **dropped** from the proposal (the wizard
  says so): a wildcard can never match a concrete `Host` header, so add the concrete
  names you will actually use (`vault.corp.example`) instead.
- At startup each server logs its certificate's names and **warns when a certificate
  name is not in the Host allowlist** — add it with `--allow-host` or `tls.allowHosts`.
- Passing `--allow-host` on `seavault gui` / `seavault serve` adds a name for that run
  in addition to the configured `tls.allowHosts`.

---

## Binding beyond loopback — the network-exposed mode

By default both servers bind `127.0.0.1` and refuse a non-loopback address, because
that would put decrypted content on the wire. Binding to a LAN address or `0.0.0.0`
is allowed **only** when TLS is configured (a resolved certificate) — plaintext never
reaches a non-loopback address without the explicit `--insecure-bind` override. Even
so, exposing the listener changes the threat model. Understand what becomes
network-facing before you do it:

- **What is exposed.** The GUI's launch-link login and the WebDAV **Basic auth**
  credential become reachable from every device that can route to the bind address.
  Anyone who can reach the port can attempt the login. Since v0.21 an
  [authentication rate limiter and lockout](#authentication-rate-limiting-and-lockout)
  stands in front of every credential surface — on by default — but a firewall and a
  VPN remain the primary controls; see [SECURITY.md](../SECURITY.md).
- **A direct non-loopback bind exposes the login to the whole network segment.**
  Binding to a LAN address or `0.0.0.0` puts the GUI launch-link login and the WebDAV
  Basic-auth credential in front of **every host that can route to that address**. The
  built-in rate limiter throttles and locks repeated failures, but it is per-process
  hygiene, not a substitute for network controls. Treat a bind to an open LAN,
  and especially to `0.0.0.0` (every interface, including docker/libvirt bridges), as
  publishing the login to everything on that network. **Prefer a VPN (Tailscale or
  WireGuard):** it keeps the listener off the untrusted LAN entirely and brings a
  trusted name with it. If you must bind an open LAN address, bind the single most
  specific interface and firewall the port to the exact subnet even then.
- **Bind to as little as possible.** Prefer a single interface address
  (`--addr 192.168.1.10:8787`) over `0.0.0.0` (every interface). Binding to every
  interface is logged as `listening on every interface`.
- **Firewall the port to the LAN subnet.** Restrict the GUI/WebDAV port
  (`8787`/`8765` here — use your own) to the exact devices or subnet that need it, and
  deny it elsewhere. Concrete examples, scoped to `192.168.1.0/24`:

  ```bash
  # Linux — ufw
  sudo ufw allow from 192.168.1.0/24 to any port 8765 proto tcp
  sudo ufw allow from 192.168.1.0/24 to any port 8787 proto tcp

  # Linux — firewalld
  sudo firewall-cmd --permanent --zone=internal --add-source=192.168.1.0/24
  sudo firewall-cmd --permanent --zone=internal --add-port=8765/tcp
  sudo firewall-cmd --permanent --zone=internal --add-port=8787/tcp
  sudo firewall-cmd --reload
  ```

  ```bat
  REM Windows — netsh advfirewall, scoped to the LAN subnet
  netsh advfirewall firewall add rule name="SeaVault WebDAV" dir=in action=allow protocol=TCP localport=8765 remoteip=192.168.1.0/24
  netsh advfirewall firewall add rule name="SeaVault GUI"    dir=in action=allow protocol=TCP localport=8787 remoteip=192.168.1.0/24
  ```

  On **macOS** there is no simple per-port UI; use the packet filter `pf`. Add a rule
  to `/etc/pf.conf` such as `block in proto tcp to any port 8765` followed by
  `pass in proto tcp from 192.168.1.0/24 to any port 8765`, then load it with
  `sudo pfctl -f /etc/pf.conf -e`. The simpler answer on macOS is to prefer a VPN so
  the port is never on the open LAN in the first place.
- **Prefer a VPN over an open LAN.** Tailscale or WireGuard gives you a private
  network and a trusted name, so the listener is never exposed to an untrusted LAN or
  the internet.

See the "Network-exposed mode" section of [SECURITY.md](../SECURITY.md) for the exact
guarantees (I-T1..I-T6) and residuals.

### Authentication rate limiting and lockout

Since v0.21 every credential-checking surface — WebDAV **Basic** auth, the GUI
**login** form, launch-link redemption, the vault-password **open**, and
recovery-phrase **redeem** — is behind a per-process rate limiter and lockout. It is
**on by default on every bind, including loopback**, and never changes how a credential
is verified; it only bounds how often a wrong one may be tried. The peer is the TCP
source address (an IPv6 peer is keyed by its /64), never a proxy header. The full
guarantees (I-R1…I-R10) and residuals are in the
"[Authentication rate limiting and lockout](../SECURITY.md#authentication-rate-limiting-and-lockout)"
section of SECURITY.md.

While enabled, the non-loopback startup line and `seavault tls status` read
`auth limits: on (5 failures → 30s…15m)`. Defaults: 5 consecutive failures within a
15-minute window lock a peer for 30 s, then doubling to a 15-minute cap; a per-account
ceiling of 20 catches source-rotating attacks; a 250 ms throttle delays every failed
attempt. What each surface does when a key is locked:

| Surface | On repeated failures |
|---|---|
| WebDAV **Basic** | after the throttle, `401` as before, until the lock — then `429 Too Many Requests` + `Retry-After: <seconds>`, and the `WWW-Authenticate` challenge is withheld so native clients stop re-prompting. The `429` **body** carries the same human wait (e.g. "try again in 30 seconds") for a client that ignores the header |
| GUI **login** (present only when a GUI login password is set — the default launch-link install has no login surface to reproduce) | the HTML login form is re-rendered with `429`, an **honest** countdown ("try again in 30 seconds" when the lock is under a minute, agreeing with `Retry-After`; whole minutes above), and a `Retry-After` header |
| vault **open** (`/api/open`) | `429` with a JSON body `{error, retryAfterSeconds}` — the `error` states the same honest wait — and a `Retry-After` header (this also bounds the 64 MiB-per-attempt KDF cost) |
| launch link, recovery **redeem** | **throttled but never locked**: a wrong guess is delayed by the throttle, then answered as before, and the correct launch secret or recovery phrase always redeems immediately — the last-resort recovery path is never locked out. A wrong or stale `?launch=` shows the **styled no-session page** with a throttle note (a short delay, never a lockout) and the current launch-link hint, not a bare `403`; a fumbled recovery phrase returns the vault's decrypt error with a `retryAfterSeconds` throttle hint |

**One household shares one bucket.** The peer key is the source address, and an IPv6 peer
is keyed by its whole **/64** — the block an ISP hands a single home router — so a home NAT
or an IPv6 /64 all share **one** lockout bucket. If one device on the network loops a wrong
WebDAV password past the threshold, everyone behind that address gets `429` until the lock
expires, even a device that typed the right password. That is the deliberate anti-rotation
control; the trade-off and its residuals are in SECURITY.md.

**Use a non-default `--user` on an exposed `serve`.** The per-account ceiling that stops
source-rotating attacks is also a lever: an attacker who can reach the port can hold one
account locked **indefinitely** by re-tripping the ceiling as each lock expires (the cap
bounds one lock, not the aggregate). On `serve` the default WebDAV username is the public,
documented `seavault`, so no guessing is needed — **pass `--user NAME` with a non-default
name** for any non-loopback bind (`serve` prints a startup warning if you do not). SECURITY.md
carries the full reasoning.

**Freeing a lock without disarming everything.** A lock clears three ways: **wait** (it
unlocks purely by time; the correct credential then works with no restart), **restart** the
server (clears all in-memory locks while keeping limits on), or **clear one lock** —
`POST /api/auth-limits/clear` with a `{peer}` or `{account}` on the GUI (session+CSRF) or
`serve` (Basic auth) releases exactly that peer or account while the limiter stays on for
everyone else. A logged-in GUI viewer also sees their own lock and a live countdown, and Open
is disabled until it clears. The residual: a lone, fully-locked-out **remote** operator has
only "wait" — the clear-lock endpoint sits behind the auth that is locked — so keep a loopback
or VPN path to the host for recovery.

**Turning it off (an incident only).** `--auth-limit off` on `seavault gui` and
`seavault serve`, or `auth.limits.enabled=false` in the app config, disables the
limiter. It is never the default and is deliberately loud: startup prints a warning
naming the flag, and because a config-file disable survives restarts, the disable is
dated (`auth.limits.disabledSince`) and the server **re-warns** about once an hour while
it runs. `seavault tls status` and the GUI settings page then read
`auth limits: OFF since <date> — re-enable with --auth-limit on or auth.limits.enabled=true`,
so a headless daemon left unprotected after an incident cannot hide. Re-enable with
`--auth-limit on` (or by dropping `auth.limits.enabled=false`): over a persisted
disable, `--auth-limit on` runs the limiter **and persists** `enabled=true`, clearing the
`disabledSince` stamp, so every readout (the startup exposure line, `seavault tls status`,
the GUI settings page and banner) reads `on` and a later **flagless** restart — a plain
`seavault serve` in a systemd unit — comes back **protected**, not silently unprotected.

**Tuning.** The knobs live in the app config under `auth.limits`
(`failuresBeforeLock`, `accountFailuresBeforeLock`, `window`, `lockStart`, `lockMax`,
`failureDelay`, `maxKeys`); a zero or invalid value falls back to the default, so a
threshold can never be misconfigured to 0 (which would lock every key on its first
attempt).

---

## Renewal and hot-reload

The app watches the configured certificate and key files and reloads a renewed pair
**within 30 seconds, with no restart**. It never swaps in an invalid pair, and it
never downgrades a valid live certificate to an expired or not-yet-valid renewal.

**Cadence — daily for lego/certbot, monthly for Tailscale.** A `lego renew` /
`certbot renew` is **idempotent**: a scheduled run only acts when the certificate is
near expiry and is otherwise a quick no-op, so running it **daily** is both safe and
recommended (it never re-issues early and catches the renewal window without you
watching). `tailscale cert <name>`, by contrast, **re-issues a fresh certificate on
every run** — it is *not* an idempotent renew — so a daily job would re-issue every day
and can hit issuance rate limits; schedule Tailscale **about monthly** (a ~90-day
certificate has ample margin) or gate the re-run on days-left. The `seavault tls setup`
wizard prints the concrete renew command for your route; drop it into a scheduler at
the cadence for that route:

- **systemd timer** — put the renew command in a `.service` unit and pair it with a
  `.timer`: `OnCalendar=daily` for lego/certbot, `OnCalendar=monthly` for Tailscale
  (`Persistent=true` in both).
- **cron** — `17 3 * * * <renew command>` runs lego/certbot daily at 03:17; use
  `0 3 1 * * <renew command>` (03:00 on the 1st) for a monthly Tailscale re-issue.
- **Windows Task Scheduler** —
  `schtasks /Create /SC DAILY /TN SeaVaultCertRenew /TR "<renew command>" /ST 03:17`
  for lego/certbot; use `/SC MONTHLY` for Tailscale.

**Staleness warning.** A renewal timer that silently stops changes no file, so the
app cannot see it stop by watching mtimes. To make that visible, the running server
writes what it is actually serving to `<config-dir>/tls/serving.json` on every load
and once a day, and **logs a warning when the serving certificate has fewer than 14
days left**. Check the running listener at any time:

```bash
seavault tls status
```

`tls status` reports the configured source, names, expiry and days-left, the
allowlist, key-file permissions, and a **running listener** line read from
`serving.json` — `running listener: N days left`, or `no running listener seen in the
last 2 days` when the file is stale (a listener that stopped, or a renewal that never
took effect). For an unattended `seavault serve --tls` daemon with no operator
watching the logs, monitor the certificate's `NotAfter` externally as well.

`seavault tls check` validates the configured pair and **exits non-zero on any error —
including an expired or not-yet-valid certificate.** An out-of-window leaf is a
health-check failure even though the pair is otherwise well-formed: `tls check` prints
the expiry (or the not-before time) and the certificate path and returns a non-zero
status, so it is safe to wire into a health check that must catch a lapsed renewal — the
single most important failure, since an expired certificate makes the Windows mount
refuse. With **nothing configured** it reports so and exits 0 (there is nothing to
validate). It never prints key material.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `NET::ERR_CERT_COMMON_NAME_INVALID` / name mismatch | connecting to an IP or a name that is not a SAN on the certificate | connect using a DNS name the certificate lists; check `tls status` names |
| "unknown authority" / "self-signed certificate" | the client does not trust the issuing CA | use a CA-issued certificate (Routes A–C) or install your internal root (Route D) into the client's trust store |
| "unable to verify the first certificate" / missing intermediate | the `--cert` PEM omits an intermediate | rebuild the PEM leaf-first with the full intermediate chain (Route D) |
| server refuses to start: `ErrKeyMismatch` | the private key does not match the leaf certificate | supply the key that pairs with this certificate; `tls check` names the mismatch |
| server refuses to start: cert without key (or key without cert) | only half the pair was given | pass both `--tls-cert` and `--tls-key` (or `tls.certFile` and `tls.keyFile`) |
| browser warns the certificate is expired | the certificate is past `NotAfter` | renew it (the app reloads within 30 s); watch for the `< 14 days left` warning next time |
| "certificate is not valid until …" / not-yet-valid | the client's clock is wrong, or the certificate starts in the future | fix system clock skew on client and server |
| `bind: address already in use` / port in use | another process (or a second `seavault`) holds the port | stop the other listener or choose another `--addr` port |
| connects locally but not from another device | a firewall blocks the port | open the GUI/WebDAV port to the intended subnet only |
| DNS-01 issuance fails right after writing the record | DNS has not propagated | wait a few minutes and retry `lego`/`certbot` |
| DNS-01 issuance rejected by the CA | a `CAA` record blocks this CA | add/fix the domain's `CAA` record for the CA you use |
| every request returns `403` despite an allowlist entry | a wildcard SAN was stored, or the connecting name is not allowed | add the exact concrete name to `tls.allowHosts` / `--allow-host` (wildcards never match) |

---

## Going back

To return to the default — HTTP on loopback, no configured certificate:

```bash
seavault tls reset
```

This clears the shared `tls` section and the legacy fields, sets the GUI back to
`http`, and prints the resulting status summary. The GUI returns to plain HTTP on
loopback and `seavault serve` returns to plaintext loopback — a user who does nothing
sees no change.
