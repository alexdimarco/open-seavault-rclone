# Design — Phase U3: certificates for the GUI and WebDAV, a guiding `tls setup` wizard, and the documentation

STATUS: pre-code design, awaiting the 10-lens review. Revision 1.

## 1. Goal and scope

Today `seavault gui` can serve HTTPS only with the self-signed pair it generates, `seavault
serve` (WebDAV) has no TLS at all, and both refuse a non-loopback bind because they would put
decrypted content on the wire in plaintext. U3 lets a user bring a real, CA-trusted certificate
— obtained with a DNS-01 challenge so the machine need not be internet-reachable — so the GUI
and WebDAV can be used from other devices on a LAN or VPN without trust prompts, and so Windows
can mount the vault at all (its WebDAV client refuses self-signed HTTPS). It ships with a wizard
that guides the whole procedure and documentation that names every step, challenge, and issue.

**A user who does nothing sees no change**: the GUI stays plain HTTP on loopback (its default
protocol is `http`; HTTPS with the self-signed floor stays opt-in), and WebDAV stays plaintext
on loopback. Certificates are added only through the precedence chain in §2.

**In scope:** `internal/tlsconfig` (resolve, validate, hot-reload); the TLS-aware bind guard;
`--tls-cert/--tls-key` on `serve` and `gui`; a shared `tls` app-config section with legacy
compatibility; `seavault tls setup` (interactive), `tls use`, `tls status`, `tls check`;
`docs/tls-and-certificates.md`; a "Network-exposed mode" section in SECURITY.md.
**Out of scope:** an embedded ACME client or DNS-provider integrations (the wizard guides
external tools; a managed `lego` runtime is a later phase); storing provider tokens; changing
auth (launch link, GUI login, WebDAV Basic auth) — exposure hardening is named as a residual.

## 2. The precedence chain (`internal/tlsconfig`)

```
type Source string   // "flags" | "config" | "legacy-gui" | "self-signed" | "none"
type Options struct { CertFlag, KeyFlag string; Cfg appconfig.Config; Purpose string /* gui|serve */; BindHost string }
type Resolved struct { TLS *tls.Config; Source Source; CertPath, KeyPath string; SelfSigned bool; Names []string; NotAfter time.Time; Warnings []string }
func Resolve(o Options) (*Resolved, error)
```
Order: `--tls-cert/--tls-key` flags → the shared `tls.certFile/keyFile` config section → the
legacy `gui.certFile/keyFile` fields (kept working; the wizard migrates them) → for `gui` when
`gui.protocol` is `https`, the existing self-signed pair (`appconfig.EnsureSelfSignedCertificate`,
unchanged) → `none`. `serve` has no self-signed floor: with nothing configured it is plaintext
loopback as today. Half a pair (cert without key or vice versa) is a typed error naming both flags.

`Validate(certPath, keyPath) (Info, error)` parses the PEM chain (leaf first), checks the private
key matches the leaf, reports SANs and `NotAfter`, warns on an expired or soon-to-expire leaf
(< 14 days), warns when the key file is group- or world-readable on Unix (names `chmod 600`),
and returns typed errors: `ErrKeyMismatch`, `ErrCertParse`, `ErrKeyParse`, `ErrHalfPair`.

**Hot-reload.** `Resolved.TLS.GetCertificate` reads from an `atomic.Value` holder. A reloader
goroutine stats both files every 30 s (portable: Windows has no SIGHUP) and, when either mtime
changes, runs `Validate` and swaps the pair in only if it validates; a failing pair keeps the
current one and logs one warning naming the failure. Startup refuses a key-mismatched pair
(`ErrKeyMismatch`) and serves an expired one with a warning (it still encrypts; clients warn).

## 3. The bind guard and the servers

`ensureLoopbackBind(addr, insecureBind, tlsOn, selfSigned bool)`: loopback and `localhost` are
always fine; a non-loopback or empty host is allowed when `tlsOn` (with a warning when
`selfSigned`: "clients will show a trust prompt; Windows WebDAV will refuse this certificate"
and, for an empty host, "listening on every interface"); without TLS it is refused exactly as
today unless `--insecure-bind`. **Plaintext never reaches a non-loopback address without that
explicit override (I-T1).**

`gui`: `Resolve(Purpose: gui)`; TLS is on when the source is anything but `none`; flags or a
configured `tls` section imply HTTPS regardless of `gui.protocol` (the wizard also sets
`gui.protocol=https` so the state is legible). `serve`: gains `--tls-cert`, `--tls-key`, and
`--tls` (use the configured section); TLS is on only when one of those is given. Both servers
log the source, the names, and the expiry at startup, and **warn when a certificate name is not
in the Host allowlist** (the DNS-rebinding guard stays authoritative; `allowedHostsForBind`
additionally admits names listed in `tls.allowHosts`).

App config gains `tls: { certFile, keyFile, allowHosts []string }`. `gui.certFile/keyFile` remain
readable for compatibility and are cleared by the wizard when it writes the shared section.

## 4. The wizard — `seavault tls setup`

Interactive, on the U1 `setup.Prompter` (numbered choices, Enter = default, hidden input never
needed — the wizard handles no secrets). Tool presence is a `Deps` seam (`LookPath`, `Run`).

1. **Who connects?** (a) Only this computer → explain that nothing is required, offer to turn on
   HTTPS-with-self-signed for the GUI, done. (b) Other devices on my network or VPN → continue.
2. **Route.** Detected tools are listed first with what they need:
   - **Tailscale** (binary found): the wizard reads the machine's tailnet name from `tailscale
     status --json`, explains that HTTPS certificates must be enabled in the tailnet admin
     console (a common dead end), and RUNS `tailscale cert --cert-file --key-file <name>` into
     the app's `tls/` directory. No secrets are involved, so running it is safe.
   - **Let's Encrypt via DNS-01** with `lego` or `certbot` (binary found or not): the wizard
     asks for the domain and the DNS provider from a curated table (provider → lego name → the
     environment variable(s) the token goes in → the least-privilege scope to grant, e.g. a
     Cloudflare token scoped to `Zone:DNS:Edit` on one zone), then PRINTS the exact command
     (it never runs a tool that needs a provider token or root) with the expected output paths,
     names the usual challenges (propagation delay, CAA records, rate limits), and waits: "press
     Enter when the files exist" — re-checking until they do or the user cancels.
   - **I already have certificate files** (corporate CA, another ACME client): paths, referenced
     in place (never copied), with the chain-order and intermediate note.
   - **Keep the self-signed certificate**: consequences stated (trust prompts on every device;
     Windows WebDAV refuses it), then the same persist step.
3. **Validate** the pair with `Validate`; show names, expiry, key permissions; on
   `ErrKeyMismatch` name the remedy and go back to step 2.
4. **Names and allowlist.** The SANs become the proposed `tls.allowHosts`; the user confirms or
   adds; the wizard explains the Host allowlist in one sentence.
5. **Where to listen.** Enumerate non-loopback interface addresses; the user picks one or "all
   interfaces"; the wizard states the exposure consequence and recommends a VPN/Tailscale over
   an open LAN. The bind address is NOT persisted (binding beyond loopback stays an explicit
   per-run choice); the wizard prints the exact `seavault gui --addr … --allow-host …` and
   `seavault serve --addr … --tls …` commands.
6. **Persist** `tls.*` and `gui.protocol=https` to the app config (legacy fields cleared).
7. **Renewal.** Prints the renewal recipe for the chosen route (`tailscale cert` re-run, `lego
   renew`, `certbot renew`) with a systemd-timer, cron, and Windows Task Scheduler snippet, and
   states that the app reloads a renewed pair within 30 s with no restart.
8. **Verify (optional, default yes).** Starts a short-lived probe listener on the chosen address
   with the resolved certificate and fetches `https://<name>:<port>/` using the system trust
   store, then reports "trusted by this machine" / "self-signed — trust prompt expected" /
   the exact failure (name mismatch, unknown authority, expired).

Non-interactive companions: `seavault tls use --cert P --key P [--allow-host N …]` (validate +
persist), `seavault tls status` (source, names, expiry, days left, allowlist, key perms —
never key material), `seavault tls check` (validate the configured pair; exit 1 on error),
`seavault tls reset` (return to self-signed / none). Every message that names a remedy names the
exact command.

## 5. Documentation — `docs/tls-and-certificates.md`

One guide, in the order a person meets the problem: **when you need this** (only for other
devices; the loopback default needs nothing); **the trust problem** (self-signed vs CA-issued,
what each client does); **why DNS-01** (no inbound port 80, machines behind NAT/VPN, wildcards);
**Route A Tailscale** step by step, including enabling HTTPS in the admin console and the 90-day
re-run; **Route B Let's Encrypt with lego** (creating a least-privilege provider token, the
provider table, the command, where files land, propagation delay, CAA, rate limits, renewal +
timer); **Route C certbot** (root, per-provider plugin packages); **Route D your own CA**
(chain order, intermediates, internal-PKI trust on each client); **Windows WebDAV specifics**
(refuses self-signed; Basic auth is only allowed over HTTPS by the WebClient service's default
`BasicAuthLevel`; the `FileSizeLimitInBytes` cap; how to map the drive); **macOS Finder and
Linux GIO/davfs2**; **the Host allowlist**; **binding beyond loopback** — the network-exposed
mode threat model, what becomes network-facing (launch link, GUI login, Basic auth), firewall the
port, prefer a VPN; **renewal and hot-reload**; a **troubleshooting table** (name mismatch,
unknown authority, missing intermediate, key mismatch, expired, port in use, firewall, DNS not
propagated, CAA blocks issuance, clock skew); **going back** (`tls reset`). SECURITY.md gains a
"Network-exposed mode" section stating the guarantees (I-T1..I-T6) and the residuals. README
links the guide from the GUI and WebDAV sections.

## 6. Security invariants (proven by §7 unless labeled)

- **I-T1** Plaintext is never served on a non-loopback address without an explicit
  `--insecure-bind`; the guard relaxes only for a TLS listener.
- **I-T2** Private key material is never logged, echoed, printed by `status`, or copied by the
  wizard; a group/world-readable key file produces a warning naming `chmod 600`.
- **I-T3** Hot-reload never swaps in an invalid pair; startup refuses a key-mismatched pair.
- **I-T4** Defaults are unchanged: GUI = HTTP on loopback with self-signed HTTPS opt-in; WebDAV =
  plaintext loopback. A user who does nothing sees identical behaviour.
- **I-T5** The wizard stores no DNS-provider token and runs only tools that need no secret
  (`tailscale cert`); everything else is printed for the user to run.
- **I-T6** Startup warns when a certificate name is absent from the Host allowlist; the
  rebinding guard remains authoritative and is not weakened.
- **I-T7** The network-exposed mode is documented in SECURITY.md with its residuals: the GUI
  login and WebDAV Basic auth become network-facing (rate limiting and lockout are a later
  phase), and clients that accept a self-signed prompt are MITM-able on first connect.
- **Conditional (labeled):** whether a client trusts the certificate depends on the route and
  on the client's own trust store; the probe in step 8 reports this machine's view only.

## 7. Test matrix (red-first; every row asserts; real listeners and real certificates)

| ID | Proves | How |
|---|---|---|
| P1 | §2 precedence | table over (flags, config, legacy, self-signed, none) × (gui, serve): each row asserts Source, paths, and whether TLS is on; half-pair → `ErrHalfPair` |
| P2 | §3 guard, I-T1 | table over host (loopback, LAN IP, empty) × (tls off, self-signed, CA) × insecureBind → allowed/refused and the exact warning; plaintext non-loopback without the override is refused in every row |
| R1 | §2 hot-reload, I-T3 | generate a test CA + leaf in the test; serve on an ephemeral TLS listener; a client with the CA pool connects; rewrite the pair → `GetCertificate` returns the new leaf within the poll; write a mismatched pair → the old leaf is still served and one warning is logged |
| R2 | `Validate`, I-T2 | table (mismatched key, expired, unparsable, world-readable key) → the typed error or warning per row |
| S1 | `serve` TLS | real listener with `--tls-cert/--tls-key`; a Go WebDAV client with the test CA performs PROPFIND over HTTPS; the same bind without TLS and without the override is refused |
| G1 | `gui` sources | flags win over config; the `tls` section is used; legacy `gui.certFile` still works; `gui.protocol` reported |
| W1–W4 | §4 routes | scripted prompter × tool seam: Tailscale present (cert command invoked with the expected args, files land in `tls/`), lego absent (command printed, file-wait loop re-checks), BYO paths (referenced, not copied), self-signed (consequences shown); each asserts the persisted config and that `Show()` output never contains key bytes |
| W5 | step 8 probe | probe listener + system-store fetch reports "self-signed — trust prompt expected" for the self-signed pair and "trusted" for a leaf from a CA injected into the test's root pool |
| U1 | `tls use/status/check/reset` | non-interactive persist/validate/report/reset; `status` output contains no key material; `check` exits 1 on mismatch |
| H1 | I-T6 | a certificate whose SAN is not in the allowlist produces the startup warning; adding it to `tls.allowHosts` clears it and the Host check admits it |
| D1 | §5 drift | every command and flag named in `docs/tls-and-certificates.md` exists in `--help`; the provider table in the doc equals the wizard's table |
| Z1 | I-T4 | the pre-U3 `gui`/`serve` tests are unmodified and green; the unfiltered race suite is green |

## 8. Failure and recovery

Wrong or missing files → the exact typed error and the remedy, nothing persisted. Renewal writes
a bad pair → the old certificate keeps serving and one warning names the file. The probe cannot
bind → the wizard says so and persists anyway (the probe is advisory). Tailscale HTTPS not
enabled → `tailscale cert` fails and the wizard prints the admin-console step. Everything is
reversible with `tls reset`.

## 9. Coexistence with U2

U3 builds in its own worktree (`feature/u3-tls`). It touches `cmd/seavault/main.go` (flags,
guard, the `tls` command) where U2's command registry also lands; U2 merges first and U3 rebases,
registering `tls` in that registry. No shared vault-format or webui-template changes.
