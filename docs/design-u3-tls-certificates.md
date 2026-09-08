# Design — Phase U3: certificates for the GUI and WebDAV, a guiding `tls setup` wizard, and the documentation

STATUS: BUILT + REVIEWED + FIX TRANCHE APPLIED — the 13 conditions of the pre-code review (`docs/review-u3-predesign.md`, GO_WITH_CONDITIONS; 58 judged / 44 refuted / 0 blockers) are applied below and in §10, and the §7 test matrix is green on `feature/u3-tls`. Shipped as v0.19 in four slices: T1 `internal/tlsconfig` resolve/validate/hot-reload (0d094a0), T2 the TLS-aware bind guard and gui/serve servers (1f17d30), T3 the `tls setup` wizard and command group (2f69ab9), and T4 the documentation (`docs/tls-and-certificates.md`, the SECURITY.md Network-exposed mode section, README links) plus the D1 drift guard and the final verification. **Reviewed** post-build: `docs/review-u3-adversarial.md` (9 confirmed / 0 refuted) and `docs/review-u3-friction.md` (HIGH_FRICTION_NOT_SHIPPABLE; 9 Type II, 16 Type III). **Fix tranche** (feature/u3-tls) closes every confirmed/Type II finding across four fixers, each addendum-mapped in the two review files: F-A reloader wiring + serving.json + `tls check` expiry + guard/warning/TOCTOU hardening (`a67fed0`, reloader teardown joined in `b6e9e30`), F-B launch/login-hint identity + settings precedence (`521fb14`), F-C wizard argv hygiene + EOF abort + listen defaults + renewal/UX honesty (`43716d0`), and F-D the documentation + review addenda + this STATUS + the D1 drift extension (docs+final, this commit). Open residuals (no design change): an opt-in `serve --tls` strict mode, and the DECRYPTED/prefer-VPN note at CLI startup for an allowed non-loopback TLS bind — both tracked in the friction addendum.

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

**Self-signed classification (C7):** `Resolve` sets `Resolved.SelfSigned` when the pair came from the
self-signed floor OR when `cfg.GUI.SelfSigned` is true for a legacy-tier pair OR when `Validate`
reports issuer == subject, so the existing HTTPS users whose self-signed pair was persisted into
the legacy fields still get the trust-prompt / Windows-WebDAV warning and `tls status` never calls
such a pair bring-your-own. **Startup (C13):** a CONFIGURED full pair whose key does not match the
leaf makes `gui`/`serve` return `ErrKeyMismatch` and bind nothing (a distinct path from the
half-pair error and from reload).

`Validate(certPath, keyPath) (Info, error)` parses the PEM chain (leaf first), checks the private
key matches the leaf, reports SANs and `NotAfter`, warns on an expired or soon-to-expire leaf
(< 14 days), warns when the key file is group- or world-readable on Unix (names `chmod 600`),
and returns typed errors: `ErrKeyMismatch`, `ErrCertParse`, `ErrKeyParse`, `ErrHalfPair`.

**Hot-reload.** `Resolved.TLS.GetCertificate` reads from an `atomic.Value` holder. A reloader
goroutine stats both files every 30 s (portable: Windows has no SIGHUP) and, when either mtime
changes, runs `Validate` and swaps the pair in only if it validates; a failing pair keeps the
current one and logs one warning naming the failure. Startup refuses a key-mismatched pair (`ErrKeyMismatch`) and serves an expired one with a warning
ONLY at cold start (it still encrypts; clients warn). **No live downgrade (C6):** the reloader
refuses to swap in a candidate whose leaf is expired or not yet valid while the currently-serving
leaf is still valid; it keeps the current pair and logs the warning. **Staleness surface (C11):**
on every successful load or reload, and once a day as a heartbeat, the reloader writes
`<appdata>/tls/serving.json` {fingerprint, names, notAfter, updatedAt} and logs a warning when the
serving leaf has fewer than 14 days left, so a silently disabled renewal timer is visible at
runtime; `tls status` reads that file and reports what the RUNNING listener serves ("running
listener: N days left", or "no running listener seen in the last 2 days") in addition to the
configured files.

## 3. The bind guard and the servers

`ensureLoopbackBind(addr, insecureBind, tlsOn, selfSigned bool)`: loopback and `localhost` are
always fine; a non-loopback or empty host is allowed when `tlsOn` (with a warning when
`selfSigned`: "clients will show a trust prompt; Windows WebDAV will refuse this certificate"
and, for an empty host, "listening on every interface"); without TLS it is refused exactly as
today unless `--insecure-bind`. **Plaintext never reaches a non-loopback address without that
explicit override (I-T1).**

`gui`: `Resolve(Purpose: gui)`; TLS is on when the source is anything but `none`; flags or a
configured `tls` section imply HTTPS regardless of `gui.protocol` (the wizard also sets
`gui.protocol=https` so the state is legible). **Resolved state drives the server (C2):** `cmdGUI`
sets the in-memory protocol to `https` (an explicit `TLSActive` passed to the webui server)
whenever `Resolve` returns a source other than `none`, BEFORE constructing the server and the
launch URL, so the launch scheme, the session cookie's `Secure` attribute, and the
`ListenAndServeTLS`-vs-plaintext decision all follow the resolved state, never the persisted
field; when the source is not `none` there is no plaintext code path at all (C10). **Launch link
identity (C1):** for a non-loopback bind the printed launch link and the login-page hint use the
first confirmed `--allow-host` name (or the certificate's first DNS SAN), not the bind address,
so the URL a person opens from another device is a name the certificate is valid for; loopback
binds keep `127.0.0.1`. `serve`: gains `--tls-cert`, `--tls-key`, and
`--tls` (use the configured section); TLS is on only when one of those is given. Both servers
log the source, the names, and the expiry at startup, and **warn when a certificate name is not
in the Host allowlist** (the DNS-rebinding guard stays authoritative; `allowedHostsForBind`
additionally admits names listed in `tls.allowHosts`).

App config gains `tls: { certFile, keyFile, allowHosts []string }`. `gui.certFile/keyFile` remain
readable for compatibility and are cleared by the wizard when it writes the shared section.
**In-app settings reconciliation (C3):** once `tls.*` is configured, the GUI's http/https toggle
is displayed as "managed by `seavault tls setup` — run `seavault tls reset` to change" and the
settings-save handler neither calls `EnsureSelfSignedCertificate` nor touches the legacy fields
(so a wizard-cleared `gui.certFile` is never resurrected); with `tls.*` empty the toggle behaves
exactly as today.

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
     Cloudflare token scoped to `Zone:DNS:Edit` on one zone), and, when the binary is NOT found, first prints how to install it (the `go install
     github.com/go-acme/lego/v4/cmd/lego@latest` line or the release-binary URL; for certbot the
     package and the root requirement) (C4), then PRINTS the exact command (it never runs a tool
     that needs a provider token or root, and it never prompts for a provider token) with the
     expected output paths,
     names the usual challenges (propagation delay, CAA records, rate limits), and waits: "press
     Enter when the files exist" — re-checking until they do or the user cancels, with the install and run guidance kept visible
     above the wait prompt (C4).
   - **I already have certificate files** (corporate CA, another ACME client): paths, referenced
     in place (never copied), with the chain-order and intermediate note.
   - **Keep the self-signed certificate**: consequences stated (trust prompts on every device;
     Windows WebDAV refuses it), then the same persist step.
3. **Validate** the pair with `Validate`; show names, expiry, key permissions; on
   `ErrKeyMismatch` name the remedy and go back to step 2.
4. **Names and allowlist.** The certificate's concrete DNS SANs become the proposed
   `tls.allowHosts`; **wildcard SANs are dropped from the proposal (C5)** and the wizard says so,
   because the Host allowlist matches exact names only (the rebinding guard stays authoritative and
   gains no wildcard matching); the user confirms or adds concrete names.
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
persist, then prints the same summary `tls status` prints — source, names, expiry, allowlist,
never key material — so the command that changes the configuration also reports it, C12), `seavault tls status` (source, names, expiry, days left, allowlist, key perms —
never key material), `seavault tls check` (validate the configured pair; exit 1 on error),
`seavault tls reset` (return to self-signed / none; prints the resulting status summary, C12). Every message that names a remedy names the
exact command.

## 5. Documentation — `docs/tls-and-certificates.md`

One guide, in the order a person meets the problem: **when you need this** (only for other
devices; the loopback default needs nothing); **the trust problem** (self-signed vs CA-issued,
what each client does); **why DNS-01** (no inbound port 80, machines behind NAT/VPN, wildcards);
**Route A Tailscale** step by step, including enabling HTTPS in the admin console and the 90-day
re-run; **Route B Let's Encrypt with lego** (installing lego without root (C4), creating a least-privilege provider token, the
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
- **I-T5** (proven by W6, C8) The wizard stores no DNS-provider token, never prompts for one, and runs
  only tools that need no secret (`tailscale cert`) — with lego AND certbot present on the machine
  the tool seam records a run ONLY for the `tailscale cert` argv; everything else is printed.
- **I-T6** Startup warns when a certificate name is absent from the Host allowlist; the
  rebinding guard remains authoritative and is not weakened.
- **I-T7** (proven by D1's SECURITY.md anchors, C9) The network-exposed mode is documented in SECURITY.md with its residuals: the GUI
  login and WebDAV Basic auth become network-facing (rate limiting and lockout are a later
  phase), and clients that accept a self-signed prompt are MITM-able on first connect.
- **Conditional (labeled):** whether a client trusts the certificate depends on the route and
  on the client's own trust store; the probe in step 8 reports this machine's view only.

## 7. Test matrix (red-first; every row asserts; real listeners and real certificates)

| ID | Proves | How |
|---|---|---|
| P1 | §2 precedence | table over (flags, config, legacy, self-signed, none) × (gui, serve): each row asserts Source, paths, and whether TLS is on; half-pair → `ErrHalfPair` |
| P2 | §3 guard, I-T1 | table over host (loopback, LAN IP, empty) × (tls off, self-signed, CA) × insecureBind → allowed/refused and the exact warning; plaintext non-loopback without the override is refused in every row |
| P3 | C13 startup refusal | a configured full-but-mismatched pair makes `gui` and `serve` startup return `ErrKeyMismatch` and bind nothing (distinct from half-pair and from reload) |
| R1 | §2 hot-reload, I-T3 | generate a test CA + leaf in the test; serve on an ephemeral TLS listener; a client with the CA pool connects; rewrite the pair → `GetCertificate` returns the new leaf within the poll; write a mismatched pair → the old leaf is still served and one warning is logged; write an EXPIRED or not-yet-valid renewed pair while the serving leaf is valid → the old leaf is still served (C6) |
| R2 | `Validate`, I-T2 | table (mismatched key, expired, unparsable, world-readable key) → the typed error or warning per row |
| R3 | C11 staleness | after load and after reload `tls/serving.json` carries the serving fingerprint and `notAfter`; a leaf with < 14 days left produces the daily warning; `tls status` reports the running-listener days-left from the file and \"no running listener seen\" when it is stale |
| S1 | `serve` TLS | real listener with `--tls-cert/--tls-key`; a Go WebDAV client with the test CA performs PROPFIND over HTTPS; the same bind without TLS and without the override is refused |
| G1 | `gui` sources, C1/C2 | flags win over config; the `tls` section is used; legacy `gui.certFile` still works; with `gui.protocol` still `http`, `--tls-cert/--tls-key` serves TLS (not plaintext), prints an `https://` launch link that uses the confirmed allow-host name for a non-loopback bind, and sets the session cookie `Secure` |
| G2 | C3 settings reconciliation | with `tls.*` configured, a settings save never calls the self-signed generator and never un-clears a wizard-cleared legacy field; the toggle is rendered as managed-by-tls-setup; with `tls.*` empty the toggle behaves as before |
| E1 | I-T1 end-to-end, C10 | bind `gui` and `serve` to a non-loopback interface address with a resolved TLS source: the first bytes on the wire are a TLS handshake and a plaintext HTTP GET is rejected |
| W1–W4 | §4 routes | scripted prompter × tool seam: Tailscale present (cert command invoked with the expected args, files land in `tls/`), lego absent (command printed, file-wait loop re-checks), BYO paths (referenced, not copied), self-signed (consequences shown); each asserts the persisted config and that `Show()` output never contains key bytes |
| W6 | I-T5, C8 | with lego AND certbot present in the tool seam, the wizard's DNS-01 route records a run ONLY for the `tailscale cert` argv when that route is chosen and NEVER for lego/certbot, and never prompts for a provider token |
| W5 | step 8 probe | probe listener + system-store fetch reports "self-signed — trust prompt expected" for the self-signed pair and "trusted" for a leaf from a CA injected into the test's root pool |
| U1 | `tls use/status/check/reset`, C12 | non-interactive persist/validate/report/reset; `use` and `reset` print the status summary; no output contains key material; `check` exits 1 on mismatch |
| H1 | I-T6, C5, C7 | a certificate whose SAN is not in the allowlist produces the startup warning; adding it to `tls.allowHosts` clears it and the Host check admits it; a wildcard SAN is never stored as an allowlist entry and the wizard says why; a legacy-tier pair that is self-signed resolves with `SelfSigned=true` and fires the trust-prompt warning |
| D1 | §5 drift, C4, C9 | every command and flag named in `docs/tls-and-certificates.md` exists in `--help`; the provider table equals the wizard's table; Route B lists the lego install step; SECURITY.md contains the "Network-exposed mode" section and the two residual sentences (login/Basic auth become network-facing; self-signed first-connect MITM) |
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

## 10. Revision 2 — how each review condition was applied

| Cond | Applied as |
|---|---|
| C1 | §3 launch link and login hint use the confirmed allow-host name for non-loopback binds; G1 |
| C2 | §3 resolved TLS state (`TLSActive`) drives scheme, cookie `Secure`, and the listener; G1 |
| C3 | §3 settings-save reconciliation: toggle shown as managed once `tls.*` is set; never resurrects legacy fields; G2 |
| C4 | §4 install guidance printed before the run command and kept visible in the wait loop; docs Route B; D1 |
| C5 | §4 wildcard SANs dropped from the allowlist proposal; exact-match guard unchanged; H1 |
| C6 | §2 reloader never downgrades a valid serving leaf to an expired/not-yet-valid candidate; R1 |
| C7 | §2 legacy self-signed pairs classified `SelfSigned=true` (GUI.SelfSigned or issuer==subject); H1 |
| C8 | I-T5 proven by W6 with lego/certbot present |
| C9 | I-T7 proven by D1's SECURITY.md anchors |
| C10 | E1 end-to-end: non-loopback + TLS source → TLS handshake on the wire, plaintext rejected |
| C11 | §2 `tls/serving.json` heartbeat + daily < 14-day warning; `tls status` reports the running listener; R3 |
| C12 | §4 `tls use` / `tls reset` print the status summary; U1 |
| C13 | §2 startup refusal of a configured mismatched pair; P3 |

