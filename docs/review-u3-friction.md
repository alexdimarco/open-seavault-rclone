<!--
Friction review — Phase U3 TLS certificates (feature/u3-tls), BUILT feature walk.
How walked: the REAL binary (go build -o /tmp/sv-u3/seavault ./cmd/seavault) from the
worktree /home/alex/gitprojects/open-seavault-rclone-u3 @ feature/u3-tls. All state
isolated under fresh SEAVAULT_APP_HOME temp dirs with --no-keychain; the real user home,
keychain, DNS/ACME/Tailscale accounts never touched. Tool-driven paths used argv-recording
SHIM scripts (tailscale/lego/certbot) on a temp PATH; certs were self-minted test CAs +
leaves (openssl / small Go minter), incl. wildcard, expired, not-yet-valid, mismatched.
Non-loopback tests bound the machine's real interfaces (192.168.1.2 eno1, 10.200.0.2 wg-sa)
and phone/LAN reach was emulated with curl --cacert + --resolve. Every process killed by PID.
Three actors walked 6 cells each (Tailscale home-phone user; no-root Cloudflare self-hoster;
Windows LAN network-drive user). One placeholder "test" actor cell was discarded.
The report agent independently CONFIRMED the two decisive code defects by grep/source read
(reloader wiring, tls check expiry) — see notes on TLS-1/TLS-3.
-->

# Phase U3 TLS — Friction Review

## Coverage

- **Cells walked:** 18 (3 actors x 6; one placeholder "test" cell discarded)
- **Functioning:** 13 `yes` / 4 `partial` / 1 `no`
- **Findings:** many Type I control-confirmations; **9 distinct Type II** (13 raw, with the reloader/serving.json defect corroborated independently by all three actors); **16 actionable Type III**, plus ~5 noted-for-record (capture artifacts, docs-only Windows claims that could not be exercised from Linux).

## Verdict: HIGH_FRICTION_NOT_SHIPPABLE

Triggered by the rule *"any Type II drives a cell to functions=no, or a golden path is high-friction."* Both conditions are met:

- **Cell `no`:** the no-root Cloudflare actor's renewal cell (c6) is `functions=no` — a renewed cert on disk is never picked up.
- **Both golden paths high-friction:** the Tailscale route and the bring-your-own/DNS-01 route each sell a renewal + monitoring story the shipped binary does not deliver.

### The Type II items that drive the verdict

1. **TLS-1 — cert hot-reload is never started (CONFIRMED in source).** The wizard, `docs/tls-and-certificates.md`, and `SECURITY.md` I-T3 all promise *"reloads a renewed pair within 30 seconds, with no restart."* `internal/tlsconfig/reload.go` implements it, but `Reloader(...)` is constructed **only** in `reload_test.go`; `cmdServe` (main.go:1696) and `cmdGUI` (main.go:1866) never call `resolved.Reloader(...).Run(ctx)`. `GetCertificate` reads a holder seeded once at `Resolve`, so a renewed pair is served only after a **manual restart**, and an expired leaf keeps serving. R1/R3 pass because they drive the Reloader in isolation; nothing exercises the serve/gui wiring, so §7 is green while the runtime capability is absent. This defeats every scheduler recipe the feature prints.
2. **TLS-2 — `serving.json` is never written at runtime, so the C11 staleness surface is inert.** Because the reloader never runs, `tls status` reports `running listener: none seen` **while a listener is actively serving TLS** (observed live), and the `< 14-day` heartbeat warning never fires. The operator's advertised way to confirm a scheduled renewal took effect does not work.
3. **TLS-3 — `tls check` exits 0 on an expired / not-yet-valid cert (CONFIRMED in source).** `cmdTLSCheck` (main.go:2007-2010) prints `OK` and returns nil whenever `Validate` succeeds, and `Validate` never compares `NotAfter`. The Renewal docs say *"`tls check` … exits non-zero on any error — use it in a health check."* An operator who wires it into a health check will not catch the single most important failure (an expired cert refusing the Windows mount).
4. **TLS-4 — the setup wizard livelocks on EOF / closed stdin** (244,971 route-menu reprints in 6s, 100% CPU, exit 124). The outer route loop is unbounded and the stdin prompter swallows EOF as "accept default", so a piped/exhausted stdin or Ctrl-D never terminates.
5. **TLS-5 — the wizard's listen-step default `:8787` is every-interface**, the least-safe choice, contradicting its own next line and `SECURITY.md`; pressing Enter binds decrypted content on all 16 interfaces (incl. docker/libvirt bridges).
6. **TLS-9 — Windows pure-LAN name-resolution dead end.** The guide forbids bare-IP connect (proven: curl to `https://192.168.1.2` fails on SAN mismatch) and the map-drive command uses a DNS name, but nowhere explains how a LAN with no internal DNS makes that name resolve (hosts file / router A record). The no-domain/no-VPN Windows actor is stranded at the mapping step (cell c1 -> `partial`).

The security **controls themselves all held** (Type I, keep as-is): exact-match allowlist with wildcard-drop (DNS-rebinding guard, C5/I-T6), plaintext-non-loopback refusal relaxed only for a TLS listener (I-T1), validate-before-persist, never-print-key-material (I-T2), launch-link identity uses the cert name not the bind IP (C1), and the admin-console dead-end pre-warning. The friction is in the *delivery, defaults, and post-issuance lifecycle*, not the crypto path.

## Findings table

| Cell | functions | Friction finding | Type | Fix / backlog |
|---|---|---|---|---|
| A2-c6 (also A1-c1/c6, A3-c6) | no | Reloader never started; 30s/no-restart hot-reload promised but renewed certs never served until manual restart (CONFIRMED) | II | Start `go resolved.Reloader(...).Run(ctx)` in cmdServe & cmdGUI when Source!=none; add integration test; until shipped, correct wizard/docs/SECURITY promises |
| A1-c6 (also A2/A3-c6) | partial | `serving.json` never written at runtime -> `tls status` "none seen" while serving; C11 heartbeat inert | II | Same wiring fix; reloader writes serving.json on start + daily heartbeat |
| A3-c6 | partial | `tls check` exits 0 on expired/not-yet-valid cert; contradicts "exits non-zero on any error" (CONFIRMED) | II | Treat out-of-window leaf as an error in Validate/check (or add --strict); fix docs wording |
| A2-c1 | yes | Wizard livelocks on EOF/closed stdin (unbounded route loop, EOF swallowed as default) | II | Propagate io.EOF out of Select/Text to abort RunTLSWizard loop; or bound the outer loop |
| A1-c4 | partial | Listen-step default `:8787` = every interface, the least-safe option | II | Default to the single most-specific interface addr; every-interface as explicit opt-in |
| A1-c4 | partial | 16 non-loopback addresses dumped as a bare list, no interface names | II | Filter virtual/container/link-local; annotate interface names; flag Tailscale + default-route |
| A1-c6 | partial | Scheduler snippets print bare `<renew command>`/`<name>` though wizard holds concrete values | II | Substitute the concrete renew command and name into each snippet |
| A2-c6 | no | Unattended headless daemon gets NO runtime expiry signal; no strict mode | II | Wire heartbeat; reconsider opt-in strict mode for serve --tls; document the residual |
| A3-c1 | partial | Windows LAN: name must be used but no how-to for making the SAN resolve without internal DNS | II | Add "Make the name resolve on the LAN" subsection (hosts file / router A record) |
| A1-c2 | yes | Raw `exit status 1` Go-ism printed above the tool's useful stderr | III | Drop the prefix; lead with tool stderr + named remedy |
| A1-c2 | yes | Failure remedy says "re-run tls setup" but wizard already sits at the route menu | III | Reword: "fix the console, then choose Tailscale again from this menu (or re-run)" |
| A1-c3 | yes | Allowlist prompt jargon ("rebinding guard"); 403 consequence not stated at decision point | III | Add "names not on this list are refused with 403; include every name a device will type" |
| A1-c4 | partial | Printed serve command derives its port only from ':8787'; any other gui port -> serve reuses same host:port -> address-in-use | III | Always offset the serve port from the gui port (or prompt separately) |
| A1-c5 | yes | Rotating launch link printed only to host terminal; no guidance for a phone reaching a headless host | III | Add a "reaching a headless host from a phone" note to the guide + step-5 output |
| A1-c6 | partial | `tailscale cert` re-issues unconditionally; a daily cron re-issues every day (waste/limits) | III | Schedule less often or gate on expiry; note tailscale cert is not an idempotent renew |
| A2-c2 | yes | Wait loop re-prints the entire guidance block on every poll | III | After first print, show a compact "still waiting; command/paths above" one-liner |
| A2-c2 | yes | File check at top of next iteration -> spurious "still waiting" even when files exist | III | Re-check fileExists(cert)&&fileExists(key) immediately after Enter, before "still waiting" |
| A2-c3 | yes | BYO route prints the self-signed renewal recipe ("re-run tls setup") — wrong for a CA/ACME cert | III | Give routeBYO its own showRenewal case: renew via your own CA/ACME and replace files in place |
| A3-c1 | partial | No decision aid mapping actor situation -> route; no-domain LAN user can conclude nothing works | III | Add a "which route am I?" pointer routing no-domain/no-VPN LAN to Route D + client-root install |
| A3-c2 | yes | `net use` uses atypical trailing-backslash https:// form (UNC `\\host@SSL@port\` is the documented form) | III | Show the UNC form or verify the https:// form on supported Windows builds |
| A3-c3 | yes | Self-signed names render duplicate `127.0.0.1` | III | De-duplicate SANs before printing the names line |
| A3-c3 | yes | keep-self-signed on the "other devices" branch persists https + renewal but cannot mount a Windows drive | III | Add one redirect line: "won't let Windows map a drive; re-run and pick Tailscale/your own CA" |
| A3-c4 | yes | Bind-refusal message steers to `--insecure-bind` even when a cert is configured | III | When a cert is configured, suggest `--tls` first; --insecure-bind only as last resort |
| A3-c5 | yes | "Firewall the port" is generic, no concrete command | III | Add per-OS example (Windows netsh scoped to LAN subnet; ufw/nftables) |
| A3-c5 | yes | DECRYPTED-content / prefer-VPN framing only in the wizard, not at serve/gui CLI startup | III | Emit the DECRYPTED-on-the-wire / prefer-VPN note at serve & gui startup for any non-loopback bind |

## Bottom line

The TLS crypto path and its security controls work and are well-surfaced. What is **not shippable** is the post-issuance lifecycle the feature advertises: hot-reload, `serving.json`/`tls status` monitoring, and `tls check` health-checking are all promised in the wizard and docs but are either **unwired** (reloader never started — one root cause behind three of the driving Type II items) or **wrong** (`tls check` passes expired certs). Fixing the reloader wiring (start it from cmdServe/cmdGUI, plus an integration test) and the `tls check` expiry gate clears the two golden paths; the EOF livelock and the every-interface default should ride along. The 16 Type III items are documentation/UX backlog once the Type II blockers land.

---

## Fix-tranche addendum (feature/u3-tls)

The two golden paths are cleared: the reloader is wired into `cmdServe`/`cmdGUI`,
`serving.json` is written at runtime, and `tls check` fails an out-of-window leaf.
The verdict blockers (Type II) are resolved in code; the Type III backlog is landed
in the wizard (F-C) and the guide (F-D). Each behavioural fix shipped prove-fail ->
prove-pass with real listeners/certs; the mock seam is limited to the tool boundary
and closed stdin.

### Type II

| Cell(s) | finding | fix commit(s) | tranche |
|---|---|---|---|
| A2-c6 / A1-c1 / A1-c6 / A3-c6 | Reloader never started; 30s/no-restart hot-reload never delivered | `a67fed0` (start `resolved.Reloader(...).Run(ctx)` in both commands + end-to-end integration test); `b6e9e30` (teardown joined) | F-A |
| A1-c6 / A2-c6 / A3-c6 | `serving.json` never written -> `tls status` "none seen" while serving; heartbeat inert | `a67fed0` (reloader writes serving.json on load + daily heartbeat; the < 14-day warning fires in-process) | F-A |
| A3-c6 | `tls check` exits 0 on an expired / not-yet-valid cert | `a67fed0` (out-of-window leaf is a non-zero exit; names path + time, never key material) | F-A |
| A2-c1 | wizard livelocks on EOF / closed stdin | `43716d0` (Select/Text/Confirm propagate `io.EOF`; the route loop is bounded and aborts with a clear message) | F-C |
| A1-c4 | listen-step default `:8787` is every-interface | `43716d0` (defaults to the single most-specific interface addr — the Tailscale addr when detected) | F-C |
| A1-c4 | 16 non-loopback addresses dumped as a bare list | `43716d0` (filters docker/bridge/virtual/link-local; annotates interface names; flags Tailscale) | F-C |
| A1-c6 | scheduler snippets print bare `<renew command>`/`<name>` | `43716d0` (concrete renew command + name substituted into every snippet) | F-C |
| A2-c6 | unattended daemon gets no runtime expiry signal | `a67fed0` (in-process heartbeat + < 14-day warning). **Residual:** an opt-in `serve --tls` strict mode is not added; monitor `NotAfter` externally, documented in the guide. | F-A |
| A3-c1 | Windows LAN: name must be used but no how-to for making the SAN resolve without internal DNS | **F-D docs (this commit)** — new "Making the certificate name resolve on the LAN" section (router/local-DNS A record; per-OS `hosts`-file lines; bare IP cannot work with a name-only cert) | F-D |

### Type III

| Cell | finding | fix commit / disposition | tranche |
|---|---|---|---|
| A1-c2 | raw `exit status 1` prefix above tool stderr | `43716d0` | F-C |
| A1-c2 | remedy "re-run tls setup" though wizard sits at the menu | `43716d0` | F-C |
| A1-c3 | allowlist-prompt jargon; 403 consequence unstated | `43716d0` | F-C |
| A1-c4 | printed serve port derived only from `:8787` | `43716d0` | F-C |
| A1-c5 | launch link host-terminal-only; no phone guidance | **F-D docs (this commit)** — "Reaching a headless host from a phone" (URL as text / QR via `qrencode`; secret rotates; name must resolve + cert trust). The wizard step-5 output line is F-C's surface. | F-D |
| A1-c6 | `tailscale cert` re-issues unconditionally; a daily cron over-issues | **F-D docs (this commit)** — renewal-cadence guidance: `lego`/`certbot` `renew` is idempotent (daily is safe/recommended), `tailscale cert` is not (schedule ~monthly or gate on days-left). **Residual:** the wizard still prints a daily-cron *template* for every route (its output is pinned by `TestShowRenewalSubstitutesConcreteValues`, `cron: 17 3 * * *`); per-route cadence in the wizard would require changing that F-C test and is left as a wizard-side follow-up. | F-D |
| A2-c2 | wait loop re-prints the whole guidance block | `43716d0` | F-C |
| A2-c2 | file check -> spurious "still waiting" | `43716d0` | F-C |
| A2-c3 | BYO route printed the self-signed renewal recipe | `43716d0` | F-C |
| A3-c1 | no decision aid mapping situation -> route | **F-D docs (this commit)** — "Which route fits your situation?" table (home LAN/no domain -> Route D + client-root, Tailscale, public domain w/o root, corporate CA) | F-D |
| A3-c2 | `net use` uses the atypical trailing-backslash `https://` form | **F-D docs (this commit)** — `\\host@SSL@port\` UNC form + WebClient prerequisites (`net start WebClient`, `sc config WebClient start= auto`) | F-D |
| A3-c3 | self-signed names render duplicate `127.0.0.1` | `43716d0` | F-C |
| A3-c3 | keep-self-signed on "other devices" cannot mount a Windows drive | `43716d0` (redirect line added) | F-C |
| A3-c4 | bind-refusal steers to `--insecure-bind` even with a cert configured | `43716d0` (leads with the TLS route; `--insecure-bind` last resort) | F-C |
| A3-c5 | "firewall the port" is generic, no concrete command | **F-D docs (this commit)** — per-OS firewall commands (ufw, firewalld, macOS `pf`, Windows `netsh advfirewall`) + stronger direct-non-loopback wording | F-D |
| A3-c5 | DECRYPTED-content / prefer-VPN framing only in the wizard, not at serve/gui CLI startup | **Residual (not F-D ownership):** emitting the note at `serve`/`gui` startup for any non-loopback bind is a `cmd/seavault/main.go` change owned by the CLI-surface fixer. The bind-*refusal* message already names DECRYPTED content + the TLS route; the *allowed* non-loopback-with-TLS startup emission is a follow-up. The guide now carries the stronger wording. | — |
