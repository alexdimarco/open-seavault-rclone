# Pre-code design review — Phase U3 (TLS certificates for the GUI and WebDAV)

## What was reviewed

- **Design under review:** `docs/design-u3-tls-certificates.md` (Revision 1, STATUS: pre-code), the whole document.
- **Worktree / branch:** `/home/alex/gitprojects/open-seavault-rclone-u3`, branch `feature/u3-tls`, base = `main` at the v0.18.0 merge.
- **Code the design builds on (read to ground findings):** `cmd/seavault/main.go` (`ensureLoopbackBind`, `allowedHostsForBind`, `cmdServe`, the `gui` command and its `serveErr` goroutine, `LaunchURL` printing, `stdinPrompter`, the app-config commands); `internal/appconfig/appconfig.go` (`GUIConfig`, `Normalize`, `Default`, `EnsureSelfSignedCertificate`, `writeSelfSigned`); `internal/setup/interactive.go` (the `Prompter` seam); `internal/webui/server.go` (`AllowedHosts`/Host check, `LaunchURL`, the session cookie `secure` flag, the `/api` config-save handler); `SECURITY.md` (T1/T2 loopback threat model); `docs/webdav-file-manager.md`, `docs/zero-knowledge-deployment-architecture.md`.
- **What U3 introduces:** an `internal/tlsconfig` precedence chain (flags → shared `tls` config section → legacy `gui.certFile` → self-signed floor (gui only) → none) with `Validate` and a 30s-poll `GetCertificate` hot-reload; a TLS-aware bind guard that relaxes the non-loopback refusal only for a TLS listener; `--tls-cert/--tls-key/--tls` on `serve` and `gui`; a `seavault tls setup` wizard on the U1 Prompter (Tailscale / Let's Encrypt DNS-01 via lego or certbot / bring-your-own / keep-self-signed) plus `tls use/status/check/reset`; `docs/tls-and-certificates.md`; a SECURITY.md "Network-exposed mode" section.

## Process run

10-lens pre-code design review per the assurance kit's `process/design-review.md`. Ten independent lens passes produced findings; a skeptic pass attempted to refute each; a rescue pass attempted to save any blocker the skeptic downgraded. This document is the synthesis: it records the surviving findings, the refutations with their quotes, the rescue outcome, the verdict, the numbered conditions, and the mapping of each condition to what the build must prove.

**Model:** claude-opus-4-8.

## Verdict

**GO_WITH_CONDITIONS.**

No finding survived as a blocker: the rescue pass recorded `{"rescues":[],"overall":"no blockers survived the skeptic pass; rescue not needed"}`, so the NO_GO trigger (a blocker surviving both skeptic and rescue with no named mechanism change) is not met. What survived the skeptic is a set of correctness, integration, migration, usability, and test-honesty gaps — each dischargeable by a concrete design revision before build. They are folded into the 13 numbered conditions below. Every condition names a mechanism change already identified in a surviving finding's fix, and every one is testable against the §7 matrix (or a named new row). The design's core — the precedence chain, the TLS-aware guard, `serve` TLS, and the red-first test matrix — is sound; the conditions harden the seams where the resolved TLS state meets the already-shipped GUI/webui code, and close the vacuous-proof gaps the honesty lens found.

## Conditions (apply as a design revision before build)

| n | Addresses | Condition |
|---|---|---|
| 1 | usability-friction-1 | **Launch-URL identity match.** The wizard and the gui command MUST emit the printed launch link using the certificate's primary SAN / confirmed `--allow-host` name (e.g. `https://<allow-host>:<port>/?launch=SECRET`), binding separately from the printed host, so the reachable URL matches a name the certificate is valid for. Today `launchURL := s.LaunchURL(scheme+"://"+*addr)` (main.go:1617) concatenates the bind IP (server.go:992) while step 4 makes the cert's DNS SANs the allowlist, so the first cross-device open shows `NET::ERR_CERT_COMMON_NAME_INVALID`, defeating U3's 'without trust prompts' goal (design lines 10-12). The hardcoded login-page hint `http://127.0.0.1:8787/?launch=...` (server.go:3666) must likewise not present a loopback link for a network-facing TLS listener. |
| 2 | integration-seams-1 | **Carry resolved TLS-on state into the webui server.** §3 must state that cmdGUI sets in-memory `cfg.GUI.Protocol="https"` (or passes an explicit `TLSActive` flag into `webui.NewWithConfig`) whenever `Resolve` returns `Source != none`, BEFORE constructing the `webui.Server` and computing `launchURL`, so the launch scheme (main.go:1613-1617), the `ListenAndServeTLS`-vs-`ListenAndServe` decision (the gui `serveErr` goroutine `if scheme=="https"`), and the session-cookie `Secure` attribute (server.go:1042 and server.go:1088, both `EqualFold(...GUI.Protocol,"https")`) all follow the resolved TLS state, not the persisted `gui.protocol`. Required test: `seavault gui --tls-cert C --tls-key K` with `gui.protocol` still `http` serves TLS (not plaintext), prints an `https://` launch link, and sets the session cookie with `Secure=true`. |
| 3 | integration-seams-2 | **Reconcile the in-app `/api` config-save path with the new precedence.** §9 (or §3) must resolve the conflict between the shipped POST handler (server.go:3176-3187 calls `EnsureSelfSignedCertificate` whenever saved `GUI.Protocol=="https"`) and 'the tls section implies HTTPS regardless of gui.protocol'. Either route the in-app HTTPS toggle through the same tlsconfig resolve/reset logic (flipping to http clears `tls.*` when it was the only source), or state the in-app toggle no longer governs TLS once `tls.*` is set and the UI must say so and point at `tls reset`. Because `EnsureSelfSignedCertificate` fills only when both legacy fields are empty (appconfig.go:148-150) and sets `GUI.SelfSigned=true`, the handler must not resurrect the `gui.certFile` the wizard cleared. Required test: a Settings save does not un-clear a wizard-cleared legacy `gui.certFile`, and the visible toggle is not silently inert once `tls.*` is set. |
| 4 | usability-friction-4 | **DNS-01 install guidance before the wait loop.** In the lego/certbot binary-not-found branch, the wizard MUST print the install path (e.g. `go install github.com/go-acme/lego/v4/cmd/lego@latest`, or a release-binary URL) BEFORE the run command, and the 'press Enter when the files exist' loop (design lines 89-90) must keep it visible, so the no-root persona is not blocked on `lego: command not found` with certbot needing root (design line 124). docs/tls-and-certificates.md §5 Route B must list the install step. |
| 5 | security-adversarial-5 | **Drop wildcard SANs when proposing the allowlist.** Step 4 turns cert SANs into the proposed `tls.allowHosts`, but `HostAllowed` does an exact case-insensitive compare (loopback.go:32), so a wildcard SAN like `*.corp.example` is stored literally and never matches a concrete Host header — every request 403s despite an apparent allowlist entry. The wizard MUST drop wildcard SANs from the proposal (or expand only the concrete host the user names) and tell the user the allowlist matches exact names only. Do NOT add wildcard matching to `HostAllowed` — the exact-match rebinding guard stays authoritative. Add H1 rows asserting a wildcard SAN is not silently stored as an allowlist entry. |
| 6 | failure-recoverability-4 | **Reloader must not downgrade a valid live cert.** `Validate` treats expiry as a warning, not a typed error, so a renewed-but-expired or clock-skewed not-yet-valid pair 'validates' and the 30s reloader swaps it in over a currently-serving valid leaf (design lines 46-50). The reloader MUST refuse to swap in a candidate whose leaf is expired or not-yet-valid when the currently-serving leaf is still valid; keep the current pair and log the warning. Serving-an-expired-pair-with-a-warning applies ONLY at cold startup. Extend R1: writing an expired/not-yet-valid renewed pair keeps the old valid leaf served. |
| 7 | migration-coexistence-1 | **Classify a legacy-tier self-signed pair as self-signed.** `EnsureSelfSignedCertificate` persists the self-signed pair into `gui.certFile/keyFile` with `GUI.SelfSigned=true` (appconfig.go:161-171) and cmdGUI saves it (main.go:1594-1596), so every existing https GUI user resolves to `Source=legacy-gui`, ordered before the self-signed floor. `Resolve` MUST consult `cfg.GUI.SelfSigned` (and/or detect issuer==subject in `Validate`) so a self-signed pair in the legacy fields still sets `Resolved.SelfSigned=true` — otherwise the §3/I-T6 'Windows WebDAV will refuse this certificate' warning is silently defeated for the migrated population it protects, and `tls status` misreports the cert as bring-your-own. Add a P1/H1 row for a legacy pair that is actually self-signed. |
| 8 | honesty-of-claims-1 | **Prove I-T5 on the binary-present path.** I-T5 ('stores no token; runs only tools that need no secret') is advertised as §7-proven but has no labeled row, and W1-W4 exercises only lego-ABSENT. Add a row (or extend W1-W4) with lego AND certbot PRESENT asserting `Deps.Run` is invoked ONLY for the `tailscale cert` argv and NEVER for lego/certbot, and the wizard never prompts for a token; label that row I-T5 in the §7 matrix. |
| 9 | honesty-of-claims-2 | **Make I-T7's SECURITY.md claim testable or drop the §7 label.** I-T7 is presented as §7-proven but D1 only scrapes docs/tls-and-certificates.md, never SECURITY.md. Either relabel I-T7 documentation-only, OR extend D1 to assert SECURITY.md contains the 'Network-exposed mode' section and the two residual sentences (login/Basic-auth become network-facing; self-signed first-connect MITM) via a substring/anchor test matching the repo's D1 pattern. |
| 10 | honesty-of-claims-8 | **Tie tlsOn to an actually-encrypted non-loopback listener.** I-T1 is proven only at the guard's boolean layer (P2 tables guard inputs); nothing couples an admitted non-loopback bind to a TLS-wrapped listener, and the gui `serveErr` goroutine already contains the plaintext-fallback shape (`if scheme=="https" { ListenAndServeTLS } else { ListenAndServe }`). Add one end-to-end row: bind gui/serve to a non-loopback interface address with a resolved TLS source and assert the first bytes on the wire are a TLS handshake (a plaintext HTTP GET is rejected / the connection is TLS). |
| 11 | purpose-threat-fit-3, durability-7 | **Give unattended renewal a runtime staleness surface.** Silent renewal failure before expiry has no runtime signal: a disabled timer changes no mtime so the reloader never fires, and detection is only a one-time startup warning or an out-of-band `tls check` against config files, not the running listener. The design MUST add at least one runtime surface: (a) `tls status` reports days-left of what the RUNNING listener serves; AND/OR (b) the reloader emits a periodic (e.g. daily) warning as the served leaf nears NotAfter independent of mtime; AND for the headless `serve --tls` daemon, an opt-in strict mode (refuse to start / exit non-zero on an expired or within-N-days pair) for a supervisor to restart-and-alert. docs/tls-and-certificates.md must state that an unattended daemon needs external NotAfter monitoring, and §6 must name any deferred part as a residual. |
| 12 | failure-recoverability-6 | **Mutating tls commands report the resulting state.** `tls use` (and `tls reset`) are 'validate + persist' with no stated output, so a scripted operator does not learn the resulting source, resolved SANs, expiry, or that the intended name landed in `tls.allowHosts` without a second `tls status`. Have `tls use` and `tls reset` print the same summary `tls status` would. Extend U1 to assert the mutating commands emit the status summary (and contain no key material). |
| 13 | honesty-of-claims-6 | **Prove startup refusal of a configured key-mismatched pair.** I-T3 and §2 assert 'startup refuses a key-mismatched pair (ErrKeyMismatch)', but R1 proves only reload and R2 only `Validate` in isolation. Add a P1/G1 row: a configured full-but-mismatched pair (both files present, mismatched) makes gui/serve startup return `ErrKeyMismatch` and bind nothing — a distinct path from half-pair and from reload, so a holder seeded without a startup key-match check is caught. |

## Per-lens findings

Severity key: **cond** = a finding tagged `[condition]` at its lens; **note** = advisory. Disposition: confirmed (survived the skeptic), refuted (skeptic quote overturned it), rescued (skeptic downgraded, rescue restored — none this run).

| id | severity | disposition | one-line |
|---|---|---|---|
| purpose-threat-fit-1 | note | refuted | Step-8 probe traces to the job; it is advisory and reports this machine's view only. |
| purpose-threat-fit-2 | note | refuted | Windows WebDAV specifics are placed in the shipped doc; no contradiction unreconciled. |
| purpose-threat-fit-3 | note | **confirmed** | Unattended renewal has no runtime signal for silent failure before expiry → **Cond 11**. |
| purpose-threat-fit-4 | note | refuted | `tls check` (validate, exit 1) and `tls status` (report) are distinct, not overlapping. |
| focus-proportionality-1 | note | refuted | P2/I-T1 shows the guard is the minimal core; scope is coherent. |
| focus-proportionality-2 | note | refuted | Docs are in the named in-scope list; D1 is a drift guard, not a coupling. |
| focus-proportionality-3 | note | refuted | The probe's CA-injected test pool is a bounded, in-unit obligation. |
| focus-proportionality-4 | note | refuted | Reloader returns a stop function and exits on shutdown; not unstoppable, not inside Resolve. |
| focus-proportionality-5 | note | refuted | This IS the design review; the wizard's friction review is a separate named gate. |
| durability-1 | note | refuted | Reload swaps only if `Validate` passes; a failing pair keeps the current one + one warning. |
| durability-2 | note | refuted | Startup serves an expired pair with a warning by explicit design choice. |
| durability-3 | note | refuted | `tls reset` returns to self-signed/none; the reset command exists. |
| durability-4 | note | refuted | Wizard prints the command and never runs a token/root tool; table is user-run. |
| durability-5 | note | refuted | Wrong/missing files → exact typed error + remedy, nothing persisted. |
| durability-6 | note | refuted | I-T1 + `ensureLoopbackBind` refusal hold across a downgrade; plaintext stays refused. |
| durability-7 | note | **confirmed** | Headless serve daemon serving an expired cert only logs one warning → **Cond 11**. |
| usability-friction-1 | cond | **confirmed** | Launch link uses bind IP; cert is issued for a DNS name → trust prompt on first open → **Cond 1**. |
| usability-friction-2 | note | refuted | Password precedence (file > env > generated) persists a stable password. |
| usability-friction-3 | note | refuted | Windows client specifics are deliberately placed in the shipped doc. |
| usability-friction-4 | cond | **confirmed** | DNS-01 prints a `lego` command with no install guidance; no-root user stranded → **Cond 4**. |
| usability-friction-5 | note | refuted | Probe reports the exact failure (name mismatch, unknown authority, expired). |
| usability-friction-6 | note | refuted | Tailscale route prints the admin-console step on `tailscale cert` failure. |
| integration-seams-1 | cond | **confirmed** | Cookie `Secure` and launch scheme read `gui.protocol`, not resolved TLS state → **Cond 2**. |
| integration-seams-2 | cond | **confirmed** | `/api` config-save independently manages HTTPS; toggle inert, resurrects legacy certFile → **Cond 3**. |
| integration-seams-3 | note | refuted | The guard signature change is covered by P2's rewritten table; Z1 governs pre-U3 tests. |
| integration-seams-4 | note | refuted | Legacy `gui.certFile/keyFile` stay readable and are cleared by the wizard. |
| security-adversarial-1 | note | refuted | serve TLS-on only when a flag is given; guard relaxes only for a TLS listener (I-T1). |
| security-adversarial-2 | note | refuted | Probe fetches with the resolved cert via system trust store and reports the verdict. |
| security-adversarial-3 | note | refuted | allowHosts come from parsed X.509 SAN dNSNames, not the raw `tailscale status` string. |
| security-adversarial-4 | note | refuted | Self-signed first-connect MITM is a named SECURITY.md residual (I-T7). |
| security-adversarial-5 | note | **confirmed** | Wildcard SANs proposed as allowHosts can never match `HostAllowed`; inert 403s → **Cond 5**. |
| security-adversarial-6 | note | refuted | Key material never logged/printed/copied; world-readable key → `chmod 600` warning. |
| failure-recoverability-1 | note | refuted | `serve --tls` with an empty section produces no cert → still refused by I-T1. |
| failure-recoverability-2 | note | refuted | Bind stays a per-run choice with printed exposure warnings; loopback default is honest. |
| failure-recoverability-3 | note | refuted | Renewal recipe covers re-run; interrupt leaves reversible state, nothing persisted. |
| failure-recoverability-4 | cond | **confirmed** | Reload swaps an expired/not-yet-valid renewed pair over a valid leaf ('validates') → **Cond 6**. |
| failure-recoverability-5 | note | refuted | Holder seeding + poll behavior specified by R1 (ephemeral TLS listener, new leaf within poll). |
| failure-recoverability-6 | note | **confirmed** | `tls use`/`reset` do not report the persisted config; scripted operator learns nothing → **Cond 12**. |
| migration-coexistence-1 | cond | **confirmed** | Migrated self-signed installs reclassify to legacy-gui, suppressing the self-signed warning → **Cond 7**. |
| migration-coexistence-2 | note | refuted | Legacy certFile with `protocol=http` → HTTPS is intended and legible (wizard sets protocol=https). |
| migration-coexistence-3 | note | refuted | serve TLS is opt-in per flag; Basic auth over HTTPS is the documented path. |
| migration-coexistence-4 | note | refuted | §9 states U2 merges first and U3 rebases, registering `tls` in that registry. |
| migration-coexistence-5 | note | refuted | The guard warns (self-signed / every-interface) for a non-loopback bind the cached cert can't name. |
| dependency-cost-1 | note | refuted | Probe fetches by name with the system trust store — consistent with the DNS-01 premise. |
| dependency-cost-2 | note | refuted | Route C certbot is documented separately (root, per-provider plugin packages). |
| dependency-cost-3 | note | refuted | 'Safe to run' = no-secret; failure surface is handled by the typed-error/remedy path. |
| dependency-cost-4 | note | refuted | Renewal recipe includes a Windows Task Scheduler snippet; certbot is route-scoped. |
| dependency-cost-5 | note | refuted | A managed lego runtime is explicitly out of scope (later phase); the wizard guides external tools. |
| dependency-cost-6 | note | refuted | Probe verdict is labeled 'this machine's view only'; divergence is disclosed. |
| honesty-of-claims-1 | cond | **confirmed** | I-T5 has no row; the binary-PRESENT path (a token/root-invoking bug) is untested → **Cond 8**. |
| honesty-of-claims-2 | cond | **confirmed** | I-T7 has no §7 drift test; D1 never reads SECURITY.md → **Cond 9**. |
| honesty-of-claims-3 | note | refuted | W5 proves 'trusted' via a CA injected into the test root pool — the stated mechanism. |
| honesty-of-claims-4 | note | refuted | Startup logging of source/names/expiry is asserted (design lines 64-65). |
| honesty-of-claims-5 | note | refuted | R1 proves reload-within-poll against I-T3; the '30 s' figure is exercised. |
| honesty-of-claims-6 | note | **confirmed** | I-T3's 'startup refuses a key-mismatched CONFIGURED pair' has no dedicated row → **Cond 13**. |
| honesty-of-claims-7 | note | refuted | P1's self-signed×serve cell asserts Source + whether TLS is on; not a contradiction. |
| honesty-of-claims-8 | cond | **confirmed** | I-T1 proven only at the guard boolean; no row couples tlsOn to a ciphertext listener → **Cond 10**. |
| honesty-of-claims-9 | note | refuted | D1's red-first, every-row-asserts discipline prevents a zero-match vacuous pass. |

## Refuted findings (with the refuting quote)

- **purpose-threat-fit-1** — "Starts a short-lived probe listener on the chosen address with the resolved certificate and fetches `https://<name>:<port>/` using the system trust store" (§4 step 8) + "the probe in step 8 reports this machine's view only" (line 156) + "The probe cannot bind → the wizard says so and persists anyway (the probe is advisory)" (§8 line 179).
- **purpose-threat-fit-2** — **Windows WebDAV specifics** (refuses self-signed; Basic auth is only allowed over HTTPS by the WebClient service's default `BasicAuthLevel`; the `FileSizeLimitInBytes` cap; how to map the drive).
- **purpose-threat-fit-4** — `seavault tls status` (source, names, expiry, days left, allowlist, key perms — never key material), `seavault tls check` (validate the configured pair; exit 1 on error).
- **focus-proportionality-1** — P2 | §3 guard, I-T1 | table over host (loopback, LAN IP, empty) × (tls off, self-signed, CA) × insecureBind → allowed/refused and the exact warning; plaintext non-loopback without the override is refused in every row.
- **focus-proportionality-2** — **In scope:** `internal/tlsconfig` (resolve, validate, hot-reload); the TLS-aware bind guard; `--tls-cert/--tls-key` on `serve` and `gui`; a shared `tls` app-config section with legacy compatibility; `seavault tls setup` (interactive), `tls use`, `tls status`, `tls check`; `docs/tls-and-certificates.md`; a "Network-exposed mode" section in SECURITY.md.
- **focus-proportionality-3** — "trusted" for a leaf from a CA injected into the test's root pool.
- **focus-proportionality-4** — internal/webui/server.go:480-482 — "It returns a stop function and also exits on server shutdown. interval <= 0 disables it."; and design:46-48 — "A reloader goroutine stats both files every 30 s ... and, when either mtime changes, runs `Validate` and swaps the pair in" (no text placing the goroutine inside Resolve or declaring it unstoppable).
- **focus-proportionality-5** — STATUS: pre-code design, awaiting the 10-lens review. Revision 1.
- **durability-1** — A reloader goroutine stats both files every 30 s ... and, when either mtime changes, runs `Validate` and swaps the pair in only if it validates; a failing pair keeps the current one and logs one warning naming the failure.
- **durability-2** — Startup refuses a key-mismatched pair (`ErrKeyMismatch`) and serves an expired one with a warning (it still encrypts; clients warn).
- **durability-3** — `seavault tls reset` (return to self-signed / none).
- **durability-4** — then PRINTS the exact command (it never runs a tool that needs a provider token or root) with the expected output paths, names the usual challenges (propagation delay, CAA records, rate limits), and waits: "press Enter when the files exist" — re-checking until they do or the user cancels.
- **durability-5** — Wrong or missing files → the exact typed error and the remedy, nothing persisted.
- **durability-6** — I-T1 Plaintext is never served on a non-loopback address without an explicit `--insecure-bind` (design line 141); reinforced by `ensureLoopbackBind` returning `fmt.Errorf("refusing to bind %q: %q is not a loopback address, and this endpoint serves DECRYPTED content...")` (cmd/seavault/main.go:1283).
- **usability-friction-2** — passwordFile (content, trailing newline trimmed, must be non-empty) > envPassword (SEAVAULT_SERVE_PASSWORD) > a freshly generated 24-byte base64url password (32 chars).
- **usability-friction-3** — "The supported Windows drive-mount path is the Phase B rclone/WinFsp mount, not this redirector." (docs/webdav-file-manager.md:141-143), combined with the design's deliberate placement of the client specifics in the shipped doc (design lines 128-130).
- **usability-friction-5** — reports "trusted by this machine" / "self-signed — trust prompt expected" / the exact failure (name mismatch, unknown authority, expired).
- **usability-friction-6** — Tailscale HTTPS not enabled → `tailscale cert` fails and the wizard prints the admin-console step.
- **integration-seams-3** — P2 | §3 guard, I-T1 | table over host (loopback, LAN IP, empty) × (tls off, self-signed, CA) × insecureBind → allowed/refused and the exact warning.
- **integration-seams-4** — `gui.certFile/keyFile` remain readable for compatibility and are cleared by the wizard when it writes the shared section.
- **security-adversarial-1** — §2: "`serve` has no self-signed floor: with nothing configured it is plaintext loopback as today." + §3: "TLS is on only when one of those is given." + I-T1: "the guard relaxes only for a TLS listener."
- **security-adversarial-2** — Starts a short-lived probe listener on the chosen address with the resolved certificate and fetches `https://<name>:<port>/` using the system trust store, then reports "trusted by this machine" / "self-signed — trust prompt expected" / the exact failure.
- **security-adversarial-3** — §4 step 4 (line 97): "The SANs become the proposed `tls.allowHosts`; the user confirms or adds" + §2 (line 42): Validate "reports SANs and `NotAfter`" — the allowlist entries come from the X.509 SAN dNSNames, not the raw `tailscale status --json` string.
- **security-adversarial-4** — I-T7: the GUI login and WebDAV Basic auth become network-facing (rate limiting and lockout are a later phase), and clients that accept a self-signed prompt are MITM-able on first connect.
- **security-adversarial-6** — Private key material is never logged, echoed, printed by `status`, or copied by the wizard; a group/world-readable key file produces a warning naming `chmod 600`.
- **failure-recoverability-1** — **I-T1** Plaintext is never served on a non-loopback address without an explicit `--insecure-bind`; the guard relaxes only for a TLS listener.
- **failure-recoverability-2** — `fmt.Println("bind is local by default; do not expose this listener on an untrusted network")` [main.go:1620 (gui) and :1477 (serve)].
- **failure-recoverability-3** — Prints the renewal recipe for the chosen route (`tailscale cert` re-run, `lego renew`, `certbot renew`) with a systemd-timer, cron, and Windows Task Scheduler snippet.
- **failure-recoverability-5** — serve on an ephemeral TLS listener; a client with the CA pool connects; rewrite the pair → `GetCertificate` returns the new leaf within the poll.
- **migration-coexistence-2** — flags or a configured `tls` section imply HTTPS regardless of `gui.protocol` (the wizard also sets `gui.protocol=https` so the state is legible).
- **migration-coexistence-3** — §3: "serve: gains --tls-cert, --tls-key, and --tls; TLS is on only when one of those is given." + §5: "Basic auth is only allowed over HTTPS by the WebClient service's default BasicAuthLevel".
- **migration-coexistence-4** — U2 merges first and U3 rebases, registering `tls` in that registry.
- **migration-coexistence-5** — "a non-loopback or empty host is allowed when `tlsOn` (with a warning when `selfSigned`: \"clients will show a trust prompt; Windows WebDAV will refuse this certificate\" and, for an empty host, \"listening on every interface\")" (design §3, lines 55-57).
- **dependency-cost-1** — Starts a short-lived probe listener on the chosen address with the resolved certificate and fetches `https://<name>:<port>/` using the system trust store.
- **dependency-cost-2** — **Route C certbot** (root, per-provider plugin packages).
- **dependency-cost-3** — No secrets are involved, so running it is safe.
- **dependency-cost-4** — "Prints the renewal recipe for the chosen route (`tailscale cert` re-run, `lego renew`, `certbot renew`) with a systemd-timer, cron, and Windows Task Scheduler snippet" (§4.7, lines 106-107).
- **dependency-cost-5** — **Out of scope:** an embedded ACME client or DNS-provider integrations (the wizard guides external tools; a managed `lego` runtime is a later phase).
- **dependency-cost-6** — **Conditional (labeled):** whether a client trusts the certificate depends on the route and on the client's own trust store; the probe in step 8 reports this machine's view only.
- **honesty-of-claims-3** — reports "self-signed — trust prompt expected" for the self-signed pair and "trusted" for a leaf from a CA injected into the test's root pool.
- **honesty-of-claims-4** — Both servers log the source, the names, and the expiry at startup (design lines 64-65).
- **honesty-of-claims-5** — R1 "Proves | §2 hot-reload, I-T3" (line 164); I-T3 (line 145): "Hot-reload never swaps in an invalid pair; startup refuses a key-mismatched pair."
- **honesty-of-claims-7** — P1 | §2 precedence | table over (flags, config, legacy, self-signed, none) × (gui, serve): each row asserts Source, paths, and whether TLS is on.
- **honesty-of-claims-9** — Test matrix (red-first; every row asserts; real listeners and real certificates).

## Rescue outcome

`{"rescues":[],"overall":"no blockers survived the skeptic pass; rescue not needed"}`

No lens produced a blocker that the skeptic left standing, so there was nothing for the rescue pass to save and no rescued blocker to fold into a condition. The verdict therefore turns entirely on the confirmed non-blocker findings, all discharged by the conditions above.

## What the build must prove (conditions → test-matrix rows)

The §7 matrix stays the red-first spine; each condition below names the row it extends or adds. A condition is discharged only when its row has been seen red before the fix and green after.

| Condition | Row(s) to add or extend | The assertion that discharges it |
|---|---|---|
| 1 (launch-URL identity) | new **G2** (gui launch link) | With a resolved cert whose SAN is `name`, the printed launch link host equals `name` (or the confirmed `--allow-host`), never the bind IP; the login-page hint (server.go:3666) is not a bare loopback link when TLS is network-facing. |
| 2 (resolved TLS into webui) | extend **G1** | `gui --tls-cert C --tls-key K` with `gui.protocol=http` → the listener is TLS (not `ListenAndServe`), the launch scheme is `https`, and the session cookie carries `Secure=true` (server.go:1042/1088 read the resolved state). |
| 3 (`/api` config reconcile) | new **G3** (coexistence) | A Settings POST does not un-clear a wizard-cleared legacy `gui.certFile` (server.go:3177 path); flipping the in-app toggle to `http` either clears `tls.*` when it was the only source or the UI states the toggle no longer governs TLS. |
| 4 (DNS-01 install guidance) | extend **W1–W4** (lego-absent) + **D1** | In the binary-not-found branch the install line is printed before the run command and remains visible in the wait loop; docs/tls-and-certificates.md §5 Route B names the install step (D1 doc-scrape). |
| 5 (drop wildcard SANs) | extend **H1** | A cert with SAN `*.corp.example` is NOT stored as a `tls.allowHosts` entry; the proposal drops it and the message states exact-match only; `HostAllowed` is unchanged. |
| 6 (no live downgrade) | extend **R1** | Writing an expired or not-yet-valid renewed pair while a valid leaf is served → the old valid leaf is still served and one warning is logged; expired-serving happens only at cold startup. |
| 7 (legacy self-signed) | extend **P1** + **H1** | A legacy `gui.certFile` pair that is self-signed (issuer==subject / `GUI.SelfSigned=true`) resolves with `Resolved.SelfSigned=true`, fires the §3/I-T6 warning, and `tls status` reports it as self-signed. |
| 8 (I-T5 binary-present) | new row labeled **I-T5** under **W1–W4** | With lego AND certbot PRESENT, `Deps.Run` is invoked ONLY for the `tailscale cert` argv and NEVER for lego/certbot, and no token prompt occurs. |
| 9 (I-T7 drift) | extend **D1** (or relabel I-T7) | D1 asserts SECURITY.md contains the "Network-exposed mode" section and the two residual sentences; OR I-T7 is relabeled documentation-only in §6. |
| 10 (ciphertext listener) | new **S2** (end-to-end) | Bind gui/serve to a non-loopback interface address with a resolved TLS source → the first bytes on the wire are a TLS handshake; a plaintext HTTP GET is rejected. |
| 11 (renewal staleness) | new **R3** + extend **U1** and **D1** | `tls status` reports days-left of the RUNNING listener's leaf; the reloader emits a periodic near-expiry warning; `serve --tls` strict mode exits non-zero on an expired/within-N-days pair; docs name the external-monitoring requirement (D1). |
| 12 (mutating cmd output) | extend **U1** | `tls use` and `tls reset` print the `tls status` summary (source, names, expiry, allowlist, key perms) and contain no key material. |
| 13 (startup key-mismatch) | new row under **P1**/**G1** | A configured full-but-mismatched pair makes gui/serve startup return `ErrKeyMismatch` and bind nothing — distinct from half-pair (P1) and reload (R1). |

Existing rows P2, R2, S1, W5, Z1 remain as specified and are unaffected by the conditions except where extended above. Z1 (pre-U3 gui/serve tests unmodified and green; unfiltered race suite green) governs regression safety for every change the conditions introduce, per the repo's testing discipline (no gate weakened, prove-fail → prove-pass for each new row).
