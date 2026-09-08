# Adversarial review — Phase U3 (TLS certificates for the GUI and WebDAV)

WHAT: An adversarial review of the BUILT Phase U3 on branch `feature/u3-tls` (worktree `open-seavault-rclone-u3`) against the design contract in `docs/design-u3-tls-certificates.md` (Revision 2, §10 conditions C1–C13), its pre-code review `docs/review-u3-predesign.md`, and the invariants I-T1..I-T3. Scope: `internal/tlsconfig` (Resolve/Validate/Reloader, serving.json heartbeat), the shared `tls` app-config section, the TLS-aware bind guard, `gui` (`--tls-cert/--tls-key`, TLSActive + launch-link identity), `serve` (`--tls-cert/--tls-key/--tls`), the settings-save reconciliation in `internal/webui`, the `seavault tls setup` wizard (`internal/setup/tlswizard.go`) and `tls use/status/check/reset`, plus `docs/tls-and-certificates.md` and the SECURITY.md network-exposed-mode section.

PROCESS: Reviewer agents drove the real built binary (`go build -o /tmp/sv-u3/seavault ./cmd/seavault`) under a throwaway `SEAVAULT_APP_HOME` with `--no-keychain`, `tailscale`/`lego`/`certbot` shims on a temp PATH, and openssl-generated test CAs/leaves; every claim was then run past a skeptic pass that either reproduced it end-to-end or established it by code inspection. Real DNS/ACME/Tailscale accounts, the real user home, and the real keychain were never touched.

MODEL: claude-opus-4-8

## Counts

- Found (raw confirmed claims carried into synthesis): 11
- Confirmed (after dedupe): 9
- Refuted: 0

Three raw claims — `tls-reload-not-wired-1`, `reload-races-1`, and `serving-heartbeat-missing-1` — describe the SAME defect (the `tlsconfig.Reloader` is never constructed or started by `cmdGUI`/`cmdServe`) and are merged into `reload-not-wired-1`. `reload-races-2` (warnings dropped on reload) and `reload-races-3` (double-read TOCTOU) are distinct defects merely LATENT behind the same missing wiring and are kept separate.

## Confirmed findings

| id | sev | title | repro (abridged) | fix |
|----|-----|-------|------------------|-----|
| reload-not-wired-1 | high | TLS hot-reload + serving.json heartbeat never started by gui/serve — I-T3 reload, §2, C11 dead | `gui`/`serve` with a resolved cert; TLS handshake succeeds but serving.json is never written, a renewed on-disk pair is NOT re-served after >30 s, and `tls status` prints `running listener: none seen` while the listener is up. `grep -rn '\.Reloader(' \| grep -v _test.go` → empty. | Construct `resolved.Reloader(...)` and `go rl.Run(ctx)` in cmdGUI/cmdServe with a ctx cancelled on shutdown; add a cmd-level integration test for serving.json + renewed-pair serving. |
| launch-allowlist-1 | high | Launch link/login hint ignore tls.allowHosts; wildcard cert → unopenable https://*.example.com URL (C1) | `tls use` a `*.example.com` cert with `--allow-host vault.example.com`, then `gui --addr <LAN>` without `--allow-host` → advertises `https://*.example.com:PORT/?launch=…`. | Merge cfg.TLS.AllowHosts into the name list; firstConfirmedName skips wildcards; fall back to bind addr; reword the impossible guidance. |
| config-precedence-1 | high | Settings-save (C3) reconciles against stale in-memory config; a GUI save clears or resurrects CLI-changed tls.* | GUI open before out-of-band `tls use`/`tls reset`; next Save WIPES tls.certFile+reverts protocol (after use) or RESURRECTS the reset cert (after reset). | Reconcile against a fresh appconfig.Load() at handler top; preserve tls.*/legacy fields; refresh s.config from disk. |
| reload-races-2 | medium | reload() discards info.Warnings; a renewal landing a world-readable key is swapped in with no chmod-600 warning (I-T2 gap) | Renew with same key but `chmod 0644`; Validate() returns a chmod-600 warning yet reloader Logf has none. Cold start still warns. | Emit info.Warnings after a successful swap, de-duped against the expiry line. |
| wizard-tools-1 | medium | Shell injection into printed lego/certbot command via unquoted --email from a hostile domain | Domain `a.io;touch INJECTED;#` → wizard prints `--email you@a.io;touch INJECTED;#`; pasting runs the touch. Same in certbot branch. | Run email through shellQuoteWizard() in both branches (or validate the domain). Quote every interpolated value. |
| guard-warning-allzero-1 | low | Every-interface advisory skipped for 0.0.0.0/::/[::] (fires only for empty host) | `gui --addr 0.0.0.0:PORT` emits no every-interface advisory; `--addr :PORT` does. Refusal logic unaffected. | `host == "" \|\| (ParseIP != nil && IsUnspecified())` before the advisory. |
| reload-races-3 | low | Double-read TOCTOU in reload(): C6 gate evaluated on different bytes than are served | Not reproduced end-to-end (µs race, attacker owns key files); code inspection — validateAt and loadCertificate read the pair separately. | Read once; drive both the C6 gate and the served cert from the same bytes, or re-check NotAfter/NotBefore on the loaded leaf before store(). |
| wizard-tools-2 | low | No validation of tailscale MagicDNS name before use as path and argv to `tailscale cert` | Shim DNSName `../../../PWNED_TS` writes outside the tls dir; `--cert-file=/tmp/HIJACK` injects a flag. Real tailscale sanitizes → defense-in-depth. | Validate against a DNS-label grammar; guard filepath.Join stays in-tree; pass name after `--`. |
| launch-hint-loopback-1 | low | No-session login hint hardcodes http://127.0.0.1:8787 for every plaintext listener | `gui --addr <LAN> --insecure-bind` → 403 page hints `http://127.0.0.1:8787/?launch=…`; non-default loopback port also wrong. | Set LoginHintURL = scheme://launchAddr/?launch=… unconditionally; drop the hardcoded fallback. |

## Refuted findings

None. Every claim carried into synthesis was reproduced end-to-end or (for `reload-races-3`) established by direct code inspection and survived the skeptic pass. The skeptic returned an empty refuted set.

## Fix-tranche ordering

**Tranche 1 — the C11/§2/I-T3 dead-wiring root (do first).** (1) `reload-not-wired-1` — construct/run the Reloader in cmdGUI/cmdServe; this is the trunk, and reload-races-2/3 cannot even execute until it lands. Land its cmd-level integration test at the same time. (2) `reload-races-2` — emit info.Warnings after a swap. (3) `reload-races-3` — collapse the double read to a single-read C6 gate.

**Tranche 2 — identity/exposure correctness on every launch.** (4) `launch-allowlist-1` (C1). (5) `config-precedence-1` (C3) — reviewed together since both touch the tls.* fields.

**Tranche 3 — paste-me / external-input hardening.** (6) `wizard-tools-1` (copy-paste RCE). (7) `wizard-tools-2` (tailscale name validation).

**Tranche 4 — advisory completeness (low).** (8) `guard-warning-allzero-1`. (9) `launch-hint-loopback-1`.

---

## Fix-tranche addendum (feature/u3-tls)

All nine confirmed findings are closed by the U3 fix tranche. Each row maps the finding
to the commit(s) that fixed it; every behavioural fix shipped prove-fail -> prove-pass
with real listeners and real in-test certificates.

| id | sev | fix commit(s) | tranche |
|----|-----|---------------|---------|
| reload-not-wired-1 | high | `a67fed0` (Reloader constructed/run in cmdGUI/cmdServe + end-to-end serving.json/renewed-pair integration test); `b6e9e30` (reloader teardown joined before the command returns; reload_test de-flaked) | F-A |
| reload-races-2 | medium | `a67fed0` (reload() emits validated warnings after a successful swap, de-duped against the expiry line) | F-A |
| reload-races-3 | low | `a67fed0` (single-read C6 gate: the downgrade gate and the served leaf come from the same bytes; fault-injection seam, red-first) | F-A |
| guard-warning-allzero-1 | low | `a67fed0` (every-interface advisory fires for `0.0.0.0`/`::`/`[::]` via `net.ParseIP(host).IsUnspecified()`) | F-A |
| launch-allowlist-1 | high | `521fb14` (cmdGUI merges `tls.allowHosts` into the launch-name list; `firstConfirmedName` skips wildcards in both lists and falls back to the bind addr; wildcard startup guidance points at the concrete names) | F-B |
| config-precedence-1 | high | `521fb14` (settings GET/POST reconciles against a fresh `appconfig.Load()` and refreshes `s.config` from disk; a Save no longer wipes a CLI-added `tls.*` nor resurrects a CLI-removed cert) | F-B |
| launch-hint-loopback-1 | low | `521fb14` (`LoginHintURL` set to the address actually served for both http and https; no hardcoded `127.0.0.1:8787`) | F-B |
| wizard-tools-1 | medium | `43716d0` (DNS-01 domain validated/normalized; every interpolated value shell-quoted in the printed lego AND certbot commands) | F-C |
| wizard-tools-2 | low | `43716d0` (tailscale MagicDNS name validated against a DNS-label grammar; `filepath.Join` kept in-tree; name passed after a `--` terminator) | F-C |

The refuted set stays empty. The design STATUS line (`docs/design-u3-tls-certificates.md`)
records the same tranche commits.
