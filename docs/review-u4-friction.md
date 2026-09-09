<!--
Friction review — Phase U4 (authentication rate limiting + lockout, and the Track P polish backlog)
Branch feature/u4-polish-ratelimit @ c574a39 (BUILT). Process: assurance-kit process/friction-review.md.
How cells were walked: four friction-review walkers drove the REAL binary built at /tmp/sv-u4/seavault
(`go build -o /tmp/sv-u4/seavault ./cmd/seavault`). All state isolated per run with SEAVAULT_APP_HOME set to a
fresh temp dir, HOME set to a temp dir where detection mattered, and --no-keychain on the CLI; the real user home
and keychain were never touched. WebDAV Basic auth was exercised with curl against a real `serve`; the GUI login,
/api/open, /api/recovery/redeem and /api/status were driven headlessly with curl through the real /api/* behind a
redeemed rotating launch link (and, for the login surface, a configured GUI password). IPv6 /64 keying,
account-ceiling arithmetic, and lock doubling were shown with the real internal/authlimit package under an injected
clock where the running binary cannot surface unexported state (throwaway probes removed, tree left clean). Every
started process was killed by PID. The four actors: (W1) a legitimate owner who mistypes WebDAV, GUI login, then
vault password; (W2) a household behind one NAT where a stale device loops a wrong Basic password on the shared
peer key; (W3) a CLI operator (exit codes, --help, keychain delete, init leftovers, the TLS wizard, --auth-limit,
the migration note); (W4) a new operator working only from SECURITY.md / tls-and-certificates.md / README.
REPORT agent spot-verified the two verdict-driving code claims against the tree: startAuthLimit enabled branch
(cmd/seavault/main.go:1798-1816) returns limits.StatusLine() from the unmodified persisted cfg and never persists
enabled=true / clears disabledSince; ensureLoopbackBind (main.go:1354) takes only a tlsOn bool, no cert state;
const version = "0.20.0" (main.go:52) while SECURITY.md/README/TLS-guide all say v0.21.
Cells walked: 24. Functioning: 15 yes, 9 partial, 0 no. Type II: 6. Type III: 26.
Verdict: SHIPPABLE_WITH_BACKLOG.
-->

# Friction review — Phase U4 (auth rate limiting + lockout, and the Track P polish backlog)

Branch `feature/u4-polish-ratelimit` @ `c574a39` (BUILT). Process: `assurance-kit/process/friction-review.md`.

## How the cells were walked

Four friction-review walkers drove the **real** binary (`go build -o /tmp/sv-u4/seavault ./cmd/seavault`), each
run isolated with `SEAVAULT_APP_HOME`, a temp `HOME`, and `--no-keychain`; the real home and keychain were never
touched. WebDAV was curl-against-a-real-`serve`; GUI login, `/api/open`, `/api/recovery/redeem`, `/api/status`
were driven headlessly through the real `/api/*` behind a redeemed rotating launch link. IPv6 `/64` keying,
account-ceiling arithmetic, and lock doubling were shown with the real `internal/authlimit` package under an
injected clock (probes removed, tree clean). All PIDs killed. Actors: **W1** legitimate owner mistyping across all
three surfaces; **W2** household behind one NAT sharing the peer key; **W3** CLI operator; **W4** new operator with
only the docs.

## Counts

| Metric | Value |
|---|---|
| Cells walked | 24 |
| Functioning (yes) | 15 |
| Partial | 9 |
| Non-functioning (no) | 0 |
| Type II (broken promise, golden path survives) | 6 |
| Type III (polish / legibility) | 26 |

## Verdict — SHIPPABLE_WITH_BACKLOG

**No cell reaches `functions=no`, and both golden paths are low-friction against the real binary.** A legitimate
owner recovering from a lockout: the lockout **is** the control (I-R1) and works on every surface — five wrong
attempts each pay the ~250 ms `FailureDelay`, the sixth returns `429` + `Retry-After: 30` denied before any
credential compare; the correct credential is refused *during* the lock and **not** counted (the lock never
self-extends); and unlock is purely time-based with **no restart** — WebDAV `207`/`200`, open `{"ok":true}`, login
`302` all recover once the window elapses. Launch and redeem are throttle-only and **never lock** (I-R9). Daily use
with limits on is the default and works. The shared-NAT and `/64` DoS costs are disclosed residuals, not defects.

**Six Type II items are real broken promises, but none drives a cell to `no` or makes a golden path high-friction**,
so they land in the backlog rather than blocking the release. The verdict-driving cluster is a **single root
defect** found independently by three walkers (W2-3, W3-5, W4-2):

> **`--auth-limit on` does not persist, and misreports while active.** `startAuthLimit`'s enabled branch
> (`cmd/seavault/main.go:1798-1816`) returns `limits.StatusLine()` computed from the **unmodified persisted**
> `cfg.Auth.Limits` and never writes `enabled=true` / clears `disabledSince`. So over a persisted
> `auth.limits.enabled=false`, `serve --auth-limit on` runs the limiter **on for that process** (no OFF warning)
> yet the startup exposure line, the GUI banner, and `tls status` all print `auth limits: OFF since <date> —
> re-enable with --auth-limit on…` (factually wrong, and it tells the operator to re-run the exact flag they just
> used); the config stays `enabled=false`, so a later **flagless restart** (a systemd unit that just runs
> `seavault serve`) comes back **unprotected** — the precise "headless daemon left unprotected" failure **C7** was
> built to prevent. Both the guide (`tls-and-certificates.md:539`) and the function docstring claim the flag
> "clears the `disabledSince` stamp." An operator who follows the documented remedy is misled.

This is a security-relevant correctness + doc-contract defect and the **must-fix backlog item** before any release
that markets the OFF/ON switch as persistent — but it lives on the operator disable→re-enable path, **not** the two
defined golden paths, which stay protected by default. The other Type II items are affordance/broken-promise gaps
that leave the golden paths working: the **per-viewer GUI lock banner** promised in design §2.2/§6 is **not built**
(the `429` rides the same generic `showError` channel as any wrong password; `retryAfterSeconds` is never read — no
countdown, no button disable); there is **no targeted runtime unlock** for one known-good peer/account (only
host-side all-or-nothing levers); and the **bind-refusal never names `--tls`** when a cert is already configured
(A3-c4 undelivered — `ensureLoopbackBind` gets only a `tlsOn` bool, no cert state). None forces a `no`.

A cross-cutting Type III also worth flagging: `const version = "0.20.0"` while **every** U4 doc says v0.21 — a new
operator running `seavault version` to confirm they are on the release carrying I-R1…I-R10 gets a contradicting
number. Bump it in the release commit.

## Findings

| Cell | Fn | Friction finding | Type | Fix / backlog |
|---|---|---|---|---|
| W1-1 WebDAV 429 to client | yes | Lockout works and suppresses `WWW-Authenticate` so Explorer stops re-prompting (I-R1). | I | Keep. |
| W1-1 | yes | `429` body omits the wait the `Retry-After` header carries; the one client that hides the header also gets no number in the body. | III | Put the human wait in the Basic `429` body. |
| W1-1 | yes | Operator lock line floors 30 s to "1 minute" (2× overstatement) and emits two near-identical lines per burst. | III | Render sub-minute in seconds (or make `LockStart` a whole minute); collapse the peer + peer/account lines. |
| W1-2 GUI login lock | yes | Login `429` re-renders the styled page (HTML not JSON, C6) with a legible reason — the control. | I | Keep. |
| W1-2 | yes | Countdown says "1 minute" for a 30 s lock, static not live; a retry at t=31 s succeeds despite the page. | III | Render true remaining seconds when sub-minute (or whole-minute `LockStart`). |
| W1-3 open 429 + banner | partial | Open lockout bounds attempts against the 64 MiB KDF (I-R10) — the control. | I | Keep. |
| **W1-3** | **partial** | **The "GUI banner shows the viewer's own lock state" promised in §2.2/§6 is NOT built; `retryAfterSeconds` is dead on the client (429 rides the generic `showError` line — no countdown, no button disable, no banner).** | **II** | Wire `retryAfterSeconds` into a real per-viewer lock banner/countdown (disable Open until it elapses), or strike the claim from §2.2/§6 and state the reason rides the generic error line. |
| W1-3 | partial | Two open handlers title the same failure differently ("Could not open the vault" vs "Could not open vault"); "1 minute" overstates 30 s. | III | Unify the titles; align the stated wait with the real 30 s. |
| W1-4 correct cred during lock | yes | Correct credential refused before it is examined and not counted, so the lock never self-extends (I-R1). | I | Keep. |
| W1-4 | yes | "When" is uneven: WebDAV body has no human duration; where present it overstates 30 s. | III | Same as W1-1: human wait in the WebDAV body, matched to true 30 s. |
| W1-5 recovery after wait | yes | Time-based auto-unlock on every surface with no restart (I-R1). | I | Keep. |
| W1-5 | yes | `--auth-limit` is not discoverable in `gui`/`serve --help` (registry leaf help omits it; grep 0). | III | List `--auth-limit on\|off` in the registry leaf-help usage. |
| W1-6 launch/redeem | yes | Launch and redeem are throttle-only and never lock (I-R9); correct secret/phrase always redeems instantly. | I | Keep. |
| W1-6 | yes | Fumbled-redeem error is the generic "wrong password or damaged vault configuration" — doesn't distinguish a phrase mismatch; `retryAfterSeconds:1` is ignored and meaningless. | III | Give the redeem-phrase mismatch its own message; drop/use the meaningless field. |
| W1-6 | yes | Wrong/stale `?launch=` returns a bare text `403`, not the styled no-session page §2.2 implies. | III | Serve the styled no-session page (which already carries the launch example) for a wrong `?launch=`. |
| W2-1 shared-peer lockout | partial | Shared-NAT lockout works and IS the control; residual disclosed in SECURITY.md. | I | Keep. |
| W2-1 | partial | Almost no legible WHY for the basic surface — `429` implies the owner failed, never hints another device; no live locked-peer readout. | III | Add a live "currently locked peers/accounts (unlocks in N s)" readout to `tls status`/GUI; reword the `429` to hint another device on the network. |
| W2-1 | partial | Lock line collapses the doubling escalation — 30 s and 60 s both print "1 minute". | III | Render sub-two-minute locks in seconds (or include seconds alongside the minutes phrase). |
| W2-2 account ceiling | yes | One source self-limits at the peer lock (5) and can never reach the account ceiling (20) — the ordering is the control. | I | Keep; do not lower the account threshold toward the peer threshold. |
| W2-2 | yes | Docs give the raw numbers 5 and 20 but never explain the interaction that reassures a worried household operator. | III | One sentence: a single source trips only the per-peer lock and can never reach the account ceiling. |
| W2-3 operator actions | partial | The OFF-switch signalling is the control and works fully (loud warning, dated `disabledSince`, hourly re-warn, `tls status` readback). | I | Keep. |
| **W2-3** | **partial** | **`--auth-limit on` re-enables only for that run; config stays `enabled=false`+`disabledSince`, `tls status` still reads OFF, a flagless restart returns UNPROTECTED — the documented remedy misleads.** | **II** | Make `serve`/`gui --auth-limit on` persist `enabled=true` and clear `disabledSince`, or reword the status line + docs so the flag is a per-run override and persistent re-enable requires editing `auth.limits.enabled`. |
| W2-3 | partial | The lock-line remedy bundles a restart with the OFF switch; a plain restart clears in-memory locks while keeping protection on (gentler) — not named. | III | Mention a plain restart clears current locks while keeping limits on, distinct from `--auth-limit off`. |
| W2-4 IPv6 /64 | yes | Two devices in one `/64` share the peer key — the anti-rotation control (C3/I-R8); disclosed in SECURITY.md and the TLS guide. | I | Keep. |
| W2-4 | yes | The household meaning of a `/64` key is in SECURITY.md but never in the lock line / `429`, which name only the raw prefix (jargon). | III | Optional note in the TLS guide that a home NAT / IPv6 `/64` all share one bucket. |
| W2-5 status readout | yes | `tls status` and the GUI settings page share one honest source (`AuthLimits.StatusLine`); it surfaced the W2-3/W3-5 mismatch. | I | Keep. |
| W2-5 | yes | The readout shows only policy/enabled-state, never the live lock state (which peer is locked, for how long). | III | Extend the status readout (CLI + GUI) with a live "currently locked: <peer/account> unlocks in N s" list. |
| W2-6 self-unlock | partial | The absence of an instant trivial self-unlock is part of the control; time-based expiry / correct-credential-after-expiry is the intended path (I-R1). | I | Keep; do not add a bypass an attacker on the same peer could trigger. |
| **W2-6** | **partial** | **No way to release ONE known-good peer/account while keeping the limiter on — only host-side all-or-nothing levers (restart clears all and re-locks fast; `--auth-limit off` disarms fleet-wide). A locked-out remote device has only "wait".** | **II** | Add a narrow operator lever that keeps protection on — a `serve`/`gui` "clear lock for <peer\|account>" action, or a configurable trusted-peer allowlist exempt from lockout. |
| W2-6 | partial | The absence of a targeted self-unlock is not spelled out as a residual. | III | Add a residual sentence enumerating the three recoveries and noting a locked-out remote device has only "wait". |
| W3-1 exit codes / help | yes | Bare group verbs exit 0 with help; unknown subcommand exits 2 naming the token; `-h`/`--help` exit 0. | III→I | (baseline correct) |
| W3-1 | yes | An unknown **top-level** command prints NO "unknown command" line (unlike subcommands) — just the usage wall, exit 2. | III | Print `error: unknown command "<x>"; run "seavault --help"` for an unrecognized top-level verb. |
| W3-1 | yes | The bad-**flag** path renders raw Go single-dash flag usage, not the clean registry row `--help` shows. | III | Route `flag.Parse` errors through the registry usage renderer. |
| W3-1 | yes | Leaf `--help` uneven: `get/list/remove/stats` show an opaque literal `[flags]` while others enumerate real flags. | III | Give every leaf's registry row a concrete flag summary instead of `[flags]`. |
| W3-2 keychain delete | yes | Plain line never leaks a password or vault-id; the raw backend error appears under `--debug` in the real-failure branches. | I | Keep. |
| W3-2 | yes | In the reachable-but-empty case `--debug` adds nothing (rawDetail=""), so the flag's help can read as a no-op there. | III | Optional: under `--debug` in the reachable-empty case print "keychain error detail: none (entry simply absent)". |
| W3-3 init leftovers | yes | Leftovers are classified before the password prompt; message names the dir. | I | Keep. |
| W3-3 | yes | The remedy names `--vault`, a flag that does not exist on `init` (it belongs to `setup`); shared `annotateSetupError` leaks the wizard flag. | III | Parameterize the remedy per entry point — `init` should say "…give a different VAULT_DIR". |
| W3-4 TLS wizard rows | partial | Port offset, BYO-renewal recipe, deduped SANs + Windows note, monthly Tailscale cadence, compact wait line + immediate re-check all delivered. | I | Keep. |
| **W3-4** | **partial** | **A3-c4 not delivered: with a cert fully configured, `serve --addr <lan>` without `--tls` is refused with the STATIC "set up TLS first" message, never naming `--tls` (the one-flag fix). `ensureLoopbackBind` (main.go:1354) gets only a `tlsOn` bool, no cert state, so it structurally cannot tell.** | **II** | Thread the configured-cert state into `ensureLoopbackBind`; when a cert is configured but `--tls` omitted, lead the refusal with "a certificate is already configured — add `--tls` to serve over HTTPS on this address". |
| W3-5 --auth-limit off/status | partial | The OFF path is fully correct: flag-only warning, persisted dated warning, `disabledSince` persistence, `tls status` OFF-since. | I | Keep. |
| **W3-5** | **partial** | **`serve --auth-limit on` over persisted `enabled=false` runs the limiter ON yet the startup exposure line and the GUI banner (fed the same `s.AuthLimitStatus`) print "auth limits: OFF since <date>…" — factually wrong and self-contradictory. Root: `startAuthLimit`'s enabled branch returns `limits.StatusLine()` from the unmodified persisted cfg.** | **II** | In the enabled branch build an effective `AuthLimits` with `Enabled=true` / `DisabledSince` cleared and return `effective.StatusLine()` (same root fix as W2-3/W4-2). |
| W3-6 migration note | yes | README "Migration for scripts (CLI 6)" is accurate against the binary (unknown subcommand exits 2; bare group verb exits 0; app-config/gui documented). | I | Keep. |
| W3-6 | yes | The older enumerated group-verb list (README:191-192) omits `tls`, a U3-added group verb that also exits 0 bare. | III | Add `tls` to the enumerated list. |
| W4-1 SECURITY.md guarantees | yes | I-R1…I-R10 + residuals are legible, honest, and match the binary on the checkable points (locked-key-denied-first, no credential in logs/429, off-switch in `tls status`, banner-coverage scope). | I | Keep. |
| W4-1 | yes | Guarantees attributed to "v0.21 (Phase U4)" but `seavault version` → 0.20.0 (`const version="0.20.0"`, main.go:52). | III | Bump `const version` to 0.21.0 in the U4 release commit. |
| W4-1 | yes | The operator-visibility paragraph shows ONE example lock line; reality emits TWO per burst (peer key + peer+account key) — can misread as two incidents. | III | State that a burst locks both keys (two log lines), or suppress the redundant peer-only line. |
| W4-2 TLS guide auth limits | partial | Per-surface `429` behaviour (Basic/open/launch) verified live and matches the guide verbatim; off-switch + `disabledSince` readback match. | I | Keep. |
| **W4-2** | **partial** | **Guide (`tls-and-certificates.md:538-540`) says `--auth-limit on` "clears the `disabledSince` stamp"; the binary does NOT — a flagless restart afterward silently reverts to UNPROTECTED (the C7 failure). The function docstring makes the same false claim.** | **II** | Persist `enabled=true` + clear `disabledSince` in `startAuthLimit`'s enabled branch (same root as W2-3/W3-5), OR correct the guide/README/design-C7 to state `--auth-limit on` is a per-run override and persistent re-enable requires editing `auth.limits.enabled`. |
| W4-2 | partial | The per-surface table lists a "GUI login" row, but that surface exists only when a GUI password is configured; the default launch-link install has nothing to reproduce. | III | Caveat the GUI-login row: it applies only when a GUI login password is set (`guiAuthEnabled`). |
| W4-3 decision aid / UNC / firewall / phone | yes | Decision-aid routes resolve, UNC `net use` form and `serve --tls` dependency exist, firewall ports match defaults, phone note matches the verified launch mechanism. | I | Keep. |
| W4-3 | yes | The phone note's `qrencode` is an unflagged third-party dependency and the QR/text carries the live launch secret. | III | Note `qrencode` is a separate package to install, and that the QR/text carries the live launch secret (treat as a password). |
| W4-4 README changelog / migration | partial | Exit-code migration claims all verified accurate against the binary; single-use redeem cross-checked. | I | Keep. |
| W4-4 | partial | Changelog headed "v0.21" but binary is 0.20.0 — operator cannot confirm the changelog applies. | III | Bump `const version` to 0.21.0 (same as W4-1). |
| W4-4 | partial | Migration note says "app-config and gui are not group verbs and are unchanged", but `app-config bogus` exits 2 (group-style) and design-u4 §3 says both are modelled as groups. | III | Reword to match: app-config and gui ARE modelled as groups (unknown subcommand exits 2). |
| W4-5 GUI docs / disclaimer | yes | Single-use redeem proven end-to-end (second redeem of the same phrase fails); read-back disclaimer names the differing word index without echoing phrase material; general disclaimer served at `/help`. | I | Keep — no findings. |
| W4-6 command/flag existence | partial | Every command and flag referenced across the U4 docs exists in the binary and runs. | I | Keep. |
| W4-6 | partial | `--auth-limit` (and `--tls`/`--tls-cert`/`--tls-key` on `serve`) exist and work but are absent from curated `gui`/`serve --help`; discoverable only via a flag-parse-error dump. Docs tell operators to use these flags. | III | Name `--auth-limit on\|off` in curated `gui`/`serve --help`, and `--tls`/`--tls-cert`/`--tls-key` in the curated `serve --help` usage line (consolidates W1-5). |

## Backlog (priority order)

1. **[Type II · security] Fix the `--auth-limit on` persistence + status defect** (W2-3 / W3-5 / W4-2, one root at `startAuthLimit` main.go:1798-1816): persist `enabled=true` + clear `disabledSince` and report the effective state, or correct the docs/docstring to a per-run override. This is the C7 regression — must fix before any release marketing the switch as persistent.
2. **[Type II] Build the per-viewer GUI lock banner** (W1-3) promised in design §2.2/§6, or strike the claim.
3. **[Type II] Thread cert-config state into `ensureLoopbackBind`** so the bind refusal names `--tls` when a cert is configured (W3-4).
4. **[Type II] A narrow "clear lock for <peer\|account>" operator lever** or trusted-peer allowlist (W2-6), so the owner can release their own network without disarming globally.
5. **[Type III · cross-cutting] Bump `const version` to 0.21.0** (W4-1 / W4-4) so the binary agrees with SECURITY.md / README / TLS guide.
6. Remaining Type III: sub-minute lock durations in seconds and collapse the duplicate lock line; human wait in the WebDAV `429` body; live locked-peer readout in `tls status`/GUI; `--auth-limit`/`--tls*` in curated `--help`; unknown-top-level "unknown command" line; registry usage on flag-parse errors; concrete flag summaries for `get/list/remove/stats`; per-entry-point leftovers remedy (`VAULT_DIR` vs `--vault`); doc notes (account-ceiling interaction, `/64` sharing, plain-restart recovery, three-recoveries residual, GUI-login-row caveat, `qrencode`, migration-note group-verb wording, `tls` in the enumerated list).
