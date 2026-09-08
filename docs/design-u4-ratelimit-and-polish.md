# Design — Phase U4: rate limiting and lockout for network-exposed auth, and the polish backlog

STATUS: Revision 2 — the 7 conditions of the pre-code review (`docs/review-u4-predesign.md`, GO_WITH_CONDITIONS; 56 judged / 46 refuted / 0 blockers) are applied below and in §8. Ready to build.

## 1. Goal and scope

U3 made the GUI and WebDAV endpoint reachable from other devices over TLS, and SECURITY.md names
the residual honestly: "the GUI login and WebDAV Basic auth become network-facing (rate limiting
and lockout are a later phase)." U4 is that phase. It also clears the Type III polish backlog the
U2 and U3 friction reviews accumulated, in a file-disjoint track so the two ship together.

- **Track R (rate limiting + lockout):** a dependency-free `internal/authlimit` package, wired into
  every credential-checking surface (WebDAV Basic auth, the GUI login, launch-link redemption,
  the vault-password open, recovery-phrase redeem), with app-config knobs, a loud emergency off
  switch, `Retry-After` semantics, operator-visible logging, and end-to-end tests through the real
  `gui`/`serve` startup path (the U3 wiring lesson).
- **Track P (polish):** the 9 U2 + 16 U3 Type III rows and the items the U2/U3 fix tranches
  deferred, grouped by file ownership: GUI copy/behaviour, CLI/wizard, docs.

**Out of scope:** any change to credential storage or verification (argon2id GUI hash, the vault
KDF, constant-time Basic compare all untouched); CAPTCHA/2FA; distributed or persisted limits (the
limiter is per process, in memory; §6 states the residual).

## 2. Track R — `internal/authlimit`

### 2.1 Model

```
type Surface string   // "basic" (WebDAV), "login" (GUI user/password), "launch" (launch-secret redemption), "open" (vault password via /api/open), "redeem" (recovery phrase)
type Key struct { Surface Surface; Peer string /* TCP remote IP, never a header */; Account string /* username, or "" */ }
type Policy struct { FailuresBeforeLock int; Window, LockStart, LockMax, FailureDelay time.Duration; MaxKeys int }
type Limiter struct { /* mutex; map[Key]*state; clock func() time.Time; policy */ }
func New(p Policy, clock func() time.Time) *Limiter
func (l *Limiter) Check(k Key) (allowed bool, retryAfter time.Duration)   // BEFORE verifying a credential; cheap
func (l *Limiter) Fail(k Key) (locked bool, retryAfter time.Duration)     // AFTER a failed verification
func (l *Limiter) Success(k Key)                                          // AFTER a successful verification: resets that key only
```

State per key: consecutive failure count within `Window`, `lockedUntil`, `lastSeen`, and an
in-flight `pending` count. **Reservation (C4):** `Check` reserves an attempt — it increments
`pending` and denies when `failures + pending >= FailuresBeforeLock`, so N concurrent requests for
one key cannot all pass the pre-check and all reach credential verification (which against
`/api/open` would multiply the 64 MiB-per-attempt KDF cost); `Fail` and `Success` each consume one
reservation. `Fail` past `FailuresBeforeLock` locks the key for `LockStart`, doubling on each
further failure while locked or within the window, capped at `LockMax`. `Check` on a locked key
returns `allowed=false` and the remaining time. `Success` clears the key. Keys idle longer than
`Window` are eligible for eviction; the map is bounded by `MaxKeys` with oldest-`lastSeen`
eviction, so an attacker spraying source addresses cannot grow memory (I-R3); a locked key is
never evicted before its lock expires, so spraying cannot unlock the attacker's own key.

**Peer identity (C3):** an IPv4 peer is keyed by its address; an IPv6 peer is keyed by its **/64
prefix**, because any IPv6 host owns a /64 and per-attempt source rotation would otherwise let
neither key accumulate. Three keys are consulted per attempt — `{surface, peer, ""}`,
`{surface, peer, account}`, and a **per-account global ceiling** `{surface, "", account}` with a
higher threshold (`AccountFailuresBeforeLock`, default 20 within the window) — so a wrong-password
loop against one account locks that account from that peer, a sprayed-username loop from one peer
locks the peer, and a rotating-source attack on one account still meets the account ceiling. The
account ceiling is itself a lockout lever against a legitimate user (§6), which is why its
threshold is higher and its lock is capped at `LockMax` like the others.

Defaults (all in app config `auth.limits`, normalized): FailuresBeforeLock 5,
AccountFailuresBeforeLock 20, Window 15m, LockStart 30s, LockMax 15m, FailureDelay 250ms,
MaxKeys 10000.

### 2.2 Where it is wired (every surface, proven end to end)

| Surface | Where | On locked `Check` | On `Fail` |
|---|---|---|---|
| basic | `internal/localdav` before the constant-time compare | `429 Too Many Requests` + `Retry-After: <s>` (the `WWW-Authenticate` challenge is NOT sent, so clients stop re-prompting) | after `FailureDelay` sleep, then `401` as today |
| login | `internal/webui` GUI login handler (a form POST) before hash verification | `429` re-rendering the HTML login template with "too many failed attempts; try again in N minutes" and a `Retry-After` header (C6) | `FailureDelay` then the existing failure re-render |
| launch | `handleLaunch` before comparing the launch secret — **throttle only, never lock (C1)**: the 256-bit secret is the defense, and a lock here would deny the only bootstrap path to a session | never `429`; the no-session page shows the throttle reason | `FailureDelay` then `403` as today; the correct secret always redeems immediately |
| open | `/api/open` before the vault unwrap (the KDF is the main cost; the limiter bounds attempts) | `429` JSON `{error, retryAfterSeconds}` + `Retry-After` (C6) | as above |
| redeem | `/api/recovery/redeem` only — **throttle only, never lock (C2)**: a fumbled 24-word phrase must never lock the last-resort path. The CLI redeem is NOT a limited surface: a single-shot process starts with an empty map and can never accumulate, so it gets a plain fixed `FailureDelay` and no limiter reference | never `429`; the JSON error carries `retryAfterSeconds` for the delay | `FailureDelay` then the existing typed error |

The peer is the TCP remote address from the connection (`r.RemoteAddr`), never `X-Forwarded-For`
or any header (I-R1). The limiter runs on loopback binds too: a local misbehaving client is the
most common source of a retry storm, and a locked key never denies anything but repeated failures
of the same credential class (§6 explains the trade-off and the escape hatch).

**Emergency off switch (C7):** `--auth-limit off` on `gui` and `serve` (and `auth.limits.enabled=false`
in config) disables the limiter with a loud startup warning naming the flag; it is never the
default. Because a config-file disable survives restarts, the disable is recorded with a timestamp
(`auth.limits.disabledSince`), the warning is **re-emitted hourly while running** (and on any burst
of network-facing failures), and `tls status` and the GUI settings page read "auth limits: OFF
since <date> — re-enable with `--auth-limit on` or `auth.limits.enabled=true`".

**Operator visibility (C6):** each lock logs one line in operator words — `auth-limit: locked WebDAV
auth for 192.0.2.7 (user "vault") for 2 minutes after 5 failures; unlocks automatically, or restart
with --auth-limit off for an incident` — with the surface enum mapped to words (basic → "WebDAV
auth", login → "GUI login", launch → "launch link", open → "vault open", redeem → "recovery
redeem"), durations in minutes, and never the credential; unlock is silent. Every locked-surface
response carries `Retry-After` and, for JSON surfaces, `{error, retryAfterSeconds}`; the
no-session page renders the reason and a countdown for the session-gating surfaces. The GUI
banner shows the viewer's own lock state for the post-login surfaces (`open`, `redeem`) only — it
is unreachable, by construction, for `basic`, `login`, and `launch` (§6).

### 2.3 Startup exposure note (friction A3-c5, moved here to avoid a file conflict)

`gui` and `serve` print, for any non-loopback bind, one line at startup: "serving DECRYPTED content
beyond this machine; prefer a VPN/Tailscale over an open LAN; auth limits: on (5 failures → 30s…15m)".

## 3. Track P — the polish backlog

**P-GUI (`internal/webui`):** GUI-OWN 4 (the read-back error names the 1-based index of the first
differing word — the server holds the pending phrase; no phrase material in the response); GUI-OWN 5
(drop the raw-ID column, keep the handle); GUI-OWN 6 (GUI-neutral rollback wording and label);
GUI-D2 1 (clear `setupSkipped` on `/api/close`); GUI-D2 2 ("enter its folder path"); GUI-D2 3
(match hint / name-this-key input); GUI-D2 5 (redeem placeholder); GUI-D2 6 (one advanced toggle,
relabeled "Keep advanced visible"); the DOCS-2 disclaimer reworded to cover the unknown-word case.

**P-CLI (`cmd/seavault`, `internal/setup/tlswizard.go`):** CLI-1 (leaf `--help` for `init`,
`put`, `gc`, `gui`, `move` rendered from the registry; `app-config` and `gui` modelled as groups so
C7 holds; unknown subcommand exits 2); DOCS-1 (`keychain delete` prints "no keychain entry for
<vault>" plainly, raw error under `--debug`); CLI 4 (`init` applies the leftovers classification);
U3 wizard rows A1-c2 (no raw Go error prefix; remedy names "choose Tailscale again from this menu"),
A1-c3 (allowlist prompt: "names not on this list are refused with 403; include every name a device
will type"), A1-c4 (serve port always offset from the gui port), A1-c6 (Tailscale renewal
scheduled monthly, not daily; note it is not an idempotent renew), A2-c2 (compact "still waiting"
line; re-check files immediately after Enter), A2-c3 (bring-your-own gets its own renewal recipe),
A3-c3 (de-duplicate SANs; after keep-self-signed say it cannot map a Windows drive and how to
re-run), A3-c4 (bind-refusal message suggests `--tls` first when a cert is configured).

**P-DOCS (`README.md`, `docs/`, `SECURITY.md`):** A3-c1 ("which route am I?" decision aid, routing
the no-domain/no-VPN LAN user to bring-your-own + client root install); A3-c2 (the UNC
`\\host@SSL@port\` form for `net use`); A3-c5 (per-OS firewall commands: `netsh advfirewall` scoped
to the LAN subnet, `ufw`, `nftables`); A1-c5 (reaching a headless host from a phone); CLI 6 (the
bare-group exit-code change in a migration note for scripts); DOCS 2 (redeem is single-use; re-mint
after redeeming); SECURITY.md network-exposed mode updated: the rate-limit residual becomes a
guarantee (I-R1..I-R7) with the new residuals in §6.

## 4. Security invariants (proven by §5 unless labeled)

- **I-R1** The limiter never weakens authentication: a locked key is denied before any credential
  is examined; unlock happens only by time; the peer is the TCP address, never a header.
- **I-R2** No credential, hash, launch secret, or phrase appears in any limiter log line or 429
  body.
- **I-R3** Memory is bounded by `MaxKeys` with oldest-idle eviction; a spray of 20,000 peers leaves
  at most `MaxKeys` entries.
- **I-R4** The limiter is on by default on every bind including loopback; the off switch is
  explicit, logged loudly at startup, and visible in status.
- **I-R5** The constant-time Basic compare and the argon2id GUI verification are unchanged (their
  pre-U4 tests untouched and green).
- **I-R6** `Success` resets only its own key; one client's success never unlocks another peer.
- **I-R7** Limits are per process and in memory: a restart clears them (labeled residual, §6).
- **I-R8** An IPv6 peer is keyed by its /64 and every account has a global failure ceiling, so
  per-attempt source rotation cannot keep an account unprotected (C3).
- **I-R9** The `launch` and `redeem` surfaces are throttled but never locked: the correct launch
  secret and a correct recovery phrase always succeed immediately after any burst (C1, C2).
- **I-R10** `FailuresBeforeLock` is an upper bound on credential verifications per lock cycle even
  under concurrency, by reservation at `Check` (C4).
- **I-P1** (C5) Track P is copy, help rendering, and messages EXCEPT four behaviour changes, each
  with a behaviour test rather than a copy assertion: GUI-OWN 4 (the server computes the 1-based
  index of the first differing read-back word), GUI-D2 1 (`/api/close` clears `setupSkipped`),
  CLI-1 (an unknown subcommand exits 2; leaf `--help` renders from the registry), and CLI 4
  (`init` applies the leftovers classification). Pre-U4 tests those changes must touch are listed
  in the Z1 exemption list (§8) with reasons; everything else is unedited and the unfiltered suite
  stays green.

## 5. Test matrix (red-first; every row asserts; real listeners)

| ID | Proves | How |
|---|---|---|
| L1 | §2.1 policy | table over (failures, elapsed) with an injected clock: allowed/locked and `retryAfter` per row; doubling to the cap; window expiry; `Success` reset |
| L2 | I-R3 | spray 20,000 distinct peers → `len(map) <= MaxKeys`; the oldest-idle key was evicted first |
| L3 | I-R6 | two peers, one account: peer A locks, peer B still allowed; A's success after unlock resets only A |
| L4 | concurrency | `-race`: 50 goroutines hammering `Fail`/`Check` on one key; counts are exact |
| B1 | basic, end to end | real `serve` startup (the U3 integration harness) on a TLS or loopback listener; 5 wrong Basic attempts → 401s with the `FailureDelay` measured; the 6th → `429` + `Retry-After`, no `WWW-Authenticate`; correct credentials while locked → still `429`; after the injected clock passes → `200`; a second peer unaffected |
| G1 | login/launch/open/redeem, end to end | real `gui` startup: a burst of wrong form-POST logins → `429` re-rendering the login template with the minutes countdown and `Retry-After`; wrong launch-secret guesses → `403` each after a measured `FailureDelay` and **never** `429`, and the correct secret redeems immediately after the burst (I-R9); wrong `/api/open` passwords → `429` JSON `{error, retryAfterSeconds}` + `Retry-After`; wrong redeem phrases → throttled, never `429`, and a correct phrase after the burst still redeems (I-R9); success resets |
| L5 | I-R10 | `FailuresBeforeLock + K` concurrent verifications against one key through the real handler under `-race`: at most `FailuresBeforeLock` reach credential verification (count the verifier calls) |
| K1 | I-R8 | K attempts from K distinct addresses in one IPv6 /64 against one account → the peer key locks; N attempts from N distinct IPv4 peers against one account → the account ceiling locks at `AccountFailuresBeforeLock`; a different account from the same peers is unaffected |
| H1 | I-R1 | requests carrying `X-Forwarded-For` / `X-Real-IP` are keyed by the TCP peer, not the header; an IPv4-mapped IPv6 peer keys as its IPv4 |
| S1 | I-R2 | capture the log sink and every 429 body and login re-render across B1/G1: no credential, hash, secret, or phrase substring; every lock line uses the operator words and a minutes duration |
| O1 | I-R4, C7 | `--auth-limit off` prints the loud warning and disables (burst → no 429); a config-file disable records `disabledSince`, and driving the injected clock past an hour re-emits the warning; `tls status` and the settings page show "auth limits: OFF since <date>" with the re-enable remedy; default is on |
| W2 | C2 | grep: the CLI redeem path in `cmd/seavault` has no `authlimit` reference (a fixed `FailureDelay` only) |
| W1 | wiring | grep: `authlimit.` is called from `internal/localdav` and `internal/webui` (non-test); B1/G1 run through the real command startup |
| X1 | §2.3 | non-loopback bind prints the exposure line; loopback does not |
| P1–P3 | Track P rows | each copy/help/message row asserted (server-rendered markup or captured CLI output), one assertion per row, table-driven where rows share a shape; the four BEHAVIOUR rows (I-P1) get behaviour tests: the read-back error carries the correct 1-based index for a phrase with word k mistyped (and no phrase material); `/api/close` clears `setupSkipped` so the next index render is Welcome-back; an unknown subcommand exits 2 and `init --help` / `put --help` render the registry row; `init` on a leftovers directory returns the leftovers remedy |
| Z1 | I-P1, I-R5 | pre-U4 tests unmodified except via the exemption list; localdav Basic-auth and webui login tests green unchanged; unfiltered race suite green |

## 6. Residuals and trade-offs (stated in SECURITY.md)

Per-process, in-memory limits reset on restart (an attacker who can restart the process already
has local control). A shared NAT or a loopback host can lock legitimate clients behind a
misbehaving one for up to `LockMax`; the lock line names the peer and account, the GUI banner
tells the viewer for the post-login surfaces only (`basic`, `login`, and `launch` cannot show a
banner — the operator learns from the log line, the `Retry-After` header, and the no-session
page), and the off switch exists for an incident. The **per-account ceiling** (I-R8) is itself a
lever: an attacker who knows a username can lock that account for everyone for up to `LockMax`
from rotating sources; the higher threshold and the cap bound it, and SECURITY.md says so plainly.
Keying IPv6 by /64 means a whole /64 shares a peer key (a household or a hosting tenant). A source
rotating across many /64s or many IPv4 addresses still meets the account ceiling but is otherwise
a distributed attack, out of scope (labeled). `FailureDelay` sleeps are bounded by the lockout and
capped per process by Go's goroutine cost. The launch secret and recovery phrase are high-entropy,
so those surfaces are throttled, never locked: their `FailureDelay` is hygiene, not the defense,
and a correct secret always succeeds immediately.

## 7. Build order

R1 (`internal/authlimit` + L1–L4) → R2 (wire every surface, flags/config, startup note, B1/G1/H1/S1/
O1/W1/W2/X1, L5, K1) → P1 (GUI rows) → P2 (CLI/wizard rows) → P3 (docs rows, SECURITY.md,
changelog, final unfiltered verify + smoke). Each slice: builder, independent verifier, one fix
cycle. The final verifier greps that every designed component has a non-test caller and re-runs
B1/G1 through the real startup path.

## 8. Revision 2 — how each review condition was applied

| Cond | Applied as |
|---|---|
| C1 | §2.2 `launch` is throttle-only (never `429`); the correct secret always redeems; I-R9; G1 amended |
| C2 | §2.2 `redeem` is throttle-only; the CLI redeem is not a limited surface (fixed `FailureDelay`, no limiter reference); I-R9; G1 amended; W2 |
| C3 | §2.1 IPv6 peers keyed by /64 and a per-account global ceiling (`AccountFailuresBeforeLock` 20); I-R8; K1; §6 states the account-lever and /64-sharing residuals; SECURITY.md discloses source rotation beyond that |
| C4 | §2.1 reservation at `Check` (pending count) so `FailuresBeforeLock` bounds verifications under concurrency; I-R10; L5 |
| C5 | I-P1 names the four behaviour changes with behaviour tests (P1–P3 amended); Z1 exemption entries listed below |
| C6 | §2.2 login is a form re-render with a minutes countdown; `open` gets a JSON body + `Retry-After`; lock lines use operator words, minutes, and the remedy; the banner's coverage limit is stated in §2.2 and §6; S1/G1 amended |
| C7 | §2.2 config-file disable records `disabledSince`, re-emits hourly, and shows in `tls status`/settings with the re-enable remedy; O1 amended |

**Z1 exemption entries the build will add to `cmd/seavault/testdata/accepted-test-edits.txt`
(each is a reviewed diff):** any pre-U4 test that asserted the old non-2 exit code for an unknown
subcommand or the old single-dash leaf `--help` output (CLI-1), and any pre-U4 test that asserted
`setupSkipped` persisting across `/api/close` (GUI-D2 1). If no pre-U4 test asserts those, no
entry is needed; the builder states which case applies.
