# Design — Phase U4: rate limiting and lockout for network-exposed auth, and the polish backlog

STATUS: pre-code design, awaiting the 10-lens review. Revision 1.

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

State per key: consecutive failure count within `Window`, `lockedUntil`, `lastSeen`. `Fail` past
`FailuresBeforeLock` locks the key for `LockStart`, doubling on each further failure while locked
or within the window, capped at `LockMax`. `Check` on a locked key returns `allowed=false` and the
remaining time. `Success` clears the key. Keys idle longer than `Window` are eligible for eviction;
the map is bounded by `MaxKeys` with oldest-`lastSeen` eviction, so an attacker spraying source
addresses cannot grow memory (I-R3). Two keys are consulted per attempt — `{surface, peer, ""}`
and `{surface, peer, account}` — so a wrong-password loop against one account locks that account
from that peer, and a sprayed-username loop from one peer locks the peer.

Defaults (all in app config `auth.limits`, normalized): FailuresBeforeLock 5, Window 15m,
LockStart 30s, LockMax 15m, FailureDelay 250ms, MaxKeys 10000.

### 2.2 Where it is wired (every surface, proven end to end)

| Surface | Where | On locked `Check` | On `Fail` |
|---|---|---|---|
| basic | `internal/localdav` before the constant-time compare | `429 Too Many Requests` + `Retry-After: <s>` (the `WWW-Authenticate` challenge is NOT sent, so clients stop re-prompting) | after `FailureDelay` sleep, then `401` as today |
| login | `internal/webui` GUI login handler before hash verification | `429` JSON `{error, retryAfterSeconds}`; the login page shows "too many failed attempts; try again in N seconds" | `FailureDelay` then the existing failure response |
| launch | `handleLaunch` before comparing the launch secret | `429` | as above |
| open | `/api/open` before the vault unwrap (the KDF is the main cost; the limiter bounds attempts) | `429` JSON | as above |
| redeem | `/api/recovery/redeem` and the CLI redeem path share the same limiter policy (the CLI is local; the limiter still applies per process) | `429` / typed CLI error | as above |

The peer is the TCP remote address from the connection (`r.RemoteAddr`), never `X-Forwarded-For`
or any header (I-R1). The limiter runs on loopback binds too: a local misbehaving client is the
most common source of a retry storm, and a locked key never denies anything but repeated failures
of the same credential class (§6 explains the trade-off and the escape hatch).

**Emergency off switch:** `--auth-limit off` on `gui` and `serve` (and `auth.limits.enabled=false`
in config) disables the limiter with a loud startup warning naming the flag; it is never the
default, and `tls status`/the GUI settings page show "auth limits: off" when it is.

**Operator visibility:** each lock logs one line `auth-limit: locked <surface> for <peer>[/<account>]
for <duration> after <n> failures` (never the credential); unlock is silent; a GUI banner shows the
viewer's own lock state.

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
- **I-P1** Track P changes copy, help rendering, and messages only; no pre-U4 test is edited
  except through the Z1 exemption list, and the unfiltered suite stays green.

## 5. Test matrix (red-first; every row asserts; real listeners)

| ID | Proves | How |
|---|---|---|
| L1 | §2.1 policy | table over (failures, elapsed) with an injected clock: allowed/locked and `retryAfter` per row; doubling to the cap; window expiry; `Success` reset |
| L2 | I-R3 | spray 20,000 distinct peers → `len(map) <= MaxKeys`; the oldest-idle key was evicted first |
| L3 | I-R6 | two peers, one account: peer A locks, peer B still allowed; A's success after unlock resets only A |
| L4 | concurrency | `-race`: 50 goroutines hammering `Fail`/`Check` on one key; counts are exact |
| B1 | basic, end to end | real `serve` startup (the U3 integration harness) on a TLS or loopback listener; 5 wrong Basic attempts → 401s with the `FailureDelay` measured; the 6th → `429` + `Retry-After`, no `WWW-Authenticate`; correct credentials while locked → still `429`; after the injected clock passes → `200`; a second peer unaffected |
| G1 | login/launch/open/redeem, end to end | real `gui` startup: burst of wrong logins → `429` JSON with `retryAfterSeconds`; launch-secret guesses → `429`; wrong `/api/open` passwords → `429`; wrong redeem phrases → `429`; success resets |
| H1 | I-R1 | requests carrying `X-Forwarded-For` / `X-Real-IP` are keyed by the TCP peer, not the header |
| S1 | I-R2 | capture the log sink and every 429 body across B1/G1: no credential, hash, secret, or phrase substring |
| O1 | I-R4 | `--auth-limit off` prints the loud warning and disables (burst → no 429); status reports "off"; default is on |
| W1 | wiring | grep: `authlimit.` is called from `internal/localdav` and `internal/webui` (non-test); B1/G1 run through the real command startup |
| X1 | §2.3 | non-loopback bind prints the exposure line; loopback does not |
| P1–P3 | Track P rows | each copy/help/message row asserted (server-rendered markup or captured CLI output), one assertion per row, table-driven where rows share a shape |
| Z1 | I-P1, I-R5 | pre-U4 tests unmodified except via the exemption list; localdav Basic-auth and webui login tests green unchanged; unfiltered race suite green |

## 6. Residuals and trade-offs (stated in SECURITY.md)

Per-process, in-memory limits reset on restart (an attacker who can restart the process already
has local control). A shared NAT or a loopback host can lock legitimate clients behind a
misbehaving one for up to `LockMax`; the lock line names the peer and account, the GUI banner
tells the viewer, and the off switch exists for an incident. `FailureDelay` sleeps are bounded by
the lockout and capped per process by Go's goroutine cost; a distributed attack is out of scope
(labeled). The launch secret and recovery phrase are high-entropy; their limits are hygiene, not
the defense.

## 7. Build order

R1 (`internal/authlimit` + L1–L4) → R2 (wire every surface, flags/config, startup note, B1/G1/H1/S1/
O1/W1/X1) → P1 (GUI rows) → P2 (CLI/wizard rows) → P3 (docs rows, SECURITY.md, changelog, final
unfiltered verify + smoke). Each slice: builder, independent verifier, one fix cycle. The final
verifier greps that every designed component has a non-test caller and re-runs B1/G1 through the
real startup path.
