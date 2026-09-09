# Adversarial review — Phase U4 (rate limiting + Track P polish)

**What.** Independent adversarial review of the BUILT Phase U4 on branch
`feature/u4-polish-ratelimit` (commit `c574a39`), covering the `internal/authlimit`
limiter (reservation-at-Check, IPv6 /64 peer keys, per-account ceiling, doubling
lockout, bounded eviction, FailureDelay), its wiring into WebDAV Basic auth
(`internal/localdav`), the GUI login form and `handleLaunch`/`/api/open`/
`/api/recovery/redeem` (`internal/webui`), the `--auth-limit on|off` off-switch and
`auth.limits` config, operator lock/exposure lines, and the Track P polish rows.

**Process.** Every claim was reproduced against the real binary
(`go build -o /tmp/sv-u4/seavault ./cmd/seavault`) with all state isolated
(`SEAVAULT_APP_HOME`/`HOME` in fresh temp dirs, `--no-keychain`, headless curl through
the real `/api/*` and WebDAV Basic serve), or against the real production types in
`internal/authlimit`/`internal/appconfig` via deterministic Go tests (several under
`-race`) where the binary could not surface the property. A skeptic pass then attempted
to refute each finding on the real code; only survivors are reported below.

**Model.** claude-opus-4-8.

**Counts.** 18 candidate findings examined → **15 confirmed** → **13 after dedup**
(2 duplicate pairs merged); **3 refuted**.

Deduped: `concurrency-reservation-3` folded into `peer-spoofing-2` (one defect: the GUI
login keychain-read-error path calls `Attempt.Success()`, over-clearing all three keys);
`off-switch-config-1` folded into `leakage-copy-1` (one defect: `--auth-limit on` over a
persisted `enabled=false` runs an active limiter but every status readout says "OFF").

## Confirmed findings (most severe first)

| id | sev | title | repro (abridged) | fix (abridged) |
|----|-----|-------|-----------------|----------------|
| lockout-dos-1 | medium | I-R3 memory bound is false when sprayed peers lock — map grows unbounded (20× MaxKeys shown) | Real Limiter, MaxKeys=1000; lock 20000 distinct /64 peers (5 fails each) → `len(l.keys)==20000`. `evictOneLocked` skips every locked key and `getOrCreateLocked` adds anyway. Unlocked spray stays at 1000. The L2 test sprays only unlocked keys. | Weaken I-R3 wording (bound holds for unlocked keys only) AND add a hard total-key ceiling: past the cap, evict the oldest *locked* key rather than grow. Add an L2 locked-spray row. |
| lockout-dos-2 | medium | Account-ceiling lockout of the owner is indefinite (not "up to lockMax") and needs no username | Real serve, `--user seavault`: 20 wrong PROPFINDs across 5 loopback sources (4 each, under the peer threshold) lock the account; the owner on a fresh source with the *correct* password gets `429`. Day-long sim: owner denied 100% at ~0.8 fails/min. | Correct SECURITY.md: the cap bounds each lock, not the aggregate (re-trigger → indefinite); the public default `--user seavault` removes the "knows a username" precondition. Recommend/randomize a non-default `--user`; stop printing the default so plainly. |
| concurrency-reservation-1 | medium | Eviction of a key holding in-flight reservations resets `pending`, breaking the I-R10/C4 concurrency bound | Deterministic -race test on real Check/getOrCreateLocked/evictOneLocked, MaxKeys=1, FailuresBeforeLock=3: 3 Checks granted (pending=3); a Check on a new peer evicts the unlocked target; 3 more granted → **6 live reservations on a threshold-3 key**. `maxKeys` is operator-settable, so reachable at small configured caps. | In `evictOneLocked` also skip any key with `st.pending>0`; if all keys are locked-or-pending, grow by one instead of evicting. Ship the -race regression test. |
| leakage-copy-1 | medium | `--auth-limit on` over persisted `enabled=false` runs an ACTIVE limiter but every status readout falsely says "OFF since <date> — re-enable" | Persist `auth.limits.enabled=false`+`disabledSince`; start `serve --addr 0.0.0.0:… --insecure-bind --auth-limit on`. Startup **exposure line** and GUI `/api/status authLimitStatus` both read "OFF since …", yet a wrong-Basic burst returns `429` at attempt 6 (limiter proven on). One-way (never overstates protection). | In `startAuthLimit`'s enabled branch render status from an EFFECTIVE copy (`eff.Enabled=true`, `DisabledSince` cleared), mirroring the disabled branch. Add an O1/X1 row: persisted-off + flag-on → both readouts say "on" and a burst returns 429. |
| off-switch-config-2 | medium | A degenerate-but-valid config value (`auth.limits.window="1ns"`, or a huge threshold) silently disables the limiter while status still says "on" | Real packages: `Window=1ns` → `refreshLocked` resets the streak between any two real attempts, so no key ever locks; 50 Check→Fail never lock. `normalizeAuthLimits` only guards the lower edge; StatusLine reports "on (5 → 30s…15m)" and omits Window. `FailuresBeforeLock=2000000000` likewise accepted. Status lies in the dangerous direction. | Floor `Window`/`LockStart`/`LockMax` to sane minima and cap the thresholds/`MaxKeys` (out-of-range → default); and/or surface `Window` in StatusLine. Add a normalize row asserting a tiny window and a huge threshold are clamped. |
| polish-behaviour-1 | medium | `serve` bind-refusal never suggests `--tls` when a cert is configured (A3-c4 not delivered) | With a cert in config, `serve --addr <lan>` (no `--tls`) → exit 1 telling the user to "set up TLS first: run `seavault tls setup`" — the step they just did — and never names `--tls`, while `serve --tls` and `gui` (auto-activates the cert) both bind. Message is byte-identical with/without a cert. | Thread a `certConfigured` signal from `cmdServe` into `ensureLoopbackBind`; when set, lead with "pass `--tls` to serve over the configured certificate". Or auto-activate a configured cert like `gui`. Extend `TestBindRefusalLeadsWithTLSRoute` with a configured-cert row. |
| wiring-1 | low | `--auth-limit on\|off` (C7) missing from `gui`/`serve` leaf `--help` while the same command's flagset error usage lists it | `gui --help`/`serve --help` (registry) omit `--auth-limit` (and, for gui, `--tls-cert/--tls-key/--exit-on-browser-close`); `serve`/`gui` no-/bad-arg flagset usage DOES list `--auth-limit` → the two usage strings for one command contradict. `gui --auth-limit bogus` errors, proving the flag exists. | Add the flags to the registry `usage` strings for the serve/gui rows in `cmd/seavault/commands.go:281-282`; add a P-CLI row asserting both `--help` outputs name `--auth-limit`. |
| wiring-2 | low | C6/§2.2 no-session throttle reason + countdown and the proactive open/redeem lock banner are not wired | `curl '…/?launch=wrongsecret'` → bare `403 forbidden: invalid launch secret`, never the friendly no-session page or any throttle text. `noSessionPage` has no lock/countdown markup; `authlimit` exports no Locked/IsLocked query, so no persistent banner can be driven. Impact negligible (launch/redeem are throttle-only, never lock) but the designed component is absent. | Build it (route the wrong-secret to the no-session page + a read-only Limiter query feeding a banner) OR correct §2.2/C6/§6 to say the reason/countdown/banner are intentionally omitted because launch/redeem never lock. |
| wiring-3 | low | Operator lock line says "1 minute" for the 30-second first lock, disagreeing with `Retry-After` on the same response | 6th wrong Basic attempt → stderr "locked … for 1 minute" while the response carries `Retry-After: 30`; same on `/api/open` (log "1 minute" vs body `retryAfterSeconds:30`). `minutesPhrase` rounds up and floors at a minute. | Render sub-minute locks honestly ("30 seconds"), or set default `LockStart` to a whole minute; assert `LockLine` duration matches `Retry-After` for the first lock. |
| lockout-dos-5 | low | Account-ceiling lock line prints an empty peer with a double space: `locked WebDAV auth for  (user "seavault")` | Real serve, after the account-ceiling lock: stderr shows `for  (user "seavault")` — two spaces, no source — because `k.Peer==""` feeds `who = fmt.Sprintf("%s (user %q)", "", account)`. Cosmetic; no credential leak. | In `LockLine`, when `k.Peer==""` render distinctly, e.g. `account %q (from any source)`, removing the stray space and naming the whole-account lock. |
| peer-spoofing-2 | low | GUI login keychain-read-error path calls `Attempt.Success()` (clearing failures/lock on all three keys, incl. the shared account ceiling) instead of releasing only the reservation | Static path (legacy keychain GUI auth, `cfg.GUI.PasswordHash` empty, keychain unreadable): `handleLogin` else-branch reads `keychain.Get`; on err calls `loginAttempt.Success()`, whose comment says "release without counting" but which zeroes failures/lockLen/lockedUntil/lastFailure on the peer, peer+account, and shared `{login,"",account}` keys. Not attacker-controllable; harm is state-masking. `Attempt` exposes only Fail/Success. | Add an exported `Attempt.Release()` (wrapping the unexported `Limiter.release`, authlimit.go:301-310) that only decrements `pending`, and call it on the keychain-read-error branch. Do not reset streak/lock on an infrastructure error. |
| concurrency-reservation-2 | low | `pending` reservations never decay → any leaked reservation is a permanent, time-incurable, cross-peer lockout; consumption is not defer/recover-guarded | -race test on production code: 3 Checks with no Fail/Success, advance clock 1h (past Window/lock) → `Check allowed=false retryAfter=0 pending=3 failures=0 locked=false` — denied forever, only a restart cures. `refreshLocked` resets failures but pointedly leaves `pending`; lock expiry never touches it. No live panic today (typed errors), but a shared `{surface,"",account}` leak would deny an account from all sources. | (a) In `refreshLocked` set `pending=0` on a Window-stale unlocked streak (a real KDF finishes in ms). (b) defer-guard consumption per handler or add a router-level recover. (c) optionally clamp `pending` at `FailuresBeforeLock`. |
| polish-behaviour-2 | low | `init` leftovers-directory remedy names a `--vault` flag that `init` does not have | `seavault init <leftovers-dir>` → "…remove that directory and re-run, or choose a different `--vault`". `annotateSetupError` is shared with `setup --preset` (which has `--vault`); `init` takes a positional `VAULT_DIR` (confirmed via `init --help`). | Give `cmdInit` its own remedy naming the positional arg ("…or pass a different `VAULT_DIR`"), or parameterize `annotateSetupError` with the command's argument name. |

## Refuted (did not survive the skeptic pass)

- **lockout-dos-3 — "FailureDelay sleeps are not bounded / unbounded goroutine holding on the never-lock launch surface."**
  Refuted by the design and SECURITY.md, which already disclose this as by-design:
  *design-u4-ratelimit-and-polish.md:192-194* — "`FailureDelay` sleeps are bounded by the
  lockout and capped per process by Go's goroutine cost. The launch secret and recovery
  phrase are high-entropy, so those surfaces are throttled, never locked: their
  `FailureDelay` is hygiene, not the defense" — and *SECURITY.md:36-37* — "NOT bounded (by
  design): … the total number of connections (there is no connection cap)."

- **lockout-dos-4 — "Window expiry never resets `pending`; a handler that skips Fail/Success (e.g. a panic) leaks a permanent per-key denial."**
  The *property* is real and is captured by the confirmed `concurrency-reservation-2`; the
  distinct *reachability* claim here (a `vault.Open` panic) is refuted: all three locking
  handlers consume on every reachable path (authorizeBasic server.go:323/326; handleLogin
  1265/1274/1284; handleOpen 1741/1758 — only the `!allowed` branch returns early,
  reserving nothing), and the hypothesized panic is unreachable — the sole vault panic
  (crypto.go:373) is guarded by `NormalizeKDFConfig` flooring Iterations (crypto.go:109-111)
  before `pbkdf2Key` (crypto.go:208). Kept as latent fragility under
  `concurrency-reservation-2`, not a live leak.

- **peer-spoofing-1 — "Fronting the listener with a reverse proxy silently collapses per-peer keying (mass lockout / defeated ceilings) and nothing warns of it."**
  Refuted: the collapse is disclosed — *SECURITY.md:273-276* "**Shared NAT and /64 sharing.**
  The peer key is the TCP source address … a **shared NAT**, a household, a hosting tenant,
  or a misbehaving loopback client can therefore lock legitimate clients that share that key
  for up to `lockMax`," plus *SECURITY.md:286* "Prefer a VPN for any exposed deployment." The
  correct behavior is also tested: `cmd/seavault/authlimit_wiring_u4_test.go:479-500` runs the
  finding's own header-spoof repro against a real serve daemon and asserts it locks at the
  sixth attempt (headers ignored, TCP peer is the key, I-R1); test passes.

## Fix-tranche ordering

**Tranche 1 — security-invariant correctness (code, do first).** These make a stated
invariant false or defeat the limiter under reachable conditions.
1. `concurrency-reservation-1` — non-evictable `pending>0` keys (restores I-R10/C4).
2. `lockout-dos-1` — hard total-key ceiling / evict-oldest-locked (restores an I-R3 bound).
3. `off-switch-config-2` — clamp degenerate `Window`/thresholds (limiter can't be silently neutralized).
4. `concurrency-reservation-2` — decay `pending` in `refreshLocked` + defer/recover-guard consumption (self-heal + no future cross-peer leak).

**Tranche 2 — honest security-status readout (code).**
5. `leakage-copy-1` — effective status line when the flag overrides a persisted disable (exposure line + `/api/status` stop lying "OFF").

**Tranche 3 — disclosure corrections (docs, no code).**
6. `lockout-dos-2` — correct SECURITY.md on the account-ceiling (indefinite, default-username precondition) and recommend a non-default `--user`.
7. `wiring-2` — reconcile design §2.2/C6/§6 with the shipped throttle-only reality (or build the missing component).

**Tranche 4 — operator/UX polish (low, ship together).**
8. `polish-behaviour-1` — `serve` bind-refusal leads with `--tls` when a cert is configured.
9. `wiring-1` — `--auth-limit` in `serve`/`gui` `--help` usage + P-CLI test.
10. `wiring-3` — sub-minute operator lock line matches `Retry-After`.
11. `lockout-dos-5` — account-ceiling lock line (no empty peer / double space).
12. `peer-spoofing-2` — add `Attempt.Release()`, use it on the keychain-read-error branch (also removes the forced over-clear behind concurrency-reservation-2's login case).
13. `polish-behaviour-2` — `init` remedy names `VAULT_DIR`, not `--vault`.

Every code fix ships prove-fail → prove-pass with its regression test, per the repo's
testing discipline (no gate weakened, no fixture edited to pass). The three medium
disclosure items in Tranches 2–3 that touch SECURITY.md/design invariants are
security-sensitive and owe the adversarial-pass gate before merge.

---

## Addendum — fix tranche (post-review), branch `feature/u4-polish-ratelimit`

Every confirmed finding above is fixed, red-first (regression test → neutralize →
prove RED for the right reason → restore → prove GREEN), across three file-disjoint
fixers. No gate was weakened and no fixture edited to pass; the only pre-U3/U4 test
edits are the sanctioned mechanical call-site changes recorded in
`cmd/seavault/testdata/accepted-test-edits.txt`. Commits: **F-A `cb3e590`** (limiter
core), **F-B `38c1b40`** (wiring + levers + banner), **F-C** (this commit — docs +
UX-copy + final verification). The design's §9 carries the same map.

| id | sev | fixer / commit | fix shipped |
|----|-----|----------------|-------------|
| lockout-dos-1 | med | F-A `cb3e590` | hard total-key ceiling: `evictOneLocked` evicts the oldest *locked* key when no idle victim exists, so a locked spray stays ≤ `MaxKeys`. I-R3 re-worded in SECURITY.md + design §4 (bound now stated as the hard ceiling, locked-key-last-resort, reservation never dropped). |
| lockout-dos-2 | med | F-B `38c1b40` (code) + **F-C** (docs) | non-loopback `serve` on the default username prints a startup WARNING recommending `--user`. SECURITY.md/README/TLS-guide now state plainly: the cap bounds each lock, **not the aggregate** (sustained re-triggering → effectively indefinite), the default WebDAV username is the public `seavault` (no username knowledge needed), and to pass a non-default `--user` for an exposed serve. |
| concurrency-reservation-1 | med | F-A `cb3e590` | a `pending>0` key is never an eviction victim; if every key holds a reservation the map grows by one — eviction can no longer drop a live reservation (restores I-R10/C4). -race regression shipped. |
| leakage-copy-1 | med | F-B `38c1b40` | `--auth-limit on` over a persisted disable renders every readout from an EFFECTIVE "on" state **and persists** `enabled=true` + clears `disabledSince` (C7), so a flagless restart stays protected. O1/X1 rows extended. |
| off-switch-config-2 | med | F-A `cb3e590` | `normalizeAuthLimits` floors `Window`/`LockStart`/`LockMax` and caps thresholds/`MaxKeys` (out-of-range → default); `StatusLine` surfaces `Window` — a degenerate-but-valid config can no longer silently neutralize the limiter. |
| polish-behaviour-1 | med | F-B `38c1b40` | `ensureLoopbackBind` takes a `certConfigured` signal; a configured cert with `--tls` omitted leads the refusal with "pass `--tls`". `TestBindRefusalLeadsWithTLSRoute` extended. |
| wiring-1 | low | F-B `38c1b40` | `serve`/`gui --help` name `--auth-limit on\|off` from the registry usage rows. |
| wiring-2 | low | F-B `38c1b40` | per-viewer banner + session-gated `GET /api/auth-limits/self`; a wrong `?launch=` shows the styled no-session page with the throttle reason (never a lock). |
| wiring-3 | low | F-A `cb3e590` | `LockLine` renders sub-minute locks honestly ("30 seconds"), agreeing with `Retry-After`. F-C carried the same honest phrase (one exported `authlimit.DurationPhrase`) into the WebDAV `429` body and the login/open copy (friction W1-1/W1-2/W1-4). |
| lockout-dos-5 | low | F-A `cb3e590` | account-ceiling lock line reads `account "seavault" (from any source)` — no empty peer, no double space. |
| peer-spoofing-2 | low | F-A `cb3e590` (pkg) + F-B `38c1b40` (call site) | new `Attempt.Release()` (decrement only) replaces the wrong `Success()` on the GUI keychain-read-error branch, so an infrastructure error no longer clears the streak on all three keys. |
| concurrency-reservation-2 | low | F-A `cb3e590` + F-B `38c1b40` | pending decays on a Window-stale unlocked streak, clamped at the threshold; per-handler `defer Release()` guards consumption against a panic/early return. |
| polish-behaviour-2 | low | F-B `38c1b40` | `init`'s leftovers remedy names the positional `VAULT_DIR`, not the `--vault` flag it lacks. |

**Post-tranche verdict:** all 13 confirmed findings resolved; the 3 refuted findings
required no change and stand as filed. No confirmed finding is deferred. The unfiltered
`go test -race -count=1 ./...` is green, `gofmt`/`go vet`/`go build` are clean, and the
windows/amd64 and darwin/arm64 cross-builds are clean. The three medium disclosure items
(lockout-dos-2, leakage-copy-1, and the I-R3 re-word) that touch SECURITY.md/design
invariants were treated as security-sensitive and carry their adversarial reasoning in
SECURITY.md §"Authentication rate limiting and lockout" and design §9. **Adversarial
verdict: RESOLVED.**
