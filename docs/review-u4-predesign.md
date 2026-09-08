# Pre-code design review — Phase U4 (rate limiting + polish)

**What was reviewed:** `docs/design-u4-ratelimit-and-polish.md` (Revision 1) — Track R (`internal/authlimit`: a dependency-free per-process limiter keyed by TCP peer + account, wired into five credential surfaces — WebDAV Basic auth, GUI login, launch-secret redemption, vault-password open, recovery-phrase redeem — with consecutive-failure lockout, doubling backoff, FailureDelay, bounded memory, 429 + Retry-After, a loud `--auth-limit off` switch, operator log lines, and end-to-end tests through the real `gui`/`serve` startup) and Track P (the U2/U3 Type III polish rows across GUI copy, CLI/wizard, and docs).

**Code the review is grounded in:** `internal/localdav/server.go` (Basic auth compare ~221-290), `internal/webui/server.go` (`serveNoSession` 772-789, `handleLaunch` 1105-1109, launch secret `randomBase64URL(32)` at 454, login/reset handlers, session steps 710-766), `cmd/seavault/main.go` + `commands.go`, `cmd/seavault/tls_reload_wiring_u3_test.go`, `internal/appconfig`, `SECURITY.md`, `docs/review-u2-friction.md`, `docs/review-u3-friction.md`, `docs/tls-and-certificates.md`.

**Process run:** assurance-kit `process/design-review.md` — 10 lenses, skeptic pass, rescue pass, synthesis. Repository `open-seavault-rclone`, branch `feature/u4-polish-ratelimit` (base `main` @ ebb11c9, after U2 v0.19.0 and U3 v0.20.0). **Model:** claude-opus-4-8.

---

## Verdict: GO_WITH_CONDITIONS

No blocker survived both the skeptic and the rescue pass (rescue outcome: *no blockers survived the skeptic pass; rescue not needed*). Everything that survived the skeptic is a design-time correction dischargeable by revising the design before build. The seven conditions below are the required revision; each is concrete, testable, and names the findings it closes and the test-matrix rows the build must add or change.

The through-line: the design applies the **full lockout policy uniformly to all five surfaces**, but two of them (`launch`, `redeem`) gate the *only* bootstrap / last-resort paths to a session and are protected by 256-bit / high-entropy secrets the design itself calls "hygiene, not the defense" (design:150-151). On those two, lockout buys ~zero guessing defense and creates a real self-DoS. Separately, the per-peer key is bypassable by any IPv6 host, the `Check→verify→Fail` window is not concurrency-safe, and two honesty rows (I-P1 scope, operator copy) need correction.

---

## Conditions (apply as a design revision before build)

| n | Condition | Addresses |
|---|---|---|
| 1 | **Do not lock the `launch` surface.** Apply `FailureDelay` only to `launch`; remove it from the lockout `Check`-before-compare so a locked key can never deny redemption of the current, valid launch secret. The 256-bit `randomBase64URL(32)` secret (server.go:454) is the defense, not the counter. Revise the design:29/design:57 table row (`launch | … | 429`) to "FailureDelay, no lockout" and update G1 so the launch leg asserts throttle-not-lock. | purpose-threat-fit-2, usability-friction-1, failure-recoverability-2 |
| 2 | **Redeem: throttle, do not lock; drop the CLI leg from the limiter.** Apply `FailureDelay` (or a much higher threshold) to `/api/recovery/redeem` so a fumbled 24-word phrase is throttled, never locked out of the last-resort path. Remove `authlimit` from the CLI redeem path — a single-shot process starts empty (I-R7) and can never lock; replace with a fixed `FailureDelay` and stop calling the CLI a "limited surface" (revise design:59). Add the redeem residual to §6. | failure-recoverability-3, dependency-cost-4 |
| 3 | **Close, or honestly disclose, the source-IP-rotation bypass.** Both keys (design:44-46) are peer-scoped; any IPv6 host owns a /64, so per-attempt source rotation never accumulates and the account is never protected across peers. Add a per-`{surface,account}` global ceiling and/or key IPv6 peers by /64 prefix (noting a global account lock is itself a lockout lever), or at minimum state the bypass plainly in SECURITY.md. Add a test row for the chosen mechanism. | durability-2 |
| 4 | **Make `FailuresBeforeLock` an upper bound under concurrency.** `Check` runs before verification and `Fail` after with no reservation, so N concurrent requests all pass `Check` and all `Fail`, making the per-cycle budget = concurrency, not 5 (and multiplying the 64 MB KDF cost on `/api/open`). Reserve in-flight attempts at `Check` or collapse `Check`+`Fail` into an atomic reserve/confirm. Add a concurrency row distinct from L4: `FailuresBeforeLock + K` concurrent verifications through the handler, assert at most `FailuresBeforeLock` reach verification, under `-race`. | security-adversarial-3 |
| 5 | **Correct I-P1's scope and enumerate the Z1 exemption list.** I-P1's "copy only" is false: GUI-OWN 4 (index computation), GUI-D2 1 (`setupSkipped` cleared on `/api/close`), CLI-1 (unknown subcommand exit 2 + leaf help), CLI 4 (leftovers classification) change behavior. Reword I-P1 to name them, require a behavior test per row, and list the exact Z1 exemption entries for the pre-U4 tests those changes edit. | honesty-of-claims-4 |
| 6 | **Fix operator-facing copy and locked-surface 429 bodies.** Map surface enum codes to operator words in the log line, name the remedy, format durations as minutes; correct the `login` row (HTML re-render, not JSON — server.go:1140-1166) and its G1 assertion; give `open`/any-locked 429 a `{error, retryAfterSeconds}` body + `Retry-After`, and render the reason on the no-session page for session-gating surfaces; state in §6 that the banner covers only post-login `open`/`redeem`. | usability-friction-6, failure-recoverability-2 |
| 7 | **Keep the persistent off-switch signalling while it runs.** `auth.limits.enabled=false` survives restarts with only a one-time boot warning, so a headless `serve` left off after an incident runs unprotected indefinitely. Record a disabled-since timestamp, re-emit the loud warning periodically while running, and include "disabled since \<date\>" in the warning and status. | durability-5 |

---

## Per-lens findings

| id | severity | disposition | one-line |
|---|---|---|---|
| purpose-threat-fit-1 | — | refuted | `open` lockout only locks the legit user — KDF is the cost, limiter bounds attempts. |
| purpose-threat-fit-2 | condition | confirmed | Lockout on `launch` (256-bit secret) is ~zero defense but a self-DoS on the sole path to a session → C1. |
| purpose-threat-fit-3 | — | refuted | "Drop the mounted drive" lever — §6 states trade-off, off switch exists. |
| purpose-threat-fit-4 | — | refuted | Per-account isolation has no mechanism — two-key model consulted. |
| focus-proportionality-1..5 | — | refuted (×5) | Surface count / Track split / launch+redeem ceremony — §6 hygiene note, build order, loopback rationale. |
| durability-1 | — | refuted | Port in peer key — key comment "TCP remote IP, never a header". |
| durability-2 | condition | confirmed | Peer-scoped keys → IPv6 /64 rotation guesses one account unlimited, lock never engages → C3. |
| durability-3 | — | refuted | No floors/ceilings — normalized defaults specified. |
| durability-4 | — | refuted | Unbounded lock-log flood — locked Check denied before verify; disjoint paths. |
| durability-5 | note | confirmed | Persistent `enabled=false` runs unprotected indefinitely; only a boot warning → C7. |
| durability-6 | — | refuted | Wall-clock step-back — injected clock seam. |
| durability-7 | — | refuted | CLI redeem no-op — folded into C2. |
| usability-friction-1 | condition | confirmed | Locked `launch` locks owner out of the browser; recovery is restart-only → C1. |
| usability-friction-2 | — | refuted | Limiter on forgotten-password path — loopback storms common; only repeated failures denied. |
| usability-friction-3 | — | refuted | Windows 429-no-challenge — design:133/55 specify the behavior. |
| usability-friction-4 | — | refuted | No runtime unlock — reset/login handlers + guiAuthEnabled logic. |
| usability-friction-5 | — | refuted | Doubling on human mistypes — threshold 5 / LockStart 30s / LockMax 15m. |
| usability-friction-6 | note | confirmed | Log/banner/copy carry enum jargon, N-seconds waits, a JSON claim for an HTML login, unreachable banner → C6. |
| security-adversarial-1 | — | refuted | Port in peer key — key comment. |
| security-adversarial-2 | — | refuted | MaxKeys eviction unlock oracle — idle>Window, oldest-lastSeen, coexists with I-R3. |
| security-adversarial-3 | condition | confirmed | `Check→verify→Fail` TOCTOU: concurrent burst passes Check before any Fail → C4. |
| security-adversarial-4 | — | refuted | Shared-source collapse — recommended Tailscale binds 0.0.0.0, own TLS, peer is r.RemoteAddr. |
| security-adversarial-5 | — | refuted | Runtime off-switch bypass — restartRequired:true; off logged at startup. |
| security-adversarial-6 | — | refuted | Account log-injection — existing `%q` quoting. |
| security-adversarial-7 | — | refuted | FailureDelay lever — bounded by lockout, distributed attack out of scope. |
| failure-recoverability-1 | — | refuted | Permanent self-lockout — I-R1 denied before verify; unlock by time only. |
| failure-recoverability-2 | note | confirmed | Locked `launch` denies the only session path with a bare 429 no viewer can see → C1 + C6. |
| failure-recoverability-3 | condition | confirmed | Rate-limiting `redeem` obstructs the last-resort recovery path → C2. |
| failure-recoverability-4 | — | refuted | Startup line hardcodes "on" — status shows "off" when off. |
| failure-recoverability-5 | — | refuted | CLI redeem no-op — folded into C2. |
| failure-recoverability-6 | — | refuted | No clamps — normalized defaults specified. |
| migration-coexistence-1..4 | — | refuted (×4) | Self-lockout / zero-value bool / cross-vault loopback / invisible status — defaults, §6, status text. |
| dependency-cost-1..3, 5, 6 | — | refuted (×5) | Port in key / clock seam / O(n²) eviction / real-sleep tests / hand-wired surfaces — cited lines. |
| dependency-cost-4 | note | confirmed | CLI redeem single-shot; per-process limiter protects nothing — cost with no benefit → C2. |
| honesty-of-claims-1..3, 5..10 | — | refuted (×9) | Clock seam / 6th→429 / CLI row / P-DOCS / S1 / I-R2 / H1 / W1 / B1 — all refuted by cited lines. |
| honesty-of-claims-4 | condition | confirmed | I-P1 "copy only" false vs behavioral rows; Z1 exemption list unenumerated → C5. |
| x1 | — | refuted | (test row) — refuted by I-R1. |

Confirmed surviving: 6 conditions + 4 notes = 10 findings, all closeable by C1–C7.

---

## Refuted findings (with the refuting quote)

- **purpose-threat-fit-1** :: `| open | /api/open before the vault unwrap (the KDF is the main cost; the limiter bounds attempts) | 429 JSON |`
- **purpose-threat-fit-3** :: "A shared NAT or a loopback host can lock legitimate clients … the lock line names the peer and account, the GUI banner tells the viewer, and the off switch exists for an incident." (§6, 146-148); trigger cost at line 77.
- **purpose-threat-fit-4** :: "The launch secret and recovery phrase are high-entropy; their limits are hygiene, not the defense." (150-151); two-key model (44-46).
- **focus-proportionality-1** :: "their limits are hygiene, not the defense."
- **focus-proportionality-2** :: G1 "wrong redeem phrases → 429; success resets".
- **focus-proportionality-3** :: "R1 … → R2 … → P1 … → P2 … → P3 …. Each slice: builder, independent verifier, one fix cycle."
- **focus-proportionality-4** :: "a locked key never denies anything but repeated failures of the same credential class (§6 explains the trade-off and the escape hatch)."
- **focus-proportionality-5** :: server.go:715 "launch-secret redemption is the only way to obtain a session"; §2.2 open row "the KDF is the main cost".
- **durability-1** :: `Peer string /* TCP remote IP, never a header */`.
- **durability-3** :: normalized defaults (FailuresBeforeLock 5, Window 15m, LockStart 30s, LockMax 15m, FailureDelay 250ms, MaxKeys 10000).
- **durability-4** :: I-R1 "a locked key is denied before any credential is examined"; §2.2 disjoint paths.
- **durability-6** :: `clock func() time.Time; … func New(p Policy, clock func() time.Time)`.
- **durability-7** :: "their limits are hygiene, not the defense." (folded into C2.)
- **usability-friction-2** :: "a local misbehaving client is the most common source of a retry storm … only repeated failures of the same credential class."
- **usability-friction-3** :: design:133 "the 6th → 429 + Retry-After, no WWW-Authenticate"; server.go:221 "401 as today" sets WWW-Authenticate.
- **usability-friction-4** :: handleLogin redirect when `!guiAuthEnabled()`; handleResetConfig `s.config = appconfig.Default()`; guiAuthEnabledLocked (server.go:1139-1143, 1290, 1009).
- **usability-friction-5** :: "Fail past FailuresBeforeLock locks … doubling … capped at LockMax. … FailuresBeforeLock 5 … LockMax 15m".
- **security-adversarial-1** :: `Peer string /* TCP remote IP, never a header */`.
- **security-adversarial-2** :: "Keys idle longer than Window are eligible for eviction; … oldest-lastSeen eviction" (42) with I-R3.
- **security-adversarial-4** :: tls-and-certificates.md:121 recommended Tailscale command binds `0.0.0.0 … --tls`; design:61 "never X-Forwarded-For or any header".
- **security-adversarial-5** :: server.go:3488 `"restartRequired": true`; §2.2 loud startup warning + I-R4.
- **security-adversarial-6** :: localdav/server.go:274 `fmt.Sprintf("… %q …", rawHost, …)` (existing quoting).
- **security-adversarial-7** :: "FailureDelay sleeps are bounded by the lockout and capped per process … a distributed attack is out of scope (labeled)."
- **failure-recoverability-1** :: I-R1 "a locked key is denied before any credential is examined; unlock happens only by time" (109-110).
- **failure-recoverability-4** :: "tls status/the GUI settings page show \"auth limits: off\" when it is." (66-68).
- **failure-recoverability-5** :: "their limits are hygiene, not the defense." (folded into C2.)
- **failure-recoverability-6** :: normalized defaults (48-49).
- **migration-coexistence-1** :: B1 "5 wrong Basic attempts → 401s …; the 6th → 429 + Retry-After …; correct credentials while locked → still 429; after the injected clock passes → 200; a second peer unaffected".
- **migration-coexistence-2** :: normalized defaults.
- **migration-coexistence-3** :: design:44-46 two-key model; design:62-64 loopback rationale; §6 146-147.
- **migration-coexistence-4** :: "tls status/the GUI settings page show \"auth limits: off\"" (66-68); I-R4; §2.3 exposure line.
- **dependency-cost-1** :: `Peer string /* TCP remote IP, never a header */`.
- **dependency-cost-2** :: main.go:1668-1670 test-seam comment + `func New(p Policy, clock func() time.Time)`.
- **dependency-cost-3** :: `type Limiter struct { /* mutex; map[Key]*state; clock …; policy */ }`.
- **dependency-cost-5** :: "FailureDelay sleeps are bounded by the lockout … a distributed attack is out of scope (labeled)."
- **dependency-cost-6** :: §2.2 open/redeem rows + two-key model (44, 58-59).
- **honesty-of-claims-1** :: main.go:1666-1670 seam comment; tls_reload_wiring_u3_test.go:127-128 overrides tlsReloadInterval.
- **honesty-of-claims-2** :: FailuresBeforeLock 5 (the 6th failure is the first past the threshold).
- **honesty-of-claims-3** :: "their limits are hygiene, not the defense." (folded into C2.)
- **honesty-of-claims-5** :: "each copy/help/message row asserted (server-rendered markup or captured CLI output), one assertion per row".
- **honesty-of-claims-6** :: G1 end-to-end + S1 "capture the log sink and every 429 body … no credential, hash, secret, or phrase substring".
- **honesty-of-claims-7** :: "each lock logs one line `auth-limit: locked <surface> for <peer>[/<account>] …` (never the credential)".
- **honesty-of-claims-8** :: H1 "requests carrying X-Forwarded-For / X-Real-IP are keyed by the TCP peer, not the header".
- **honesty-of-claims-9** :: W1 line 138 + §7 line 158 "every designed component has a non-test caller and re-runs B1/G1 through the real startup path".
- **honesty-of-claims-10** :: "## 5. Test matrix (red-first; every row asserts; real listeners)".
- **x1** :: I-R1.

---

## Rescue outcome

`{"rescues":[],"overall":"no blockers survived the skeptic pass; rescue not needed"}`

No finding reached blocker severity after the skeptic pass, so no rescue was required. The surviving findings are two-condition (`launch`/`redeem` policy) and one-condition each (IPv6 bypass, TOCTOU, I-P1 honesty) plus four notes — all closeable by a pre-build design revision. Hence GO_WITH_CONDITIONS rather than NO_GO.

---

## What the build must prove (conditions → test-matrix rows)

The design's own matrix (L1–L4, B1, G1, H1, S1, O1, W1, X1, P1–P3, Z1) stands. The revision adds or amends these rows; the final verifier runs an unfiltered `make test` (`go test ./...`) with `-race`, red-first per the repo's prove-fail→prove-pass discipline.

- **C1 (launch: no lockout)** — amend **G1**: wrong `?launch=` values yield `403` + measured `FailureDelay` but no `429`, and the correct secret still redeems immediately after the burst. Add a row: after N wrong redemptions from one peer, the current valid secret still mints a session.
- **C2 (redeem: throttle, drop CLI leg)** — amend **G1**: a correct phrase after a fumble burst still redeems (throttle only). Delete any CLI redeem limiter assertion; add a grep row (alongside W1) asserting the CLI path has no `authlimit` reference. Cover the §6 residual text via P3/Z1 doc assertions.
- **C3 (IPv6 bypass)** — new **L-row**: with the chosen mechanism (per-`{surface,account}` ceiling and/or /64-prefix key), assert K attempts from K distinct /64 addresses against one account still lock; or, if disclosure-only, a **Z1/doc** assertion that SECURITY.md states the bypass verbatim. H1 remains.
- **C4 (TOCTOU)** — new concurrency row (distinct from L4): `FailuresBeforeLock + K` concurrent verifications through the handler; assert at most `FailuresBeforeLock` reach verification; under `-race`.
- **C5 (I-P1 honesty + Z1)** — amend **Z1** to enumerate the exemption entries; add behavior rows under **P1/P2** for GUI-OWN 4, GUI-D2 1 (`/api/close`), CLI-1 (exit 2 + leaf help), CLI 4 — each a behavior assertion, not a copy substring.
- **C6 (operator copy + 429 bodies)** — amend **S1/G1**: log line uses operator words + remedy + minutes; `login` asserted as HTML re-render not JSON; `open`/any-locked 429 carries `{error, retryAfterSeconds}` + `Retry-After`; no-session page renders the lock reason. **P3** covers the §6 banner-scope sentence.
- **C7 (persistent off re-warning)** — amend **O1**: with `enabled=false`, drive the injected clock past the interval and assert re-emission of the loud warning plus the "disabled since \<date\>" string in status.

---

*Filed by the synthesis agent of the 10-lens pre-code design review at `docs/review-u4-predesign.md`. Model: claude-opus-4-8.*
