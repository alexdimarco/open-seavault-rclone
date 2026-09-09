# Security notes

## Threat model

open-seavault-rclone assumes the cloud provider, cloud administrators, and sync transport may read, copy, delete, reorder, or replace files in the vault directory. The application encrypts and authenticates vault contents before data reaches that directory.

## Protected

- File contents.
- Virtual file paths and file metadata stored in encrypted manifests.
- Manifest and chunk integrity through AEAD tags.
- Wrong-chunk substitution through AAD and keyed object-ID verification.
- Password entry on the CLI through hidden terminal input.
- Optional password storage using the operating-system credential store.
- **(T1)** Access to the `serve` WebDAV endpoint and the GUI by another OS account
  or process on the shared `127.0.0.1` loopback: `serve` always requires an HTTP
  Basic credential, and the GUI is reachable only through a launch-secret-minted
  session cookie. Conditional on the operator not writing the credential to a
  world-readable file. A *generated* `serve` credential is printed to stdout once
  on start and so enters terminal scrollback and any redirected log; supply the
  credential with `--password-file` (kept `chmod 600`) plus `--quiet-credentials`
  for non-interactive/daemon use to keep it out of scrollback and logs.
- **(T2)** A web page in the user's browser reaching the loopback listener through
  DNS rebinding, cross-site form posts, or `<img>`/`fetch` GETs: every request to
  the GUI and to `serve` is rejected with `403` unless its `Host` header names a
  loopback address, `localhost`, or an explicit `--allow-host` value. No DNS
  lookups are performed. Conditional on browsers scoping cookies by host (they do)
  for the GUI session leg.
- **(T3)** Leakage of the GUI's session/CSRF secret through URL history or
  `Referer`: the launch secret is redeemed once and the browser is redirected so
  the secret leaves the address bar, and every response carries
  `Referrer-Policy: no-referrer`.
- **(T4, narrow)** Slow-header (slowloris) and idle keep-alive connections are
  bounded by `ReadHeaderTimeout` (10 s) and `IdleTimeout` (2 min); a stalled
  reader or dribbling writer is bounded by a 60 s per-request body-inactivity
  deadline. NOT bounded (by design): a slow-but-progressing transfer, total
  throughput, and the total number of connections (there is no connection cap).
- **(T5)** Partial-read clients (rclone VFS, media players) that issue HTTP `Range`
  requests are served correct `206 Partial Content` responses that decrypt only
  the chunks covering the requested range.

## Not protected

- Vault existence.
- Approximate vault size.
- Number of encrypted objects and manifests.
- Sync timing and churn.
- Device compromise before encryption or after decryption.
- A malicious local GUI/WebDAV client running under the same user account.
- **Within-vault content equality.** Deduplication is keyed on content, so a
  caller who can write to the vault learns whether byte-identical content is
  already stored: `put` reports `PutResult.NewChunkCount` (printed by the `put`
  command), and a value of zero for a freshly put file confirms every one of its
  chunks was already present. This is a content-equality oracle *within a single
  vault* — it does not reveal the matching file's name or path, and it does not
  cross vault boundaries (chunk ids are keyed with the per-vault index key).

## Key derivation

New vaults default to Argon2id. scrypt and PBKDF2-HMAC-SHA256 are available for compatibility or constrained environments. KDF parameters are stored in `vault.json` because they are required to unlock the vault and are not secret.

## Keychain behavior

The OS keychain stores only the vault password and uses the vault ID as the account key. This improves usability but changes the local-device risk model: anyone who can unlock the OS account and access the credential store may be able to unlock the vault.

## Sync conflicts

New vaults keep their encrypted metadata in a visible `SeaVaultData` directory; legacy vaults use the hidden `.seavault` directory, and both are opened transparently. A vault this version creates is not located by a 0.15 or older client on another device (that client fails to find a vault rather than corrupting anything). See [docs/local-sync-location.md](docs/local-sync-location.md) for this metadata-directory compatibility boundary.

Sync-client conflict files are expected in real cloud folders. open-seavault-rclone treats duplicate manifest variants conservatively: it keeps the newest generation as the main file and preserves other live versions as conflict copies instead of silently discarding them. A delete tombstone records the generation of the record it superseded (`deletedGeneration`): a live copy at or below that generation is a stale version the deleter had already seen and stays suppressed, while a live copy above it — a concurrent edit the deleter never saw — survives as a `*.conflict-*` copy rather than being lost to the delete. A tombstone written by an older client that lacks the field keeps every live copy as a conflict. Reconciliation itself writes nothing: a load computes these outcomes in memory and an explicit `compact` (CLI, or the GUI's Reclaim space) materialises them.

## Configuration integrity and freshness

`vault.json` carries a `configTag`: an HMAC-SHA256 over the whole config, keyed by
a subkey derived from the vault master key. The server holds no master key, so it
cannot forge or recompute the tag — editing any covered field (VaultID, chunk
parameters, KDF cost, `minReader`, `formatEpoch`, or the wrapped-key set, and
adding a recovery entry) invalidates it. The tag is checked **after** a successful
unlock, so a wrong password still fails as a wrong password (no MAC oracle) and a
mismatch is then reported as tampering. This protects config **integrity after
unlock, not freshness on its own**: a validly-tagged *older* config still passes
the tag check — a signed monotonic root that would reject any stale-but-authentic
config is out of scope for this phase.

Freshness is a separate, device-local mechanism. Each device records, under its
app-data directory (never synced), the highest `formatEpoch` it has trusted for a
vault and whether it has ever seen a valid tag. A config whose epoch is **lower**
than that high-water is a possible rollback (an old `vault.json` replayed to
re-enable a retired password): open-seavault-rclone **refuses to open it** and prints how to
proceed — re-run with `--accept-rollback` if you deliberately restored the vault
from an older backup, or, if the rollback was unexpected, do not enter a retired
password and restore `vault.json` from a good backup. `--accept-rollback` accepts
the config as a deliberate restore, clears the device anchor so it re-establishes
freshness, and requires the unlocking credential to be re-supplied. This is a trust-on-first-use (TOFU) anchor, and it
is **explicitly weaker than a signed monotonic root**: its residuals are accepted
for this phase and stated here:

- **Coerced or mistaken `--accept-rollback`.** `--accept-rollback` clears the
  device's anchor for that vault so the restored config re-establishes trust
  (re-TOFU). An operator who is tricked or coerced into passing it drops rollback
  protection for that vault on that device until a newer config re-anchors it.
- **Reinstall / app-data reset resets protection to TOFU.** The anchor lives only
  in app data. Reinstalling open-seavault-rclone, wiping its app-data directory, or opening
  the vault from a fresh device starts with no anchor, so the first config seen is
  trusted on faith — a rolled-back config presented to a fresh install is not
  detected as a rollback.
- **Device / app-data compromise.** The anchor is a plaintext, `0600`,
  unauthenticated local file (a never-synced file the in-model server cannot reach
  gains nothing from a MAC). An attacker who can already write the app-data
  directory can raise or erase it; that is within the conceded device-compromise
  boundary above.

`configTag` is written and verified only by v0.17 (A2) and later clients, so during
the grace release (before `seavault vault seal-format`) config-tamper and rollback
protection hold **only on A2 devices**; a v0.16 peer ignores the field and runs its
prior behaviour. `seal-format` retires v0.16 access and is the point this protection
becomes fleet-wide.

## Grace-release GC data-loss residual (mixed fleet)

Before the fleet is sealed with `seavault vault seal-format`, a v0.16 peer computes
chunk liveness from generation-only reconciliation, while an A2 device may keep a
concurrently-edited file alive as a causal conflict copy. The v0.16 peer can then
garbage-collect the chunk backing that conflict copy — a chunk its own
reconciliation considers dead — past the two-phase fence. This is **worse** than a
pure-v0.16 fleet, which drops the losing edit with no dangling reference: here an A2
device holds a conflict entry whose backing chunk a v0.16 peer removed. It is a
reconciliation-*disagreement* loss, distinct from the timing-only fence residuals
below. Mitigation: complete the fleet upgrade and `seal-format` before relying on
A2's causal conflict preservation.

## Garbage-collection fence

Chunk removal is gated by a two-phase, time-fenced protocol: an unreferenced
chunk is first marked with a synced *intent* (`gc-intents/<id>.intent`, one
RFC 3339 line), and is only deleted on a later `gc --confirm` run once the
intent's recorded time, this device's first-seen time for it, and the chunk
file's mtime are all older than the fence (default 72h, `--fence` to change).
The fence is measured on the **deleting device's local wall clock**, and the
device-local first-seen record (`<appdir>/gc-seen/<vaultID>.json`) removes the
*writer's* clock from the decision. Residuals remain, and are accepted for this
phase:

- A device offline for longer than the fence that deduplicated against a chunk
  another device is deleting can lose that chunk. Nothing in this phase proves an
  intent propagated to every peer.
- Clock skew and a paused or backlogged sync client **on the deleter** shorten
  the effective window: the first-seen record fixes the writer's clock but not
  the deleter's own sync lag.

In every case `verify` on an affected device reports the chunk as missing (and
lists pending intents with their age so a delete in flight is visible), and
`--fence` can be raised. Phase A2 (v0.17) adds the per-record vector clock and the
device-local config-freshness anchor described above, so causal reconciliation and
config rollback-detection now exist; the *chunk*-GC fence remains timing-based
because A2 does not add manifest-set freshness (a signed `head.json`), which is
deferred to A3.

## Portable file names

New virtual paths must be restorable on Windows as well as POSIX: a segment
containing `<>:"|?*`, a control character, a trailing dot or space, or a Windows
reserved device stem (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`)
is refused at creation on **every** OS. This is a deliberate portability decision
(a colon that reached a Windows path would silently write an alternate data
stream of an empty file). Existing files with such names — created by a 0.15 peer
or another OS before this rule — still read, overwrite, delete, and export
normally; export sanitises each illegal segment (illegal characters become `_`,
trailing dots/spaces are trimmed, a reserved stem gains a `_` prefix) and
disambiguates a collision with a deterministic `.conflict-<stamp>-<hash>` suffix,
so no colon ever reaches the output path.

## Password entry

The hidden CLI prompt suppresses echo on a real Windows console, a POSIX tty, and
via `CONIN$` when the console mode is unreadable; a recognised mintty/Cygwin/MSYS2
pseudo-terminal is **refused** (`ErrNoHiddenInput`) because it would echo typed
input. An unrecognised pseudo-terminal that presents stdin as an anonymous pipe
(a future mintty naming, some ConEmu/WSL bridges) is **not** detected and may echo
what is typed — use Windows Terminal, PowerShell, winpty, or `SEAVAULT_PASSWORD`
in that case. Secrets are never placed in a process argument list: the macOS
keychain write feeds its command to `security -i` on stdin, and a password or
account containing a control character is refused (`ErrSecretNotStorable`) rather
than risk desynchronising that line-oriented reader — the vault still opens with
the password typed or via `SEAVAULT_PASSWORD`.

## Network-exposed mode

By default the GUI serves plain HTTP on loopback and `seavault serve` (WebDAV) is
plaintext on loopback: decrypted content never leaves the machine. Bringing a
CA-trusted certificate (obtained with a DNS-01 challenge — see
[docs/tls-and-certificates.md](docs/tls-and-certificates.md)) lets the GUI and
WebDAV be served to other devices over TLS. Turning that on is *network-exposed
mode*, and it carries these guarantees:

- **I-T1** Plaintext is never served on a non-loopback address without an explicit
  `--insecure-bind`; the bind guard relaxes for a non-loopback address only when a
  TLS certificate is configured.
- **I-T2** Private key material is never logged, echoed, printed by `tls status`,
  placed in an error message, or copied by the wizard; a group- or world-readable
  key file produces a warning naming `chmod 600`.
- **I-T3** Hot-reload never swaps in an invalid pair, and startup refuses a
  configured key-mismatched pair (`ErrKeyMismatch`) and binds nothing.
- **I-T4** Defaults are unchanged: the GUI is HTTP on loopback (with self-signed
  HTTPS opt-in) and WebDAV is plaintext loopback. A user who does nothing sees
  identical behaviour.
- **I-T5** The `seavault tls setup` wizard stores no DNS-provider token and never
  prompts for one; the only tool it runs is `tailscale cert`, which needs no secret.
  The lego and certbot commands are printed for you to run yourself.
- **I-T6** Startup warns when a certificate name is absent from the Host allowlist;
  the DNS-rebinding guard remains authoritative and matches exact names only.

**Residuals.** Turning on network-exposed mode widens the attack surface in two ways
that this phase does not close:

- Exposure hardening of the authentication endpoints. Through v0.20 (Phase U3) this residual read: "the GUI login and WebDAV Basic auth become network-facing (rate limiting and lockout are a later phase)." **v0.21 (Phase U4) closes it** — see [Authentication rate limiting and lockout](#authentication-rate-limiting-and-lockout) below for the guarantees (I-R1…I-R10) and the residuals that remain. Firewall the port and prefer a VPN.
- Trust-on-first-use is inherent to self-signed certificates:
  clients that accept a self-signed prompt are MITM-able on first connect.
  Use a CA-issued certificate for any cross-device use.

## Authentication rate limiting and lockout

v0.21 (Phase U4) adds a dependency-free, per-process rate limiter and lockout in front
of every credential-checking surface network-exposed mode reaches — WebDAV **Basic**
auth, the GUI **login** form, launch-link redemption, the vault-password **open**, and
recovery-phrase **redeem**. It is **on by default on every bind, including loopback**
(a misbehaving local client is the most common source of a retry storm), and it never
touches how a credential is verified — it only bounds how often a wrong one may be
tried. It carries these guarantees:

- **I-R1** The limiter never weakens authentication: a locked key is denied *before*
  any credential is examined; unlock happens only by the passage of time; the peer is
  the TCP remote address, never `X-Forwarded-For` or any other header.
- **I-R2** No credential, password hash, launch secret, or recovery phrase appears in
  any limiter log line or any `429` body — the only identifiers held are the surface,
  the peer IP (or IPv6 /64), the account username, and counters.
- **I-R3** Memory is bounded by `maxKeys` (default 10 000) with oldest-idle eviction; a
  spray of 20 000 distinct source addresses leaves at most `maxKeys` entries, and a
  locked key is never evicted before its lock expires.
- **I-R4** The limiter is on by default on every bind including loopback; the off
  switch (`--auth-limit off`, or `auth.limits.enabled=false`) is explicit, logged
  loudly at startup and re-warned while it runs, and shows in `seavault tls status`.
- **I-R5** The constant-time WebDAV Basic compare and the argon2id GUI-login
  verification are unchanged; their pre-U4 behaviour and tests are untouched.
- **I-R6** `Success` resets only its own key: one client's correct credential never
  unlocks another peer or another account.
- **I-R7** Limits are per process and in memory: a restart clears them (a labelled
  residual below — an attacker who can restart the process already has local control).
- **I-R8** An IPv6 peer is keyed by its **/64** prefix and every account has a global
  failure **ceiling** (`accountFailuresBeforeLock`, default 20), so per-attempt source
  rotation — which any IPv6 host can do within its own /64 — cannot keep an account
  unprotected.
- **I-R9** The **launch** and **redeem** surfaces are throttled but never locked: the
  256-bit launch secret and a high-entropy recovery phrase are the defence, so the
  correct secret and a correct phrase always succeed immediately after any burst — a
  fumbled 24-word phrase can never lock the last-resort recovery path.
- **I-R10** `failuresBeforeLock` is an upper bound on credential verifications per lock
  cycle even under concurrency: `Check` reserves an in-flight attempt, so N concurrent
  requests for one key cannot all pass the pre-check and all reach verification (which
  against `/api/open` would otherwise multiply the 64 MiB-per-attempt KDF cost).

When a key locks, the operator sees one line in plain words — for example
`auth-limit: locked WebDAV auth for 192.0.2.7 (user "vault") for 2 minutes after 5
failures; unlocks automatically, or restart with --auth-limit off for an incident` —
with durations in whole minutes and never a credential. A locked `basic`/`open`
response carries `Retry-After` (and, for JSON surfaces, `{error, retryAfterSeconds}`);
the GUI login re-renders its HTML form with a minutes countdown and `Retry-After`.

**Residuals.** These trade-offs remain and are accepted:

- **Per-process reset.** Limits are held per process and in memory, so they **reset on restart**.
  This is intentional — the limiter is exposure hygiene, not a persistent security boundary.
- **Shared NAT and /64 sharing.** The peer key is the TCP source address, and an IPv6
  peer is keyed by **a whole /64**. A **shared NAT**, a household, a hosting tenant, or
  a misbehaving loopback client can therefore lock legitimate clients that share that
  key for up to `lockMax`. The lock line names the peer and account, the `Retry-After`
  header and no-session page tell the caller, and the off switch exists for an incident.
- **The account-ceiling lever.** The per-account global ceiling (I-R8) protects an
  account against source rotation, but **the per-account ceiling is itself a lever**:
  an attacker who knows a username can lock that account for everyone, from rotating
  sources, for up to `lockMax`. Its higher threshold (20 vs 5) and the `lockMax` cap
  bound the harm; that is the deliberate trade for closing the rotation bypass.
- **Distributed attacks are out of scope.** A source rotating across **many** /64s or
  many IPv4 addresses still meets the account ceiling but is otherwise a
  **distributed attack**, which a per-process limiter does not defend and which is
  out of scope for this phase (labelled). Prefer a VPN for any exposed deployment.
- **Banner coverage.** The GUI's in-page lock banner reports the viewer's own lock
  state for **only the post-login** surfaces (`open`, `redeem`). The `basic`, `login`,
  and `launch` surfaces **cannot show a banner** — there is no logged-in page to render
  it on — so for those the operator learns of a lock from the log line, the
  `Retry-After` header, and the no-session page.

## Production work still required

- Independent cryptographic review.
- A signed monotonic config/manifest-set root (A3 `head.json`) to replace the
  device-local TOFU freshness anchor.
- Signed release pipeline and reproducible build notes.
- Installer packages and auto-update policy.
- More exhaustive WebDAV compatibility testing.
- Fuzzing for encrypted object parsing.
- Admin policy controls for KDF floors, keychain use, and allowed vault locations.

## Rclone transport boundary

Rclone is used only as a transport runtime. It receives paths under `.seavault` and does not receive plaintext source files or decrypted virtual paths. Default remote operations use copy-safe transfers rather than destructive mirror sync.

The app-managed rclone binary is stored outside the vault, has its SHA256 hash recorded in a runtime manifest, and can be verified before use. Online installs verify the archive against official SHA256SUMS. Optional or required GPG verification is available when a local `gpg` executable is present.

## Remote credential handling

Remote profiles and rclone configuration are stored under app configuration, not in the vault. Redacted export removes common token, secret, password, and key fields. Some rclone backends still require credentials in `rclone.conf`; for those backends, restrict file permissions and prefer OS keychain or short-lived provider credentials where supported.

SSH private keys for SFTP are stored in app configuration and are never synchronized inside `.seavault`.
