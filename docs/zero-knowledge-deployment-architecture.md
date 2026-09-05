# SeaVault Zero-Knowledge Deployment: Reference Architecture, Threat Model & Roadmap

*Audience: SeaVault engineering team + future security auditor. Status: pre-ship review. All claims grounded in `/home/alex/gitprojects/seavault-fast-rclone`.*

---

## 1. Overview & the Zero-Knowledge Property

SeaVault is a **client-side** encryption application. It runs exclusively on the **end user's own computer** (home or work machine) — never on a server. It chunks and encrypts a user's files locally into a `.seavault` directory. That directory contains **only ciphertext and non-sensitive crypto metadata**, and is synced up to a **Crescendum-managed, customer-owned Nextcloud server** via the Nextcloud desktop sync client or via rclone to Nextcloud WebDAV.

### What zero-knowledge guarantees, and for whom

| Party | What they hold | What they can read |
|---|---|---|
| **End user (client machine)** | Plaintext, password, derived keys (in RAM after unlock) | Everything — this is the trust anchor |
| **Managed provider / Nextcloud server** | `.seavault` ciphertext only | **Nothing in plaintext.** Decryption is impossible without the user's password |

The guarantee: **vault unlock, key derivation, and all decryption happen ONLY on the user's client machine.** The server stores `.seavault` ciphertext and never possesses any decryption key. The managed provider hosts and operates the server but is cryptographically prevented from reading customer content.

The cryptographic foundation, verified in code:
- Each chunk is sealed with **AES-256-GCM** before any byte enters `.seavault` (`internal/vault/vault.go:485`).
- File paths and per-file metadata are encrypted **inside** the manifest body; on-disk manifest names are keyed `HMAC-SHA256(indexKey, "manifest:"+path)` and are unlinkable to real names (`internal/vault/manifest.go:298-307,327`).
- `masterKey` and `indexKey` (32 bytes each) are generated with `crypto/rand` (`internal/vault/vault.go:132-139`) and on disk are AES-256-GCM-wrapped under a password-derived key — the master/index bundle is sealed at `internal/vault/crypto.go:185`. The server cannot unwrap without the user password.
- The unlock password is run through Argon2id/scrypt/PBKDF2 on the client (`internal/vault/crypto.go:138`) and is **never transmitted to the server**.

> **Bottom line of the flow audit:** zero-knowledge **HOLDS** for the intended client-side deployment, with **one notable enforcement gap** (LR-1, see §4). It is true *in practice* under normal use, but it is not yet *structurally guaranteed* by a code-level destination guard.

---

## 2. Data-Flow Diagram (encryption / trust boundary marked)

```
        =============== USER'S OWN MACHINE (TRUSTED) ===============
        ‖                                                          ‖
  user's  ‖   ┌──────────────────────────────────────────────┐    ‖
  plaintext ─►│  SeaVault CLIENT                               │    ‖
  files   ‖   │  • chunk + AES-256-GCM seal (vault.go:485)     │    ‖
        ‖     │  • encrypt manifest body (manifest.go:298-307) │    ‖
        ‖     │  • wrap keys w/ password-KDF (crypto.go:185)   │    ‖
        ‖     │  password ─► Argon2id/scrypt (crypto.go:138)   │    ‖
        ‖     └───────────────────────┬──────────────────────┘    ‖
        ‖                              │ writes CIPHERTEXT only      ‖
        ‖                              ▼                             ‖
        ‖              ┌─────────────────────────────────┐          ‖
        ‖              │ .seavault/  (ciphertext + meta)  │          ‖
        ‖              │  vault.json (KDF params+wrapped  │          ‖
        ‖              │             keys)               │          ‖
        ‖              │  objects/chunks/<2hex>/<id>.chunk│          ‖
        ‖              │  manifests/<2hex>/<id>.manifest  │          ‖
        ‖              │  tombstones/                     │          ‖
        ‖              └────────────────┬────────────────┘          ‖
        ‖                               │                            ‖
        ‖====== ⇩⇩ ENCRYPTION / TRUST BOUNDARY ⇩⇩ ===================‖
                                        │ rclone copy / Nextcloud
                                        │ desktop sync (ciphertext)
                                        ▼
        ┌──────────────────────────────────────────────────────────┐
        │  CRESCENDUM-MANAGED NEXTCLOUD SERVER  (UNTRUSTED for      │
        │  confidentiality; honest-but-curious)                     │
        │  Stores ONLY .seavault ciphertext. Runs no SeaVault code. │
        │  Cannot decrypt anything without the user password.       │
        └──────────────────────────────┬───────────────────────────┘
                                        │ sync down (ciphertext)
        ============= ⇧⇧ TRUST BOUNDARY ⇧⇧ =========================
        ‖                               ▼                            ‖
        ‖        OTHER DEVICE = ANOTHER USER'S OWN MACHINE (TRUSTED) ‖
        ‖              ┌─────────────────────────────────┐          ‖
        ‖              │ .seavault/ (ciphertext)          │          ‖
        ‖              └────────────────┬────────────────┘          ‖
        ‖   ┌───────────────────────────▼──────────────────────┐   ‖
        ‖   │  SeaVault CLIENT                                   │   ‖
  user ◄─── │  • unlock w/ password ► unwrap keys (crypto.go)    │   ‖
  plaintext ‖ │  • AEAD-Open chunks (loadChunk vault.go:600-621) │   ‖
        ‖   │  • decrypt manifest, restore to chosen destination│   ‖
        ‖   └───────────────────────────────────────────────────┘  ‖
        ‖                                                          ‖
        =============== USER'S OWN MACHINE (TRUSTED) ===============
```

**Everything inside the `‖ ‖` rails is the user's own trusted machine. Everything that crosses the boundary is ciphertext.** Plaintext never crosses the boundary in either direction.

---

## 3. Enforced Invariants (and how each could break)

These invariants keep zero-knowledge true. Each is stated with its enforcement mechanism and its failure mode.

**INV-1 — Everything under `.seavault` is ciphertext or non-sensitive crypto metadata.**
Chunks AEAD-sealed (`vault.go:485-486`), manifests/tombstones AEAD-sealed (`manifest.go:306-307`), index AEAD-sealed (`vault.go:318-319`), `vault.json` holds only KDF params + wrapped keys (`crypto.go:185`).
*Enforce:* keep all write paths routed through the sealing primitives; add the destination guard from INV-4.
*Breaks if:* any code path writes plaintext file content inside `.seavault` (today reachable via LR-1).

**INV-2 — Decryption happens only on the user's client machine.**
`Open`/`unwrapKeys`, `loadChunk`, `restoreFile`, `WriteFileTo`, `ExportPath` all run client-side; the server runs no SeaVault code.
*Enforce:* never ship a server-side build that links the vault/decrypt packages; the managed Docker template must not run the GUI/WebDAV (see W4).
*Breaks if:* a future server-side or WASM build (W6) moves decryption off the trusted device — the explicit reason W6 is weaker.

**INV-3 — Push/sync transfers only the `.seavault` subtree.**
Both transports scope `src` to `localMeta(vault) = filepath.Join(vaultRoot, ".seavault")`. The rclone `pushSequence` copies exactly `objects/chunks`, `manifests`, optional `tombstones`, and `vault.json` (`internal/transport/rclone/rclone.go:177-190`); local push `copyDir` walks only `.seavault` (`internal/transport/local/local.go:88-120`). **No transport path references plaintext sources, OS temp dirs, or export destinations.**
*Enforce:* keep transport `src`/`dst` pinned to `localMeta`; regression-test that no other tree is ever copied.
*Breaks if:* a transport change widens the copy scope, or plaintext lands inside `.seavault` (INV-4).

**INV-4 — Export/restore destinations must be rejected if they resolve inside `.seavault`. *(CURRENTLY NOT ENFORCED — see LR-1.)***
The codebase knows how to write this guard but applies it only to the *source* of a put (`rejectMetadataSource`, `internal/rsyncput/rsyncput.go:210-221`).
*Enforce:* mirror `rejectMetadataSource` on the export/restore *destination* in `ExportPath`/`GetPath` and the webui export handler; stage temp files in an OS temp dir.
*Breaks if:* a user or script chooses a destination inside `.seavault` — plaintext (and transient temp files) sync to the server.

**INV-5 — rsync/ingest plaintext staging uses an OS temp dir outside the vault, removed after use.**
Verified: `os.MkdirTemp("", ...)` with `defer os.RemoveAll` in `rsyncput.go:152-158` and `rsyncingest.go:112-116,129-133`; rsync invocations exclude `.seavault` and `.git` (`rsyncput.go:162-163`).
*Enforce:* keep staging out of the vault tree; keep the excludes.
*Breaks if:* staging is relocated into the vault, or the excludes are dropped.

**INV-6 — GUI/WebDAV listeners bind to loopback; decrypted responses are no-store/no-cache.**
Defaults: GUI `127.0.0.1:8787`, serve `127.0.0.1:8765` (`cmd/seavault/main.go:562,466`). `no-store`/`no-cache` set (`internal/localdav/server.go:33-34`; `internal/webui/server.go:1254`).
*Enforce:* hard-reject non-loopback binds behind an explicit override (W4).
*Breaks if:* `--addr` is set to `0.0.0.0` — decrypted content becomes network-reachable (LR-2).

**INV-7 — Web servers never cache decrypted content to disk.**
Download/zip endpoints stream plaintext straight to the loopback HTTP client (`server.go:1164,1284`; `localdav` `server.go:110`). The only `os.WriteFile` in webui is the log-save handler (`server.go:1946`), which writes log text, not vault content.
*Enforce:* keep decrypt endpoints as pure streams.
*Breaks if:* a caching/temp layer is added to the download path.

---

## 4. Plaintext-Flow Audit Result

### Verdict
**Zero-knowledge HOLDS for the intended client-side deployment, with one notable enforcement gap.** Every *persistent* write into `.seavault` is ciphertext (AES-256-GCM-sealed chunks, manifests, tombstones, index) plus `vault.json` (KDF params + password-wrapped keys). Both push transports copy **only** the `.seavault` subtree, so under normal use **the server receives ciphertext only and can decrypt nothing without the user's password.**

### What the server sees
Proven by the push path. `rclone pushSequence` (`rclone.go:177-190`) and local push (`local.go:53-55,112,88-120`) take `src = localMeta(vault) = filepath.Join(vaultRoot, ".seavault")`. The server therefore receives exactly:
- `.seavault/objects/chunks/...` — AES-256-GCM-sealed chunks
- `.seavault/manifests/...` — AES-256-GCM-sealed file manifests/tombstones
- `.seavault/tombstones/...` if present
- `.seavault/vault.json` — KDF params + AEAD-wrapped keys (`crypto.go:185`); the server cannot unwrap without the user password

No transport path ever references plaintext source files, OS temp staging dirs, or any user-chosen export destination. The wrapped key material and KDF salt in `vault.json` are intended to travel and are **not** plaintext content (see LR-4).

### Confirmed client-side decryption points (all stay client-side)
| Decryption point | Location | Plaintext sink | Temp-file handling |
|---|---|---|---|
| `vault.GetPath -> restoreFile` | `vault.go:492-573` | User dest via temp-then-rename (`vault.go:535,572`) | Temp **beside destination**, removed on error — safe only if dest is outside `.seavault` |
| `vault.WriteFileTo` (streaming) | `vault.go:575-598` | Caller's `io.Writer` (HTTP/zip/pipe) | None — pure stream |
| `vault.ExportPath -> restoreFileWithOverwrite` | `export.go:62-150,231-276` | User dest dir via temp-then-rename (`export.go:235,275`) | Temp **beside target**, removed on error |
| `vault.ExportPath (zip) -> writeZip` | `export.go:278-342` | User `.zip` via temp-then-rename (`export.go:279,338`) | Temp **beside zip**, removed on error |
| `webui handleDownload` | `server.go:1134-1168` | Loopback HTTP body (`server.go:1164`) | None |
| `webui handleExportZipDownload` | `server.go:1202-1288` | Loopback HTTP body, `no-store` (`server.go:1254,1284`) | None |
| `webui handleExport` (POST `/api/export`) | `server.go:1170-1200` | User dest via `ExportPath` (`server.go:1187`) | Inherits export.go behavior; UI warns only (`server.go:2877`) |
| `localdav handleGet` / `copyFile` | `localdav/server.go:87-124,297-315` | GET: loopback HTTP body; COPY/MOVE: in-memory `io.Pipe`, dest re-encrypted | None; internal paths blocked (`server.go:487-489`) |

### Surviving leak risks

| ID | Sev | Title | Mitigation |
|---|---|---|---|
| **LR-1** | **HIGH** | No guard prevents export/restore destination from being inside `.seavault` | Add a destination check in `ExportPath`/`GetPath` + webui handler that rejects any `destPath`/`zipPath` resolving inside `filepath.Join(vaultRoot, MetadataDirName)`, mirroring `rejectMetadataSource`. Stage temp files in an OS temp dir. |
| **LR-2** | MED | GUI/WebDAV listener is user-rebindable to a non-loopback interface | Refuse non-loopback binds (or require an explicit `--insecure-bind`); require GUI auth before serving decrypted content; add auth/token to `localdav` GET. |
| **LR-3** | LOW | Export/restore plaintext temp files live unencrypted on client disk during the operation | Acceptable for a client-side tool; document it; clean stale `.seavault-restore-*`/`.seavault-export-*` on next run; never let dest resolve inside `.seavault` (LR-1). |
| **LR-4** | INFO | `vault.json` (wrapped keys + KDF salt) is intentionally synced | No change; ensure KDF params stay strong so the wrapped blob resists offline brute force. |

**LR-1 in detail (verified against code).** `restoreFile` uses `os.CreateTemp(filepath.Dir(destPath), ".seavault-restore-*")` then `os.Rename(tmpName, destPath)` (`vault.go:535,572`); `restoreFileWithOverwrite` uses `.seavault-export-*` (`export.go:235,275`); `writeZip` uses `.seavault-zip-*` (`export.go:279,338`). Both entrypoints `GetPath` (`vault.go:492-528`) and `ExportPath` (`export.go:62-150`) only `filepath.Join(destPath, rel)` and write — no check that `destPath` lies outside the metadata dir (`MetadataDirName=".seavault"`, `vault.go:20`). All callers pass arbitrary destinations through only `userpath.Abs`, which merely expands/cleans (`internal/userpath/userpath.go:16-26`): webui `handleExport` (`server.go:1187-1194`), CLI export (`cmd/seavault/main.go:270-274`), CLI get (`cmd/seavault/main.go:239-241`). The existing guard `rejectMetadataSource` (`rsyncput.go:210-221`) covers only the put **source**, not the export **destination**. The sole present mitigation is an advisory UI hint string (`server.go:2877`) — not enforcement, and absent from the CLI. **Severity is HIGH, not critical:** the leak is contingent on a user/script deliberately choosing a destination inside `.seavault`; exports default elsewhere and nothing silently routes plaintext into the synced dir. It is a missing defense-in-depth guard, trivially fixable by mirroring `rejectMetadataSource` on the destination.

---

## 5. Threat Model

### Adversary table

| Adversary | Can see | Cannot see | Can do | Cannot do |
|---|---|---|---|---|
| **Managed provider / curious or compromised Nextcloud admin** | All ciphertext at rest: `vault.json` (KDF algo/params, base64 salt, random vaultID, createdAt, wrapped bundle + nonce — `vault.go:149-167`), every `.chunk` and `.manifest`, tombstones. Derives: vault existence, total size, object/chunk count, file count (1 manifest/file), per-chunk plaintext length (no padding), intra-vault dedupe equality (`vault.go:469-472`), churn/timing | Any plaintext, paths, filenames (encrypted in manifest body `manifest.go:298-307`; on-disk names are keyed HMAC `manifest.go:327`). Password, masterKey, indexKey | Delete/reorder/roll back/withhold/replay ciphertext objects (DoS, point-in-time rollback). Run **offline brute-force** on the password using cleartext salt + wrapped bundle. Cross-customer metadata analysis | Forge/tamper undetectably (AEAD + AAD + post-decrypt keyed objectID recheck `vault.go:609-619`). Inject readable plaintext, learn a key, decrypt, or mix objects across vaults (keys are per-vault) |
| **Server compromise / storage exfiltration (offline `.seavault` copy)** | Same ciphertext + metadata, frozen at exfil time | Plaintext, paths, filenames, keys — identical boundary | **Unlimited offline guessing** of the password against the stolen `vault.json` (salt `vault.go:144`, bundle `vault.go:165-166`). Harvest-now/decrypt-later if password is weak | Decrypt with a strong password; recover keys without the password; tamper undetectably. No server-side secret helps |
| **Network attacker (MITM on WebDAV/Nextcloud/rclone)** | TLS metadata: that a `.seavault` tree is syncing, object sizes/counts/timing, source IP, account identity. If TLS stripped / rogue CA: same ciphertext as the server | Plaintext, paths, filenames, keys (payload is encrypted before transport — `DESIGN.md:5`, `SECURITY.md:49-50`) | Block/delay/drop transfers; replay/roll back if able to write; fingerprint by size/timing; attempt TLS downgrade | Read/forge plaintext, derive keys, tamper undetectably (AEAD fails on client). Transport confidentiality still depends on external TLS config |
| **Client-device attacker (malware / same-user process / unlocked session)** | **Everything once unlocked:** plaintext, decrypted restores, masterKey/indexKey in RAM, password as typed, OS-keychain password keyed by vaultID (`SECURITY.md:29-31`, `server.go:890`). Loopback GUI/WebDAV reachable by any same-user process | Little that matters; before unlock, on-disk data is still ciphertext | Read/exfiltrate all plaintext, capture keys/password, impersonate user to server. **Full compromise** for that user. Out of scope (`SECURITY.md:22-23`) | Nothing meaningful is withheld; SeaVault provides no in-product defense — mitigation is OS-level (account isolation, FDE, EDR, keychain ACLs) |
| **Another tenant on shared Nextcloud (no admin)** | Only what Nextcloud ACLs expose. If mis-shared: same ciphertext + metadata as provider view | Plaintext/paths/filenames/keys of another vault under any circumstance | At most metadata observation; if mis-shared write, same DoS as a malicious server | Decrypt/tamper, **cross-vault dedupe correlation** (object IDs keyed per vault — `DESIGN.md:54,66`), or obtain another tenant's keys |

### Metadata the provider still learns (residual leakage)
- **Vault existence and shape** (`.seavault` with `vault.json`, `objects/chunks/`, `manifests/`).
- **Total size and object/chunk count** — each chunk is its own file (`vault.go:904-909`); summing is trivial.
- **File count** — one manifest per logical file (`manifest.go:330-336`); manifest count = file count.
- **Per-chunk plaintext length** — **no padding**: `aead.Seal` + write `magic(7) + nonce(12) + plaintext + tag(16)` (`vault.go:485`, `crypto.go:224-230`). File size − 35 bytes = exact plaintext chunk length. Chunk bounds (min 2 MiB / avg 8 MiB / max 16 MiB, `chunker.go:15-21`) coarsen but do not hide this.
- **Intra-vault duplicate-chunk equality** — content-addressed keyed dedupe skips re-writes (`vault.go:469-472`); the provider learns internal repeats. **Does not cross vaults** (keyed per vault).
- **Churn / upload-download timing / edit cadence**; **deletion activity** via tombstones + pre-GC chunk over-retention.
- **`vault.json` cleartext fields**: vaultID (stable correlator, reused as keychain account key), createdAt, KDF algo/params, base64 salt (enables offline attack).
- **Not leaked (verified):** virtual paths, filenames, per-file mode/modTime/size, cross-vault content correlation.

### Residual risks
- **Password is the single point of failure.** A stolen `vault.json` permits unlimited offline guessing. Argon2id defaults (time=1, 64 MiB, p=4; `crypto.go:27-29`) are modest; **no enforced password-strength or KDF floor** (`SECURITY.md:46`).
- **No anti-rollback / freshness binding** across objects. Each object is individually AEAD-authenticated, but there is no signed global root/version, so point-in-time rollback and selective withholding are undetectable.
- **No availability/integrity-of-deletion guarantee** — server can silently drop objects; only detected on access (`vault.go:801-818`).
- **Metadata side channels persist** — no padding, cover traffic, or chunk-size obfuscation.
- **Client-device compromise is unmitigated by design** (largest practical risk; out of scope).
- **OS keychain broadens local attack surface** (password keyed by vaultID).
- **AES-GCM with random 96-bit nonces** (`vault.go:480`, `crypto.go:135`) — safe at expected volumes; no nonce-misuse-resistant mode and no documented rekey threshold.
- **No recovery / rotation / revocation flow yet** — lost password = permanent loss; planned IAM-tied recovery introduces a new escrow/trust party (see W2).
- **Supply-chain / runtime integrity** — rclone hash/GPG verification exists (`SECURITY.md:51-52`), but a signed SeaVault release pipeline is still outstanding (`SECURITY.md:42`). Future WASM unlock expands the trusted delivery surface.
- **Transport metadata confidentiality depends on external TLS config**, not on SeaVault.

### Trust assumptions
1. The client device is trusted/uncompromised at unlock and use.
2. The unlock password is high-entropy and secret — the entire guarantee rests on its resistance to offline KDF attack.
3. The server is **honest-but-curious for confidentiality**; SeaVault relies on AEAD for tamper detection but does **not** defend rollback/withholding.
4. `crypto/rand` is a sound CSPRNG; AES-256-GCM, Argon2id, HMAC-SHA256, HKDF-SHA256 are correctly implemented (incl. bundled `xcrypto`).
5. Only `.seavault` syncs; transport credentials/SSH keys stay in app config (`SECURITY.md:54-58`); the sync client is a transport that never sees plaintext.
6. The transport uses correctly configured TLS.
7. Each vault has independent keys → no cross-vault/tenant dedupe correlation (`DESIGN.md:54,66`); multi-tenant raw-access isolation is delegated to Nextcloud.
8. The provider's operational governance (region, subprocessors, support-access, retention, breach notification) is validated separately.
9. The SeaVault binary and bundled rclone/rsync are authentic (signed releases pending).
10. Users accept the documented residual metadata leakage as inherent to a cloud-folder zero-knowledge design.

---

## 6. Multi-Device Sync Risks (Top Technical Risk)

**Verdict: NOT SHIP-READY for advertised multi-device sync without fixes.** The manifest layer handles the Nextcloud conflict-copy case well, but two ship-blockers remain.

### What works (regression-lock it)
`manifestIDFromFileName` (`manifest.go:141-155`) recovers the real 64-hex manifest id from any `*.sync-conflict-*` / `(conflicted copy)` / `.old-sync-conflict` suffix via `prefix[:64]` (verified). `loadManifestIndex` merges duplicates via `candidateCompare` and writes a deterministic `content/<path>.conflict-<stamp>-<hash>` copy (`manifest.go:79-138`) — so **no edit is silently dropped at the manifest level.** Both conflict copies decrypt under the same AAD (`manifest.go:306,315`), so the suffix never breaks authentication. Exercised by `TestManifestConflictCopyPreserved`-style tests (`vault_test.go:200-221`).

### Failure scenarios

**(1) Clock-skew lost update — SHIP-BLOCKER, `silent-wrong-version`.** `generation` is assigned from local wall-clock `time.Now()` (`vault.go:459-460`) with the only monotonicity guard against the *local* prior value (`vault.go:461-463`). A device with a fast clock always wins; an older edit can resurrect over a newer one. Example: Device A (+5 min fast) saves `v1`, Device B (correct) later saves `v2`; A's numerically larger generation wins and B's newer `v2` is demoted to a `.conflict-` copy. `candidateCompare` (`manifest.go:179-220`) orders strictly by this skewed generation.
*Fix:* add a per-record monotonic logical counter + stable device id; on save set `generation = max(localPriorGen, observedRemoteMaxGenForPath)+1` by reading **all** candidate manifests for the path (including conflict copies); within a skew window, preserve **both** as conflict copies rather than picking a winner; surface a "clock skew detected" warning.

**(2) Permanent chunk loss on canonical conflict-rename — SHIP-BLOCKER, `data-loss`.** The chunk store has **none** of the manifest's conflict-recovery logic. `loadChunk` reads only `chunkPath(id)` (`vault.go:600-609,904-909`) and never inspects sync-conflict siblings. `GarbageCollect` computes `id := strings.TrimSuffix(name, ".chunk")` (`vault.go:858-868`), which for `<id>.sync-conflict-....chunk` yields `<id>.sync-conflict-...` (≠ real id), marks it not-live, and deletes it. Because chunks are content-addressed and immutable, a conflict copy is usually redundant — **but if Nextcloud renames the canonical `<id>.chunk`** (it arrived second, or a partial upload left the canonical name on the conflict side), the only surviving copy is the sync-conflict sibling, which `loadChunk` ignores and GC then deletes = permanent, unrecoverable loss on every device.
*Fix:* (a) in `loadChunk`, if `chunkPath(id)` is missing, scan the `<2hex>` shard for any sibling that strips to the target id, verify `HMAC==id` (the recheck already exists at `vault.go:616-619`), and adopt/rename to canonical; (b) add a `chunkIDFromFileName` helper mirroring `manifestIDFromFileName` so GC reconciles conflict copies of live chunks instead of deleting; (c) make GC refuse to run while any `*.sync-conflict-*` is present.

**(3) Partial sync looks like corruption — `transient-error`.** A device can receive `<id>.manifest` before its referenced chunks. `restoreFile` hard-fails on the first unreadable chunk (`vault.go:547-557`); `VerifyReport` classifies `os.ErrNotExist` as `missing_chunk` (`vault.go:798-819,829`). There is no "pending sync" notion.
*Fix:* add a `pending_sync` classification distinct from corruption; advise "wait for sync to finish"; do not GC while `pending_sync` chunks exist.

**(4) Stale `Config` on long-lived process — `silent-wrong-version`.** `Vault.Config` is captured once at `Open` (`vault.go:64-71,217-242`) and never reloaded; the webui holds the `*Vault` for the session (`server.go:881,2116-2119`). A remote `vault.json` / `ManifestShards` / KDF change is invisible. **Note:** the in-memory file index is **not** stale — `LoadIndex` re-reads manifests every call (`vault.go:264`) — so the "stale cached index" concern does **not** apply to this build; only `Config` is stale.
*Fix:* re-stat `vault.json` and reload `Config` when it changes; treat a changed VaultID/KDF/ManifestShards as "re-keyed remotely → force re-Open/re-unlock"; refuse to write under a stale Config.

**(5) True concurrent same-path edits + concurrent MOVE/edit — `conflict-copy`.** On generation/UpdatedAt ties, `candidateCompare` falls back to lexicographic manifest id (`manifest.go:201-219`) — stable but content-meaningless (loser still preserved). `localdav` MOVE/COPY is `RemovePath(src)+PutReader(dst)` over `AllEntries` (`server.go:225-312`) — non-atomic across many manifest writes; interleaving with a remote edit can tombstone a just-rewritten path (`RemovePath` uses `nowBase=time.Now().UnixNano()` at `vault.go:722`, same skew problem).
*Fix:* make the tie-break intentional (prefer non-deleted, then larger size, then device-id priority); write a single move-intent manifest record (old + new path + generation) so peers apply the rename idempotently.

### `vault.json` conflict
If Nextcloud forks `vault.json` into a sync-conflict copy, `ReadConfig` reads only the canonical name (`vault.go:189-206`); a clobbered/renamed canonical `vault.json` makes the whole vault unopenable. Needs a clear "config conflict, choose a version" recovery path.

### Pre-ship test matrix
1. **Clock-skew lost update** — A writes with future generation, B writes real; assert live = B's `new` (currently FAILS) and/or both retained. `vault.go:459-463`, `manifest.go:179-220`.
2. **Manifest conflict merge (lock the good path)** — multiple Nextcloud naming variants; assert one live + one conflict copy per distinct version, strays removed. Extends `vault_test.go:200-221`.
3. **Chunk conflict / canonical-rename data loss** — rename canonical `<id>.chunk`; assert restore succeeds (FAILS) and GC does not delete the live chunk (FAILS). `vault.go:600-609,858-868,904-909`.
4. **Partial sync (manifest before chunk)** — assert `pending_sync`, not `missing_chunk`/hard error. `vault.go:547-557,798-819,829`.
5. **Partial sync (chunk before manifest; tombstone vs re-add)** — orphan incoming chunk not eagerly GC'd; re-add survives older tombstone. `vault.go:839-871,692-742`.
6. **Stale config on long-lived process** — swap `vault.json` (different ManifestShards/VaultID/KDF); assert detect/reload/re-unlock. `vault.go:64-71,217-242`, `server.go:881,2116-2119`.
7. **`vault.json` conflict copy** — clobber canonical; assert clear "config conflict" error + recovery. `vault.go:189-206`.
8. **Three-way concurrent same path (home/work/mobile)** — arbitrary arrival order; assert exactly one live + N−1 distinct conflict copies. `manifest.go:79-138`.
9. **Concurrent MOVE vs edit** — assert B's edit lands under new path or as a conflict copy, never tombstoned away. `localdav/server.go:225-312`, `vault.go:721-729`.
10. **Case-insensitive / reshard interop** — different ManifestShards or case-insensitive FS (mobile/macOS); assert all manifests located, no case shadowing. `manifest.go:43,330-336`.
11. **End-to-end Nextcloud loop (integration)** — two real desktop clients, interleaved edits with induced network pauses to force real `*.sync-conflict-*`, then GC; assert byte-identical restores and zero `missing_chunk` after settling.

---

## 7. Build Roadmap

| ID | Workstream | Effort | Phase |
|---|---|---|---|
| W0 | Vault-core portability refactor (io/fs storage abstraction + frozen format spec) | large | 0 (first) |
| W2 | Client-controlled key recovery + rotation tied to IAM | large | 1 |
| W4 | GUI-client-side invariant enforcement + multi-device hardening + audit prep | medium | 1 |
| W3 | Signed, reproducible packaging + provisioning (pin rclone/Nextcloud) | medium | 1 (parallel) |
| W1 | Mobile clients (Android + iOS) over shared Go vault core | xlarge | 2 |
| W6 | **FUTURE: in-browser (WASM/JS) unlock** | large | 3 (last, gated) |

### W0 — Vault-core portability refactor (PHASE 0, prerequisite for W1 and W6)
`internal/vault` and `internal/xcrypto` are already pure-Go with zero cgo/os-exec/net/syscall imports (verified empty grep), so the crypto and exact format are inherently portable. The blocker is ~63 direct filesystem calls hardwired into `vault.go`/`manifest.go` (e.g. `ReadConfig` `vault.go:194`, `storeChunk` `vault.go:472/486`, `loadChunk` `vault.go:601`, `loadManifestIndex` `filepath.WalkDir` `manifest.go:43`, `atomicWriteFile` `vault.go:912`). On Android/iOS scoped storage and in a browser there is no POSIX FS.
*Key steps:* define a minimal `ObjectStore` interface (Get/Put/Stat/List/Remove/AtomicWrite) keeping the existing fan-out scheme (`chunkPath` `vault.go:904`, `manifestPath` `manifest.go:330`); provide an `osStore` reproducing today's exact behavior (0o700 dirs, temp+rename atomicity, WalkDir scan); thread the store through `Vault` (`vault.go:64`); leave `crypto.go` untouched; write a **frozen-format conformance spec + golden-vector suite** (fixed keys+salt → exact bytes for `vault.json`/chunk/manifest/tombstone) as the cross-platform oracle; confirm `GOOS=js GOARCH=wasm` and `c-archive` builds.
*Risk:* the WalkDir conflict resolution **mutates on read** (deletes loser manifests, `manifest.go:34-139`) — the abstraction must preserve that semantic. `atomicWriteFile` relies on same-dir rename atomicity not all backends (object store, browser OPFS) provide. **Must not fork the format.**

### W2 — Key recovery + rotation tied to IAM (zero-knowledge preserved)
Today the vault is single-secret: one password → one wrapKey → unwraps `{MasterKey,IndexKey}` (`crypto.go:168-214`, `vault.go:145,224`); no rotation exists (`README:392`, `SECURITY.md:41-42`). The wrap design already supports multiple independent wraps of the **same** bundle, so org-admin-mediated recovery is possible **without** giving the provider read access.
*Key steps:* generalize `vault.json` from a single `WrappedKeys`/`WrapNonce` (`vault.go:32-33`) to a **list of key-slots**, each an independent AEAD wrap of the same bundle (password slot, recovery-key slot, admin-escrow slot); bump version, keep read-compat (`Open` `vault.go:221`). Recovery-key option: high-entropy random key generated client-side, shown once. **Org-admin escrow (IAM-tied):** the customer admin holds an asymmetric recovery keypair whose **private half never touches the managed server**; the client wraps the bundle to the admin's public key. **IAM gates *who* may request recovery and authenticates the admin; it does not hold decryption keys** — so the provider, even operating IAM, still cannot read. Rotation is rewrap-only (`DESIGN.md:53`). Add CLI/GUI: `add-recovery-key`, `rotate-password`, `add-admin-slot <pubkey>`, `recover --slot`.
*Risk:* admin-escrow changes the org trust model — a malicious admin (or compromised laptop) can recover any user's data; document it and ideally split via quorum/Shamir. The key-slot format is a format change → land it in the W0 frozen spec. Argon2id per slot is heavy on mobile/WASM → per-slot KDF params must be tunable.

### W4 — GUI-client-side invariant + multi-device hardening + audit prep
The whole claim rests on plaintext + keys living only on the user's machine. The GUI/WebDAV decrypts into the local browser session and is loopback by default (`main.go:466,562`), but enforcement is only a default flag + printed warning (`main.go:605`); `--addr` can bind any interface (LR-2). For an audited managed product this must be a **hard invariant**.
*Key steps:* reject non-loopback binds for GUI/serve by default (validate `*addr` resolves to loopback at `main.go:466,562`), require an explicit dangerous override, add Origin/Host allowlist + server-side token check; document that the managed Docker template **must not** run the GUI; add a build/runtime guard so the server-side image cannot start GUI/WebDAV at all; stress-test manifest conflict resolution under real Nextcloud filenames; **add fuzzing** for `decodeEncrypted` (`crypto.go:232`) and `decryptManifest` (`manifest.go:310`) — `SECURITY.md:46`; write threat-model deltas, KDF-floor admin policy, plaintext-free security logging, and an integration test that a managed server image cannot recover any plaintext/key.
*Risk:* hard loopback enforcement may break advanced tunnel users (offer a loud override). Fuzzing may surface real parser bugs to fix before audit. **Independent crypto audit (`README:384`) is gated on W0 (format frozen) + W2 (slots final).**

### W3 — Signed, reproducible packaging + provisioning
The managed rclone runtime is currently fetched **at runtime** from `downloads.rclone.org` (`rclonebin.go:28,114,679`), verified by SHA256 + optional gpg only when local gpg exists (`README:294,387`). For a bundled, audit-ready product shipped via signed Docker templates + vps-capture, the transport binary must be a **pinned artifact baked into the template**, not a runtime download.
*Key steps:* bake a specific rclone version + SHA256 (and Nextcloud version) into the template/build; default `rclonebin` to `install --from-binary` against the bundled artifact (offline path exists, `README:276`), network install behind an off-by-default flag; make client builds reproducible + signed (`-trimpath`, pinned toolchain, codesign/notarize macOS, Authenticode Windows, publish detached sigs + provenance); integrate with vps-capture, recording hashes in the runtime `Manifest` (`rclonebin.go:36-52`); author SBOM + THIRD_PARTY_NOTICES update; add a policy switch disabling all network fetch in managed deployments.
*Risk:* pinning trades auto-updates for reproducibility → needs a controlled update channel (`README:252`); notarization/code-signing need paid certs + CI secrets; the server Docker template **must never bundle or run the client** (W4). Reusable by W6's SRI/hashing recipe.

### W1 — Mobile clients (Android + iOS)
The pure-Go core means crypto is **not** reimplemented per platform (which would risk format divergence — the highest-risk path for a zero-knowledge product). Recommended: a thin **C-ABI/FFI** library (`-buildmode=c-archive`/`c-shared`) exposing open/unlock/list/put/get/remove, rather than heavyweight gomobile bind. The hard parts are storage (no POSIX FS — needs W0 over Android SAF / iOS file coordination) and **sync** (no Nextcloud desktop client on mobile).
*Key steps:* stable FFI surface (stream plaintext, never persist it, zero keys on close); storage backend over Android SAF / iOS file coordination + device keychain (reuse `internal/keychain` per-OS pattern); **sync directly over WebDAV** to the customer Nextcloud — the push/pull object set (`rclone.go:177-197`) maps 1:1 to PROPFIND/GET/PUT — reusing manifest conflict resolution (`manifest.go`); native/Flutter UI; run W0 golden vectors on-device for byte parity.
*Risk:* iOS background limits make large sync hard; partial-sync correctness (`classifyVerifyIssue` `vault.go:825`) must be handled; mobile WebDAV lacks rclone's retry/chunking maturity; recursive WebDAV listing for large vaults is slow (may need a zero-knowledge server index hint); app-store review of an encryption app.

### W6 — FUTURE PHASE (later): optional in-browser (WASM/JS) unlock
> **This is a clearly-labeled LATER phase. It depends on W0 (portable core) and W2 (recovery slots) being frozen first, and ships only after the native + mobile guarantees are locked and audited (Phase 3).**

Lets users open vaults from a web app with no native install: the pure-Go core compiles to `GOOS=js/GOARCH=wasm` and reuses the exact format, so password → Argon2id → unwrap → AES-GCM decrypt all run in the user's browser tab.

**CRITICAL TRUST CAVEAT — stated plainly:** because the **managed server delivers the browser code**, this is **strictly weaker zero-knowledge than the native client.** A compromised or malicious server could serve tampered JS/WASM that captures the password or exfiltrates plaintext at decrypt time. It does **not** match the native-client guarantee and must be presented as a **convenience tier, not the security tier.**

*Mandatory mitigations (reduce, but do not eliminate, the risk):*
- Serve the web app from a domain/CDN **outside** the per-customer managed server, so the origin hosting ciphertext is not the origin serving unlock code.
- **Subresource Integrity (SRI)** pinned on every script/wasm asset.
- **Reproducible builds** of the wasm bundle (reuse W3 recipe) with published hashes so the served bundle is verifiable.
- **Strict CSP.**
- **Short-lived in-memory sessions only** — password entered in-tab, keys unwrapped to memory, no `localStorage`/`IndexedDB` persistence of keys, wiped on tab close/timeout, never sent to the server.
- **Admin policy switch** so security-sensitive customers can disable web unlock entirely.
- **Explicit user-facing + audit documentation** that this is a weaker convenience mode; recommend native/mobile for high-assurance use.

*Fundamental residual risk:* SRI/CSP/off-server hosting reduce but do not eliminate the server-delivered-code risk — any breach of the bundle-serving origin can still serve malicious code. This can never equal the native guarantee and must be documented that way. Argon2id 64 MiB (`crypto.go:28`) is heavy in a tab (may need lower per-slot params, interacting with W2); JS lacks secure memory wipe.

### Recommended sequencing
- **Phase 0 (do first):** W0. Hard dependency for W1 and W6; forces the one-format invariant. **Land W2's key-slot format change into the same frozen spec so the on-disk schema changes only once.**
- **Phase 1 (parallel after W0):** W2 + W4 together (both pure desktop/format work, both audit prerequisites) and W3 in parallel (build/ops, independent of the core API; its reproducible-build recipe is reused by W6).
- **Phase 2:** W1 mobile, once W0 + W2 are stable (mobile users especially need recovery). Largest effort; do not start before the format is frozen.
- **Phase 3 (explicitly last, gated):** W6 WASM unlock — depends on frozen W0, finalized W2 slots, W4 trust-boundary docs, W3 SRI/reproducible recipe.
- **Cross-cutting:** schedule the independent crypto audit (W4) **after** W0 + W2 freeze the format and key model but **before** W6 ships, so the audited surface is the native/mobile core, not the weaker web path.

---

## 8. Open Decisions for Alex

1. **LR-1 priority and shape.** Confirm we land the destination-inside-`.seavault` guard (mirroring `rejectMetadataSource` for the export/restore destination) **before any multi-device/mobile GA**, and decide whether export/restore temp files move to an OS temp dir or stay beside the destination once the guard exists. This is the one thing standing between "holds in practice" and "structurally guaranteed."
2. **Ship-blocker ordering for sync.** Sync fixes #1 (clock-skew lost update) and #2 (chunk conflict data loss) gate any advertised multi-device feature. Decide whether to fix both before the next release or to ship single-device-only and gate multi-device behind a flag until fixed.
3. **Generation model.** Approve the move away from raw wall-clock ordering to a logical counter + device id (and a clock-skew "preserve both" window). This is a format-adjacent decision — it should land in the W0 frozen spec alongside W2's key slots so the schema changes once.
4. **Listener binding policy (LR-2).** Decide whether non-loopback binds are hard-rejected with an explicit `--insecure-bind` override, and whether `localdav` GET gets auth/token. This affects advanced tunnel users.
5. **KDF / password-strength floor.** Set an enforced minimum password strength and an admin-configurable KDF floor (`SECURITY.md:46`), and a documented rekey threshold for GCM nonce volume. The whole server-side guarantee rests on password entropy.
6. **Key-recovery trust model (W2).** Decide between recovery-key-only, admin-escrow, or both — and if admin-escrow, whether to require quorum/Shamir splitting so no single admin slot unlocks. This explicitly introduces a new trusted party into today's pure zero-knowledge model.
7. **Mobile sync transport.** Approve direct WebDAV-from-app (no rclone) for mobile, accepting reduced retry/chunking maturity, vs. investing in a mobile rclone embedding. Also decide on a zero-knowledge-safe server index hint for large-vault listing.
8. **Packaging policy (W3).** Approve dropping runtime rclone auto-download in favor of pinned, baked-in artifacts, accepting the controlled-update-channel cost; and commit to paid code-signing/notarization certs + CI secret handling.
9. **WASM tier — ship or not (W6).** Decide whether the weaker in-browser convenience tier is offered at all, and if so, confirm it is off by default per customer, hosted off the managed origin, and documented as non-security-tier. This is a product/positioning call as much as a technical one.
10. **Audit timing.** Lock the independent crypto audit to *after* W0 + W2 freeze and *before* W6 ships, so the audited surface is the native/mobile core.
