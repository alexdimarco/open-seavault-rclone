# 10-Lens Pre-Code Design Review — Phase U2

**What was reviewed:** `docs/design-u2-gui-and-polish.md` (Revision 1) — Phase U2: Track G (four-destination GUI restructure, returning-user unlock view, runtimes on demand, plain-language messages, BIP-39 word recovery phrases as an encoding layer over the same 256-bit secret, printable card, device-local recovery-key labels, last-key revoke warning, GUI accept-rollback) and Track C (command registry with per-command synopsis and group help, double-dash flags, the 25-row Type III sweep).

**Repository / base:** `github.com/alexdimarco/open-seavault-rclone`, branch `feature/u2-gui-restructure`, base = `main` at the v0.18.0 merge.

**Process run:** assurance-kit `process/design-review.md` — 10 lenses, adversarial skeptic pass, rescue pass, synthesis. Model: **claude-opus-4-8**.

**Code grounding verified in-session (not from the doc):**
- `internal/vault/recovery_phrase.go:62-64` — `canonicalRecovery` keeps only the base32 alphabet (`strings.ToUpper` then keep A–Z/2–7). A 24-word phrase that fails strict decode is therefore silently reducible to a letters-only base32 string rather than raising a typed word error. Grounds **failure-recoverability-1**.
- `cmd/seavault/main.go:2845-2848` — `usageText` advertises rclone `status | install | check-update | update | rollback | verify-runtime` and remote `list | show | test | dry-run | push | pull | check`, but the dispatch switches also accept rclone `version` (`:2361`) / `path` (`:2372`) and remote `sync` (`:2467`) / `config` (`:2472`). The registry reproduces this drift class. Grounds **dependency-cost-3**.

---

## Verdict: **GO_WITH_CONDITIONS**

No blocker survived both the skeptic and the rescue with a required mechanism change, so this is not a NO_GO. Nine findings survived the skeptic pass — five at `[condition]` severity, four at `[note]` severity — each with a concrete, testable fix that is a design revision applied **before** build. All nine are folded into the numbered conditions below. The design's security core (encoding-only word layer, MAC exclusion of labels, unchanged strict rollback gate and read-back ceremony) is sound and survived the adversarial lens intact; every surviving finding is about legibility, drift-proofing of tests, and unspecified edge behavior — none requires a change to a security mechanism.

---

## Conditions (apply as a design revision before build)

| n | Condition | Addresses |
|---|---|---|
| 1 | Specify the word-vs-base32 discriminator and forbid silent degradation. State the rule (e.g. exactly 24 whitespace tokens AND all in the wordlist ⇒ words; else base32) and REQUIRE that a word-shaped input which fails strict decode returns the typed `ErrRecoveryWordUnknown`/`ErrRecoveryWordCount`/`ErrRecoveryChecksum` on BOTH the GUI read-back path AND the redeem (`OpenWithRecovery`) path — never falling through to base32 stripping (`canonicalRecovery` keeps only A–Z/2–7, recovery_phrase.go:62-64). Add a test row: a 24-token phrase with one bad word at redeem yields the word/checksum message, not `errWrongSecret`. | failure-recoverability-1 |
| 2 | Pin the wordlist to an external reference with a golden-vector + hash test outside the vendored file. Assert published BIP-39 English test vectors (fixed entropy → fixed known 24-word STRING constant → `DecodeRecoveryWords` returns that exact secret) AND a SHA-256 of the wordlist against a committed constant. Locks the list against a silent re-vendor that would void every printed card. | durability-1 |
| 3 | Add a registry⟷dispatch equivalence test (both directions): `registry-names == dispatchable-names`. Fold the existing omissions in as red-first rows: rclone `version`/`path` (main.go:2361, 2372) and remote `sync`/`config` (main.go:2467, 2472). H1 today proves only row well-formedness, not set completeness. | dependency-cost-3 |
| 4 | Give the card and the list one stable shared handle. Print the entry-ID first-4-hex on the card AND always show that handle in the list on every device regardless of a local label record; OR a non-destructive "which key is this?" phrase→entry-ID mapping that does not redeem. Today they share only the creation date and the ordinal renumbers on any earlier revoke (rotation.go:241-259). | usability-friction-1 |
| 5 | Render the Welcome-back view whenever no vault is open, including zero profiles, with a "point me at my existing vault folder" path picker calling `/api/open`; reserve the stepper for the genuine no-vault-anywhere case; OR add an explicit "I already have a vault" branch to stepper step 0. Second-device owners (zero profiles) hit `firstRunTrigger` (server.go:1307-1319) and land in the create stepper today. | usability-friction-2 |
| 6 | Gate the printable card / CLI `--save` file on commit — enable only after `handleRecoveryCommit` succeeds, OR stamp the pre-commit card "DRAFT — not yet confirmed". State the ordering in §2.5. As written the card is produced during show-once, before commit. | failure-recoverability-5 |
| 7 | Document and bound the group-help exit-code change: state that bare/`--help` group invocations now exit 0 instead of erroring; keep non-zero for an UNKNOWN subcommand while returning 0 only for explicit `--help`/bare-group help. | migration-coexistence-3 |
| 8 | Reword (or re-harness) the client-side-behavior rows so a Go httptest proves what they claim (no JS engine/DOM parser in any `*_test.go`). For G1/G3/S3/I-U7 either declare a headless harness or reword to server-provable assertions and drop the behavioral phrasing ("reveals", "only after consent", "absent after commit"). | honesty-of-claims-3 |
| 9 | Close the "every message change is covered" gap in §6: add rows for the GUI checksum disclaimer copy, the recovery-saved and keychain-unavailable humanize sentences (§2.4), the consequence-naming revoke-last confirmation text (409 body contains "no recovery path"), and the `--no-open`-under-`--preset` behavior change. Reconcile the "25 rows" figure or narrow §6. | honesty-of-claims-5 |

---

## Per-lens findings

Disposition legend: **confirmed** = survived the skeptic (→ a numbered condition); **refuted** = withdrawn under a refuting quote; **rescued** = a blocker saved by a named mechanism change (none this review).

| id | severity | disposition | one-line |
|---|---|---|---|
| purpose-threat-fit-1 | — | refuted | "3 dropped stepper rows" already exist on the v0.18.0 base. |
| purpose-threat-fit-2 | — | refuted | Word phrases + card trace to a stated job (§2.5). |
| purpose-threat-fit-3 | — | refuted | "A2 backlog" cited concretely (§2.6/§2.7). |
| purpose-threat-fit-4 | — | refuted | Labels degrade to ordinal on other devices by design (§6). |
| focus-proportionality-1 | — | refuted | Security affordances are independently sliced (§7). |
| focus-proportionality-2 | — | refuted | Combine-rationale holds: §2.5/§2.7 encoding/one-request only. |
| focus-proportionality-3 | — | refuted | The word layer is split as its own unit W (§7). |
| focus-proportionality-4 | — | refuted | Both tracks file-disjoint and each small. |
| durability-1 | condition | **confirmed** | Wordlist pinned by nothing external; a re-vendor silently voids printed cards. |
| durability-2 | — | refuted | Labels display-only; redeem/revoke use entry ID (§2.6). |
| durability-3 | — | refuted | Registry is the single help source (§3.1). |
| durability-4 | — | refuted | Panels re-parented with same ids/handlers/api (§2.1). |
| durability-5 | — | refuted | Base32 compact form retained; 0.17 path preserved. |
| usability-friction-1 | condition | **confirmed** | No stable card↔list handle; targeted revoke can retire the wrong key. |
| usability-friction-2 | condition | **confirmed** | Second-device owner (zero profiles) lands in the create stepper. |
| usability-friction-3 | — | refuted | Restructure moves markup only; auth unchanged (I-U1). |
| usability-friction-4 | — | refuted | Browse files stays under Files; DTO has no credential field. |
| usability-friction-5 | — | refuted | Label display-only; ordinal fallback (§2.6). |
| integration-seams-1 | — | refuted | Strict typed decode supplies the read-back message. |
| integration-seams-2 | — | refuted | Generate exposes the 32-byte secret (W1/W3). |
| integration-seams-3 | — | refuted | Profile store shape fits; WrapEntryRefs gives order. |
| integration-seams-4 | — | refuted | §2.7/S2 state the exact server change. |
| integration-seams-5 | — | refuted | Single registry table is the design (§3.1). |
| security-adversarial-1 | — | refuted | Strict typed decode + checksum message (§2.5/W3/I-U2). |
| security-adversarial-2 | — | refuted | Keychain unlock non-interactive → hard-refuses rollback. |
| security-adversarial-3 | — | refuted | Tampered label within conceded device boundary; revoke uses ID. |
| security-adversarial-4 | — | refuted | Print leak within "device compromise after decryption". |
| security-adversarial-5 | — | refuted | textContent render; PII within conceded boundary. |
| security-adversarial-6 | — | refuted | Card client-rendered; humanize never renders raw JSON. |
| failure-recoverability-1 | condition | **confirmed** | Word/base32 discrimination unspecified; mistyped phrase → errWrongSecret. |
| failure-recoverability-2 | — | refuted | Label decoupled; config bytes byte-identical (W5). |
| failure-recoverability-3 | — | refuted | Accept-rollback scoped to rolled-back config (§2.7/S2). |
| failure-recoverability-4 | — | refuted | On-demand install reuses endpoint/consent (I-U6). |
| failure-recoverability-5 | note | **confirmed** | Card produced before commit; failed read-back leaves a card for no entry. |
| failure-recoverability-6 | — | refuted | Single registry table (§3.1); residual gap carried as condition 3. |
| failure-recoverability-7 | — | refuted | Welcome-back reuses open form; read error already swallowed. |
| failure-recoverability-8 | — | refuted | Missing label → ordinal, never an error (§6). |
| migration-coexistence-1 | — | refuted | 0.18 words redeem in 0.17 via the compact form (§6). |
| migration-coexistence-2 | — | refuted | Panels keep ids/handlers; jump-links become in-destination list. |
| migration-coexistence-3 | note | **confirmed** | Group help exits 0 instead of erroring — undocumented cross-version change. |
| migration-coexistence-4 | — | refuted | --json + unchanged positional contract are the stable surface. |
| migration-coexistence-5 | — | refuted | Last-key confirm client-side by design; 0.17 client out of scope. |
| dependency-cost-1 | — | refuted | Provenance substance carried as condition 2. |
| dependency-cost-2 | — | refuted | Flat registry expresses the tree; row per command (§3.1). |
| dependency-cost-3 | condition | **confirmed** | No registry⟷dispatch equivalence test; the drift exists today. |
| dependency-cost-4 | — | refuted | Print sink pre-exists on the base (server.go:4214, 6079). |
| dependency-cost-5 | — | refuted | Label written only inside the commit closure. |
| honesty-of-claims-1 | — | refuted | Z1 git-diff is the stated proof for "no test edited". |
| honesty-of-claims-2 | — | refuted | Registry subsumes standalone functions; Z1 governs no-edit. |
| honesty-of-claims-3 | note | **confirmed** | G1/G3/S3/I-U7 assert client-side behavior the Go harness cannot execute. |
| honesty-of-claims-4 | — | refuted | G1 "How" is a render assertion; presence test is I-U1. |
| honesty-of-claims-5 | note | **confirmed** | §6 over-claims message coverage; disclaimer/humanize/consequence/--no-open uncovered. |
| honesty-of-claims-6 | — | refuted | Same completeness gap; carried as condition 3. |

---

## Refuted findings (with refuting quotes)

- **purpose-threat-fit-1** — server.go:4144 `A few quick steps: choose where the vault lives...` and :4146 `1. Location &amp; cloud`, both from commit e42c1e5 (v0.18.0, ancestor of HEAD).
- **purpose-threat-fit-2** — §2.5 (design:85) "shows the **24 numbered words** by default; the base32 \"compact form\" is shown beneath" + design:88-91 the *Print recovery card*.
- **purpose-threat-fit-3** — §2.6 (design:96) "listed today by a 16-hex ID." + §2.7 (design:110-111) accept-rollback change.
- **purpose-threat-fit-4** — §2.6 "device-local by constraint" + §6:192 "degrades to the ordinal label, never an error."
- **focus-proportionality-1** — §7 slicing + S2 (`rollback_test.go` unchanged).
- **focus-proportionality-2** — Conditional + I-U2/I-U5 ("no re-wrap, no config write"; "rollback_test.go unmodified").
- **focus-proportionality-3** — §7:201 "W (vault words + labels core...)".
- **focus-proportionality-4** — "Two file-disjoint tracks ship in one phase because each is small."
- **durability-2** — §2.6 "Redeem/revoke keep using the entry ID; the label is display-only."
- **durability-3** — §3.1 "one command registry table ... that `usage()` and each `--help` render from."
- **durability-4** — §2.1 "same element ids, same handlers, same `/api` calls."
- **durability-5** — §2.5/§6 (compact base32 form retained beneath the words).
- **usability-friction-3** — I-U1 (doc:145-147) "every pre-U2 element id, handler, /api route, auth check ... unchanged."
- **usability-friction-4** — server.go:4253 (Browse files inside files-panel) + server.go:312-324 (webdavStatusDTO has no credential field).
- **usability-friction-5** — §2.6 (label display-only, ordinal fallback).
- **integration-seams-1** — §2.5 bullet 1 (typed strict decode) + bullet 3 (checksum message at read-back).
- **integration-seams-2** — W1/W3 (secret → words round-trip proven).
- **integration-seams-3** — §2.6 store shape + rotation.go:263-271 WrapEntryRefs().
- **integration-seams-4** — §2.7 + S2 (server passes AcceptRollback only for that request).
- **integration-seams-5** — §3.1 (single registry table).
- **security-adversarial-1** — §2.5 + W3 + I-U2 (strict typed decode; never panics).
- **security-adversarial-2** — main.go:663-665 (keychain/env unlock non-interactive → hard-refuse) + vault.go:76-81.
- **security-adversarial-3** — SECURITY.md (app-data write within conceded device boundary) + §2.6 (revoke uses entry ID).
- **security-adversarial-4** — §2.5 (U1 save rules) + SECURITY.md "Device compromise before encryption or after decryption."
- **security-adversarial-5** — server.go:4795 (textContent) + SECURITY.md conceded boundary.
- **security-adversarial-6** — §2.5/I-U7 (client-rendered) + §2.4 (humanize never renders raw JSON).
- **failure-recoverability-2** — §2.6/W5 (config bytes byte-identical; label display-only).
- **failure-recoverability-3** — §2.7 (110-113) + S2 (180) (scoped to rolled-back config).
- **failure-recoverability-4** — I-U6 (158) + §2.3 (55-56).
- **failure-recoverability-6** — §3.1 (124-126); residual gap carried as condition 3.
- **failure-recoverability-7** — §2.2 + server.go:1380 (`entries, _ := profile.Entries()` swallows the read error).
- **failure-recoverability-8** — §6 + §2.6 (missing record → ordinal).
- **migration-coexistence-1** — §6 "redeem in 0.17 only via the compact form shown beneath the words."
- **migration-coexistence-2** — §2.1 (same ids/handlers/api; jump-links become the section list).
- **migration-coexistence-4** — main.go:175 (--json) + positional contract at main.go:1968, :2839.
- **migration-coexistence-5** — I-U4 + §2.7 (explicit consequence-naming confirmation).
- **dependency-cost-1** — W1 (round-trip proven); provenance carried as condition 2.
- **dependency-cost-2** — §3.1 (one row per command).
- **dependency-cost-4** — server.go:4214 (setupRecoveryPrint) + :6079 (win.print()); pre-U2 base.
- **dependency-cost-5** — rotation.go:178-184 (makeRecoveryEntry inside commit closure) + §6:192.
- **honesty-of-claims-1** — Z1 (`git diff --stat` against base + green race suite is the stated proof).
- **honesty-of-claims-2** — §3.1 (registry subsumes functions) + Z1.
- **honesty-of-claims-4** — §5:170 (G1 render assertion) vs :147 (I-U1 presence test).
- **honesty-of-claims-6** — §3.1 (single table); residual gap carried as condition 3.

---

## Rescue pass

`{"rescues":[],"overall":"no blockers survived the skeptic pass; rescue not needed"}`

No finding reached NO_GO severity after the skeptic, so none entered the rescue pass and nothing was rescued by a named mechanism change. The verdict rests on the nine confirmed findings, all discharged as conditions.

---

## What the build must prove (conditions → test-matrix rows)

| Condition | Existing row it amends | New assertion the build must add |
|---|---|---|
| 1 (word/base32 discriminator) | W2, W3 | A 24-token phrase with one bad word, redeemed via `OpenWithRecovery`, returns the typed `ErrRecoveryWord*`/`ErrRecoveryChecksum` message — NOT `errWrongSecret`. Extend W2 to assert the discriminator boundary. |
| 2 (wordlist pin) | H3 | (a) fixed BIP-39 entropy → known 24-word STRING constant → `DecodeRecoveryWords` == exact secret; (b) `sha256(wordlist)` == committed constant. Independent of W1/W3/W4. |
| 3 (registry⟷dispatch) | H1 | `registry-names == dispatchable-names` both directions, with rclone version/path and remote sync/config as red-first rows. |
| 4 (stable handle) | W5 | Card carries the entry-ID first-4-hex AND the list shows that handle on a device with NO local label record; OR a non-destructive phrase→entry-ID test. |
| 5 (Welcome-back zero profiles) | G2 | Zero profiles + none open + resolvable existing-vault path → Welcome-back view, NOT the stepper; picker calls `/api/open`. |
| 6 (card gated on commit) | S3 | Print affordance / CLI `--save` unavailable (or DRAFT-stamped) before commit; present only after `handleRecoveryCommit` succeeds. |
| 7 (exit code) | H1 | UNKNOWN subcommand exits non-zero while explicit `--help`/bare-group help exits 0; documented in changelog. |
| 8 (honest client rows) | G1, G3, S3 | Server-provable assertions (hidden default; status/install contract + consent source present; server never re-serves the phrase after commit), or a headless harness. |
| 9 (message coverage) | G4, S1, H2 | GUI checksum disclaimer copy; recovery-saved and keychain-unavailable humanize sentences; revoke-last 409 body contains "no recovery path"; `--no-open`-under-`--preset` behavior. |

**Gate discipline reminder (per CLAUDE.md):** each condition ships prove-fail → prove-pass (write the regression test, neutralize the fix, confirm it fails for the right reason, restore, confirm it passes, commit fix + test together). Conditions 1, 2, and 3 are the recovery-critical ones — a green suite today catches none of the three failure modes, which is why they are conditions rather than notes.

*Filed at `docs/review-u2-predesign.md`.*
