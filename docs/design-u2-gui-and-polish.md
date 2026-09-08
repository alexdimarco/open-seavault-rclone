# Design — Phase U2: the four-destination GUI, word recovery phrases, and the operability polish backlog

STATUS: Revision 2 — the 9 conditions of the pre-code review (`docs/review-u2-predesign.md`, GO_WITH_CONDITIONS; 53 judged / 44 refuted / 0 blockers) are applied below and in §8. Ready to build.

## 1. Goal and scope

U1 gave a new user a guided first run. U2 makes the product **usable every day by an average
person without hiding anything from an expert**, and clears the operability backlog the three
friction reviews accumulated. Two file-disjoint tracks ship in one phase because each is small
and both are pure UX/legibility over unchanged security mechanisms:

- **Track G (GUI, `internal/webui` + a small `internal/vault` encoding layer):** the four-
  destination restructure, a returning-user unlock view, runtimes installed on demand inside the
  cloud flow, plain-language messages, word-based recovery phrases with a printable card,
  friendly recovery-key labels, a last-key revoke warning, and a GUI accept-rollback affordance.
- **Track C (CLI + docs, `cmd/seavault` + `docs/` + README):** a synopsis for every command and
  working group-level help, double-dash flag presentation, and the 25 Type III rows from the U1
  friction review plus the A2-era doc items.

**Out of scope:** any vault-format change, any change to the recovery read-back ceremony, the
strict rollback gate, the GC fence, session auth, or transports. If a U2 change would need one,
it stops and comes back as a design question.

## 2. Track G — the GUI

### 2.1 Four destinations (replaces 22 stacked panels)

A top-level destination bar (`<nav class="destinations">`, four buttons) shows exactly ONE
destination at a time; the existing panels are re-parented, renamed by job, and otherwise
unchanged (same element ids, same handlers, same `/api` calls). The jump-links nav becomes the
in-destination section list.

| Destination | Panels (current name → shown name) |
|---|---|
| **Files** (default when a vault is open) | Open or create vault → *Your vault*; Saved vault locations → *Switch vault*; Upload into encrypted archive → *Add files*; Export plaintext from vault → *Get files out*; WebDAV file manager → *Browse files*; Result and progress (pinned at the bottom of every destination) |
| **Cloud sync** | Remote repositories → *Cloud sync*; SSH keys for rclone SFTP → *SFTP keys* (disclosure inside Cloud sync) |
| **Security** | Password & recovery → *Password and recovery key*; the health actions (Verify, Garbage-collect) gathered as *Check vault health*; the notice banner is rendered here AND at the top of every destination |
| **Advanced** (collapsed behind a "Show advanced" toggle) | Advanced raw file list, Move vault location, Managed rsync runtime, Rclone runtime, Settings, the "How to start" guide → *Help* |

The "Show advanced" state is per-browser (`localStorage`, default off, guarded try/catch). The
current *Help* page and the first-run stepper are unchanged; the stepper's "Skip to advanced"
lands on Files with advanced shown.

### 2.2 Returning-user unlock view (U1 friction GUI-5)

Whenever no vault is open the index renders a small *Welcome back* view (C5): the saved-vault
list (if any), a password field, Open, an **"I already have a vault — choose its folder"** path
picker that calls the existing `/api/open` (the profile store is device-local, so a returning owner
on a second device has zero profiles but a vault in a synced folder), a **"Create a new vault"**
button that leads to the first-run stepper, plus one link "Go to the full app". The stepper is
no longer the automatic landing for zero profiles; it is reached through that button. It is the existing
open form re-skinned; it calls the existing `/api/open` and sets nothing new server-side. The
first-run trigger (no vaults) still renders the stepper; a vault open renders Files.

### 2.3 Runtimes on demand (U1 review C11 pattern, A2 backlog)

The *Cloud sync* flow calls the EXISTING `/api/rclone/status` and, when the runtime is missing,
shows one consent step ("Download rclone <version> from rclone.org?") that calls the EXISTING
`/api/rclone/install`, then continues. No new download path. The Advanced runtime panels stay
for status/update/rollback.

### 2.4 Plain-language messages (A2 backlog, U1 GUI-5/GUI-6)

`humanize()` gains per-endpoint sentences so no success message ever renders raw JSON:
password change → "Password changed. The old password no longer opens this vault. Other devices
will need the new password after `vault.json` syncs."; recovery saved → "Recovery key saved and
labeled *<label>*."; keychain unavailable → a plain lead line before the technical detail. The
*Password and recovery key* panel header names the open vault. Password fields get inline
mismatch validation and a light strength hint (empty-password guard unchanged).

### 2.5 Word-based recovery phrases + printable card (A2 backlog, U1 C6)

Today a recovery phrase is a fresh 256-bit secret rendered as 52 base32 characters in 13
groups; the **canonical wrap secret fed to the KDF is the ungrouped base32 string**
(`internal/vault/recovery_phrase.go`). U2 adds an **encoding layer only**:

- `internal/vault/recovery_words.go`: a vendored **BIP-39 English wordlist** (2048 words, 11
  bits each; license recorded in THIRD_PARTY_NOTICES.md), **pinned (C2)** by a golden-vector
  test (a published BIP-39 English vector: fixed entropy → the exact known 24-word string →
  `DecodeRecoveryWords` returns that secret) and a SHA-256 of the wordlist asserted against a
  constant held outside the vendored file, so a silent re-vendor that would make printed cards
  unredeemable is red and two pure functions —
  `EncodeRecoveryWords(secret [32]byte) []string` (24 words: 256 bits + an 8-bit SHA-256
  checksum, exactly BIP-39 mnemonic construction) and `DecodeRecoveryWords(words []string)
  ([32]byte, error)` with **strict** decoding: unknown word, wrong count, or checksum mismatch
  return typed errors (`ErrRecoveryWordUnknown`, `ErrRecoveryWordCount`,
  `ErrRecoveryChecksum`); input is normalized (trim, lowercase, collapse whitespace) before
  lookup and never panics on any input.
- **Discriminator (C1):** after normalization, an input of **exactly 24 whitespace-separated tokens
  that are all in the wordlist** is a word phrase; anything else is treated as base32. A
  word-shaped input (24 tokens, or 20–28 tokens where most are wordlist words) that fails strict
  decode returns the typed word error (`ErrRecoveryWordUnknown` / `ErrRecoveryWordCount` /
  `ErrRecoveryChecksum`) on BOTH the GUI read-back path AND the redeem path
  (`OpenWithRecovery`), and **never falls through to base32 stripping** — today
  `canonicalRecovery` keeps only A–Z/2–7, which would map mistyped words to a wrong secret and
  surface only a wrong-secret error. `canonicalRecovery(input)` therefore: word phrase → decode
  → canonical base32; otherwise grouped or ungrouped base32 → as today. So **redeem accepts either form for the same secret**, no
  re-wrap, no config change, and every phrase issued by 0.15–0.18 keeps working.
- Generate (CLI and GUI) shows the **24 numbered words** by default; the base32 "compact form"
  is shown beneath for people who prefer it. The read-back ceremony is unchanged (hide, re-type,
  paste and drop blocked in the GUI); the checksum now also catches a mistyped word at
  read-back with a specific message.
- **Printable card:** the GUI gets *Print recovery card* — a print-styled view (vault name, date,
  the 24 numbered words, "keep this on paper away from the computer; anyone holding it can open
  the vault") rendered client-side from the phrase already on screen; **Ordering (C6):** the card printed during the show-once step (before the read-back
  commits) is stamped **DRAFT — not confirmed until you complete the read-back; destroy this card
  if you cancel**, and after `handleRecoveryCommit` succeeds a *Print confirmed card* action
  re-renders the same words without the stamp (the phrase is retained in memory only until the
  panel is closed). The CLI `--save` file (U1) becomes the same card in text; the U1 rules apply
  (0600, refused inside the vault dir, warned under a synced folder).

### 2.6 Friendly recovery-key labels (A2 backlog) — device-local by constraint

Recovery entries are listed today by a 16-hex ID. **Labels must NOT enter the MAC-covered
config**: `vault.json` is shared by mixed 0.17/0.18 fleets and the ConfigMAC canonicalizes the
config struct, so a field a 0.17 client does not know would make it compute a different tag and
refuse the vault as tampered (the A2 mixed-fleet guarantee). Therefore labels live in the app-
data profile store (`profile` package, per device): `{entryID: {label, created, device}}` written
at generate time; every entry carries a **stable handle** — the first four hex characters of its entry ID —
shown on the printable card AND in the list on EVERY device (C4), so a targeted revoke can never
retire the wrong key even after earlier revokes renumber ordinals; the list shows *Recovery key
#ad82 — created 2026-09-07 on alex-laptop* when a local record exists and *Recovery key #ad82*
otherwise. A test proves the config bytes are byte-identical before and after
labeling. Redeem/revoke keep using the entry ID; the label is display-only.

### 2.7 Last-key warning and GUI accept-rollback (A2 backlog)

Revoking the last remaining recovery key (GUI and CLI) requires an explicit confirmation that
states the consequence ("the vault will have no recovery path; a forgotten password cannot be
recovered"); CLI non-interactive requires `--yes`. For a rolled-back config the GUI open today
just shows the strict-gate refusal; U2 adds a *I restored this from a backup — accept and open*
button that re-submits `/api/open` with `acceptRollback:true` **and the password re-entered**
(the same rule the CLI follows: acceptance always re-supplies the credential); the server passes
`AcceptRollback` only for that request. The non-interactive path and `checkFreshness` are
untouched.

## 3. Track C — CLI and docs

### 3.1 `--help` that teaches (A2 backlog, U1 ADM-6)

**Exit-code contract (C7):** an explicit `--help` or a bare group invocation prints help and exits
0 (a documented change from today's error exit, noted in the changelog); an UNKNOWN subcommand
still exits non-zero so error-guarding scripts detect typos.

Every registered subcommand gets a one-line synopsis and a usage line with **double-dash** flags
matching the README; group-level help (`seavault password --help`, `recovery`, `vault`,
`keychain`, `rclone`, `rsync`, `remote`, `ssh-key`, `profile`) lists its subcommands with their
synopses instead of erroring. Implemented as one command registry table
(`cmd/seavault/commands.go`: name, group, synopsis, usage, handler) that `usage()` and each
`--help` render from — so a test can iterate every row. **Completeness (C3):** `main()` dispatches FROM the registry (one
shared table), and a test asserts registry-names == dispatchable-names in both directions; the
already-known omissions become its first red-first rows (rclone `version`/`path`, remote
`sync`/`config`, which `usage()` does not advertise today).

### 3.2 The Type III sweep (U1 friction, 25 rows) and A2 doc items

CLI: show a provider caveat once; strip the doubled "Note: note:" prefix; re-emit the recovery-
deferral reminder when a keyless vault is opened and in `profile list`; note that `recovery
generate` will ask for the vault password; drop the "open the app" trailer and neutralize
`--no-open` under `--preset`; `ErrVaultDirLeftovers` names the remedy; keychain-failure summary
is a plain one-liner with the raw error only under `--debug`; `profile remove` prints what it
removed; the U1 exit-code note. Docs: README qualifies detected providers by OS, foreshadows the
three-way cloud question, removes the stale "future work" bullet, shows how to obtain the
"existing" rclone remote and where `remote config validate` looks; states that `--preset` stores
the password in the keychain by default and how to opt out; states the reversible-pre-A3 seal
fact, `SEAVAULT_NEW_PASSWORD`, that write commands now write a `configTag`, and that `recovery
generate` is interactive-only.

## 4. Security invariants (proven by §5 unless labeled)

- **I-U1** The restructure moves markup only: every pre-U2 element id, handler, `/api` route,
  auth check, and control (read-back, paste/drop block, strict rollback gate, GC fence) is
  unchanged. Proven by the pre-U2 webui test suite passing **without any test edited** plus a
  presence test that every pre-U2 panel/control id still exists on the page.
- **I-U2** Word phrases are an encoding of the same 256-bit secret: encode/decode round-trips;
  redeem accepts words, grouped, and ungrouped base32 for one secret; decode is strict with typed
  errors and never panics; no re-wrap, no config write.
- **I-U3** Labels never enter the MAC-covered config: config bytes are byte-identical before and
  after labeling; mixed-fleet compatibility is preserved.
- **I-U4** Revoking the last recovery key requires an explicit consequence-naming confirmation
  (GUI confirm; CLI prompt or `--yes`).
- **I-U5** GUI accept-rollback re-supplies the password and applies to one request; the
  non-interactive path and `checkFreshness` are untouched (`rollback_test.go` unmodified).
- **I-U6** Runtimes on demand reuse the existing install endpoint and consent; no new download
  path; the Advanced panels remain.
- **I-U7** The printable card is rendered client-side from the phrase already displayed, stamped DRAFT before commit and re-rendered clean only after commit (C6); it is never served again once the panel closes, and it is rendered client-side
  from the phrase already displayed; the CLI card file follows the U1 save rules.
- **I-U8** Track C is text-only: no behaviour change outside the listed message fixes; the
  unfiltered suite stays green with no test edited.
- **Conditional:** the BIP-39 checksum catches a single mistyped word with probability 255/256;
  it is a usability aid, not a security control (labeled in the GUI copy).

## 5. Test matrix (red-first; every row asserts)

| ID | Proves | How |
|---|---|---|
| G1 | §2.1 | the server-rendered page has exactly four destination controls; every pre-U2 panel id appears under exactly one; the Advanced container carries `hidden` by default and the toggle's source is present (the harness has no JS engine — client behaviour is not claimed, C8) |
| G2 | §2.2 | no vault open + profiles → *Welcome back* with the list; no vault open + zero profiles → *Welcome back* with the folder picker and the Create button (no automatic stepper, C5); the Create button reaches the stepper; open → Files |
| G3 | §2.3 | the status/install endpoint contract: `/api/rclone/status` reports missing; `/api/rclone/install` is the only install route and is unchanged; the consent-gating source is present in the page (C8) |
| G4 | §2.4 | change-password success body/text contains no `{` and the plain sentence; panel header names the vault |
| W1 | I-U2 | 1,000 random secrets: words → decode == secret; canonicalRecovery(words) == canonicalRecovery(base32) |
| W2 | I-U2 | strict-decode table (unknown word, 23/25 words, bad checksum, mixed case/whitespace) → the typed error per row, no panic |
| W3 | I-U2 | generate emits 24 words + compact form; RecoveryPhraseMatches accepts all three forms; a mistyped word yields the checksum message |
| W4 | crossversion | a vault whose phrase was issued as base32 (0.17 fixture) redeems by base32 AND by its word form |
| W5 | I-U3 | config bytes identical before/after labeling; label store keyed by entry ID; listing shows the label |
| S1 | I-U4 | revoke-last confirms (GUI 409 without confirm, 200 with; CLI refuses without `--yes` non-interactively) |
| S2 | I-U5 | rolled-back config: GUI open payload carries `canAcceptRollback`; `/api/open` with `acceptRollback` + password opens; without the password → 400; `rollback_test.go` unchanged |
| S3 | I-U7 | the server never re-serves the phrase after commit or cancel; the pre-commit card source carries the DRAFT stamp and the post-commit render does not; CLI card file 0600, DRAFT line rewritten on commit, refused in-vault (C6/C8) |
| H1 | §3.1 | table over the command registry: every row's `--help` prints a non-empty synopsis and double-dash usage; every group help lists its subcommands |
| H2 | §3.2 | each message fix asserted (caveat once, no doubled Note, leftovers remedy, profile remove output, keyless-open reminder, recovery password note) |
| H3 | docs | README provider list matches the catalog with OS qualification (drift guard extended); THIRD_PARTY_NOTICES carries the wordlist license |
| W6 | C1 | a 24-token phrase with one bad word at GUI read-back AND at redeem yields the typed word/checksum message, never the wrong-secret error |
| W7 | C2 | the BIP-39 golden vector decodes to its known secret; the wordlist SHA-256 equals the pinned constant |
| H4 | C3 | registry-names == dispatchable-names both directions (rclone version/path, remote sync/config included) |
| H5 | C7 | `--help`/bare-group exits 0; unknown subcommand exits non-zero |
| M1 | C9 | each message asserted: the checksum \"usability aid, not a security control\" GUI copy; the humanize() recovery-saved and keychain-unavailable sentences; the revoke-last 409 body contains \"no recovery path\"; `--no-open` under `--preset` is inert |
| Z1 | I-U1, I-U8 | `git diff --stat` against the branch base shows no deleted/edited pre-U2 test; the unfiltered race suite is green |

## 6. Failure and coexistence

A 0.17 client on the same vault sees no config change (I-U2/I-U3). A user who wrote down a base32
phrase in 0.17 redeems it in 0.18 unchanged; a user who writes down 24 words in 0.18 can redeem
in 0.17 only via the compact form shown beneath the words (stated in the GUI copy and README).
The label store is per device; a missing record degrades to the ordinal label, never an error.
`localStorage` failures degrade to "advanced hidden". Every message change LISTED IN THE MATRIX (§5, incl. M1) is covered by a test so a future wording
edit is a visible diff, not a silent regression (C9).

## 7. Build order

W (vault words + labels core, THIRD_PARTY_NOTICES) → G1 (restructure, returning view, advanced
toggle, plain messages) → G2 (recovery UX: words, card, labels, last-key, accept-rollback,
runtimes on demand) → C1 (command registry, synopses, group help, double-dash) → C2 (Type III
sweep + docs) → final verification. Each slice: builder, independent verifier, one fix cycle.

## 8. Revision 2 — how each review condition was applied

| Cond | Applied as |
|---|---|
| C1 | §2.5 discriminator rule; word-shaped failures return typed word errors on GUI read-back AND redeem, never base32 fall-through; W6 |
| C2 | §2.5 wordlist pinned by golden vector + SHA-256 constant outside the vendored file; W7 |
| C3 | §3.1 one shared table drives dispatch; registry==dispatch equivalence test with the known omissions as first rows; H4 |
| C4 | §2.6 stable 4-hex handle on card and list on every device |
| C5 | §2.2 Welcome-back whenever no vault is open, with "I already have a vault" picker and "Create a new vault" → stepper |
| C6 | §2.5 pre-commit card stamped DRAFT, confirmed reprint after commit; CLI --save rewritten on commit; S3 |
| C7 | §3.1 exit-code contract: help exits 0, unknown subcommand non-zero; H5; changelog note |
| C8 | G1/G3/S3 reworded to what a Go httptest harness proves (no client-behaviour claims) |
| C9 | M1 row for every message change; §6 narrowed to the matrix |

