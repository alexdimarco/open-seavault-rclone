# Design — Phase U2: the four-destination GUI, word recovery phrases, and the operability polish backlog

STATUS: pre-code design, awaiting the 10-lens review. Revision 1.

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

When saved vaults exist and none is open, the index renders a small *Welcome back* view: the
saved-vault list, a password field, Open, plus one link "Go to the full app". It is the existing
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
  bits each; license recorded in THIRD_PARTY_NOTICES.md) and two pure functions —
  `EncodeRecoveryWords(secret [32]byte) []string` (24 words: 256 bits + an 8-bit SHA-256
  checksum, exactly BIP-39 mnemonic construction) and `DecodeRecoveryWords(words []string)
  ([32]byte, error)` with **strict** decoding: unknown word, wrong count, or checksum mismatch
  return typed errors (`ErrRecoveryWordUnknown`, `ErrRecoveryWordCount`,
  `ErrRecoveryChecksum`); input is normalized (trim, lowercase, collapse whitespace) before
  lookup and never panics on any input.
- `canonicalRecovery(input)` accepts, in order: 24 words → decode → canonical base32; grouped or
  ungrouped base32 → as today. So **redeem accepts either form for the same secret**, no
  re-wrap, no config change, and every phrase issued by 0.15–0.18 keeps working.
- Generate (CLI and GUI) shows the **24 numbered words** by default; the base32 "compact form"
  is shown beneath for people who prefer it. The read-back ceremony is unchanged (hide, re-type,
  paste and drop blocked in the GUI); the checksum now also catches a mistyped word at
  read-back with a specific message.
- **Printable card:** the GUI gets *Print recovery card* — a print-styled view (vault name, date,
  the 24 numbered words, "keep this on paper away from the computer; anyone holding it can open
  the vault") rendered client-side from the phrase already on screen; it exists only during the
  show-once step. The CLI `--save` file (U1) becomes the same card in text; the U1 rules apply
  (0600, refused inside the vault dir, warned under a synced folder).

### 2.6 Friendly recovery-key labels (A2 backlog) — device-local by constraint

Recovery entries are listed today by a 16-hex ID. **Labels must NOT enter the MAC-covered
config**: `vault.json` is shared by mixed 0.17/0.18 fleets and the ConfigMAC canonicalizes the
config struct, so a field a 0.17 client does not know would make it compute a different tag and
refuse the vault as tampered (the A2 mixed-fleet guarantee). Therefore labels live in the app-
data profile store (`profile` package, per device): `{entryID: {label, created, device}}` written
at generate time; the list shows *Recovery key 2 — created 2026-09-07 on alex-laptop* when a
local record exists and *Recovery key 2* (ordinal by config order, plus the first four hex
characters) otherwise. A test proves the config bytes are byte-identical before and after
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

Every registered subcommand gets a one-line synopsis and a usage line with **double-dash** flags
matching the README; group-level help (`seavault password --help`, `recovery`, `vault`,
`keychain`, `rclone`, `rsync`, `remote`, `ssh-key`, `profile`) lists its subcommands with their
synopses instead of erroring. Implemented as one command registry table
(`cmd/seavault/commands.go`: name, group, synopsis, usage, handler) that `usage()` and each
`--help` render from — so a test can iterate every row.

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
- **I-U7** The printable card exists only during the show-once step and is rendered client-side
  from the phrase already displayed; the CLI card file follows the U1 save rules.
- **I-U8** Track C is text-only: no behaviour change outside the listed message fixes; the
  unfiltered suite stays green with no test edited.
- **Conditional:** the BIP-39 checksum catches a single mistyped word with probability 255/256;
  it is a usability aid, not a security control (labeled in the GUI copy).

## 5. Test matrix (red-first; every row asserts)

| ID | Proves | How |
|---|---|---|
| G1 | §2.1 | the page renders exactly four destinations; every pre-U2 panel id appears under exactly one; Advanced is `hidden` by default; the toggle reveals it |
| G2 | §2.2 | profiles exist + none open → *Welcome back* view; none exist → stepper; open → Files |
| G3 | §2.3 | with a fake runtime seam reporting "missing", the Cloud flow presents the consent step and calls the existing install endpoint only after consent |
| G4 | §2.4 | change-password success body/text contains no `{` and the plain sentence; panel header names the vault |
| W1 | I-U2 | 1,000 random secrets: words → decode == secret; canonicalRecovery(words) == canonicalRecovery(base32) |
| W2 | I-U2 | strict-decode table (unknown word, 23/25 words, bad checksum, mixed case/whitespace) → the typed error per row, no panic |
| W3 | I-U2 | generate emits 24 words + compact form; RecoveryPhraseMatches accepts all three forms; a mistyped word yields the checksum message |
| W4 | crossversion | a vault whose phrase was issued as base32 (0.17 fixture) redeems by base32 AND by its word form |
| W5 | I-U3 | config bytes identical before/after labeling; label store keyed by entry ID; listing shows the label |
| S1 | I-U4 | revoke-last confirms (GUI 409 without confirm, 200 with; CLI refuses without `--yes` non-interactively) |
| S2 | I-U5 | rolled-back config: GUI open payload carries `canAcceptRollback`; `/api/open` with `acceptRollback` + password opens; without the password → 400; `rollback_test.go` unchanged |
| S3 | I-U7 | the card view is absent after commit/cancel; CLI card file 0600 and refused in-vault |
| H1 | §3.1 | table over the command registry: every row's `--help` prints a non-empty synopsis and double-dash usage; every group help lists its subcommands |
| H2 | §3.2 | each message fix asserted (caveat once, no doubled Note, leftovers remedy, profile remove output, keyless-open reminder, recovery password note) |
| H3 | docs | README provider list matches the catalog with OS qualification (drift guard extended); THIRD_PARTY_NOTICES carries the wordlist license |
| Z1 | I-U1, I-U8 | `git diff --stat` against the branch base shows no deleted/edited pre-U2 test; the unfiltered race suite is green |

## 6. Failure and coexistence

A 0.17 client on the same vault sees no config change (I-U2/I-U3). A user who wrote down a base32
phrase in 0.17 redeems it in 0.18 unchanged; a user who writes down 24 words in 0.18 can redeem
in 0.17 only via the compact form shown beneath the words (stated in the GUI copy and README).
The label store is per device; a missing record degrades to the ordinal label, never an error.
`localStorage` failures degrade to "advanced hidden". Every message change is covered by a test
so a future wording edit is a visible diff, not a silent regression.

## 7. Build order

W (vault words + labels core, THIRD_PARTY_NOTICES) → G1 (restructure, returning view, advanced
toggle, plain messages) → G2 (recovery UX: words, card, labels, last-key, accept-rollback,
runtimes on demand) → C1 (command registry, synopses, group help, double-dash) → C2 (Type III
sweep + docs) → final verification. Each slice: builder, independent verifier, one fix cycle.
