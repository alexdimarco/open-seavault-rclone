<!--
Friction review — BUILT Phase U2 (open-seavault-rclone @ feature/u2-gui-restructure)
Method: assurance-kit process/friction-review.md, walked against the REAL binary, not source reading.
  Binary: go build -o /tmp/sv-u2/seavault ./cmd/seavault (reports version 0.19.0).
  State isolation on every actor: SEAVAULT_APP_HOME + HOME = fresh temp dirs; --no-keychain on the CLI;
  savePassword never sent, so the real Secret Service / user home / real rclone.conf were never touched
  (rclone.conf mtime confirmed unchanged). Every process started was killed by PID.
  GUI walked HEADLESSLY via curl through the real /api/*: redeem the printed launch link
  (GET /?launch=<secret> -> cookie), CSRF browserToken from GET /api/status, state-changing calls as
  POST with the X-open-seavault-rclone-Token header re-read per response. Client-rendered copy (print
  card, humanize() sentences, native window.confirm) read from served page source — curl runs no JS
  (the C8-acknowledged harness limit); every server RESPONSE was exercised live and quoted verbatim.
  CLI walked under a PTY where a typed read-back / interactive unlock was required.
  Four actors: non-technical GUI owner; returning owner on a bare SECOND DEVICE (synced vault, 3 keys);
  CLI operator; new operator inheriting cold from docs only.
Cells walked: 24. Functioning: 19 yes / 4 partial / 1 no.
Verdict: HIGH_FRICTION_NOT_SHIPPABLE.
-->

# Phase U2 friction review — GUI restructure, recovery UX, CLI registry

**Method.** Four friction-review actors (assurance-kit `process/friction-review.md`) drove the built
`/tmp/sv-u2/seavault` (v0.19.0) headlessly against the real `/api/*` and under a PTY on the CLI, all state
isolated in throwaway `SEAVAULT_APP_HOME`/`HOME` temp dirs with `--no-keychain`. No real home, keychain, or
rclone config was touched; every launched process was killed by PID.

**Cells walked: 24. Functioning: 19 yes / 4 partial / 1 no.**

## Verdict: HIGH_FRICTION_NOT_SHIPPABLE

One cell is `functions=no` on a Type II control gap, and the primary recovery-redeem golden path on a second
device is high-friction. The Type II items that drive the verdict:

1. **CLI last-key revoke has no gate (drives `functions=no`, security-sensitive).** `seavault recovery revoke`
   of the *only* remaining recovery key succeeds silently (exit 0) with no confirmation, and `--yes` is not even
   a defined flag. The last-key refusal exists only in the GUI (verified live: HTTP 409 without `confirm`, 200
   with). This violates design **I-U4**, **§2.7**, and test-matrix rows **S1/M1**, and no `cmd/seavault` test
   asserts the refusal, so the green suite does not catch it. This owes an **adversarial pass** (key handling),
   not merely a friction note, and a prove-fail → prove-pass cmd-level regression.
2. **Recovery-redeem golden path is unsignposted on a second device.** Welcome-back — exactly where a locked-out
   returning owner lands — has no forgot-password / redeem affordance; redeem is reachable only by clicking the
   generic "Go to the full app" then hunting the Security destination. The redeem panel then reads the vault path
   from `#vaultPath`, which the four-destination restructure moved to a *different tab*, and its hint still says
   "enter the vault path above" (stale). ~8 actions for the primary redeem user.
3. **`recovery generate` leaks the phrase on a non-interactive invocation.** The v0.19 changelog promises the
   command is interactive-only and "a phrase nobody has seen must not be committed", but a redirected run prints
   all 24 words + the compact base32 to stdout *before* failing the read-back with a bare `error: EOF`. The
   secret reaches any log/redirect even though nothing is committed.
4. **`remote config create --help` has a filesystem side effect.** It executes rather than printing help —
   creating the managed `rclone.conf` on disk and exiting 0 — so the universal "show usage, change nothing" idiom
   mutates state, contradicting the v0.19 "every subcommand honors `--help`" promise.
5. **Files daily golden path still shows the old jargon.** Only the nav links were renamed; the panel `<h2>`
   headings the owner lands on (and their hints) still read "Upload into encrypted archive", "Export plaintext
   from vault", "WebDAV file manager", "Remote repositories", "SSH keys for rclone SFTP" — the very jargon the
   restructure existed to retire. Security's headings *were* job-named, proving the rename was left half-done.
6. **`recovery generate` cannot save/print a card.** The DRAFT recovery-card ceremony exists only in the `setup`
   wizard; there is no `--save` on standalone `recovery generate`, so a key added later has no CLI path to paper.
   Either the build or the design §2.5/S3 / task framing must move.

Everything else that is not a golden-path blocker is Type III polish (backlog), and the two recovery **golden
paths that were exercised end to end work correctly**: generate (24 words + compact form, mandatory read-back,
DRAFT→confirmed card in setup) and redeem (words, grouped base32, and 0.17 ungrouped base32 all redeem; the
**C1 discriminator holds** — a bad/unknown word returns a typed word/checksum error, never a generic wrong-secret
line — and a failed redeem consumes nothing). Password rotation, the revoke-last GUI 409, rollback re-supply
(I-U5), device-local labels (C4), the cloud caveat catalog (drift-guard green), and the BIP-39 license notice all
verified clean.

## Findings by cell

| Cell | Fn | Friction finding (headline) | Type | Fix / backlog |
|---|---|---|---|---|
| GUI-OWN 1 — Files landing | partial | Panel `<h2>`s + hints still carry old jargon; only nav renamed | **II** | Rename Files/Cloud `<h2>`s to design shown-names, de-jargon hints (ids unchanged, §2.1) |
| GUI-OWN 2 — change password | yes | Plain rotation message; real rotation verified (old pw fails) | — | None |
| GUI-OWN 3 — generate key | yes | ~5-step read-back is the off-screen-capture control (by design) | I | Do not reduce |
| GUI-OWN 4 — mistype a word | yes | Typed checksum error never names *which* word, though server holds the phrase | III | Diff read-back vs pending token-by-token; append 1-based index of first differing word |
| GUI-OWN 5 — revoke last key | yes | Doubly gated (window.confirm + server 409); raw 16-hex ID shown in owner row | I / III | Keep the gate; drop raw-ID column (hover/Advanced only) |
| GUI-OWN 6 — rollback restore | yes | Re-supply gate correct; but strict-gate body says CLI `--accept-rollback`, and empty-pw path points at a control with no persistent label | I / III | GUI-neutral wording in canAcceptRollback branch; reword/label "I restored this from a backup" |
| GUI-D2 1 — first launch | yes | Lands on Welcome-back (C5 ✓); but `setupSkipped` is sticky per session | III | Clear setupSkipped on /api/close, or render Welcome-back whenever no vault open |
| GUI-D2 2 — open-by-folder | yes | Works; label "choose its folder" implies a picker but it's a free-text path field | III | Reword to "enter its folder path" or wire a directory input |
| GUI-D2 3 — handle list | yes | Handles match card (C4 ✓); no "match to card" hint; friendly-label writer unreachable; list needs open vault | I / III | Add match hint; add a "name this key" input or drop the Label framing; allow listing for a closed vault |
| GUI-D2 4 — redeem 24 words | yes | C1 holds; but no redeem link on Welcome-back; vault-path lives in a different tab; "above" copy stale | **II** | Add Welcome-back redeem link; give redeem its own vault-path input; fix wording |
| GUI-D2 5 — redeem base32 | yes | Same box auto-detects base32/words; placeholder doesn't say both forms accepted; same reach friction | II / III | Placeholder "24 words, or the compact XXXX-XXXX form"; same redeem-reach fix as cell 4 |
| GUI-D2 6 — Advanced toggle | yes | All five old panels reachable + well-labeled; two controls do the same reveal | III | Keep one, or relabel toggle "Keep advanced visible" |
| CLI 1 — help / group help | yes | Registry surfaces correct double-dash; but leaf `--help` (init/put/gc/gui/move) prints single-dash Go block; app-config/gui/version don't honor the C7 help contract; unknown top-level exits 2 vs unknown subcommand exits 1 | III | Render leaf `--help` from the registry; model app-config/gui leaves as groups; return 2 for unknown subcommand |
| CLI 2 — recovery generate | partial | 24 words + compact form + read-back all correct, but NO `--save`; DRAFT card lives only in `setup` | **II** | Add card-save to `recovery generate` or amend §2.5/S3 + task |
| CLI 3 — redeem 0.17 base32 | yes | Words, grouped + ungrouped base32 all redeem; typed errors; failed redeem consumes nothing | III | None |
| CLI 4 — Type III sweep | yes | profile-remove / keyless reminder / no doubled Note / caveat-once / `--json` all verified; `init` alone skips the leftovers remedy setup enforces | III | Optionally apply the leftover classification at the top of cmdInit |
| CLI 5 — revoke last non-interactively | **no** | Last-key revoke succeeds silently; `--yes` undefined; gate exists only in GUI | **II** | Add `--yes`; refuse non-interactive last-key revoke; share the isLast check in vault.RevokeRecovery; prove-fail→prove-pass cmd test |
| CLI 6 — script-facing output | yes | Bare-group exit 0 is the one intended change (documented); usage now lists the C3-omitted commands | III | Note the exit-code change in migration guidance for scripts shelling out to bare group verbs |
| DOCS 1 — README / changelog / undo | partial | `recovery generate` non-interactive prints the phrase then `error: EOF`; `keychain delete` (no entry) dumps a raw backend error; changelog's "bare group exits 0" isn't universal | **II** / III | Refuse non-tty before printing; plain "no keychain entry" + gate raw error behind --debug; qualify the changelog |
| DOCS 2 — word vs compact / 0.17 | yes | Both forms redeem to one secret (I-U2 ✓); but redeem is single-use and undocumented; "checksum" disclaimer mislabels the unknown-word case | III | Document single-use retirement + prompt to re-mint; reword disclaimer to cover word/checksum |
| DOCS 3 — device-local labels | yes | List matches design §2.6 / C4 exactly (handle = first 4 hex; device-local store) | — | None |
| DOCS 4 — cloud caveats | yes | Detector `note` fields byte-for-byte match the doc; drift-guard test green | — | None |
| DOCS 5 — THIRD_PARTY_NOTICES | yes | BIP-39 wordlist source, SHA-256 pin, and 2-clause BSD license all recorded (C2 ✓) | — | None |
| DOCS 6 — every command/flag in help | partial | Every README command/flag exists EXCEPT two islands: `remote config create --help` executes (writes rclone.conf); other `remote config` leaves treat `--help` as a positional path; `app-config` isn't a registry group; README omits `remote edit`/`sync` | **II** / III | Route remote-config leaves + app-config through registry `--help`; add edit/sync to README overview |

## Backlog owed before a re-review

The six Type II items above must be resolved (the CLI last-key gate first, as a security control with an
adversarial pass and a prove-fail→prove-pass regression). The 22 Type III items are polish and may land as a
tracked backlog. Verify at re-review that the last-key gate is shared between GUI and CLI, that the redeem golden
path is signposted from Welcome-back with its own vault-path field, that `recovery generate` refuses a non-tty
before emitting the phrase, that `remote config create --help` no longer writes to disk, and that the Files/Cloud
panel headings carry the design's job-named copy.

---

## Fix-tranche addendum (post-build)

The build was **HIGH_FRICTION_NOT_SHIPPABLE** on six Type II items (one drove
`functions=no`). All six are resolved on `feature/u2-gui-restructure`; every behavioural
fix shipped red-first with no pre-U2 test edited. The 22 Type III items are tracked
backlog, with the doc/copy subset applied by F-D here.

### Type II (all resolved)

| # | item (cell) | fix commit | disposition |
|---|-------------|-----------|-------------|
| 1 | CLI last-key revoke has no gate (CLI-5; `functions=no`) | 9f520e6 (F-B) | FIXED — a shared last-key check refuses the last key without an interactive y/N or `--yes`; cmd-level S1 regression added. |
| 2 | Redeem golden path unsignposted on a second device (GUI-D2 4/5) | 4949221 (F-C) | FIXED — Welcome-back gains "Forgot your password? Use a recovery key" with its OWN vault-path field; the Security redeem panel gets its own field and the stale "above" copy is gone. |
| 3 | `recovery generate` leaks the phrase non-interactively (DOCS-1) | 9f520e6 (F-B) + F-D docs | FIXED — refuses a non-interactive stdin BEFORE opening the vault or printing any phrase (real isatty; no env override); the changelog + recovery docs now state this. |
| 4 | `remote config create --help` writes rclone.conf (DOCS-6) | 9f520e6 (F-B) | FIXED — `--help` anywhere in the nested path renders usage and runs nothing. |
| 5 | Files golden path still shows old jargon (GUI-OWN 1) | 4949221 (F-C) | FIXED — Files/Cloud panel `<h2>` headings renamed by job (element ids unchanged; I-U1 presence test green). |
| 6 | `recovery generate` cannot save/print a card (CLI-2) | 9f520e6 (F-B) + F-D docs | FIXED — `recovery generate --save PATH` writes the DRAFT→confirmed card (0600, refused in-vault, warned under a sync folder, offer-to-delete on abandon); documented in README. |

### Type III (22 rows — tracked backlog; doc/copy subset applied)

**Applied by F-D (docs, this commit):**

- **CLI-6** — the bare-group exit-0 change is called out in the changelog with explicit migration guidance for scripts that shelled out to bare group verbs.
- **DOCS-1 (doc leg)** — the changelog's "bare group exits 0" is qualified to the nine group verbs (`app-config`/`gui` are not group verbs); the `recovery generate` non-interactive refusal is stated with its remedy.
- **DOCS-2 (doc leg)** — redeem's single-use retirement is documented with the prompt to re-mint; the mistyped-vs-unknown-word wording is corrected (an unknown word is caught by the wordlist lookup, a single mistype by the checksum).
- **DOCS-6 (doc leg)** — the README CLI overview lists `remote edit` and `remote sync`.

**Deferred (with why):**

- **GUI copy/behaviour** — GUI-OWN 4 (token-by-token read-back diff), GUI-OWN 5 (drop raw-ID column), GUI-OWN 6 (GUI-neutral rollback wording + label), GUI-D2 1 (clear `setupSkipped`), GUI-D2 2 (reword "choose its folder"), GUI-D2 3 (match hint / name-this-key input), GUI-D2 5 (redeem placeholder), GUI-D2 6 (relabel the advanced toggle): all `internal/webui`, owned by the GUI leg — polish the review sanctions as backlog, not doc/copy in F-D's ownership.
- **CLI copy/behaviour** — CLI-1 (leaf `--help` polish remainder / unknown-subcommand exit code), CLI-4 (`cmdInit` leftover classification): `cmd/seavault`, owned by the CLI leg.
- **DOCS-1 (code leg)** — `keychain delete` still returns the raw backend error (no plain "no keychain entry" line, no `--debug` gate); a `cmd/seavault` change owned by the CLI leg, not a doc fix. Deferred.
- **DOCS-2 (GUI copy leg)** — the read-back disclaimer's "usability aid, not a security control" wording lives in `internal/webui/server.go` and is pinned by matrix M1; a reword belongs to the GUI leg. Deferred.

**Post-tranche verdict.** All six Type II items resolved. The last-key gate is shared
between GUI and CLI; the redeem golden path is signposted from Welcome-back with its own
vault-path field; `recovery generate` refuses a non-tty before emitting a phrase;
`remote config create --help` writes nothing; the Files/Cloud headings carry the design's
job-named copy. The six re-review preconditions are met. The 22 Type III rows remain
tracked backlog (doc/copy subset applied). Recommend re-review → **SHIPPABLE**.
