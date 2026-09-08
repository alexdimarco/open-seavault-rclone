# Phase U2 — Adversarial Review (BUILT)

**What.** Adversarial review of the built Phase U2 ("GUI restructure & polish") on branch `feature/u2-gui-restructure`, against `docs/design-u2-gui-and-polish.md` (Revision 2 — §8 conditions C1–C9, §5 test matrix) and `docs/review-u2-predesign.md`.

**Process.** Findings reproduced against a freshly built binary (`go build -o /tmp/sv-u2/seavault ./cmd/seavault`) in a fully isolated environment (`SEAVAULT_APP_HOME`+`HOME`=throwaway temp dirs, `--no-keychain` on the CLI, real home/keychain never touched); the GUI driven headlessly with curl through the real `/api/*`. Every candidate then went through a skeptic pass.

**Model.** claude-opus-4-8.

**Counts.** Found 14 candidates → 13 confirmed (after de-duplicating one pair naming the same defect), 0 refuted. Severity mix: 1 high, 3 medium, 9 low.

> De-dup: "labels/handle wired only to GUI; CLI list shows bare ID and CLI generate writes no label" and "CLI recovery generate writes no device-local label record" name the same defect (CLI leg of the label/handle component unwired on generate + list). Merged into **cli-label-gap** at the higher (medium) severity.

## Confirmed findings

| id | sev | title | repro | fix |
|----|-----|-------|-------|-----|
| wiring-1 | high | CLI `recovery revoke` has no last-key confirmation gate (I-U4 CLI leg unwired) | init $VDIR; add one recovery entry; `recovery revoke $VDIR <id> </dev/null` → prints `revoked recovery entry <id>`, exit 0, no --yes/prompt; list → no keys. GUI last-key returns 409; CLI destroys the only route back. No CLI test covers it. | last-key gate in cmdRecoveryRevoke (enumerate WrapTypeRecovery refs) requiring confirmPrompt or --yes; add --yes to usage; CLI S1 regression. |
| cli-label-gap | medium | Recovery label/handle component unwired on CLI (generate writes no label; list shows bare ID) — merges wiring-2 + wordlist-labels-1 | CLI generate commit writes no recovery-labels.json (GUI does, with {created,device}); `recovery list` prints bare 16-hex id, no #handle. §2.6/C4 says handle shown on every device. | SetRecoveryLabel in cmdRecoveryGenerate; LabelledRecoveryKeys in cmdRecoveryList; CLI label regression. Or scope §2.6 to GUI. |
| sweep-docs-1 | medium | C7 exit-code contract violated for several `--help`; `remote config create --help` performs its action | `remote config create --help` writes rclone.conf, exit 0 (state mutation on help); validate/import --help exit 1; app-config --help exit 1. dispatchGroup only intercepts help at args[0]/[1]. | isHelpFlag guard in cmdRemoteConfig + cmdAppConfig before dispatch; H5 rows incl. prove-fail no rclone.conf. |
| sweep-docs-2 | medium | 11 leaf commands render stdlib single-dash `--help`, not registry double-dash usage+synopsis (ADM-6) | put/init/get/export/list/remove/gc/stats/serve/gui/move print `Usage of put:` single-dash, no synopsis; only setup/verify/compact use registry line. | custom fs.Usage per leaf (or run() intercept); extend H1 to real `<cmd> --help`. |
| word-encoding-1 | low | RecoveryPhraseWords decodes base32 non-strictly (latent word/base32 disagreement) | secret vs secret[:51]+"R" yield identical words yet different canonicalRecovery. Not reachable today; latent if user-typed base32 is passed. | Strict() decode or re-encode-and-compare. |
| word-encoding-2 | low | n==24 unconditional word classification → confusing 'word not in wordlist' | 24-chunk base32 routed to word decode; counts 20–23/25–28 fall through cleanly. No bypass. | gate n==24 on wordlist majority, or document. |
| wordlist-labels-2 | low | Label store 0600 not enforced on a pre-existing file | pre-create labels.json 0644, GUI commit leaves 644 (hostname world-readable). | unconditional Chmod 0600 / temp+rename; dir 0700. |
| wordlist-labels-3 | low | Revoke orphans the label record; hostname+date persist indefinitely | no label-deletion code anywhere; neither revoke path touches the store. | DeleteRecoveryLabel from both revoke paths; prune stale keys. |
| recovery-gui-2 | low | Secret-bearing /api/recovery/generate sets no Cache-Control: no-store | POST returns phrase+words with no cache headers; peers set no-store. I-U7/S3 still holds. | no-store on generate / any writeJSON with phrase. |
| registry-cli-1 | low | remote add/edit --help hides --config, --fast-list | usage shows 6 flags; handler accepts 8 (both parse, exit 0). | add flags to usage or trailing [flags]. |
| registry-cli-2 | low | Undocumented hidden sub-action aliases on gui + app-config | gui clear-login/reset-password, app-config reset-config/clear-gui-login/reset-password exit 0, in no help; H4 doesn't cover leaf sub-actions. | drop aliases or document; extend H4-style parser. |
| registry-cli-3 | low | `version` ignores all args → unknown flag accepted, exit 0 | `version --json` / `version bogus` exit 0; contrast gc/list exit 2. Pre-U2 behavior. | reject non-empty args (exit 2) or document. |
| sweep-docs-3 | low | providers.go comment stale: claims doc carries no caveat text, but DOC-3 mirrored the catalog under a drift guard | comment says "no caveat text"; TestDocsMirrorCaveatCatalog passes proving verbatim mirror. | correct the comment; code stays authoritative. |

## Refuted findings

None. Every candidate carried into the skeptic pass reproduced. (0 refuted.)

## Fix-tranche ordering

**Tranche 1 — safety-of-recovery.** wiring-1 (high): last-key confirmation gate + --yes + CLI S1 regression. The one finding that can irreversibly destroy access; self-contained.

**Tranche 2 — contract & cross-surface correctness (medium).** sweep-docs-1 (stop create-on-help mutation + honor C7 on nested paths + H5 rows); cli-label-gap (wire SetRecoveryLabel/LabelledRecoveryKeys into CLI or scope §2.6 to GUI); sweep-docs-2 (registry double-dash from `<cmd> --help` + extend H1).

**Tranche 3 — hardening & hygiene (low, batchable).** Invariant hardening: word-encoding-1, wordlist-labels-2, recovery-gui-2. Lifecycle/robustness: wordlist-labels-3, word-encoding-2. CLI help/flag surface: registry-cli-1/2/3. Docs: sweep-docs-3.

Every fix follows prove-fail → prove-pass; wiring-1 and the sweep-docs-1 create side effect must ship with a regression seen red.

---

## Fix-tranche addendum (post-build)

The 13 confirmed findings were resolved across four fix commits on
`feature/u2-gui-restructure`; every behavioural fix shipped red-first (regression seen
fail for the right reason, then pass) and no pre-U2 test was edited (matrix Z1).

| id | sev | fix commit | disposition |
|----|-----|-----------|-------------|
| wiring-1 | high | 9f520e6 (F-B) | FIXED — `recovery revoke` gates the LAST recovery key (interactive y/N, or `--yes` non-interactively); `--yes` added to the flag set/usage; CLI S1 regression added. |
| cli-label-gap | med | 9f520e6 (F-B) | FIXED — `recovery generate` records the device-local label; `recovery list` prints the stable 4-hex handle + label/creation detail + full ID; `recovery revoke` deletes the label. |
| sweep-docs-1 | med | 9f520e6 (F-B) | FIXED — a `--help` anywhere in `remote config`/`app-config` renders usage and runs NOTHING; `remote config create --help` no longer writes rclone.conf (H5 rows). |
| sweep-docs-2 | med | 9f520e6 (F-B) | FIXED — every top-level leaf renders the registry double-dash usage + synopsis on `--help` (H1 driven through the real `<cmd> --help` path). |
| word-encoding-1 | low | 22ef5fe (F-A) | FIXED — `RecoveryPhraseWords` rejects a non-canonical base32 phrase, so the word form and the base32 form can never name different wrap secrets. |
| word-encoding-2 | low | 22ef5fe (F-A) | FIXED — the discriminator gates even the 24-token count on a wordlist majority; a base32 phrase split into 24 chunks falls through to base32, and a single mistyped word keeps a 23/24 majority so C1 stands. |
| wordlist-labels-2 | low | 22ef5fe (F-A) | FIXED — profiles.json and recovery-labels.json are forced to 0600 (dir 0700) even over a pre-existing 0644 file, via a shared device-local writer. |
| wordlist-labels-3 | low | 22ef5fe (F-A) + 9f520e6 (F-B) + 4949221 (F-C) | FIXED — `DeleteRecoveryLabel` + orphan pruning in core; both revoke paths (CLI and GUI) call it after a successful revoke. |
| recovery-gui-2 | low | 4949221 (F-C) | FIXED — `/api/recovery/generate` sets `Cache-Control: no-store` + `Pragma: no-cache` before the first write. |
| registry-cli-1 | low | 9f520e6 (F-B) | FIXED — `remote add`/`edit` usage lists `--config` and `--fast-list`. |
| registry-cli-2 | low | 9f520e6 (F-B) | FIXED — undocumented `gui`/`app-config` sub-action aliases dropped (accepted set == documented set, H4-style leaf parser). |
| registry-cli-3 | low | 9f520e6 (F-B) | FIXED — `version` rejects stray args (exit 2). |
| sweep-docs-3 | low | 22ef5fe (F-A) | FIXED — the stale providers.go caveat comment is corrected; the doc mirrors the catalog under the DOC-3 drift guard and the code stays authoritative. |

**Docs/final (F-D, this commit).** The v0.19 README was reconciled to the shipped
behaviour: `recovery generate`'s non-interactive refusal and the `--save` DRAFT card,
the group-verb exit-0 scope + script-migration note, single-use redeem, and the
`remote edit`/`sync` overview rows. The `recovery generate` registry usage line now
advertises `--save` so `--help` matches the docs (regression
`TestRecoveryGenerateHelpAdvertisesSaveFlag`, red-first).

**Post-tranche verdict.** All 13 confirmed findings **FIXED**; 0 open. The one
high-severity finding (wiring-1, CLI last-key gap) is closed and the gate is shared
with the GUI. Unfiltered `go test -race -count=1 ./...` green; windows/amd64 and
darwin/arm64 cross-builds clean; `scripts/smoke-test.sh` passes against a fresh build.
