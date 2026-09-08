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
