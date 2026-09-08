<!--
Friction review — Phase U1 setup wizard (BUILT), process/friction-review.md
Repo: open-seavault-rclone   Branch: feature/setup-wizard (main never touched)
How the cells were walked:
  - REAL binary built from source: go build -o /tmp/sv-u1/seavault ./cmd/seavault
  - Four actors: (1) non-technical GUI-first owner, (2) curious owner on the CLI,
    (3) admin/operator scripting 50 machines, (4) new operator inheriting cold from docs.
  - ALL state isolated: SEAVAULT_APP_HOME set to a fresh temp dir per run; a temp HOME
    holding fake provider folders (Dropbox/Nextcloud/OneDrive/Syncthing) for detection;
    --no-keychain on the CLI; DBUS_SESSION_BUS_ADDRESS unset so any keychain write
    autolaunched an isolated keyring under the fake HOME. The real user home/keychain
    were never used; one accidental real-keyring write was detected and cleared, a final
    sweep confirmed the real keyring holds no test entry, a stray 52-byte header written
    to the real ~/.config/seavault/rclone during a `remote config create` probe was
    removed. Every GUI/daemon process was killed by PID; temp state removed.
  - GUI cells were driven headlessly through the REAL /api/setup/detect|validate|run and
    /api/recovery/* with curl over a redeemed rotating launch link (cookie + CSRF token).
  - CLI interactive cells were driven over an allocated PTY because passphrase.Read opens
    /dev/tty directly (read_posix.go) — piped stdin does NOT answer the password/re-type
    prompts; an interactive terminal is mandatory.
  - Secret-leakage checks: response bodies, gui.log, and stdout+stderr were grepped for
    the password/recovery phrase on every path — 0 hits everywhere (I-S1/T13 hold).
  - Verdict source of truth: docs/design-setup-wizard.md Revision 2 (§9 = conditions
    C1-C14); design-vs-built gaps are called out where the built code diverges from §9.
-->

# Phase U1 setup wizard — friction review

**Cells walked:** 24 (4 actors x 6 cells). **Functioning:** 17 `yes`, 7 `partial`, 0 `no`.
**Findings:** 18 Type II (friction that blocks/derails a task), 33 Type III (papercuts);
the Type II / Type III arrays below are the **deduped** actionable backlog (14 and 23
distinct items) — several defects were found independently by more than one actor.

## Verdict: SHIPPABLE_WITH_BACKLOG

Every golden path functions and creates a working, round-trip-verified vault:
- **GUI first-run** (non-technical owner) — lands on the stepper, one-Continue Dropbox
  default, honest C2 wording, safe deferrable recovery, safe password-mismatch and
  empty-password guards. `yes`.
- **CLI `seavault setup`, accept every default** — builds a vault, real put/get matches. `yes`.
- **`--preset local` (fleet)** — exit 0, no secret leak, clean footprint, real round-trip. `yes`.
- **Docs-only zero-to-vault** — buildable from README + `--help` alone. `yes`.

No cell reached `functions=no`, and no Type II finding breaks a golden path outright, so
the bar for HIGH_FRICTION_NOT_SHIPPABLE is not met. But the Type II list is substantial
and two items are **fix-first before U1 is advertised**:

1. **Correctness bug — `--preset rclone` can never verify a remote** (ADM-3). RemoteTest
   passes `--log-format date,time,level,msg`; the rclone that `RcloneEnsure` installs
   rejects the `level` token, so `rclone lsf` dies on flag parsing before it resolves the
   remote. This affects **every** rclone transport op, not just setup. Drop `level` and
   add a real-binary argv-hygiene test (CLAUDE.md: real binaries over mocks).
2. **Golden-path contradiction — misleading "synced" default with no sync client**
   (CLI-1 / DOC-1). The cloud step hard-defaults to "watched by my own sync client" even
   when detection found nothing; a user who accepts defaults is told to check a client
   they do not have. Let detection pick the safe default (local when nothing is detected).

The remaining Type II items are real friction but recoverable and confined to non-golden
cells: the interactive path validates the target dir and surfaces typed-error remedies
only at the last step (CLI-5) and throws away the reassuring `res.CloudNote` on failure
(CLI-6/DOC-5); the GUI "Skip to advanced" is a one-way door with no in-app way back
(GUI-4) and returning users land in the 22-panel page (GUI-5); fleet scripting lacks
`--json` output and idempotent rerun semantics (ADM-1/ADM-5); the I-S6 provider caveat is
dropped on the typed-custom-path (CLI-3) and `--preset synced-folder` (DOC-4) branches;
and there is no documented undo (DOC-6). None gate the golden path; all belong in the U1
follow-up backlog.

### Controls confirmed working — do NOT weaken (Type I)
- **I-S1 / password never on argv** — taken only from SEAVAULT_PASSWORD in preset mode;
  unset AND empty both refuse (exit 1, no prompt fallback, nothing created). No password
  or recovery phrase in any stdout/stderr/log/response body.
- **C11 network-consent gate** — `--preset rclone` without `--allow-download` refuses
  deterministically before any disk/network side effect and names the offline options.
- **C2 honest synced wording** — never asserts "synced"; hands liveness to the human.
- **C6 recovery ceremony** — deferrable with consequence stated; Download/Print offered
  before the paste-blocked re-type gate; a phrase nobody saw is never written (I-S3);
  mismatch returns HTTP 400 and commits nothing.
- **C8 refuse-to-overwrite** — ErrVaultDirNotEmpty vs ErrVaultDirLeftovers are distinct
  typed errors; neither clobbers.
- **C12 session control** — bare-URL visit returns 403 with a legible remedy; the
  rotating launch secret is the control.
- **I-S5 footprint** — vault dir + one profiles.json entry + (optional) one keychain
  entry; no stray files.

## Findings table

| Cell | Fn | Friction finding | Type | Fix / backlog |
|---|---|---|---|---|
| GUI-1 First launch | yes | "Three steps" text vs 5-dot rail mismatch | III | Reword to "a few quick steps" or frame recovery+done as finishing steps |
| GUI-1 | yes | "Location" dot is really Location + cloud-transport | III | Rename "Location & cloud" or split transport into its own step |
| GUI-2 Synced Dropbox | yes | "verify uploaded" wording only on final Done screen | III | Surface it in the review step / add "I can see it in Dropbox" confirm |
| GUI-4 Skip to advanced | partial | One-way door; **no in-GUI route back to the wizard** | II | Persistent "Back to guided setup" link while first-run holds |
| GUI-4 | partial | Recovery affordance after skip only reachable via terminal | III | Surface in-app (same fix as above) |
| GUI-5 Reopen app | yes | Returning owner dropped into 22-panel page, no unlock view | II | Add minimal returning-user unlock view (vault list + password) |
| GUI-5 | yes | Keychain-unavailable remedy is technical | III | Add a plain-language lead line |
| GUI-6 Mistype confirm | yes | Mismatch renders in top banner, no inline/live indicator | III | Inline field validation + live match indicator |
| GUI-6 | yes | No password strength/min-length guidance (weak accepted) | III | Add a light strength hint (keep empty-password guard) |
| CLI-1 Accept defaults | yes | **Local default vault but "synced" cloud default → told to check a client they lack** | II | Default cloud Select to "local only" when detection finds nothing |
| CLI-1 | yes | Keychain-failure summary leaks raw secret-tool error | III | Plain one-liner; raw exec error to debug log only |
| CLI-2 Defaults + Dropbox | yes | Dropbox caveat printed twice (Select + pr.Show) | III | Show the caveat once |
| CLI-2 | yes | Doubled "Note:  note:" label on preflight note | III | Strip leading "note:" or the "Note:" prefix |
| CLI-3 Custom path in Dropbox | yes | **Provider on-demand caveat NEVER shown for typed path (I-S6 gap; design §3.1 C5 claims it is)** | II | pr.Show(Caveat(prov)) in custom-path branch / resolveCustomLocation |
| CLI-4 Defer recovery | yes | Reminder is one-shot summary line; no persistent CLI surface | III | Re-emit hint when opening a keyless vault / in profile list |
| CLI-4 | yes | `recovery generate` re-prompts for password unexpectedly | III | Note "(you'll be asked for the vault password)" |
| CLI-5 Rerun same folder | partial | **Collision detected only at Execute — password typed twice + all prompts wasted** | II | vaultDirState right after location is chosen |
| CLI-5 | partial | **Every promised typed-error affordance absent (bare `error:`)** | II | Branch on ErrVaultDirNotEmpty/Leftovers/ProfileNameInUse/DownloadRefused |
| CLI-6 Decline rclone dl | partial | **Not told vault+profile were created; res.CloudNote discarded** | II | Print res.CloudNote + "vault created at <dir>" before returning error |
| ADM-1 preset local | yes | **No machine-readable output; VaultID never printed** | II | Add `--json` or at least print VaultID |
| ADM-1 | yes | "Next: open the app" trailer / --no-open a no-op on fleets | III | Drop/neutralize trailer under --preset |
| ADM-2 preset synced | yes | No path-in-sync-folder check; name over-promises "synced" | III | Document: synced-folder only sets wording + preflight note |
| ADM-3 preset rclone | partial | **`level` token in --log-format breaks RemoteTest → remote can never verify (all rclone ops)** | II | Drop `level` (rclone.go:213); add real-binary lsf argv test |
| ADM-3 | partial | **rclone usage block dumped twice (~120 lines)** | II | Truncate subprocess stderr; stop double-printing |
| ADM-3 | partial | rclone preset assumes a pre-existing remote; undocumented | II | Document the pre-existing/imported-remote precondition |
| ADM-4 missing password | yes | (control) env-only password source holds for unset + empty | I | none |
| ADM-5 rerun existing | yes | **Idempotency dead-end: exit 1, no remedy, no distinct code** | II | Exit 0 / dedicated code when plan matches, or append remedy |
| ADM-5 | yes | ErrVaultDirLeftovers message names no remedy | III | Append "remove the directory and re-run, or choose a different --vault" |
| ADM-6 docs cold | yes | No documented exit-code contract for setup | III | Add a one-line exit-code note |
| ADM-6 | yes | --help prints single-dash flags vs double-dash usage/README | III | Normalize presentation |
| DOC-1 README zero-to-vault | yes | **"synced" default routes a no-client user into synced outcome** | II | Detection-driven default (see CLI-1) |
| DOC-1 | yes | README doesn't foreshadow the 3-way cloud question | III | Add one sentence to the quick-start |
| DOC-2 Defer reminder | yes | README:467 lists recovery keys / rotation as "future work" (shipped in v0.17) | III | Remove both from the future-work bullet |
| DOC-3 Synced caveats | partial | cloud-provider-notes.md has NO caveat text (points at Go source) | III | Mirror the catalog into the doc (generated) or state where caveats appear |
| DOC-3 | partial | README lists all 6 providers as detected; iCloud/GDrive are macOS/Windows-only | III | Qualify detection by OS |
| DOC-4 What --preset does | yes | **`--preset synced-folder` never surfaces provider caveat even under a real root** | II | Include Caveat(provider) in Result via ProviderRootFor |
| DOC-4 | yes | --no-open inert under preset; preset stores keychain by default | III | Drop --no-open from preset usage / warn about default keychain save |
| DOC-5 Add rclone remote | partial | **Interactive rclone failure prints no summary; vault-created + C9 remedy discarded** | II | Print res.CloudNote + "vault created" before error (mirror preset) |
| DOC-5 | partial | README rclone example never says how to get the "existing" remote | III | Add `rclone config` / `remote config import` line |
| DOC-5 | partial | `remote config validate` fails on a config just imported + exported | III | Point validate at the managed config/rclone/rclone.conf path |
| DOC-6 Footprint & undo | partial | **No documented undo/teardown; no single command** | II | Add "Undo a setup" section and/or `setup --undo` |
| DOC-6 | partial | `profile remove` succeeds silently (exit 0, no output) | III | Print "removed profile NAME" |

## Design-vs-built gaps against §9 (built code diverges from Revision 2)

- **C5** (§3.1): "custom path under a detected root … its caveat is shown" — the built
  typed-custom-path (CLI-3) and `--preset synced-folder` (DOC-4) branches do **not** show
  the provider caveat. I-S6 hazard unwarned on exactly the paths a user is most likely to
  take by hand or by script.
- **C8/C9** (§3.1, §6): "existing vault … offers open-it-instead"; "FailedStep →
  step-appropriate retry command" — the built interactive path emits a bare `error:` with
  no typed-error affordance (CLI-5) and discards `res.CloudNote` on failure (CLI-6/DOC-5).
- **C1** (§2/§3.3): scope holds and is a control — the wizard never half-configures a
  backend and never reports an unverified remote as working. Working as designed.

## Not covered — pending lab tier (per CLAUDE.md, no real cloud remotes here)
A verified rclone remote could not be exercised end-to-end (no managed/system rclone with
a real backend in the isolated env). The rclone-preset gates, the consent refusal, and
the (buggy) RemoteTest argv were all validated; a real put/get against a live remote
remains a throwaway-remote lab drill (ALWAYS destroyed).
