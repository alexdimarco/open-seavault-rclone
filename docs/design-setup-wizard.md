# Design — Phase U1: the setup wizard (`seavault setup` + GUI first-run stepper)

STATUS: Built. Phase U1 shipped on `feature/setup-wizard` in four slices: S1 `internal/setup` detect/plan/execute (4c626f7), S2 the interactive wizard + `seavault setup` CLI (1592909), S3 the GUI first-run stepper + `/api/setup/*` (f756328), and S4 docs + final verification (this commit). The 14 conditions of the pre-code review (`docs/review-setup-wizard-predesign.md`, GO_WITH_CONDITIONS) are applied below and in §9; the T1–T15 matrix in §7 is implemented and the unfiltered `go test -race ./...` suite is green.

## 1. Goal and scope

An average person wants three things: make an encrypted folder, put files in and get
them back, and have it reach their cloud. Today they must first learn ~10 concepts
(vaults, profiles, keychain, KDF tuning, chunk sizes, transports, two runtimes, remotes,
SSH keys, the launch link) presented flat. U1 adds one guided path that gets a new user
from nothing to a working, synced, recoverable vault with **every default chosen for
them and every advanced knob one flag away**. Nothing is removed; it is ranked.

**In scope (U1):**
- `internal/setup`: a UI-agnostic package (detect, plan, execute) shared by CLI and GUI.
- `seavault setup`: an interactive CLI wizard on the standard library (no TUI dependency),
  with `--expert` (KDF/chunk/profile knobs) and a non-interactive `--preset` form.
- GUI first-run stepper: when the GUI starts with zero saved vaults and nothing open, it
  renders the same steps instead of the 22-panel page, with a "Skip to advanced" link.

**Out of scope (U2, separate design):** the four-destination GUI restructure (Files /
Cloud sync / Security / Advanced), on-demand runtime install UX, word-based recovery
phrases and the printable card, `--help` synopses, plain-language message sweep. U1 uses
the recovery phrase format that exists today.

## 2. The key product insight the wizard leads with

The vault is ciphertext in a plain folder that ANY sync client moves. So the easiest and
most common setup needs **no transport, no rclone, no remote**: put the vault inside the
folder Dropbox / OneDrive / iCloud Drive / Google Drive already syncs. The wizard detects
those folders and offers "inside your <Provider> folder" as the first choice. Only if the
user has no sync client, or wants an rclone-backed remote, does the cloud step ask anything.
In U1 the rclone branch is scoped to **an rclone remote that already exists** (configured in
rclone, or imported with the existing `seavault remote config import`); driving `rclone config`
per backend is a later phase (C1). The wizard never reports a remote as working unless
`RemoteTest` passed.

## 3. Architecture

### 3.1 `internal/setup` (new, UI-agnostic)

```
type Provider  string               // "dropbox" | "onedrive" | "icloud" | "googledrive" | "nextcloud" | "box" | "pcloud" | "mega" | "syncthing"
type SyncFolder struct { Provider Provider; Path string; Note string }   // Note = provider caveat from docs/cloud-provider-notes.md
func DetectSyncFolders(home string, goos string) []SyncFolder          // pure: existence checks on well-known paths; injectable home/goos for tests

type Plan struct {
    VaultDir     string
    ProfileName  string   // default: basename of VaultDir
    SaveKeychain bool     // default true
    Cloud        CloudChoice   // SyncedFolder{Provider} | RcloneRemote{Name, RemotePath} | LocalOnly
    Expert       *ExpertOptions // nil = defaults; KDF + params + chunk params, validated against the SAME floor cmdInit enforces
}
func (p Plan) Validate() error     // typed errors: ErrVaultDirNotEmpty, ErrKDFBelowFloor, ErrRemoteNameInvalid, ...
type Result struct { VaultID string; VaultDir string; ProfileName string; KeychainSaved bool; KeychainNote string; RecoveryNote string; CloudNote string; PreflightNote string; FailedStep string }
func Execute(p Plan, password string, deps Deps) (Result, error)
```

`Deps` is the seam for the privilege boundaries and side effects (the ONLY things mocked
in tests): `CreateVault` (wraps the existing vault.Create path used by cmdInit),
`KeychainSet`, `ProfileAdd`, `RcloneEnsure` (NEW: install-if-missing + verify, see §3.5),
`RemoteAdd`/`RemoteTest` (existing remote commands).

Execute rules (C3, C4, C8, C9): the vault is built in a sibling temp directory and
`os.Rename`d into place only on success, so an interrupted create leaves either a complete
vault or nothing; "an existing vault" means `vault.json` is present, and a non-empty dir
WITHOUT one is reported as leftovers from an interrupted setup with a remove-and-retry
offer. Before `ProfileAdd`, an existing same-name profile pointing at a DIFFERENT path is a
typed `ErrProfileNameInUse` (the CLI offers a suffixed name; nothing is repointed silently).
When VaultDir sits under a detected provider folder, Execute populates `PreflightNote` from
the existing `vault.SyncClientPreflightNote`, whose segment matcher is broadened to
prefix-match the org-suffixed CloudStorage forms (OneDrive-*, GoogleDrive-*, Box-*).
`FailedStep` names the step that failed so `CloudNote` carries the step-appropriate retry
command: an `RcloneEnsure` failure prints `seavault rclone install` (with the
`--offline-archive`/`--from-binary` options); only a `RemoteTest` failure on an installed
runtime prints `seavault remote test NAME`. Execute is sequential and reports
what exists after any failure (§6). Recovery generation is NOT inside Execute: it stays
in the caller's interactive step so the read-back ceremony is untouched (§5, I-S3).

### 3.2 Prompter seam (CLI and GUI share the flow, not the I/O)

```
type Prompter interface {
    Select(title string, options []Option, defaultIdx int) (int, error)
    Confirm(question string, defaultYes bool) (bool, error)
    Text(label, def string) (string, error)
    Secret(label string) (string, error)        // hidden; CLI = passphrase.Read
    Show(msg string)                            // plain lines, never secrets
}
func RunInteractive(pr Prompter, deps Deps, opts RunOptions) (Result, error)
```
The CLI supplies a stdlib prompter (numbered options, read a line, Enter = default;
`passphrase.Read` for secrets). Tests supply a **scripted prompter** (a queue of answers).
The GUI does NOT use Prompter; it drives the same `Plan` through `/api/setup/*` (§3.4).

### 3.3 `seavault setup` (CLI)

Steps, Enter accepts the default at each:
1. **Where should the vault live?** Default `~/open-seavault-rclone/MyVault` (portable via
   os.UserHomeDir). If DetectSyncFolders finds providers, they are listed FIRST as
   "inside your Dropbox folder (…/Dropbox/MyVault)" etc.; the single detected provider is
   the default; a custom path is always an option. The provider's caveat Note is shown
   inline when chosen (e.g. OneDrive Files On-Demand, iCloud "optimize storage").
2. **Choose a password.** Secret + confirm; on mismatch re-ask (bounded, 3 tries).
   Then "Remember it in your OS keychain? [Y/n]" (I-S4).
3. **Create a recovery key.** Offered as "Set it up now (recommended)" vs "Remind me after
   my first file", with the consequence stated ("without it, a forgotten password means the
   vault cannot be opened"); default = now. It runs the EXISTING generate → show-once →
   hide → re-type → commit ceremony (the same code path as `recovery generate`), and the
   user may download/print the shown phrase BEFORE the re-type gate so the re-type verifies a
   stored copy rather than working memory; paste stays blocked in the GUI. On mismatch
   nothing is written and the wizard offers retry or defer. Deferring sets a one-line
   reminder in the summary and on the GUI banner. Non-interactive runs SKIP this step and
   print the remedy (I-S3).
4. **How does it reach your cloud?** Pre-answered "already synced" when step 1 chose a
   provider folder OR when the chosen custom path sits under any detected provider root
   (C5); a manual choice "my own sync client already watches this folder" reaches the same
   outcome for providers the detector does not know. The synced-folder outcome is worded
   "placed inside <folder> — check that your sync client shows it as uploaded" and the
   wizard asks the user to confirm they see it syncing; it never asserts "synced" (C2).
   Otherwise: (a) **existing rclone remote** → `RcloneEnsure` (install-if-missing + verify,
   with an explicit consent prompt before any network download and the offline-archive /
   from-binary options offered inline if refused, C11), then pick or import the remote,
   then `RemoteTest` with the result shown; (b) local / external drive only.
5. **Open the app now? [Y/n]** → `seavault gui <profile>`.

Flags: `--expert` (adds KDF choice + params and chunk params in step 1, validated against
the existing floor), `--preset synced-folder|rclone|local` + `--vault PATH` (+ `--remote
NAME` for an existing rclone remote) for a fully non-interactive run that reads the
password from `SEAVAULT_PASSWORD` only (I-S1), `--allow-download` (required for a
non-interactive rclone preset to fetch the runtime; without it the run fails with the
offline options named, C11), `--no-keychain`, `--profile NAME`, `--no-open`. Output on success is a short plain-language summary (what was created, where,
whether the keychain holds the password, whether a recovery key exists, next step).

### 3.4 GUI first-run stepper

- **Trigger:** `profile.List()` is empty AND no vault is open → the index handler renders
  the stepper page instead of the full page. A "Skip to advanced" link sets a session flag
  and renders the full page. After a successful setup the full page renders (with the new
  vault open).
- **Endpoints (all behind the existing authenticated session, I-S7):**
  `GET /api/setup/detect` → DetectSyncFolders for the server's real home (the SAME detector
  `userpath.SuggestedVaultPaths` delegates to, C10).
  `POST /api/setup/validate` → Plan.Validate (no side effects).
  `POST /api/setup/run` → Execute (init + keychain + profile [+ rclone/remote]); opens the
  vault into the session on success. Password arrives in the JSON body over the loopback
  session exactly as `/api/init` does today; it is never logged or echoed (I-S1).
  Recovery uses the EXISTING `/api/recovery/generate` + `/api/recovery/commit` (hide-then-
  retype, paste blocked) — no new recovery surface.
- The stepper is plain HTML/JS in the existing embedded page (no new assets).

### 3.5 `RcloneEnsure` (new work, C11)

No install-if-missing + verify function exists today (`rclonebin` has Install / Status /
VerifyRuntime). `RcloneEnsure(consent func() bool) error` returns immediately when a verified
runtime is present; otherwise it calls `consent` BEFORE any network access (the online path
fetches version.txt, the archive and SHA256SUMS from downloads.rclone.org) and, if refused,
returns a typed `ErrDownloadRefused` whose message names the `--offline-archive` and
`--from-binary` alternatives. It has its own tests (present → no fetch; refused → no fetch,
typed error; a fake-fetch success → verified). The non-interactive `--preset rclone` path
supplies consent only when `--allow-download` was passed.

## 4. Sync-folder detection (§3.1, T1)

Existence checks only, never writes. `DetectSyncFolders` is the single OS-path detector:
`userpath.SuggestedVaultPaths` delegates to it and a test asserts the two never diverge (C10). Per-OS well-known paths (all relative to home unless
stated): Dropbox `Dropbox`; OneDrive `OneDrive`, Windows `%OneDrive%`, macOS
`Library/CloudStorage/OneDrive-*`; iCloud Drive macOS `Library/Mobile Documents/
com~apple~CloudDocs`, Windows `iCloudDrive`; Google Drive macOS
`Library/CloudStorage/GoogleDrive-*/My Drive`, Windows `Google Drive` and `G:\My Drive`;
Nextcloud `Nextcloud`; Syncthing `Sync`. (Box, pCloud and MEGA are dropped from U1's
Provider enum until they have a verified caveat, C7.) Globs are expanded; a hit requires an
existing directory. Detection is advisory: it changes the default, never silently
selects. The caveat catalog is the ONE source of truth and lives in code, `internal/setup/providers.go`
(a table of Provider → caveat), because `docs/cloud-provider-notes.md` contains no caveat
text today (C7); that doc gains a section that points at the catalog. T1/T7 assert the
catalog strings.

## 5. Security invariants (proven by the tests in §7 unless labeled)

- **I-S1** The password is never on argv, never logged, never in any JSON/HTTP response,
  never in the summary. Sources: hidden prompt, OS keychain, `SEAVAULT_PASSWORD` (non-
  interactive only). `Show()` and the result struct carry no secrets.
- **I-S2** The wizard cannot lower the KDF floor: `--expert` validates through the SAME
  floor check `cmdInit` uses; defaults are the current argon2id defaults.
- **I-S3** The recovery read-back ceremony is unchanged (same code path; GUI hide-then-
  retype with paste blocked). A non-interactive run never generates a recovery key (a
  phrase nobody saw must never be committed); it prints the remedy instead.
- **I-S4** (proven by T2's Confirm-call assertion, C14) Keychain storage is an explicit, visible choice (default yes) and follows the
  existing keychain rules (refresh on rotation; unavailable keychain is a warning naming
  the remedy, not a failure).
- **I-S5** Footprint: the wizard writes only the chosen vault dir, the app-data profile
  entry, the keychain entry, and (rclone path) the runtime + remote config the user chose.
  A failure leaves no half-vault (vault.Create is already atomic) and the summary states
  exactly what exists.
- **I-S6** Provider placement surfaces the provider caveat; the wizard never enables a
  transport, runtime, or remote the user did not pick.
- **I-S7** `/api/setup/*` sit behind the same session auth as every `/api` route; a request
  with NO session gets the existing `serveNoSession` **403** (server.go), and a session that
  is present but not logged in gets the existing 401 path; no new unauthenticated surface,
  no new listener (C12).
- **Conditional (labeled):** sync-client conflict handling and provider eviction behaviour
  are the EXISTING product's properties (documented in cloud-provider-notes.md); the wizard
  only points the user at them.

## 6. Failure and recovery (C8, C9 applied in §3.1)

Each step is idempotent from the user's view: a rerun on an existing non-empty vault dir
refuses with `ErrVaultDirNotEmpty` and offers "open it instead". Password mismatch re-asks
(bounded). Recovery mismatch writes nothing (existing behaviour) and offers retry/skip.
Keychain unavailable → vault still created, warning names the remedy. Rclone install or
`RemoteTest` failure → vault + profile still exist; the cloud step reports the error and
the exact command to retry (`seavault remote test NAME`). Ctrl-C at any step: whatever
was completed is reported; nothing is rolled back silently.

## 7. Test matrix (red-first; every row asserts; real binaries where a process is involved)

| ID | Proves | How |
|---|---|---|
| T1 | §4 detection | table over (goos × provider × present/absent) with an injected temp home; each row asserts hit/miss AND the Note is non-empty for hits |
| T2 | §3.2/§3.3 default flow | scripted prompter drives all defaults; asserts the vault opens with the password, profile registered, keychain seam called once; result carries no secret |
| T3 | I-S1/I-S3 non-interactive | `--preset synced-folder` with `SEAVAULT_PASSWORD`; asserts vault created, NO recovery entry, remedy line printed, no phrase on stdout; without the env var → typed refusal, password never read from argv |
| T4 | I-S2 expert floor | `--expert` KDF below floor → same error as `init`; at floor → accepted |
| T5 | §6 failures | keychain seam fails → vault exists + remedy warning; recovery mismatch → no entry, wizard completes; rclone ensure fails → vault+profile exist + retry command shown |
| T6 | §3.4 stepper | fresh server (no profiles) serves the stepper; after `/api/setup/run` the full page; every `/api/setup/*` returns **403** with no session (serveNoSession) and 401 when a session exists but is not logged in |
| T7 | I-S6 caveat | detected OneDrive → the specific caveat string appears in Show() output / detect JSON |
| T8 | real binary | `scripts/smoke-test.sh` gains a `setup --preset local` run followed by `put`/`get` round-trip against the built binary |
| T9 | I-S5 footprint | after a default run, walk the temp home: only the vault dir, the profile file, and the fake keychain entry exist |
| T10 | C10 one detector | `userpath.SuggestedVaultPaths` and `DetectSyncFolders` agree on every row of the T1 table |
| T11 | C8 atomic create | kill/fail injected between mkdir and config write → the target dir does not exist (temp sibling cleaned); a non-empty dir without vault.json is reported as leftovers with the remove-and-retry offer |
| T12 | C3 profile collision | same-name profile at a different path → `ErrProfileNameInUse`, the original is untouched |
| T13 | C13 I-S1 response/log | decode the success AND error bodies of `/api/setup/run` and a captured log sink; fail if the password substring appears |
| T14 | C11 RcloneEnsure | present → no fetch; refused consent → typed `ErrDownloadRefused` naming the offline options, no fetch; `--preset rclone` without `--allow-download` → refused |
| T15 | C9 branched remedy | inject an ensure failure → CloudNote names `seavault rclone install`; inject a RemoteTest failure → CloudNote names `seavault remote test NAME` |

## 8. Honesty of claims

This section is the single authoritative proven-list (C14). Proven by tests: I-S1 argv+stdout+summary clauses (T3) and the response/log clauses (T13); I-S2 (T4); I-S3 (T3); I-S4 (T2); I-S5 (T9, T11); I-S6 (T7); I-S7 (T6). Conditional: provider
caveats are only as good as cloud-provider-notes.md; detection is heuristic (a user with
a non-default sync folder gets the manual path, not a failure). Unproven / U2: whether the
stepper alone is enough for a first-time user — that is what the U1 friction review walks.

## 9. Revision 2 — how each review condition was applied

| Cond | Applied as |
|---|---|
| C1 | §2/§3.3: U1 rclone branch = existing/imported remote only; never reports a remote working unless RemoteTest passed |
| C2 | §3.3 step 4: synced-folder wording + user confirmation; never asserts "synced" |
| C3 | §3.1 Execute rules: `ErrProfileNameInUse`, no silent repoint; T12 |
| C4 | §3.1: `Result.PreflightNote` from `SyncClientPreflightNote`; matcher prefix-matches org-suffixed CloudStorage forms |
| C5 | §3.3 step 4: custom path under a detected root, or manual "my sync client watches it", reaches the no-transport outcome |
| C6 | §3.3 step 3: recovery deferrable (default now, consequence stated), print/download before the re-type gate, paste still blocked |
| C7 | §4: caveat catalog lives in `internal/setup/providers.go`; Box/pCloud/MEGA dropped; docs point at the catalog; T1/T7 assert catalog strings |
| C8 | §3.1: temp-sibling build + rename; "existing vault" = vault.json present; leftovers offer; T11 |
| C9 | §3.1: `FailedStep` → step-appropriate retry command; T15 |
| C10 | §3.4/§4: one detector, `SuggestedVaultPaths` delegates; T10 |
| C11 | §3.5: `RcloneEnsure` is named new work with consent-before-download, `--allow-download` for presets, own tests; T14 |
| C12 | I-S7 and T6 corrected to 403 (no session) / 401 (not logged in) |
| C13 | T13: response bodies + captured log asserted free of the password |
| C14 | §8 is the single proven-list; I-S4 proven by T2's Confirm assertion; I-S6 by T7 |

