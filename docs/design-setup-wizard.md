# Design — Phase U1: the setup wizard (`seavault setup` + GUI first-run stepper)

STATUS: pre-code design, awaiting the 10-lens review. Revision 1.

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
user has no sync client, or wants an rclone-backed remote (S3, B2, SFTP, ...), does the
cloud step ask anything.

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
type Result struct { VaultID string; VaultDir string; ProfileName string; KeychainSaved bool; KeychainNote string; RecoveryNote string; CloudNote string }
func Execute(p Plan, password string, deps Deps) (Result, error)
```

`Deps` is the seam for the privilege boundaries and side effects (the ONLY things mocked
in tests): `CreateVault` (wraps the existing vault.Create path used by cmdInit),
`KeychainSet`, `ProfileAdd`, `RcloneEnsure` (existing runtime install+verify),
`RemoteAdd`/`RemoteTest` (existing remote commands). Execute is sequential and reports
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
3. **Create a recovery key.** Runs the EXISTING generate → show-once → hide → re-type →
   commit ceremony (the same code path as `recovery generate`). On mismatch nothing is
   written and the wizard offers retry or skip-with-warning. Non-interactive runs SKIP this
   step and print the remedy (I-S3).
4. **How does it reach your cloud?** Pre-answered "already synced" when step 1 chose a
   provider folder. Otherwise: (a) rclone remote → `RcloneEnsure` (install+verify if
   missing), then name + remote path, then `RemoteTest` with the result shown;
   (b) local / external drive only.
5. **Open the app now? [Y/n]** → `seavault gui <profile>`.

Flags: `--expert` (adds KDF choice + params and chunk params in step 1, validated against
the existing floor), `--preset synced-folder|rclone|local` + `--vault PATH` (+ `--remote
NAME --remote-path P` for rclone) for a fully non-interactive run that reads the
password from `SEAVAULT_PASSWORD` only (I-S1), `--no-keychain`, `--profile NAME`,
`--no-open`. Output on success is a short plain-language summary (what was created, where,
whether the keychain holds the password, whether a recovery key exists, next step).

### 3.4 GUI first-run stepper

- **Trigger:** `profile.List()` is empty AND no vault is open → the index handler renders
  the stepper page instead of the full page. A "Skip to advanced" link sets a session flag
  and renders the full page. After a successful setup the full page renders (with the new
  vault open).
- **Endpoints (all behind the existing authenticated session, I-S7):**
  `GET /api/setup/detect` → DetectSyncFolders for the server's real home.
  `POST /api/setup/validate` → Plan.Validate (no side effects).
  `POST /api/setup/run` → Execute (init + keychain + profile [+ rclone/remote]); opens the
  vault into the session on success. Password arrives in the JSON body over the loopback
  session exactly as `/api/init` does today; it is never logged or echoed (I-S1).
  Recovery uses the EXISTING `/api/recovery/generate` + `/api/recovery/commit` (hide-then-
  retype, paste blocked) — no new recovery surface.
- The stepper is plain HTML/JS in the existing embedded page (no new assets).

## 4. Sync-folder detection (§3.1, T1)

Existence checks only, never writes. Per-OS well-known paths (all relative to home unless
stated): Dropbox `Dropbox`; OneDrive `OneDrive`, Windows `%OneDrive%`, macOS
`Library/CloudStorage/OneDrive-*`; iCloud Drive macOS `Library/Mobile Documents/
com~apple~CloudDocs`, Windows `iCloudDrive`; Google Drive macOS
`Library/CloudStorage/GoogleDrive-*/My Drive`, Windows `Google Drive` and `G:\My Drive`;
Nextcloud `Nextcloud`; Box `Box` and macOS `Library/CloudStorage/Box-Box`; pCloud
`pCloudDrive`; MEGA `MEGA`; Syncthing `Sync`. Globs are expanded; a hit requires an
existing directory. Detection is advisory: it changes the default, never silently
selects. Each provider carries the caveat text lifted from `docs/cloud-provider-notes.md`.

## 5. Security invariants (proven by the tests in §7 unless labeled)

- **I-S1** The password is never on argv, never logged, never in any JSON/HTTP response,
  never in the summary. Sources: hidden prompt, OS keychain, `SEAVAULT_PASSWORD` (non-
  interactive only). `Show()` and the result struct carry no secrets.
- **I-S2** The wizard cannot lower the KDF floor: `--expert` validates through the SAME
  floor check `cmdInit` uses; defaults are the current argon2id defaults.
- **I-S3** The recovery read-back ceremony is unchanged (same code path; GUI hide-then-
  retype with paste blocked). A non-interactive run never generates a recovery key (a
  phrase nobody saw must never be committed); it prints the remedy instead.
- **I-S4** Keychain storage is an explicit, visible choice (default yes) and follows the
  existing keychain rules (refresh on rotation; unavailable keychain is a warning naming
  the remedy, not a failure).
- **I-S5** Footprint: the wizard writes only the chosen vault dir, the app-data profile
  entry, the keychain entry, and (rclone path) the runtime + remote config the user chose.
  A failure leaves no half-vault (vault.Create is already atomic) and the summary states
  exactly what exists.
- **I-S6** Provider placement surfaces the provider caveat; the wizard never enables a
  transport, runtime, or remote the user did not pick.
- **I-S7** `/api/setup/*` sit behind the same session auth as every `/api` route; no new
  unauthenticated surface, no new listener.
- **Conditional (labeled):** sync-client conflict handling and provider eviction behaviour
  are the EXISTING product's properties (documented in cloud-provider-notes.md); the wizard
  only points the user at them.

## 6. Failure and recovery

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
| T6 | §3.4 stepper | fresh server (no profiles) serves the stepper; after `/api/setup/run` the full page; every `/api/setup/*` returns 401 without a session |
| T7 | I-S6 caveat | detected OneDrive → the specific caveat string appears in Show() output / detect JSON |
| T8 | real binary | `scripts/smoke-test.sh` gains a `setup --preset local` run followed by `put`/`get` round-trip against the built binary |
| T9 | I-S5 footprint | after a default run, walk the temp home: only the vault dir, the profile file, and the fake keychain entry exist |

## 8. Honesty of claims

Proven by tests: I-S1, I-S2, I-S3, I-S5, I-S7 (T3/T4/T6/T9). Conditional: provider
caveats are only as good as cloud-provider-notes.md; detection is heuristic (a user with
a non-default sync folder gets the manual path, not a failure). Unproven / U2: whether the
stepper alone is enough for a first-time user — that is what the U1 friction review walks.
