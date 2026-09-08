# Adversarial Review — Setup Wizard (Phase U1, BUILT)

**What:** Adversarial review of the built Phase U1 setup wizard on branch `feature/setup-wizard`
of `open-seavault-rclone` — `internal/setup` (providers/detect/plan/execute/rclone_ensure/interactive),
`cmdSetup` in `cmd/seavault/main.go`, the GUI first-run stepper and `/api/setup/detect|validate|run`
in `internal/webui/server.go`, README Quick start, and `scripts/smoke-test.sh`. Findings are scored
against `docs/design-setup-wizard.md` Revision 2 (§9 conditions C1–C14) and the I-S invariants.

**Process:** Parallel adversarial probes (built binary at `/tmp/sv-u1/seavault`, all state isolated
via fresh `SEAVAULT_APP_HOME`/`HOME` temp dirs, `--no-keychain`, in-package `httptest` probes for the
API) → skeptic verification pass → this synthesis. Every confirmed finding below survived the skeptic;
throwaway probe tests were removed after running.

**Model:** claude-opus-4-8

## Counts

- Candidate findings entering synthesis: **17** (16 confirmed by the skeptic, 1 refuted)
- Confirmed after de-duplication: **14** (three same-root findings merged — see note below)
- Refuted: **1**
- All confirmed findings reproduced locally except `detection-preflight-5` (case-insensitive FS
  path; Linux CI host is case-sensitive, constructed case only).

**De-dup note:** `api-setup-2`, `preset-noninteractive-1`, and `atomic-create-1` are three views
(API validate/run, CLI `--preset`, and the atomic-create/keychain-ordering angle) of one root defect:
`Execute` commits the vault and, when enabled, the OS-keychain password entry **before** the
profile-collision check. They are merged into **`profile-collision-orphan`** (high — the highest
severity among the three).

## Confirmed findings (most severe first)

| id | sev | title | repro | fix |
|----|-----|-------|-------|-----|
| recovery-integration-1 | high | CLI recovery save-to-file writes the plaintext phrase to ANY path with no guard against the vault dir or a synced/provider folder — uploads the master recovery secret to the untrusted remote, defeating the zero-knowledge model (critical when the path is inside the synced vault folder) | Throwaway `internal/setup` test: create a real vault, `runRecoveryCeremony(pr, vaultDir, pw)` with `texts:[filepath.Join(vaultDir,"recovery.txt")]`, read the file back; second case with vaultDir under `<home>/Dropbox/MyVault` and savePath in the same Dropbox folder. `go test ./internal/setup/ -run TestReproRecoveryFile -v`. `runRecoveryCeremony` has `vaultDir` but never uses it to reject an in-vault path and is not passed sync-root info. | Pass detected sync roots + vaultDir into `runRecoveryCeremony`; reject a save path inside vaultDir or under any `ProviderRootFor(...)` root; refuse outright for the in-vault case, warn + second-confirm for in-provider. Regression on refusal. |
| profile-collision-orphan | high | Profile-name collision commits a full vault (and keychain password entry) before the name is checked, leaving an unreported orphan; `Plan.Validate` omits the check so `/api/setup/validate` greenlights a plan `run` then fails on; C3's suffixed-name recovery is structurally precluded (subsumes api-setup-2, atomic-create-1) | `setup --preset local --vault $H/vaultA --profile shared` (exit 0) then `--vault $H/vaultB --profile shared` (exit 1) → `vaultB/SeaVaultData/vault.json` EXISTS, `profile list` shows only `shared→vaultA`, output is only `error: ...points at <other>` with no mention of the created vault. API: `profile.Add("MyVault", ...)`, POST `/api/setup/validate` → 200 `{ok:true,profileName:"MyVault"}`, POST `/api/setup/run` → 400 with `result.vaultId` set and vault on disk. Keychain ordering (`execute.go:216` before `ProfileLookup` at `:226`) proven with a fake KeychainSet: `KeychainSaved=true`, `vault.json` present, all before `ErrProfileNameInUse`, `KeychainNote`/`CloudNote` empty. | Move ProfileLookup to the very start of `Execute` (before `CreateVault`/`KeychainSet`) and add it + profile-name validation to `Plan.Validate` (side-effect-free). Write keychain only after a successful `ProfileAdd`. If detectable only post-create, populate Result + a note naming the created vault/keychain entry and print the summary on the error path (I-S5/§6); implement C3 suffixed-name retry by registering the built vault under a new name, not re-running Execute. |
| detection-preflight-1 | high | `PreflightNote` (C4) silently empty for iCloud (mac `com~apple~CloudDocs` + Windows `iCloudDrive`), Syncthing (`~/Sync`), and Windows `G:\My Drive` Google Drive — exactly the cross-device sync folders where the cross-version-compat warning matters most | Package-`setup` probe: for each `DetectSyncFolders(home,goos)` hit, print `vault.SyncClientPreflightNote(join(f.Path,"MyVault"))!=""`. Dropbox/Nextcloud/OneDrive(plain+glob)/GoogleDrive-glob = true; syncthing `~/Sync`, darwin `com~apple~CloudDocs`, windows `iCloudDrive` = false; `SyncClientPreflightNote("G:\\My Drive\\MyVault")=="".` Root cause: S1 refactor (4c626f7) renamed the detector's folder segments but left `syncClientFolderNames` (`metadir.go:64`) keyed on the old names. | Make preflight matcher + detector share ONE folder-name source (C10 single-source, already used by DetectSyncFolders/SuggestedVaultPaths); have `hasSyncClientSegment` recognize the detector's real segments. Add a T-row asserting non-empty note for every `DetectSyncRoots` path across the goos table. |
| api-setup-1 | medium | Cloud-step (rclone/remote) failure is reported as "Could not create the vault" and the fully-created vault is abandoned, not opened — defeats §6/C9 soft-failure contract and I-S5 ("summary states exactly what exists") | `httptest`: POST `/api/setup/run` with `cloud.mode=rclone` while no rclone runtime present → HTTP 400, body carries `result.vaultId`, correct step-branched `cloudNote`, `failedStep:"rclone-ensure"`; post-conditions: `vault.ResolveMetaDir` exists, 1 profile entry, but `s.vault==nil`/`s.vaultPath==""` (not opened). GUI `setupRun()` catch shows "Could not create the vault" though the vault was created. Same for remote-add/remote-test branches. | In `handleSetupRun`, when Execute errors but `res.VaultID` is set and `res.FailedStep` is a cloud step, open the vault into the session and return 200 with `CloudNote` as a warning; have GUI `setupRun` render `res.result.cloudNote` whenever a result with a vaultId is present. |
| detection-preflight-2 | medium | Bare `~/Sync` (Syncthing) is a false-positive magnet and pre-answers the cloud step as 'already synced' with no transport — the same artifact treats `Sync` as a sync folder in the detector while the note matcher deliberately rejects it as "too generic" | Package-`setup` probe: `mkdir home/Sync`; `DetectSyncFolders(home,"linux")` → `{Provider:syncthing, Path:.../Sync}`; `ProviderRootFor(.../Sync/MyVault,...)` → `("syncthing", true)`; `SyncClientPreflightNote(.../Sync/MyVault)` fires=false. U1 changed the target from `~/Syncthing` (bb24d0d) to generic `~/Sync` (`userpath.go:229`). | Detect Syncthing on a specific signal (config marker, or the specific `~/Syncthing` name), or gate the 'already synced' pre-answer behind explicit confirmation. Align detector and preflight matcher on one decision about `Sync`. |
| preset-noninteractive-2 | low | Printed recovery/keychain remedy commands are not shell-runnable for profile names with spaces | `setup --preset local --vault "$H/My Vault"` prints ``create one with `seavault recovery generate My Vault` `` (main.go:264); pasting it splits into two args → usage error. Same for the keychain-store note (execute.go:218). ProfileName defaults to the basename of `--vault`. | Shell-quote the profile name when it contains whitespace/metacharacters before interpolating into both printed remedies. |
| rclone-ensure-1 | low | Interactive rclone-download consent defaults EOF/Ctrl-D to YES (download), opposite the repo's own destructive-action pattern (`confirmPrompt` at main.go:1889) | Unit proof against real `stdinPrompter`: `&stdinPrompter{in:bufio.NewReader(strings.NewReader(""))}`, `Confirm(q,true)` → true. Path: `interactive.go:335` calls `Confirm(...,true)`, binds `deps.RcloneEnsure`; with a missing runtime this fetches ~15MB from downloads.rclone.org. SHA256SUMS still gates the archive (hardening, not a secret bypass). GUI + `--preset` unaffected. | Treat EOF/blank at the download consent as DECLINE: default the prompt to No, or make `readLine` surface EOF so `Confirm` returns false on closed stdin for consequential prompts. Regression: EOF-driven interactive rclone setup must not call rcloneInstall. |
| sync-race-1 | low | Vault is staged inside the actively-synced parent (`os.MkdirTemp(parent,...)`, execute.go:175/180) before rename; a mid-build failure can orphan a partial vault in the cloud that local `RemoveAll` cannot un-upload | Code-level + local: `--preset synced-folder --vault <SyncFolder>/MyVault` builds the whole vault under `<SyncFolder>/.MyVault.setup-XXXX` before renaming. Local success footprint is clean (no `*.setup-*` remains), confirming it exists only transiently in-scope; a client snapshotting the parent (or keeping rename-source history) retains it. `vault.json` is wrapped keys only — footprint/hygiene, no plaintext. | Stage outside the sync scope where atomic rename still holds (sibling ignored root, or app-data dir on the same FS), rename in at the end; where cross-FS staging breaks atomicity, keep in-parent staging but qualify I-S5 to document the residual cloud-orphan behavior. |
| detection-preflight-3 | low | Detection follows symlinks (`os.Stat`, userpath.go:210), so a symlinked `~/Dropbox` to any directory is reported as a sync root and its children classified 'already synced' | Package-`setup` probe: `os.Symlink(target, home/Dropbox)`; `DetectSyncFolders(home,"linux")` → dropbox hit; `ProviderRootFor(home/Dropbox/MyVault)` → `("dropbox", true)`. Advisory only (no writes) — misleading suggestion, not a security hole. | `os.Lstat` and skip symlinks, or `EvalSymlinks` and require the resolved path to stay under home; otherwise document that symlinked provider folders are accepted. |
| detection-preflight-4 | low | iCloud caveat text is macOS-only ("Optimize Mac Storage", providers.go:50) but is attached to Windows iCloud (`~/iCloudDrive`) detection | Package-`setup` probe: iCloudDrive dir; `DetectSyncFolders(home,"windows")` returns Provider=icloud with the macOS "Optimize Mac Storage" note. | Make `Caveat` OS-aware for iCloud (macOS vs Windows client wording) or word it platform-neutrally. |
| detection-preflight-5 | low | `pathWithin` (detect.go:67) classifies 'custom path under a detected root' case-sensitively, missing matches on case-insensitive Windows/macOS filesystems — the C5 'already synced' pre-answer is silently skipped | By inspection: case-sensitive `target==root` + `HasPrefix(target, root+sep)`, no fold. Constructed: root `C:\Users\me\OneDrive`, target `C:\Users\me\onedrive\vault` → HasPrefix false → `("", false)`. **Not locally reproduced** — Linux host FS is case-sensitive; CI cross-builds but does not run these OSes. | On windows/darwin compare with `strings.EqualFold` / a case-folded prefix, mirroring `hasSyncClientSegment`'s existing EqualFold. |
| recovery-integration-2 | low | Saved plaintext phrase file is written before the commit gate (interactive.go:434) and never cleaned up on mismatch/defer — a secret-shaped file with no committed recovery entry left behind | `runRecoveryCeremony` with `texts:[savePath]` and `recoveryReType` returning a wrong phrase (interactive_test.go:305 pattern); after 3 mismatches the function returns the defer note but `savePath` still exists. C6 requires save-before-gate (intended); the abandoned-file cleanup is missing. | On any non-commit exit (defer, mismatch-exhaustion, commit error) offer to delete the saved file, and state in the label that the file exists regardless of whether a key was saved. |
| recovery-integration-3 | low | GUI 'be reminded after your first file' is promised (server.go:4074) but never implemented; deferral reminder is not persisted (design 3.3 step 3 requires a summary line + banner) | Static read: `setupRecoveryDefer` (server.go:5927) writes one sentence into the stepper's `#setupDone` box, then `setupFinish()` reloads to `/`; `#noticeBanner` carries only sync notes. Grep for 'first file'/'remind'/persistent recovery banner → only the promise text and the defer button, no implementation. | Render a persistent, dismissible 'this vault has no recovery key' banner whenever the open vault holds no `WrapTypeRecovery` entry, or drop the 'after your first file' wording. |
| recovery-integration-4 | low | GUI re-type paste-block (`onpaste="return false"`, server.go:4097/4313) does not cover drag-and-drop text drop | Static read: `onpaste` blocks Ctrl+V/context-menu only; a drop event into `#setupRecoveryReadback` inserts the value with no `onpaste` firing. Marginal — the re-type is a user self-check, not an auth control, and the phrase is cleared from screen first. | Also cancel `drop`/`dragover` on these inputs and/or strip on input; otherwise document that the paste-block is clipboard-only. |

## Refuted

- **api-setup-3 — `/api/setup/run` is not gated on the first-run condition; an authenticated user
  can create extra vaults/profiles and silently swap the open session vault.**
  Refuted: this is the design's own specified behavior, not a defect. Design §3.4 states the setup
  endpoints sit "behind the existing authenticated session, I-S7" and that
  `POST /api/setup/run → Execute ...; opens the vault into the session on success. Password arrives
  in the JSON body over the loopback session exactly as `/api/init` does today`. The session swap in
  `handleSetupRun` (server.go:1942–1943) exactly mirrors the un-guarded, sanctioned swaps in
  `handleInit` (server.go:1398–1399) and `handleOpen` (server.go:1489–1490); the endpoint is
  authenticated and same-origin, so no privilege boundary is crossed.

## Fix-tranche ordering

**Tranche 1 — confidentiality / zero-knowledge model (do first):**
`recovery-integration-1` (plaintext recovery phrase can be written into the synced vault folder and
uploaded to the untrusted remote — escalates to critical for the in-vault path).

**Tranche 2 — data-integrity + honesty on the flagship first-run paths (high):**
`profile-collision-orphan` (reorder `Execute`: ProfileLookup and `Plan.Validate` before any FS/keychain
write; keychain after ProfileAdd; honest summary on the error path; C3 suffixed-name retry) and
`detection-preflight-1` (single-source the folder names so the C4 preflight note fires on iCloud/
Syncthing/`G:\My Drive`). These two share the same "single source of truth for sync-folder segments"
remedy the design already applies elsewhere (C10) — land them together.

**Tranche 3 — soft-failure UX + detector precision (medium):**
`api-setup-1` (surface cloud-step soft failures as a 200 warning with the vault opened) and
`detection-preflight-2` (stop treating bare `~/Sync` as a Syncthing 'already synced' root). Both align
the shipped detector/reporter with the design's own §6/C9 and C4 contracts.

**Tranche 4 — hardening + hygiene (low, batchable):**
`rclone-ensure-1` (EOF→decline for the network-download consent), `sync-race-1` (stage outside sync
scope or qualify I-S5), `detection-preflight-3/4/5` (symlink follow, macOS-only iCloud caveat on
Windows, case-insensitive `pathWithin`), `preset-noninteractive-2` (shell-quote remedy commands), and
the three recovery-UX gaps `recovery-integration-2/3/4` (abandoned-file cleanup, persistent no-recovery
banner, drag-drop on the re-type inputs).

Each fix ships prove-fail → prove-pass per the repo's testing discipline; several confirmations already
have a throwaway regression that can be promoted (kept, not deleted) — notably the profile-collision
orphan assertion, the `SyncClientPreflightNote`-over-`DetectSyncRoots` T-row, and the recovery in-vault
refusal test.

---

## Addendum — fix tranche (2026-09-07)

All 14 confirmed findings are closed on `feature/setup-wizard` by the four fix-tranche commits
(`a60aa1c` setup package + rclone transport, `4e5a701` CLI, `e42c1e5` GUI, `dab4d80` docs), each
behaviour carrying a red-first regression test that an independent verifier re-proved red.
Highlights: the recovery save-to-file now refuses an in-vault path and requires a second
confirmation under a cloud-synced folder; the profile-name collision is caught in
`Plan.Validate` and at the start of `Execute` before anything is created, and the keychain is
written only after a successful profile add; the preflight matcher and the detector share one
folder-name source so every detected root yields a note; a bare `~/Sync` no longer pre-answers
"already synced"; the EOF consent default is now decline; the rclone `--log-format` token bug
that failed every real RemoteTest is fixed with a real-binary test. Residuals documented in the
design (I-S5 staging-in-synced-parent, symlinked provider roots accepted).
