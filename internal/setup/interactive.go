// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// defaultVaultName is the leaf folder the wizard proposes for a fresh vault, so
// the default profile name (basename of the vault dir) is a friendly "MyVault"
// (design §3.3 step 1).
const defaultVaultName = "MyVault"

// Option is one choice presented by Prompter.Select (design §3.2). Label is the
// line shown; Note is an optional inline caveat rendered under the option when it
// is offered or chosen (e.g. a provider's on-demand-eviction caveat, I-S6).
type Option struct {
	Label string
	Note  string
}

// Prompter is the I/O seam the CLI and (a scripted test) implement so the wizard
// flow is shared but the input/output is not (design §3.2). Show never carries a
// secret. The GUI does NOT use Prompter; it drives the same Plan through
// /api/setup/* (§3.4).
type Prompter interface {
	Select(title string, options []Option, defaultIdx int) (int, error)
	Confirm(question string, defaultYes bool) (bool, error)
	Text(label, def string) (string, error)
	Secret(label string) (string, error) // hidden; the CLI uses passphrase.Read
	Show(msg string)                     // plain lines, never secrets
}

// RunOptions carries the wizard's non-interactive configuration: where to detect
// sync folders, the CLI flag choices that pre-answer or skip a step, and the
// seam that opens the app at the end (design §3.3). All fields are optional; the
// zero value runs a fully interactive default flow against the real home.
type RunOptions struct {
	// Home and GOOS drive sync-folder detection; empty means the real home and
	// runtime.GOOS. They are injected so tests can present a controlled set of
	// provider folders.
	Home string
	GOOS string
	// Expert turns on the KDF/chunk questionnaire in step 1 (--expert). The
	// chosen parameters are still validated through the SAME floor cmdInit
	// enforces (I-S2); a below-floor choice fails in Execute's Plan.Validate.
	Expert bool
	// NoKeychain skips the "remember it in your OS keychain?" question and never
	// stores the password (--no-keychain).
	NoKeychain bool
	// ProfileName overrides the default profile name (basename of the vault dir)
	// when set (--profile).
	ProfileName string
	// NoOpen skips the final "open the app now?" step (--no-open).
	NoOpen bool
	// OpenApp launches the app for the created profile at step 5. Nil means no
	// launcher is wired (the summary then names the command to run by hand). The
	// CLI supplies a launcher that runs `seavault gui <profile>`.
	OpenApp func(profileName string) error
}

// maxPasswordTries bounds the confirm-mismatch retry loop in step 2 (design §3.3
// step 2 / §6): three attempts, then a typed failure rather than an unbounded
// prompt.
const maxPasswordTries = 3

// maxRecoveryTries bounds the recovery read-back retry loop (design §3.3 step 3):
// after three mismatches the wizard defers recovery rather than looping, and
// nothing is written.
const maxRecoveryTries = 3

// RunInteractive drives the five wizard steps over a Prompter, builds the Plan,
// runs Execute, then runs the recovery read-back ceremony on the created vault
// and (optionally) opens the app (design §3.2/§3.3). Steps are presented in the
// design's order; because the recovery phrase can only be minted once the vault
// exists and Execute owns the create, the phrase show/re-type physically follows
// Execute — recovery generation deliberately stays OUT of Execute so the
// read-back ceremony is the same code path as `recovery generate` (§3.1, I-S3).
// The password is read from a hidden Secret prompt, used only to create the vault
// and (optionally) store in the keychain, and never placed in the Result, a log,
// a note, or the summary (I-S1).
func RunInteractive(pr Prompter, deps Deps, opts RunOptions) (Result, error) {
	home := opts.Home
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}

	// Step 1: where should the vault live?
	vaultDir, cloud, err := stepVaultLocation(pr, home, goos)
	if err != nil {
		return Result{}, err
	}

	// CLI-5: validate the chosen location immediately (side-effect-free) and offer
	// the typed-error remedy IN PLACE — before the password and the rest of the
	// ceremony are spent — so a collision does not waste every later prompt and
	// then fail at Execute with a bare "error:" (design §6). profileOverride may
	// carry a suffixed profile name chosen to dodge a name collision.
	vaultDir, cloud, profileOverride, openedExisting, err := resolveLocationConflicts(pr, vaultDir, cloud, opts.ProfileName, home, goos, opts.OpenApp)
	if err != nil {
		return Result{}, err
	}
	if openedExisting {
		// The user chose to open the existing vault instead of creating a new one;
		// nothing new was built.
		return Result{}, nil
	}

	// Step 1 (--expert): KDF + chunk knobs, validated against the floor later.
	var expert *ExpertOptions
	if opts.Expert {
		expert, err = stepExpert(pr)
		if err != nil {
			return Result{}, err
		}
	}

	// Step 2: choose a password (bounded confirm) + keychain decision.
	password, err := stepPassword(pr)
	if err != nil {
		return Result{}, err
	}
	saveKeychain := false
	if !opts.NoKeychain {
		saveKeychain, err = pr.Confirm("Remember the password in your OS keychain?", true)
		if err != nil {
			return Result{}, err
		}
	}

	// Step 3: recovery DECISION (the ceremony itself runs after the vault exists).
	recoveryNow, err := pr.Confirm(
		"Set up a recovery key now? (recommended — without it, a forgotten password means the vault cannot be opened)",
		true)
	if err != nil {
		return Result{}, err
	}

	// Step 4: how does it reach your cloud? Pre-answered when step 1 chose (or the
	// path sits under) a provider folder; otherwise ask.
	if cloud == nil {
		cloud, err = stepCloud(pr, &deps)
		if err != nil {
			return Result{}, err
		}
	}

	plan := Plan{
		VaultDir:     vaultDir,
		ProfileName:  profileOverride,
		SaveKeychain: saveKeychain,
		Cloud:        cloud,
		Expert:       expert,
	}

	res, err := Execute(plan, password, deps)
	if err != nil {
		// The vault/profile may exist (a cloud-step failure); the caller surfaces
		// res.CloudNote and the error. Recovery/open are skipped.
		return res, err
	}

	// Step 4 outcome for the no-transport path: the wizard never asserts the
	// vault is "synced" (C2). It surfaces the placement note and asks the user to
	// confirm their sync client is picking the folder up — advisory only, it gates
	// nothing (Execute's CloudNote carries the never-asserts-synced wording).
	if _, ok := plan.Cloud.(SyncedFolder); ok {
		if _, cerr := pr.Confirm(
			"Does your sync client show the vault folder starting to upload? (just a check — the vault is placed and ready either way)",
			true); cerr != nil {
			return res, cerr
		}
	}

	// Step 3 ceremony: the EXISTING generate -> show-once -> re-type -> commit
	// path on the just-created vault (I-S3). A failure to run it never costs the
	// user the vault; it downgrades to a "set it up later" note.
	if recoveryNow {
		res.RecoveryNote = runRecoveryCeremony(pr, res.VaultDir, home, goos, password)
	} else {
		res.RecoveryNote = recoveryDeferNote(res.ProfileName)
	}

	// Step 5: open the app now?
	opened := false
	if !opts.NoOpen {
		open, cerr := pr.Confirm("Open the app now?", true)
		if cerr != nil {
			return res, cerr
		}
		if open {
			opened = true
		}
	}

	for _, line := range SummaryLines(res, opened) {
		pr.Show(line)
	}

	if opened {
		if opts.OpenApp == nil {
			pr.Show(fmt.Sprintf("Start it any time with: seavault gui %s", res.ProfileName))
		} else if oerr := opts.OpenApp(res.ProfileName); oerr != nil {
			return res, oerr
		}
	}

	return res, nil
}

// stepVaultLocation runs step 1: it lists any detected provider folders first
// (the single detected provider is the default), always offers a custom path,
// shows the provider caveat inline when one is chosen, and returns the chosen
// vault dir plus a pre-answered CloudChoice when the location is (or sits under)
// a provider folder (design §3.3 step 1 / §4 / C5). A nil CloudChoice means step
// 4 must ask.
func stepVaultLocation(pr Prompter, home, goos string) (string, CloudChoice, error) {
	detected := DetectSyncFolders(home, goos)
	def := defaultCustomVaultDir(home)

	if len(detected) == 0 {
		// No providers: ask for the path directly, defaulting to the standard
		// no-sync location.
		path, err := pr.Text("Where should the vault live?", def)
		if err != nil {
			return "", nil, err
		}
		path = strings.TrimSpace(path)
		if path == "" {
			path = def
		}
		return resolveCustomLocation(pr, filepath.Clean(path), home, goos)
	}

	options := make([]Option, 0, len(detected)+1)
	for _, f := range detected {
		options = append(options, Option{
			Label: fmt.Sprintf("Inside your %s folder (%s)", DisplayName(f.Provider), filepath.Join(f.Path, defaultVaultName)),
			Note:  f.Note,
		})
	}
	options = append(options, Option{Label: fmt.Sprintf("A custom folder (default: %s)", def)})

	idx, err := pr.Select("Where should the vault live?", options, 0)
	if err != nil {
		return "", nil, err
	}
	if idx < 0 || idx >= len(options) {
		idx = 0
	}
	if idx < len(detected) {
		f := detected[idx]
		if f.Note != "" {
			pr.Show(f.Note)
		}
		return filepath.Join(f.Path, defaultVaultName), SyncedFolder{Provider: f.Provider}, nil
	}
	// Custom path.
	path, err := pr.Text("Vault folder path", def)
	if err != nil {
		return "", nil, err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = def
	}
	return resolveCustomLocation(pr, filepath.Clean(path), home, goos)
}

// resolveCustomLocation classifies a typed vault path: when it sits under a
// detected provider root, the cloud step is pre-answered SyncedFolder for that
// provider (C5) and its caveat is shown inline (CLI-3 — a typed path under a
// provider folder is exactly as exposed to on-demand eviction as one picked
// from the list, so it must be warned the same way); otherwise the cloud choice
// is left nil so step 4 asks.
func resolveCustomLocation(pr Prompter, path, home, goos string) (string, CloudChoice, error) {
	if prov, ok := ProviderRootFor(path, home, goos); ok {
		if cav := Caveat(prov); cav != "" {
			pr.Show(cav)
		}
		return path, SyncedFolder{Provider: prov}, nil
	}
	return path, nil, nil
}

// stepPassword runs step 2's bounded password entry: a hidden secret plus a
// hidden confirmation, re-asked on mismatch up to maxPasswordTries, then a typed
// failure (design §3.3 step 2 / §6). It never echoes or returns anything but the
// agreed password.
func stepPassword(pr Prompter) (string, error) {
	for try := 1; try <= maxPasswordTries; try++ {
		p1, err := pr.Secret("Choose a password")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(p1) == "" {
			pr.Show("The password must not be empty.")
			continue
		}
		p2, err := pr.Secret("Confirm the password")
		if err != nil {
			return "", err
		}
		if p1 == p2 {
			return p1, nil
		}
		if try < maxPasswordTries {
			pr.Show("The passwords did not match — try again.")
		}
	}
	return "", fmt.Errorf("the password and its confirmation did not match after %d tries; nothing was created", maxPasswordTries)
}

// stepCloud runs step 4 when no provider was pre-answered: the manual "my own
// sync client already watches this folder" outcome (C5), an existing rclone
// remote (binding a download-consent decision onto deps.RcloneEnsure before
// Execute reaches it, C11), or local-only (design §3.3 step 4). deps is mutated
// in place so Execute uses the consent the user just gave.
//
// The DEFAULT is "local / external drive only" (CLI-1/DOC-1): reaching this step
// at all means detection found no provider AND the chosen path sits under no
// detected root, so a user who just presses Enter must NOT be told to check a
// sync client they may not have. The safe, honest default is local-only; the
// "already watched" choice is opt-in.
func stepCloud(pr Prompter, deps *Deps) (CloudChoice, error) {
	options := []Option{
		{Label: "This folder is already watched by my own sync client (Dropbox, OneDrive, Nextcloud, ...)"},
		{Label: "Use an existing rclone remote"},
		{Label: "Local or external drive only (no cloud sync)"},
	}
	const localOnlyIdx = 2
	idx, err := pr.Select("How does the vault reach your cloud?", options, localOnlyIdx)
	if err != nil {
		return nil, err
	}
	switch idx {
	case 0:
		return SyncedFolder{Provider: ""}, nil
	case 1:
		name, err := pr.Text("Name of the existing rclone remote (configured in rclone, or imported with `seavault remote config import`)", "")
		if err != nil {
			return nil, err
		}
		remotePath, err := pr.Text("Remote path (e.g. myremote:vaults/MyVault)", "")
		if err != nil {
			return nil, err
		}
		// Default NO for the network-download consent (rclone-ensure-1): this is a
		// consequential action (fetches ~15MB from downloads.rclone.org), so an
		// EOF/blank answer on a closed stdin must DECLINE, not silently download —
		// matching the repo's destructive-action prompt convention. A user who
		// wants the download types "y".
		consent, err := pr.Confirm("If the rclone runtime is missing, download and install it now? (fetches from downloads.rclone.org)", false)
		if err != nil {
			return nil, err
		}
		deps.RcloneEnsure = func() error { return RcloneEnsure(func() bool { return consent }) }
		return RcloneRemote{Name: strings.TrimSpace(name), RemotePath: strings.TrimSpace(remotePath)}, nil
	default:
		return LocalOnly{}, nil
	}
}

// stepExpert runs the --expert questionnaire: a KDF algorithm plus its primary
// cost knobs and the chunk sizes, all defaulted (design §3.3 step 1). The chosen
// KDF is validated against the SAME floor cmdInit enforces inside Plan.Validate
// (I-S2), so a below-floor choice fails there rather than here.
func stepExpert(pr Prompter) (*ExpertOptions, error) {
	algIdx, err := pr.Select("Key derivation function", []Option{
		{Label: "argon2id (recommended)"},
		{Label: "scrypt"},
		{Label: "pbkdf2"},
	}, 0)
	if err != nil {
		return nil, err
	}
	kdf := vault.DefaultKDFConfig()
	switch algIdx {
	case 1:
		kdf = vault.KDFConfig{
			Algorithm: "SCRYPT",
			ScryptN:   promptInt(pr, "scrypt N", vault.DefaultScryptN),
			ScryptR:   promptInt(pr, "scrypt r", vault.DefaultScryptR),
			ScryptP:   promptInt(pr, "scrypt p", vault.DefaultScryptP),
		}
	case 2:
		kdf = vault.KDFConfig{
			Algorithm:  "PBKDF2-HMAC-SHA256",
			Iterations: promptInt(pr, "pbkdf2 iterations", vault.DefaultKDFIterations),
		}
	default:
		kdf = vault.KDFConfig{
			Algorithm:   "ARGON2ID",
			Time:        promptInt(pr, "argon2id time cost", vault.DefaultArgon2Time),
			MemoryKiB:   promptInt(pr, "argon2id memory (KiB)", vault.DefaultArgon2Memory),
			Parallelism: promptInt(pr, "argon2id parallelism", vault.DefaultArgon2Threads),
		}
	}
	def := vault.DefaultChunkParams()
	chunk := vault.ChunkParams{
		MinSize: promptInt(pr, "minimum chunk size (bytes)", def.MinSize),
		AvgSize: promptInt(pr, "target average chunk size (bytes)", def.AvgSize),
		MaxSize: promptInt(pr, "maximum chunk size (bytes)", def.MaxSize),
	}
	return &ExpertOptions{KDF: kdf, Chunk: chunk}, nil
}

// promptInt asks for an integer with a default; a blank answer or an unparseable
// one keeps the default (the floor check downstream still guards a too-weak
// number, so this never has to reject).
func promptInt(pr Prompter, label string, def int) int {
	s, err := pr.Text(label, strconv.Itoa(def))
	if err != nil {
		return def
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// runRecoveryCeremony opens the just-created vault and runs the existing
// generate -> show-once -> (optionally save) -> re-type -> commit ceremony
// (design §3.3 step 3, I-S3). The phrase is shown BEFORE the re-type gate and may
// be saved to a file first, so the re-type verifies a stored copy. On a mismatch
// nothing is written and the user is offered retry-or-defer; on defer, or any
// setup error, recovery is left for later and a reminder is returned. It returns
// the RecoveryNote to place in the summary and never returns the phrase.
//
// home/goos drive the save-path safety guards (recovery-integration-1): the
// plaintext recovery phrase is the master secret, so it must never be written
// inside the vault directory (it would be encrypted-then-uploaded alongside the
// vault, but the plaintext copy would ride the same synced folder to the
// untrusted remote), and writing it under any OTHER detected provider root needs
// an explicit second confirmation. A file that IS written but the ceremony then
// does not commit (defer/mismatch/commit error) is offered for deletion
// (recovery-integration-2).
func runRecoveryCeremony(pr Prompter, vaultDir, home, goos, password string) string {
	remedy := shellQuote(vaultDir)
	v, err := vault.Open(vaultDir, password)
	if err != nil {
		return fmt.Sprintf("the vault was created, but the recovery key could not be set up now (%v); set one up later with `seavault recovery generate %s`.", err, remedy)
	}
	phrase, commit, err := v.PrepareRecovery()
	if err != nil {
		return fmt.Sprintf("the vault was created, but the recovery key could not be set up now (%v); set one up later with `seavault recovery generate %s`.", err, remedy)
	}

	pr.Show("Your recovery phrase — write it down or print it and store it safely. It is shown once and never stored:")
	pr.Show(phrase)

	// Let the user save the shown phrase before the re-type gate (C6). A blank
	// answer skips saving; the re-type still verifies whatever they wrote down.
	// The file is a plaintext recovery phrase, so it is written owner-only
	// (0600), the destination is validated against the vault dir and detected
	// provider roots (recovery-integration-1), and the confirmation LABELS it as
	// sensitive AND as written-before-confirmation (C6, recovery-integration-2).
	savedPath := ""
	if path, terr := pr.Text("Optional: a file to save the phrase to now (leave blank to skip)", ""); terr == nil {
		if path = strings.TrimSpace(path); path != "" {
			target := filepath.Clean(path)
			if allowRecoverySavePath(pr, target, vaultDir, home, goos) {
				if werr := os.WriteFile(target, []byte(phrase+"\n"), 0o600); werr != nil {
					pr.Show(fmt.Sprintf("could not save the phrase to %s: %v", target, werr))
				} else {
					savedPath = target
					pr.Show(fmt.Sprintf("saved the recovery phrase to %s — this file is sensitive: it holds the plaintext recovery phrase, so anyone who can read it can unlock the vault, and it was written now, BEFORE you confirm the phrase below. It is written owner-only; keep it that way, and delete it once the phrase is stored somewhere safe.", target))
				}
			}
		}
	}

	// noCommitExit runs on every path that leaves WITHOUT committing a recovery
	// key: it offers to delete a phrase file that was written before the gate
	// (recovery-integration-2), then returns the caller's note.
	noCommitExit := func(note string) string {
		if savedPath != "" {
			offerDeleteAbandonedPhrase(pr, savedPath)
		}
		return note
	}

	for try := 1; try <= maxRecoveryTries; try++ {
		readback, err := pr.Secret("Re-type the recovery phrase to confirm")
		if err != nil {
			return noCommitExit(recoveryDeferNote(vaultDir))
		}
		if vault.RecoveryPhraseMatches(phrase, readback) {
			if cerr := commit(); cerr != nil {
				return noCommitExit(fmt.Sprintf("the recovery phrase matched but could not be saved (%v); set one up later with `seavault recovery generate %s`.", cerr, remedy))
			}
			return "A recovery key was created. Keep the phrase safe: it is the only way back into the vault if you forget the password."
		}
		if try >= maxRecoveryTries {
			break
		}
		again, cerr := pr.Confirm("That did not match the phrase shown. Try entering it again? (choosing No sets up recovery later)", true)
		if cerr != nil || !again {
			return noCommitExit(recoveryDeferNote(vaultDir))
		}
	}
	return noCommitExit(recoveryDeferNote(vaultDir))
}

// allowRecoverySavePath decides whether the plaintext recovery phrase may be
// written to target (recovery-integration-1). A path inside the vault directory
// is REFUSED outright — the master recovery secret must never live inside the
// synced vault folder, where it would be uploaded to the untrusted remote and
// defeat the zero-knowledge model. A path under any OTHER detected provider root
// is allowed only after an explicit second confirmation naming the risk. Any
// other path is allowed. It shows the reason on a refusal and never writes.
func allowRecoverySavePath(pr Prompter, target, vaultDir, home, goos string) bool {
	fold := caseInsensitiveFS(goos)
	if pathWithin(target, filepath.Clean(vaultDir), fold) {
		pr.Show(fmt.Sprintf("refusing to save the recovery phrase to %s: that path is inside the vault folder. The recovery phrase is the master key — a plaintext copy inside the vault folder would be uploaded to your cloud/remote, defeating the encryption. Choose a location OUTSIDE the vault (a password manager, a USB key, or print it).", target))
		return false
	}
	if prov, ok := ProviderRootFor(target, home, goos); ok {
		ok2, err := pr.Confirm(fmt.Sprintf("that path is inside your %s folder, so the plaintext recovery phrase would be UPLOADED to your cloud in the clear — anyone with access to that cloud could unlock the vault. Save it there anyway?", DisplayName(prov)), false)
		if err != nil || !ok2 {
			pr.Show("did not save the recovery phrase there. Choose a location outside your sync folders (a password manager, a USB key, or print it).")
			return false
		}
	}
	return true
}

// offerDeleteAbandonedPhrase offers to delete a recovery-phrase file that was
// written before the re-type gate when the ceremony did NOT commit a key
// (recovery-integration-2): the file is a secret-shaped artefact with no
// matching recovery entry, so deletion is the default. It never returns the
// phrase and reads no secret.
func offerDeleteAbandonedPhrase(pr Prompter, path string) {
	del, err := pr.Confirm(fmt.Sprintf("A recovery-phrase file was written to %s before the phrase was confirmed, but NO recovery key was set up. It holds the plaintext phrase. Delete that file now?", path), true)
	if err != nil {
		return
	}
	if del {
		if rerr := os.Remove(path); rerr != nil {
			pr.Show(fmt.Sprintf("could not delete %s: %v — remove it by hand; it holds the plaintext recovery phrase.", path, rerr))
		} else {
			pr.Show(fmt.Sprintf("deleted the abandoned recovery-phrase file %s.", path))
		}
	} else {
		pr.Show(fmt.Sprintf("kept %s — it holds the plaintext recovery phrase and was written before confirmation; delete it by hand once you no longer need it.", path))
	}
}

// recoveryDeferNote is the one-line reminder shown when recovery is deferred or
// left unset (design §3.3 step 3 / §6). It never asserts a key exists. The
// remedy names the vault/profile shell-quoted so it pastes cleanly when the name
// contains spaces (preset-noninteractive-2).
func recoveryDeferNote(profileOrDir string) string {
	return fmt.Sprintf("No recovery key was set up. Without one, a forgotten password means the vault cannot be opened — set one up any time with `seavault recovery generate %s`.", shellQuote(profileOrDir))
}

// SummaryLines renders the plain-language success summary (design §3.3): what was
// created, where, whether the keychain holds the password, whether a recovery key
// exists, the cloud outcome, and the next step. It carries NO secret (I-S1): it
// reads only the non-secret Result fields.
func SummaryLines(res Result, opened bool) []string {
	lines := []string{
		"Your vault is ready.",
		fmt.Sprintf("  Location: %s", res.VaultDir),
		fmt.Sprintf("  Profile:  %s", res.ProfileName),
	}
	if res.KeychainSaved {
		lines = append(lines, "  Password: saved in your OS keychain (you won't be asked for it each time).")
	} else if res.KeychainNote != "" {
		lines = append(lines, "  Password: "+res.KeychainNote)
	} else {
		lines = append(lines, "  Password: not saved; you'll be asked for it when you open the vault.")
	}
	if res.RecoveryNote != "" {
		lines = append(lines, "  Recovery: "+res.RecoveryNote)
	}
	if res.CloudNote != "" {
		lines = append(lines, "  Cloud:    "+res.CloudNote)
	}
	if res.CaveatNote != "" {
		// The provider placement caveat (on-demand/online-only eviction). Shown
		// in the summary so a custom-path or --preset synced-folder run under a
		// detected root surfaces it even though no inline step displayed it
		// (CLI-3/DOC-4).
		lines = append(lines, "  Sync tip: "+res.CaveatNote)
	}
	if res.PreflightNote != "" {
		lines = append(lines, "  Note:     "+res.PreflightNote)
	}
	if opened {
		lines = append(lines, fmt.Sprintf("Opening the app for %q now.", res.ProfileName))
	} else {
		lines = append(lines, fmt.Sprintf("Next: open it with  seavault gui %s", res.ProfileName))
	}
	return lines
}

// defaultCustomVaultDir is the standard no-sync default location for a vault
// (design §3.3 step 1): ~/open-seavault-rclone/MyVault, portable via the injected
// home (falling back to the working directory when home is unknown).
func defaultCustomVaultDir(home string) string {
	if strings.TrimSpace(home) == "" {
		return filepath.Join("open-seavault-rclone", defaultVaultName)
	}
	return filepath.Join(home, "open-seavault-rclone", defaultVaultName)
}
