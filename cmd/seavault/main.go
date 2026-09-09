// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/authlimit"
	"github.com/alexdimarco/open-seavault-rclone/internal/importer"
	"github.com/alexdimarco/open-seavault-rclone/internal/keychain"
	"github.com/alexdimarco/open-seavault-rclone/internal/localdav"
	"github.com/alexdimarco/open-seavault-rclone/internal/passphrase"
	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/rsyncbin"
	"github.com/alexdimarco/open-seavault-rclone/internal/rsyncput"
	"github.com/alexdimarco/open-seavault-rclone/internal/setup"
	"github.com/alexdimarco/open-seavault-rclone/internal/sshkeys"
	"github.com/alexdimarco/open-seavault-rclone/internal/tlsconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/transport"
	localtransport "github.com/alexdimarco/open-seavault-rclone/internal/transport/local"
	rclonetransport "github.com/alexdimarco/open-seavault-rclone/internal/transport/rclone"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
	"github.com/alexdimarco/open-seavault-rclone/internal/vaultmove"
	"github.com/alexdimarco/open-seavault-rclone/internal/webui"
)

const version = "0.21.0"

func main() {
	// main() dispatches FROM the command registry (commands.go). All command
	// wiring, the exit-code contract, and usage rendering live there, so a single
	// table is the one source of truth and run() stays testable without os.Exit.
	os.Exit(run(os.Args[1:]))
}

// exitCodeError lets a command request a specific process exit code without the
// generic "error:..." print that main applies to a real failure. The command
// is responsible for emitting any human-facing line before returning it. Exit
// code 3 means "action required": a bare `seavault gc` dry run found chunks it
// would reclaim but did not, so an automated caller that omitted --confirm can
// detect via the exit status that reclamation did not happen.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

// setupSynopsis is the one-line description shown by `setup --help` and asserted
// by TestSubcommandSynopses.
func setupSynopsis() string {
	return "setup is the guided first-run wizard: it picks a vault location (inside a detected cloud-sync folder when one is found), takes a password, offers a recovery key and OS-keychain storage, wires up cloud sync, then opens the app — every default chosen for you, every advanced knob one flag away. Use --preset synced-folder|rclone|local for a non-interactive run that reads the password from SEAVAULT_PASSWORD."
}

// setupFlags holds the parsed `seavault setup` flags. It is populated by
// registerSetupFlags so cmdSetup and the --help renderer (and its test) share ONE
// flag definition — the long-form names the usage line advertises can never drift
// from the flags actually registered (ADM-6).
type setupFlags struct {
	expert        *bool
	preset        *string
	vaultFlag     *string
	remoteFlag    *string
	allowDownload *bool
	noKeychain    *bool
	profileName   *string
	noOpen        *bool
	jsonOut       *bool
	debug         *bool
}

// registerSetupFlags defines every `setup` flag on fs. It is the single source of
// the flag set, used by cmdSetup and by writeSetupUsage/the usage test.
func registerSetupFlags(fs *flag.FlagSet) *setupFlags {
	return &setupFlags{
		expert:        fs.Bool("expert", false, "show the KDF and chunk-size knobs during setup (validated against the same floor as init)"),
		preset:        fs.String("preset", "", "non-interactive run: synced-folder | rclone | local (reads the password from SEAVAULT_PASSWORD)"),
		vaultFlag:     fs.String("vault", "", "vault directory (required with --preset)"),
		remoteFlag:    fs.String("remote", "", "existing rclone remote name (with --preset rclone); the remote must ALREADY exist in this machine's rclone config"),
		allowDownload: fs.Bool("allow-download", false, "permit a --preset rclone run to download the rclone runtime if it is missing"),
		noKeychain:    fs.Bool("no-keychain", false, "do not store the password in the OS keychain"),
		profileName:   fs.String("profile", "", "profile name for the new vault (default: the vault folder's name)"),
		noOpen:        fs.Bool("no-open", false, "do not open the app at the end"),
		jsonOut:       fs.Bool("json", false, "with --preset, emit the machine-readable result as JSON instead of prose (never a secret)"),
		debug:         fs.Bool("debug", false, "print extra diagnostic detail (e.g. the raw keychain error) that the plain summary omits"),
	}
}

// setupUsageLine is the two-line usage synopsis. It uses the double-dash long
// flag forms so the flag block writeSetupUsage renders below it agrees (ADM-6).
func setupUsageLine() string {
	return "usage: seavault setup [--expert] [--no-keychain] [--profile NAME] [--no-open]\n" +
		"       seavault setup --preset synced-folder|rclone|local --vault PATH [--remote NAME] [--allow-download] [--json] [--no-keychain] [--profile NAME] [--no-open]"
}

// setupScopeAndExitHelp documents the rclone-remote precondition (ADM-3) and the
// exit-code contract (ADM-5/ADM-6) so an operator scripting a fleet can read both
// from `setup --help` alone.
func setupScopeAndExitHelp() string {
	return "The --preset rclone form requires --remote NAME to name an rclone remote that ALREADY EXISTS in\n" +
		"each machine's rclone config (configured with rclone, or imported via `seavault remote config import`);\n" +
		"setup never creates or edits a remote.\n\n" +
		"Exit codes:\n" +
		"  0  setup completed — or, with --preset, a vault already existed at --vault and matched the\n" +
		"     requested plan, so nothing was changed (an idempotent re-run of a provisioning loop)\n" +
		"  1  setup failed: bad flags, a refused rclone download, an existing vault whose profile name\n" +
		"     already points at a DIFFERENT vault, or an error while creating the vault\n"
}

// writeSetupUsage renders `setup --help`: the usage line, the synopsis, the flags
// in their double-dash long form (matching the usage line, ADM-6), then the
// rclone-scope statement and the exit-code contract. It renders the flags from
// the live FlagSet so a new flag can never be missing from --help.
func writeSetupUsage(fs *flag.FlagSet) {
	out := fs.Output()
	fmt.Fprintf(out, "%s\n\n%s\n\nFlags (long forms match the usage line above):\n", setupUsageLine(), setupSynopsis())
	fs.VisitAll(func(f *flag.Flag) {
		name := "  --" + f.Name
		if f.DefValue != "" && f.DefValue != "false" {
			name += "=" + f.DefValue
		}
		fmt.Fprintf(out, "%s\n        %s\n", name, f.Usage)
	})
	fmt.Fprint(out, "\n"+setupScopeAndExitHelp())
}

// cmdSetup is the first-run wizard (design §3.3). With no --preset it runs the
// interactive flow over a stdlib prompter; with --preset it runs a fully
// non-interactive setup that reads the password from SEAVAULT_PASSWORD only
// (I-S1) and skips recovery (I-S3).
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	f := registerSetupFlags(fs)
	fs.Usage = func() { writeSetupUsage(fs) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("setup takes no positional arguments (the vault path is --vault with --preset, or a wizard prompt otherwise)")
	}

	if strings.TrimSpace(*f.preset) != "" {
		return runSetupPreset(setupPresetArgs{
			preset:        strings.ToLower(strings.TrimSpace(*f.preset)),
			vaultArg:      *f.vaultFlag,
			remoteName:    *f.remoteFlag,
			allowDownload: *f.allowDownload,
			noKeychain:    *f.noKeychain,
			profileName:   *f.profileName,
			jsonOut:       *f.jsonOut,
			debug:         *f.debug,
		})
	}

	// --json describes the machine-readable result of a scripted preset run; the
	// interactive wizard writes prompts and a human summary to stdout, where a JSON
	// document would be meaningless, so reject the combination rather than emit
	// garbled output.
	if *f.jsonOut {
		return fmt.Errorf("--json only applies to a --preset run; the interactive wizard prints a human summary")
	}

	deps := setup.DefaultDeps()
	pr := newStdinPrompter()
	res, err := setup.RunInteractive(pr, deps, setup.RunOptions{
		Expert:      *f.expert,
		NoKeychain:  *f.noKeychain,
		ProfileName: *f.profileName,
		NoOpen:      *f.noOpen,
		OpenApp:     func(profile string) error { return cmdGUI([]string{profile}) },
	})
	if err != nil {
		// CLI-6/DOC-5: on a failure after the vault was already created (a cloud
		// step, most often), tell the operator the vault exists and surface the
		// step-branched CloudNote BEFORE the error, so a failed cloud step never
		// looks like a lost vault. RunInteractive does not print CloudNote on the
		// error path, so this prints it exactly once.
		for _, line := range setupFailureLines(res) {
			fmt.Fprintln(os.Stderr, line)
		}
		return err
	}
	// Under --debug, surface the raw keychain error detail the plain summary
	// one-liner (CLI-1) deliberately omits.
	if *f.debug && res.KeychainErrDetail != "" {
		fmt.Fprintln(os.Stderr, "keychain error detail:", res.KeychainErrDetail)
	}
	return nil
}

// setupFailureLines returns the operator-facing reassurance to print BEFORE a
// failed setup's error (CLI-6/DOC-5): a "your vault was created" line whenever a
// vault was actually built (res.VaultID set), then the step-branched CloudNote
// when Execute set one. Each appears at most once, so no caller double-prints the
// CloudNote. It reads only non-secret Result fields (I-S1).
func setupFailureLines(res setup.Result) []string {
	var lines []string
	if res.VaultID != "" {
		lines = append(lines, fmt.Sprintf("Your vault was created at %s (profile %s) — the failure below is a later step; the vault is safe.", res.VaultDir, res.ProfileName))
	}
	if res.CloudNote != "" {
		lines = append(lines, res.CloudNote)
	}
	return lines
}

// annotateSetupError names the remedy for a typed setup error that the
// non-interactive --preset path would otherwise surface bare (ADM-5). --preset
// takes the `--vault` flag, so the leftovers remedy names it.
func annotateSetupError(err error) error {
	return annotateLeftovers(err, "--vault")
}

// annotateInitLeftovers is annotateSetupError for `init`, which takes a positional
// VAULT_DIR rather than a --vault flag: the remedy must name the real argument so
// it is actionable (polish-behaviour-2 / W3-3 — the shared helper must not tell an
// `init` user to pass a `--vault` flag `init` does not have).
func annotateInitLeftovers(err error) error {
	return annotateLeftovers(err, "VAULT_DIR")
}

// annotateLeftovers gives a leftovers directory (a non-empty target with no
// vault.json, from an interrupted setup) the "remove it or choose a different
// <target>" remedy the interactive flow offers as a prompt, parameterized by how
// the calling command names its vault-directory argument. Any other error is
// returned unchanged.
func annotateLeftovers(err error, targetName string) error {
	if errors.Is(err, setup.ErrVaultDirLeftovers) {
		return fmt.Errorf("%w — remove that directory and re-run, or choose a different %s", err, targetName)
	}
	return err
}

type setupPresetArgs struct {
	preset        string
	vaultArg      string
	remoteName    string
	allowDownload bool
	noKeychain    bool
	profileName   string
	jsonOut       bool
	debug         bool
}

// setupResultJSON is the machine-readable shape `setup --preset --json` emits
// (ADM-1). It carries only non-secret Result fields — NEVER the password or a
// recovery phrase (I-S1). RecoveryCreated is always false for a preset run
// (recovery is skipped, I-S3). AlreadyExisted marks an idempotent re-run.
type setupResultJSON struct {
	VaultID         string `json:"vaultID"`
	VaultDir        string `json:"vaultDir"`
	Profile         string `json:"profile"`
	KeychainSaved   bool   `json:"keychainSaved"`
	RecoveryCreated bool   `json:"recoveryCreated"`
	Cloud           string `json:"cloud"`
	PreflightNote   string `json:"preflightNote"`
	AlreadyExisted  bool   `json:"alreadyExisted"`
}

// emitSetupJSON writes the setup result to stdout as indented JSON (ADM-1). It is
// the machine-readable counterpart of setup.SummaryLines and carries no secret.
func emitSetupJSON(res setup.Result, cloud string, alreadyExisted bool) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(setupResultJSON{
		VaultID:         res.VaultID,
		VaultDir:        res.VaultDir,
		Profile:         res.ProfileName,
		KeychainSaved:   res.KeychainSaved,
		RecoveryCreated: false,
		Cloud:           cloud,
		PreflightNote:   res.PreflightNote,
		AlreadyExisted:  alreadyExisted,
	})
}

// runSetupPreset performs a non-interactive setup (design §3.3). It reads the
// password from SEAVAULT_PASSWORD ONLY — never argv, never a prompt (I-S1) — and
// never generates a recovery key (a phrase nobody saw must not be committed,
// I-S3); it prints the remedy instead. The preset-specific validation, including
// the rclone download gate (C11), runs before the password is read so a refusal
// is deterministic. A re-run whose --vault already holds a matching vault is an
// idempotent no-op that exits 0 (ADM-5), so a fleet provisioning loop is safe to
// re-run.
func runSetupPreset(a setupPresetArgs) error {
	if strings.TrimSpace(a.vaultArg) == "" {
		return fmt.Errorf("--preset requires --vault PATH")
	}
	switch a.preset {
	case "synced-folder", "local", "rclone":
	default:
		return fmt.Errorf("unknown --preset %q; want synced-folder, rclone, or local", a.preset)
	}
	vaultPath, err := userpath.Abs(a.vaultArg)
	if err != nil {
		return err
	}

	// ADM-5 idempotent re-run: a provisioning loop re-runs the SAME command; a
	// vault already present at --vault must not fail the loop. This check needs
	// neither the password nor the rclone download, so it runs FIRST — before the
	// C11 download gate and before SEAVAULT_PASSWORD is read. A vault that matches
	// the requested plan reports and exits 0; a profile-name clash with a DIFFERENT
	// vault is a real mismatch and keeps its non-zero exit.
	if handled, herr := setupIdempotentRerun(vaultPath, a); handled || herr != nil {
		return herr
	}

	deps := setup.DefaultDeps()
	var cloud setup.CloudChoice
	switch a.preset {
	case "synced-folder":
		// Resolve the provider when the vault sits under a detected sync root so
		// Execute can surface that provider's placement caveat in the summary
		// (DOC-4). An unknown/undetected root leaves Provider empty (no caveat).
		prov := setup.Provider("")
		if home, herr := os.UserHomeDir(); herr == nil {
			if p, ok := setup.ProviderRootFor(vaultPath, home, runtime.GOOS); ok {
				prov = p
			}
		}
		cloud = setup.SyncedFolder{Provider: prov}
	case "local":
		cloud = setup.LocalOnly{}
	case "rclone":
		if strings.TrimSpace(a.remoteName) == "" {
			return fmt.Errorf("--preset rclone requires --remote NAME (an existing rclone remote configured in rclone or imported with `seavault remote config import`)")
		}
		if !a.allowDownload {
			return fmt.Errorf("`setup --preset rclone` will not download the rclone runtime without --allow-download; pass --allow-download, or install it offline first with `seavault rclone install --offline-archive <zip>` or `seavault rclone install --from-binary <path>`, then re-run")
		}
		deps.RcloneEnsure = func() error { return setup.RcloneEnsure(func() bool { return true }) }
		name := strings.TrimSpace(a.remoteName)
		cloud = setup.RcloneRemote{Name: name, RemotePath: name + ":"}
	}

	// Password from SEAVAULT_PASSWORD ONLY (I-S1): never read from argv, never
	// prompted in a non-interactive run.
	password := os.Getenv("SEAVAULT_PASSWORD")
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("a non-interactive `setup --preset` run reads the password from SEAVAULT_PASSWORD only; set that environment variable and re-run (the password is never taken from the command line)")
	}

	plan := setup.Plan{
		VaultDir:     vaultPath,
		ProfileName:  a.profileName,
		SaveKeychain: !a.noKeychain,
		Cloud:        cloud,
	}
	res, err := setup.Execute(plan, password, deps)
	if err != nil {
		// CLI-6/DOC-5: name the created vault (if any) and the step-branched
		// CloudNote before returning; each prints at most once.
		for _, line := range setupFailureLines(res) {
			fmt.Fprintln(os.Stderr, line)
		}
		// ADM-5: a leftovers directory has no interactive remove-and-retry prompt
		// on the --preset path, so name the remedy in the error itself.
		return annotateSetupError(err)
	}

	// I-S3: recovery is skipped in a non-interactive run; print the remedy. The
	// profile name is shell-quoted so the printed command pastes cleanly when the
	// name (the vault folder's basename) contains spaces (preset-noninteractive-2).
	res.RecoveryNote = fmt.Sprintf("skipped in a non-interactive run (a recovery key nobody has seen is never created); create one with `seavault recovery generate %s`.", shellQuoteArg(res.ProfileName))
	if a.jsonOut {
		return emitSetupJSON(res, a.preset, false)
	}
	// offerOpen=false: a scripted --preset run never launches the GUI, so the
	// "Next: open it with …" trailer is dropped for fleets (ADM-1). --no-open is
	// likewise inert under --preset (it is not even read here); it is accepted
	// only for symmetry with the interactive form.
	for _, line := range setup.SummaryLines(res, false, false) {
		fmt.Println(line)
	}
	// Under --debug, surface the raw keychain error detail that the plain
	// one-liner (CLI-1) deliberately omits.
	if a.debug && res.KeychainErrDetail != "" {
		fmt.Fprintln(os.Stderr, "keychain error detail:", res.KeychainErrDetail)
	}
	return nil
}

// setupIdempotentRerun implements ADM-5: when a vault already exists at vaultPath,
// a --preset re-run reports it and exits 0 if it matches the requested plan (the
// requested profile name is free or already points at THIS vault), registering
// the profile when it was missing so the machine ends fully provisioned. A
// profile name that already points at a DIFFERENT vault is a genuine mismatch and
// returns an error (a non-zero exit, distinct from the exit-0 match). It returns
// handled=true when it fully handled the run (an existing vault, match or the
// caller already got the mismatch error). handled=false means no vault exists yet
// and normal creation should proceed. It reads no password and never downloads.
func setupIdempotentRerun(vaultPath string, a setupPresetArgs) (handled bool, err error) {
	resolvedName := setup.Plan{VaultDir: vaultPath, ProfileName: a.profileName}.ResolvedProfileName()
	// Side-effect-free classification of the target dir. Only an EXISTING vault
	// (vault.json present) is idempotent; leftovers and a clear dir fall through to
	// the normal create path.
	probe := setup.Plan{VaultDir: vaultPath, ProfileName: a.profileName, Cloud: setup.LocalOnly{}}
	if verr := probe.Validate(); !errors.Is(verr, setup.ErrVaultDirNotEmpty) {
		return false, nil
	}

	e, found, rerr := profile.Resolve(resolvedName)
	if rerr != nil {
		return false, rerr
	}
	if found && filepath.Clean(e.VaultPath) != filepath.Clean(vaultPath) {
		return true, fmt.Errorf("a vault already exists at %s, but the profile name %q already points at a different vault (%s); re-run with a different --profile or --vault (nothing was changed)", vaultPath, resolvedName, e.VaultPath)
	}
	if !found {
		// The vault is present but not registered under this name (e.g. the
		// app-data store was reset while the vault dir survived); complete the
		// provisioning by registering it, so the profile the loop expects exists.
		if _, aerr := profile.Add(resolvedName, vaultPath); aerr != nil {
			return true, aerr
		}
	}

	res := setup.Result{
		VaultDir:      vaultPath,
		ProfileName:   resolvedName,
		PreflightNote: vault.SyncClientPreflightNote(vaultPath),
	}
	if cfg, cerr := vault.ReadConfig(vaultPath); cerr == nil {
		res.VaultID = cfg.VaultID
	}
	if a.jsonOut {
		return true, emitSetupJSON(res, a.preset, true)
	}
	fmt.Printf("a vault already exists at %s (profile %s); it matches the requested --preset %s plan, so nothing was changed.\n", vaultPath, resolvedName, a.preset)
	return true, nil
}

// shellQuoteArg renders s so it survives a copy-paste into a POSIX shell as a
// single argument (preset-noninteractive-2). A profile name defaults to the vault
// folder's basename, so it can hold spaces or shell metacharacters ("My Vault");
// interpolating it raw into a printed remedy command splits it into two arguments.
// A name of only safe characters is returned unchanged; anything else is wrapped
// in single quotes with embedded single quotes escaped the POSIX way. It is
// display-only (nothing here is executed) and never carries a secret.
func shellQuoteArg(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == '/' || r == '@' || r == '%' || r == '+' || r == ':' || r == ',':
		default:
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// stdinPrompter is the CLI implementation of setup.Prompter (design §3.2):
// numbered options, a line read for text/choices with Enter accepting the
// default, and passphrase.Read for secrets so a password is never echoed.
type stdinPrompter struct {
	in *bufio.Reader
}

func newStdinPrompter() *stdinPrompter { return newStdinPrompterFrom(os.Stdin) }

// newStdinPrompterFrom builds a prompter over an arbitrary reader; the tests use
// it to drive a closed/exhausted stdin without touching os.Stdin.
func newStdinPrompterFrom(r io.Reader) *stdinPrompter {
	return &stdinPrompter{in: bufio.NewReader(r)}
}

// readLine returns the next line with the newline trimmed. It DISTINGUISHES a
// closed/exhausted stdin: when ReadString hits EOF (or a read error) with nothing
// buffered, it returns that error so the caller can abort rather than loop
// forever treating EOF as "accept the default" (A2-c1). A final line WITHOUT a
// trailing newline is still delivered (its EOF is not raised until the next read).
func (p *stdinPrompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	if line == "" && err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *stdinPrompter) Select(title string, options []setup.Option, defaultIdx int) (int, error) {
	fmt.Println(title)
	for i, o := range options {
		marker := " "
		if i == defaultIdx {
			marker = "*"
		}
		fmt.Printf("  %s %d) %s\n", marker, i+1, o.Label)
		if o.Note != "" {
			fmt.Printf("      note: %s\n", o.Note)
		}
	}
	fmt.Printf("Choose [1-%d] (default %d): ", len(options), defaultIdx+1)
	raw, err := p.readLine()
	if err != nil {
		return defaultIdx, err
	}
	line := strings.TrimSpace(raw)
	if line == "" {
		return defaultIdx, nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(options) {
		return defaultIdx, nil
	}
	return n - 1, nil
}

func (p *stdinPrompter) Confirm(question string, defaultYes bool) (bool, error) {
	hint := "Y/n"
	if !defaultYes {
		hint = "y/N"
	}
	fmt.Printf("%s [%s]: ", question, hint)
	raw, err := p.readLine()
	if err != nil {
		return defaultYes, err
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultYes, nil
	}
}

func (p *stdinPrompter) Text(label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	raw, err := p.readLine()
	if err != nil {
		return def, err
	}
	line := strings.TrimSpace(raw)
	if line == "" {
		return def, nil
	}
	return line, nil
}

func (p *stdinPrompter) Secret(label string) (string, error) {
	return passphrase.Read(label + ": ")
}

func (p *stdinPrompter) Show(msg string) { fmt.Println(msg) }

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	min := fs.Int("min", 2*1024*1024, "minimum chunk size in bytes")
	avg := fs.Int("avg", 8*1024*1024, "target average chunk size in bytes")
	max := fs.Int("max", 16*1024*1024, "maximum chunk size in bytes")
	kdf := fs.String("kdf", "argon2id", "key derivation function: argon2id, scrypt, or pbkdf2")
	argonTime := fs.Int("argon2-time", vault.DefaultArgon2Time, "Argon2id time cost")
	argonMemory := fs.Int("argon2-memory", vault.DefaultArgon2Memory, "Argon2id memory cost in KiB")
	argonParallelism := fs.Int("argon2-parallelism", vault.DefaultArgon2Threads, "Argon2id parallelism")
	scryptN := fs.Int("scrypt-n", vault.DefaultScryptN, "scrypt N parameter")
	scryptR := fs.Int("scrypt-r", vault.DefaultScryptR, "scrypt r parameter")
	scryptP := fs.Int("scrypt-p", vault.DefaultScryptP, "scrypt p parameter")
	pbkdf2Iter := fs.Int("pbkdf2-iterations", vault.DefaultKDFIterations, "PBKDF2 iterations for legacy mode")
	savePassword := fs.Bool("save-password", false, "store the vault password in the OS keychain after initialization")
	profileName := fs.String("profile", "", "optional local profile name for this vault path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault init [flags] VAULT_DIR")
	}
	vaultPath, err := userpath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := userpath.ValidateCreatableVaultPath(vaultPath); err != nil {
		return err
	}
	// Apply the same interrupted-setup leftovers classification `setup` enforces
	// (CLI 4): a target that is non-empty but holds no vault.json is leftovers from
	// an interrupted run, and `init` names the remove-and-retry remedy instead of
	// letting CreateWithOptions fail with a lower-level message. Only the leftovers
	// case is intercepted here; an EXISTING vault and an empty/absent directory
	// fall through to the create path exactly as before.
	if verr := (setup.Plan{VaultDir: vaultPath, Cloud: setup.LocalOnly{}}).Validate(); errors.Is(verr, setup.ErrVaultDirLeftovers) {
		// init takes a positional VAULT_DIR, not a --vault flag; name the real
		// argument so the remedy is actionable (polish-behaviour-2 / W3-3).
		return annotateInitLeftovers(verr)
	}
	params := vault.ChunkParams{MinSize: *min, AvgSize: *avg, MaxSize: *max}
	var kdfCfg vault.KDFConfig
	switch strings.ToLower(strings.TrimSpace(*kdf)) {
	case "", "argon2id", "argon2-id":
		kdfCfg = vault.KDFConfig{Algorithm: "ARGON2ID", Time: *argonTime, MemoryKiB: *argonMemory, Parallelism: *argonParallelism}
	case "scrypt":
		kdfCfg = vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: *scryptN, ScryptR: *scryptR, ScryptP: *scryptP}
	case "pbkdf2", "pbkdf2-hmac-sha256":
		kdfCfg = vault.KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: *pbkdf2Iter}
	default:
		return fmt.Errorf("unsupported KDF %q", *kdf)
	}
	// Enforce the KDF strength floors before prompting for a password:
	// normalise so a request that names only the algorithm gets the defaults,
	// then validate the normalised config. The check never lives inside
	// NormalizeKDFConfig (existing tests rely on it not rejecting weak configs).
	normalizedKDF, err := vault.NormalizeKDFConfig(kdfCfg, true)
	if err != nil {
		return err
	}
	if err := vault.ValidateKDFStrength(normalizedKDF); err != nil {
		return err
	}
	password, err := readPasswordPrompt("New vault password: ")
	if err != nil {
		return err
	}
	if err := vault.CreateWithOptions(vaultPath, password, vault.CreateOptions{Chunk: params, KDF: normalizedKDF}); err != nil {
		return err
	}
	if *profileName != "" {
		if _, err := profile.Add(*profileName, vaultPath); err != nil {
			return err
		}
	}
	if *savePassword {
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		if err := keychain.Set(cfg.VaultID, password); err != nil {
			return err
		}
	}
	metaName, _, err := vault.ResolveMetaDir(vaultPath)
	if err != nil {
		metaName = vault.MetadataDirName
	}
	fmt.Printf("initialized vault at %s\n", filepath.Join(vaultPath, metaName))
	if note := vault.SyncClientPreflightNote(vaultPath); note != "" {
		fmt.Println(note)
	}
	return nil
}

// openVaultForCLI resolves the vault password (SEAVAULT_PASSWORD, then the OS
// keychain, then a hidden prompt) and opens the vault, threading the
// freshness-rollback disposition: a password TYPED at
// the prompt is an INTERACTIVE unlock (a rollback warns and opens), while a
// password auto-supplied by SEAVAULT_PASSWORD or the keychain is NON-INTERACTIVE
// (a rollback hard-refuses with ErrConfigRolledBack unless --accept-rollback).
// It surfaces the preflight note, the rollback warning, and the
// anchor note to stderr, never stdout, so machine-readable output stays clean.
func openVaultForCLI(vaultPath string, useKeychain, acceptRollback bool) (*vault.Vault, error) {
	password, interactive, err := resolveVaultPasswordSource(vaultPath, useKeychain)
	if err != nil {
		return nil, err
	}
	v, err := vault.OpenWithOptions(vaultPath, password, vault.OpenOptions{AcceptRollback: acceptRollback})
	if err != nil {
		return nil, err
	}
	if note := v.PreflightNote(); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	if note := v.FreshnessAnchorNote(); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	// CLI-4: re-emit the recovery-deferral reminder when a keyless vault is opened
	// interactively (a human typed the password), so the one-shot setup note is
	// not the only surface. It is gated on the interactive unlock so a scripted
	// run (SEAVAULT_PASSWORD / keychain) is never nagged, and goes to stderr so it
	// never contaminates machine-readable stdout.
	if interactive {
		if reminder := recoveryDeferralReminder(v.WrapEntryRefs(), vaultPath); reminder != "" {
			fmt.Fprintln(os.Stderr, reminder)
		}
	}
	return v, nil
}

// vaultHasRecoveryKey reports whether any wrap entry is a recovery entry. A
// recovery key is ALWAYS stored as a recovery-type wrap entry, so the absence of
// one (including an empty wrap-entry array — a fresh vault keeps its password in
// the legacy wrap, not the array) means the vault has no recovery key.
func vaultHasRecoveryKey(refs []vault.WrapEntryRef) bool {
	for _, ref := range refs {
		if ref.Type == vault.WrapTypeRecovery {
			return true
		}
	}
	return false
}

// recoveryDeferralReminder returns the "no recovery key" reminder for a vault
// whose wrap entries carry no recovery entry (CLI-4), or "" when the vault has a
// recovery key. The remedy names the vault shell-quoted so it pastes cleanly. It
// carries no secret. vaultArg is the argument the user opened with (a path or
// profile); it is echoed only as a pasteable remedy target.
func recoveryDeferralReminder(refs []vault.WrapEntryRef, vaultArg string) string {
	if vaultHasRecoveryKey(refs) {
		return ""
	}
	return fmt.Sprintf("note: this vault has no recovery key. If you forget the password, the vault cannot be opened. Add one any time with `seavault recovery generate %s`.", shellQuoteArg(vaultArg))
}

// openVaultForWrite opens a vault for a WRITE-CAPABLE command (put, remove, gc,
// compact, serve) and fires the ConfigMAC ratchet (, build-order
// step 3): on the first such open of a legacy/untagged
// vault it opportunistically writes the ConfigTag, bumps FormatEpoch, and latches
// the device anchor's has-tag bit — ending the TOFU window that config
// forgery (VaultID / ChunkParams / KDF / wrap edits) exploits. EnsureConfigMAC is
// a no-op on an already-tagged vault, so repeated write opens ratchet exactly
// once, and it is NEVER called by a read-only command, so a bare
// `list`/`get`/`verify` never mutates the config. The ratchet is best-effort: a
// failed tag write surfaces a warning and does not block the primary operation
// (the anchor half is already best-effort inside EnsureConfigMAC).
func openVaultForWrite(vaultPath string, useKeychain, acceptRollback bool) (*vault.Vault, error) {
	v, err := openVaultForCLI(vaultPath, useKeychain, acceptRollback)
	if err != nil {
		return nil, err
	}
	if _, err := v.EnsureConfigMAC(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not write the vault.json integrity tag:", err)
	}
	return v, nil
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	method := fs.String("method", "auto", "put method: auto, native, managed-rsync, system-rsync, or rsync; auto prefers managed rsync, then system rsync, then native")
	rsyncBinary := fs.String("rsync", "", "system rsync binary path or name; ignored by managed-rsync")
	large := fs.Bool("large", false, "stream a large local file or folder through a bounded-memory import path")
	dryRun := fs.Bool("dry-run", false, "scan and report what a large import would process without writing to the vault")
	skipExisting := fs.Bool("skip-existing", true, "large import skips existing destination files with matching size")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 || fs.NArg() > 3 {
		return fmt.Errorf("usage: seavault put [--no-keychain] [--large] [--dry-run] [--method auto|native|managed-rsync|system-rsync|rsync] [--rsync PATH] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForWrite(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	virtual := ""
	if fs.NArg() == 3 {
		virtual = fs.Arg(2)
	}
	if *large || *dryRun {
		progress := importer.ImportPath(context.Background(), v, fs.Arg(1), importer.Options{VirtualPath: virtual, DryRun: *dryRun, Method: *method, RsyncBinary: *rsyncBinary, SkipExisting: *skipExisting}, nil)
		data, _ := json.MarshalIndent(progress, "", "  ")
		fmt.Println(string(data))
		if progress.Status == "failed" || progress.Status == "cancelled" {
			return fmt.Errorf(progress.LastError)
		}
		return nil
	}
	res, err := rsyncput.PutPath(context.Background(), v, fs.Arg(1), virtual, rsyncput.Options{Method: *method, RsyncBinary: *rsyncBinary})
	if err != nil {
		return err
	}
	fmt.Printf("put method: %s\n", res.Method)
	if res.Method == rsyncput.MethodRsync && res.RsyncBinary != "" {
		fmt.Printf("rsync binary: %s\n", res.RsyncBinary)
	}
	for _, r := range res.Results {
		fmt.Printf("put %-50s %10d bytes %4d chunks %4d new\n", r.Path, r.Size, r.ChunkCount, r.NewChunkCount)
	}
	// Surface the advisory lines (a source directory named like a open-seavault-rclone
	// metadata dir imported as plain content, never silently skipped). Dropping
	// these was.
	for _, warning := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	return nil
}
func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: seavault get [--no-keychain] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	if err := v.GetPath(fs.Arg(1), fs.Arg(2)); err != nil {
		return err
	}
	fmt.Printf("restored %s to %s\n", fs.Arg(1), fs.Arg(2))
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	overwrite := fs.String("overwrite", vault.OverwriteFail, "overwrite policy: fail, skip, or replace")
	zipOut := fs.Bool("zip", false, "export to a ZIP archive")
	dryRun := fs.Bool("dry-run", false, "count files and planned destinations without writing plaintext output")
	asJSON := fs.Bool("json", false, "print the ExportResult (including per-file original->written entries) as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] [--json] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	dest, err := userpath.Abs(fs.Arg(2))
	if err != nil {
		return err
	}
	res, err := v.ExportPath(context.Background(), fs.Arg(1), dest, vault.ExportOptions{Overwrite: *overwrite, Zip: *zipOut, DryRun: *dryRun})
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	if *dryRun {
		fmt.Printf("dry run: %d file(s), %d bytes, destination %s\n", res.Files, res.Bytes, res.DestPath)
	} else {
		fmt.Printf("exported %d file(s), skipped %d, %d bytes to %s\n", res.Exported, res.Skipped, res.Bytes, res.DestPath)
	}
	// Surface the (original -> written) mapping (C6). On a
	// real export only the sanitised/disambiguated entries are listed (silence when
	// every file kept its name); a dry run lists every planned destination and
	// flags the ones that will be renamed, so a scripting operator sees in advance
	// that a:b.txt will not land as a:b.txt.
	for _, line := range exportMappingLines(res, *dryRun) {
		fmt.Println(line)
	}
	return nil
}

// exportEntryRenamed reports whether an export entry's written leaf name differs
// from its original virtual leaf name, i.e. the segment was sanitised (an
// illegal character or reserved stem rewritten) or disambiguated (a collision
// suffix appended). ZIP entries all share the archive DestPath and are never
// flagged here.
func exportEntryRenamed(res vault.ExportResult, e vault.ExportEntry) bool {
	if res.Zip {
		return false
	}
	return path.Base(e.Path) != filepath.Base(e.DestPath)
}

// exportWrittenDisplay returns the written destination shown to the operator: for
// a filesystem export it is the path relative to the export destination root
// (slash-separated), so the mapping reads `content/a:b.txt -> a_b.txt`; a path
// that cannot be made relative falls back to the absolute DestPath.
func exportWrittenDisplay(res vault.ExportResult, e vault.ExportEntry) string {
	if res.Zip {
		return e.DestPath
	}
	rel, err := filepath.Rel(res.DestPath, e.DestPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return e.DestPath
	}
	return filepath.ToSlash(rel)
}

// exportMappingLines renders the (original -> written) mapping lines for the CLI
// (C6). In dry-run mode every planned entry is listed
// and the sanitised/disambiguated ones are flagged `(renamed)`; otherwise only
// the renamed entries are listed under a header, so a plain export whose files
// all kept their names prints nothing extra. Returns an empty slice when there
// is nothing to show.
func exportMappingLines(res vault.ExportResult, dryRun bool) []string {
	if dryRun {
		if len(res.Entries) == 0 {
			return nil
		}
		lines := make([]string, 0, len(res.Entries)+1)
		lines = append(lines, "planned destinations (original -> written):")
		for _, e := range res.Entries {
			line := fmt.Sprintf("  %s -> %s", e.Path, exportWrittenDisplay(res, e))
			if exportEntryRenamed(res, e) {
				line += " (renamed)"
			}
			lines = append(lines, line)
		}
		return lines
	}
	var renamed []string
	for _, e := range res.Entries {
		if exportEntryRenamed(res, e) {
			renamed = append(renamed, fmt.Sprintf("  %s -> %s", e.Path, exportWrittenDisplay(res, e)))
		}
	}
	if len(renamed) == 0 {
		return nil
	}
	return append([]string{"renamed on export (Windows-illegal or colliding names):"}, renamed...)
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault list [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	paths, err := v.List()
	if err != nil {
		return err
	}
	for _, p := range paths {
		fmt.Println(p)
	}
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: seavault remove [--no-keychain] VAULT_DIR_OR_PROFILE VIRTUAL_PATH")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForWrite(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	if err := v.Remove(fs.Arg(1)); err != nil {
		return err
	}
	fmt.Println("removed", fs.Arg(1))
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	fs.Usage = func() {
		writeSubcommandUsage(fs, "usage: seavault verify [--no-keychain] VAULT_DIR_OR_PROFILE", verifySynopsis())
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault verify [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	report, err := v.VerifyReport()
	if err != nil {
		return err
	}
	printVerifyReport(report)
	if !report.OK {
		return &vault.VerifyError{Report: report}
	}
	return nil
}

func printVerifyReport(report vault.VerifyReport) {
	status := "FAILED"
	if report.OK {
		status = "PASSED"
	}
	fmt.Printf("vault verification %s\n", status)
	fmt.Printf("files checked: %d\n", report.FilesChecked)
	fmt.Printf("chunks checked: %d\n", report.ChunksChecked)
	fmt.Printf("referenced bytes checked: %d\n", report.BytesChecked)
	if len(report.PendingIntents) > 0 {
		fmt.Printf("pending gc intents: %d (oldest age: %s)\n", len(report.PendingIntents), oldestIntentAge(report.PendingIntents))
	}
	if len(report.Issues) == 0 {
		return
	}
	fmt.Printf("issues: %d (missing chunks: %d, corrupt chunks: %d, other errors: %d)\n", len(report.Issues), report.MissingChunks, report.CorruptChunks, report.OtherErrors)
	for i, issue := range report.Issues {
		fmt.Printf("\nissue %d:\n", i+1)
		fmt.Printf("  kind: %s\n", issue.Kind)
		if issue.Path != "" {
			fmt.Printf("  file: %s\n", issue.Path)
		}
		if issue.ChunkID != "" {
			fmt.Printf("  chunk: %s\n", issue.ChunkID)
		}
		if issue.ChunkPath != "" {
			fmt.Printf("  chunk path: %s\n", issue.ChunkPath)
		}
		fmt.Printf("  error: %s\n", issue.Error)
	}
}

func cmdGC(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	confirm := fs.Bool("confirm", false, "reclaim space; without it gc is a dry run that writes nothing")
	fence := fs.Duration("fence", vault.GCFenceDefault, "minimum age before a queued chunk is removed (min 1h)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault gc [--no-keychain] [--confirm] [--fence 72h] [--json] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForWrite(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	// Notice when --fence is clamped up to the 1h minimum or falls back to the
	// default (C5), so an operator who passed --fence 30m is not
	// left believing it took effect. The notice goes to stderr; --json stdout is
	// unchanged.
	effectiveFence, fenceNotice := clampFence(*fence)
	if fenceNotice != "" {
		fmt.Fprintln(os.Stderr, fenceNotice)
	}
	// Default is a dry run: compute candidates and the compaction
	// plan, change nothing. --confirm runs the two-phase, fenced collection: it
	// compacts, writes deletion intents in phase 1, and removes only chunks whose
	// intent, first-seen record, and file mtime are all older than the fence.
	report, err := v.GarbageCollect(vault.GCOptions{Confirm: *confirm, Fence: effectiveFence})
	if err != nil {
		return err
	}
	if *asJSON {
		// --json output is unchanged: the machine-readable report is printed on
		// stdout and the command exits 0, so a JSON caller that inspects the
		// candidates itself is never surprised by the exit-3 advisory below.
		return printJSON(report)
	}
	printGCReport(report)
	// Friction: a bare `seavault gc` that would reclaim something but did not
	// (no --confirm) writes a one-line advisory to stderr and exits 3, so a legacy
	// cron/reclaim script no longer no-ops silently with exit 0.
	if msg, code := gcDryRunAdvisory(report); code != 0 {
		fmt.Fprintln(os.Stderr, msg)
		return &exitCodeError{code: code, msg: msg}
	}
	return nil
}

func printGCReport(r vault.GCReport) {
	if !r.Confirm {
		if r.Compact != nil {
			printCompactPlan(*r.Compact)
		}
		fmt.Printf("fence: %s\n", r.Fence)
		fmt.Printf("unreferenced chunks: %d (%d bytes)\n", len(r.Candidates), r.CandidateBytes)
		if len(r.Pending) > 0 {
			fmt.Printf("deletion intents pending: %d (oldest age: %s)\n", len(r.Pending), oldestIntentAge(r.Pending))
		}
		fmt.Println("dry run: nothing was changed. Re-run with --confirm to reclaim space.")
		return
	}
	if r.Compact != nil {
		printCompactReport(*r.Compact)
	}
	fmt.Printf("fence: %s\n", r.Fence)
	fmt.Printf("unreferenced chunks: %d (%d bytes)\n", len(r.Candidates), r.CandidateBytes)
	fmt.Printf("intents written: %d\n", len(r.IntentsWritten))
	fmt.Printf("intents cancelled (chunk referenced again): %d\n", len(r.Cancelled))
	fmt.Printf("intents reaped (chunk already gone): %d\n", len(r.Reaped))
	fmt.Printf("chunks removed: %d (%d bytes)\n", len(r.RemovedChunks), r.RemovedBytes)
	fmt.Printf("intents pending after this run: %d\n", len(r.Pending))
}

func printCompactPlan(r vault.CompactReport) {
	fmt.Printf("conflict copies to materialise: %d\n", len(r.Conflicts))
	for _, c := range r.Conflicts {
		fmt.Printf("  %s\n", c)
	}
	fmt.Printf("redundant/superseded manifests to remove: %d\n", r.RemovedManifests)
	fmt.Printf("temp-file orphans to sweep: %d\n", len(r.TmpOrphans))
	for _, o := range r.TmpOrphans {
		fmt.Printf("  %s\n", o)
	}
}

// gcReportActionable reports whether a dry-run gc report found anything a
// --confirm run would act on: unreferenced chunk candidates, deletion intents
// already pending, or a non-empty compaction plan (conflict copies to
// materialise, superseded manifests to remove, or temp-file orphans to sweep).
// It is the trigger for the advisory.
func gcReportActionable(r vault.GCReport) bool {
	if len(r.Candidates) > 0 || len(r.Pending) > 0 {
		return true
	}
	if r.Compact != nil {
		c := r.Compact
		if len(c.Conflicts) > 0 || c.RemovedManifests > 0 || len(c.TmpOrphans) > 0 {
			return true
		}
	}
	return false
}

// gcDryRunAdvisory returns the one-line stderr advisory and the process exit
// code for a completed gc report. When
// --confirm was absent and the dry run found something actionable, it returns
// the advisory naming the unreferenced-chunk count and bytes plus exit code 3
// ("action required"), so a scripted caller that ran a bare `seavault gc` sees —
// both on stderr and in the exit status — that nothing was reclaimed and
// --confirm is required. A dry run with nothing to do, and every --confirm run,
// return ("", 0): the silent exit-0 success that existing automation expects.
func gcDryRunAdvisory(r vault.GCReport) (string, int) {
	if r.Confirm || !gcReportActionable(r) {
		return "", 0
	}
	return fmt.Sprintf("gc: dry run — %d chunk(s) (%d bytes) would be queued for deletion; pass --confirm to reclaim (scripted callers must add --confirm)", len(r.Candidates), r.CandidateBytes), 3
}

// clampFence mirrors vault.GarbageCollect's fence clamping (GCFenceMin 1h,
// GCFenceDefault 72h) and returns the effective fence alongside a one-line
// stderr notice when the requested value had to be changed, so an operator who
// passed --fence 30m is not left believing they set a 30-minute fence (friction
// ). A value at or above the 1h minimum is used unchanged (no notice); a
// positive value below it is raised to 1h; a zero or negative value selects the
// 72h default. The notice is empty exactly when the requested value is used as-is.
func clampFence(requested time.Duration) (time.Duration, string) {
	if requested <= 0 {
		return vault.GCFenceDefault, fmt.Sprintf("requested fence %s selects the default; using %s", requested, vault.GCFenceDefault)
	}
	if requested < vault.GCFenceMin {
		return vault.GCFenceMin, fmt.Sprintf("requested fence %s is below the %s minimum; using %s", requested, vault.GCFenceMin, vault.GCFenceMin)
	}
	return requested, ""
}

// oldestIntentAge is a human summary of the oldest pending deletion intent for
// the verify and gc reports.
func oldestIntentAge(pending []vault.PendingIntent) string {
	oldest := int64(-1)
	for _, p := range pending {
		if p.AgeSeconds > oldest {
			oldest = p.AgeSeconds
		}
	}
	if oldest < 0 {
		return "unknown"
	}
	return (time.Duration(oldest) * time.Second).String()
}

// compactSynopsis is the one-line description shown by `compact --help` (friction
// ): a cold operator scanning the flags learns what compact does and, in
// particular, that it never removes chunk objects (that is gc's job).
func compactSynopsis() string {
	return "compact reclaims metadata only: it materialises deferred sync-conflict copies, removes superseded/redundant manifests, and sweeps stale .tmp-* orphans. It never removes chunk objects — use `seavault gc --confirm` to reclaim chunk space."
}

// verifySynopsis is the one-line description shown by `verify --help` (friction
// ).
func verifySynopsis() string {
	return "verify checks that every referenced chunk is present and decrypts, and lists any garbage-collection deletion intents still pending (a delete in flight)."
}

// writeSubcommandUsage renders a subcommand's --help block: the usage line, a
// one-line synopsis, then the flag defaults. Shared by the command's fs.Usage
// and by tests, so the wiring is exercised (C5).
func writeSubcommandUsage(fs *flag.FlagSet, usageLine, synopsis string) {
	out := fs.Output()
	fmt.Fprintf(out, "%s\n\n%s\n\n", usageLine, synopsis)
	fs.PrintDefaults()
}

func cmdCompact(args []string) error {
	fs := flag.NewFlagSet("compact", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	fs.Usage = func() {
		writeSubcommandUsage(fs, "usage: seavault compact [--no-keychain] VAULT_DIR_OR_PROFILE", compactSynopsis())
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault compact [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForWrite(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	report, err := v.Compact()
	printCompactReport(report)
	return err
}

func printCompactReport(r vault.CompactReport) {
	fmt.Printf("conflict copies materialised: %d\n", len(r.Conflicts))
	for _, c := range r.Conflicts {
		fmt.Printf("  %s\n", c)
	}
	fmt.Printf("manifests removed: %d\n", r.RemovedManifests)
	fmt.Printf("temp-file orphans swept: %d\n", len(r.TmpOrphans))
	for _, o := range r.TmpOrphans {
		fmt.Printf("  %s\n", o)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(os.Stderr, "  error: %s\n", e)
	}
}

func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault stats [--no-keychain] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	s, err := v.Stats()
	if err != nil {
		return err
	}
	fmt.Printf("files: %d\nreferenced chunks: %d\nstored chunk objects: %d\nreferenced MiB: %.2f\n", s.Files, s.Referenced, s.Objects, s.ReferencedMB)
	return nil
}

// hostOf returns the trimmed host portion of a listen address, tolerating an
// address that carries no port (net.SplitHostPort fails, so addr is the host).
func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return strings.TrimSpace(host)
}

// isLoopbackOrLocalhost reports whether host names this machine's loopback
// interface: the literal "localhost" (case-insensitive) or any IP that
// net.ParseIP considers loopback (127.0.0.0/8, ::1). An empty host is NOT
// loopback — it binds every interface.
func isLoopbackOrLocalhost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// selfSignedTrustWarning is the warning surfaced when a non-loopback bind is
// admitted on the strength of a self-signed certificate: clients cannot verify
// it, and Windows' WebDAV client refuses it outright.
const selfSignedTrustWarning = "clients will show a trust prompt; Windows WebDAV will refuse this certificate"

// everyInterfaceWarning is surfaced when the bind host is empty, so the operator
// knows the listener is reachable on every interface, not just one.
const everyInterfaceWarning = "listening on every interface"

// isEveryInterface reports whether host binds every interface: an empty host, or
// an unspecified address (0.0.0.0, ::, [::]). The advisory must fire for the
// explicit wildcard forms too, not only the empty host (guard-warning-allzero-1).
func isEveryInterface(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return true
	}
	return false
}

// ensureLoopbackBind decides whether the GUI / WebDAV listener (which serves
// DECRYPTED vault content) may bind addr, and returns any advisory warnings for
// an admitted non-loopback bind. Loopback and "localhost" are always fine. A
// non-loopback or every-interface host is admitted when tlsOn (the wire is
// encrypted) — with the self-signed trust warning when selfSigned, and the
// every-interface warning when the host binds all interfaces (empty, 0.0.0.0,
// ::, [::]). Without TLS it is refused exactly as before unless insecureBind
// overrides. Plaintext therefore never reaches a non-loopback address without
// the explicit override (I-T1); the guard relaxes only for a TLS listener.
//
// certConfigured says a certificate is already configured but the operator did
// not pass --tls (A3-c4 / polish-behaviour-1): the one-flag fix is to add --tls,
// so the plaintext refusal leads with that before the generic "set up TLS first"
// route — otherwise a user who just ran `seavault tls setup` is told to do it
// again and is never told the flag that would work.
func ensureLoopbackBind(addr string, insecureBind, tlsOn, selfSigned, certConfigured bool) ([]string, error) {
	host := hostOf(addr)
	if isLoopbackOrLocalhost(host) {
		return nil, nil
	}
	if tlsOn {
		var warnings []string
		if selfSigned {
			warnings = append(warnings, selfSignedTrustWarning)
		}
		if isEveryInterface(host) {
			warnings = append(warnings, everyInterfaceWarning)
		}
		return warnings, nil
	}
	if insecureBind {
		return nil, nil
	}
	// A certificate is configured but --tls was omitted: lead with the one-flag
	// remedy before the generic route (A3-c4 / polish-behaviour-1).
	if certConfigured {
		return nil, fmt.Errorf("refusing to bind %q: a certificate is already configured — pass --tls to serve over the configured certificate. Otherwise set up TLS first: run `seavault tls setup` (or pass --tls-cert/--tls-key). As a last resort, pass --insecure-bind to serve plaintext on this address (not recommended)", addr)
	}
	if isEveryInterface(host) {
		return nil, fmt.Errorf("refusing to bind %q: an unspecified host listens on every interface and would expose DECRYPTED content. To reach other devices, set up TLS first: run `seavault tls setup` (or pass --tls-cert/--tls-key), then bind a specific address. As a last resort, pass --insecure-bind to serve plaintext (not recommended)", addr)
	}
	return nil, fmt.Errorf("refusing to bind %q: %q is not a loopback address, and this endpoint serves DECRYPTED content. To reach other devices, set up TLS first: run `seavault tls setup` (or pass --tls-cert/--tls-key). As a last resort, pass --insecure-bind to serve plaintext on this address (not recommended)", addr, host)
}

// certConfiguredFor reports whether an actual certificate pair is configured that
// `--tls` would serve over (the shared tls.* section or the legacy gui.* pair),
// independent of whether TLS was activated for this run. It never triggers the
// self-signed floor's generation (configuredPair is side-effect-free), and the
// self-signed floor is deliberately NOT counted: serve has no self-signed floor
// (resolveServeTLS), so there is no configured cert for --tls to serve there.
func certConfiguredFor(cfg appconfig.Config) bool {
	_, _, source := configuredPair(cfg)
	return source == tlsconfig.SourceConfig || source == tlsconfig.SourceLegacyGUI
}

// repeatableString collects a repeatable string flag (e.g. --allow-host NAME).
type repeatableString []string

func (r *repeatableString) String() string { return strings.Join(*r, ",") }

func (r *repeatableString) Set(v string) error {
	*r = append(*r, v)
	return nil
}

// generateServePassword returns 24 random bytes as base64url without padding
// (32 characters). See.
func generateServePassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// resolveServeCredentials resolves the WebDAV Basic-auth credentials for
// `seavault serve`. Password source precedence, first wins:
// passwordFile (content, trailing newline trimmed, must be non-empty) >
// envPassword (SEAVAULT_SERVE_PASSWORD) > a freshly generated 24-byte base64url
// password (32 chars). printIt reports whether the resolved password should be
// echoed to stdout: a generated password is always printed, and
// --quiet-credentials (an error unless a password source is present) suppresses
// the echo. The returned user is the flag value with the "seavault" default
// applied when blank.
func resolveServeCredentials(user, passwordFile, envPassword string, quiet bool) (string, string, bool, error) {
	if strings.TrimSpace(user) == "" {
		user = "seavault"
	}
	hasSource := strings.TrimSpace(passwordFile) != "" || envPassword != ""
	if quiet && !hasSource {
		return "", "", false, fmt.Errorf("--quiet-credentials requires --password-file or SEAVAULT_SERVE_PASSWORD; refusing to start a server whose generated password nobody can read")
	}
	var password string
	switch {
	case strings.TrimSpace(passwordFile) != "":
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", "", false, err
		}
		password = strings.TrimRight(string(data), "\r\n")
		if password == "" {
			return "", "", false, fmt.Errorf("password file %q is empty", passwordFile)
		}
	case envPassword != "":
		password = envPassword
	default:
		p, err := generateServePassword()
		if err != nil {
			return "", "", false, err
		}
		password = p
	}
	return user, password, !quiet, nil
}

// allowedHostsForBind computes the localdav/webui AllowedHosts for a bind
// address: the bind host is added only when it is a real non-loopback,
// non-unspecified name or IP (loopback and localhost are always accepted, and an
// unspecified address is never added), followed by the explicit --allow-host
// values, followed by the exact names listed in the shared tls.allowHosts
// config (I-T6): a certificate SAN the wizard recorded is admitted by the
// rebinding guard without a second --allow-host flag. Matching stays exact — no
// wildcard expansion — so the DNS-rebinding guard is not weakened. See.
func allowedHostsForBind(addr string, extra, tlsAllowHosts []string) []string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	var hosts []string
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				hosts = append(hosts, host)
			}
		} else if !strings.EqualFold(host, "localhost") {
			hosts = append(hosts, host)
		}
	}
	hosts = append(hosts, extra...)
	hosts = append(hosts, tlsAllowHosts...)
	return hosts
}

// firstConfirmedName returns the name a cross-device launch link should use for
// a non-loopback TLS bind: the first confirmed name (a --allow-host value or a
// tls.allowHosts entry the operator merged in), or, failing that, the
// certificate's first DNS SAN. A wildcard entry is skipped in BOTH lists so the
// first CONCRETE name wins — https://*.example.com is not a URL a person can open
// (launch-allowlist-1, C1) — and an IP SAN is skipped because a launch link wants
// a name. It returns "" when no concrete name is available, so launchAddrForBind
// falls back to the bind address.
func firstConfirmedName(allowHosts, certNames []string) string {
	for _, h := range allowHosts {
		h = strings.TrimSpace(h)
		if h == "" || strings.Contains(h, "*") {
			continue // a wildcard is not an openable launch-link name
		}
		return h
	}
	for _, n := range certNames {
		n = strings.TrimSpace(n)
		if n == "" || strings.Contains(n, "*") {
			continue // a wildcard SAN is not an openable launch-link name
		}
		if net.ParseIP(n) != nil {
			continue // an IP SAN is not a launch-link name
		}
		return n
	}
	return ""
}

// launchAddrForBind returns the host:port the printed launch link and login
// hint should carry (C1). A loopback bind keeps its own address (127.0.0.1). A
// non-loopback TLS bind swaps the bind host for the first confirmed CONCRETE name
// (a --allow-host / tls.allowHosts entry, or the certificate's first DNS SAN),
// skipping wildcards, so the URL a person opens from another device is a name the
// certificate is valid for; when no such name is available it falls back to the
// bind address (never a wildcard, launch-allowlist-1).
func launchAddrForBind(addr string, tlsOn bool, allowHosts, certNames []string) string {
	host := hostOf(addr)
	if !tlsOn || isLoopbackOrLocalhost(host) {
		return addr
	}
	name := firstConfirmedName(allowHosts, certNames)
	if name == "" {
		return addr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return name
	}
	return net.JoinHostPort(name, port)
}

// serveOn serves srv.Handler on ln, wrapping ln in a TLS listener built from the
// resolved certificate holder when a TLS source is present, and otherwise
// serving plaintext. It is the single serve-decision seam shared by gui and
// serve: when resolved carries a TLS config there is no code path that yields a
// plaintext listener (C2, C10), so a resolved TLS source can never fall through
// to plaintext on the wire (I-T1). srv.Serve returns http.ErrServerClosed on a
// graceful Shutdown, exactly as ListenAndServe/ListenAndServeTLS would.
func serveOn(ln net.Listener, srv *http.Server, resolved *tlsconfig.Resolved) error {
	if resolved != nil && resolved.TLS != nil {
		srv.TLSConfig = resolved.TLS
		return srv.Serve(tls.NewListener(ln, resolved.TLS))
	}
	return srv.Serve(ln)
}

// resolveServeTLS resolves the TLS state for `seavault serve`. Unlike gui, serve
// has no self-signed floor and never auto-enables TLS from config: TLS is on
// ONLY when the operator passes --tls-cert/--tls-key or --tls. When --tls is
// passed but nothing is configured (an empty tls section) it returns a typed
// error naming the remedy rather than silently serving plaintext. When no TLS
// flag is given it returns (nil, nil): plaintext loopback exactly as today.
func resolveServeTLS(certFlag, keyFlag string, useTLS bool, cfg appconfig.Config, bindHost string) (*tlsconfig.Resolved, error) {
	if strings.TrimSpace(certFlag) == "" && strings.TrimSpace(keyFlag) == "" && !useTLS {
		return nil, nil
	}
	resolved, err := tlsconfig.Resolve(tlsconfig.Options{
		CertFlag: certFlag,
		KeyFlag:  keyFlag,
		Cfg:      cfg,
		Purpose:  tlsconfig.PurposeServe,
		BindHost: bindHost,
	})
	if err != nil {
		return nil, err
	}
	if resolved.Source == tlsconfig.SourceNone {
		return nil, fmt.Errorf("--tls was requested but no certificate is configured: set tls.certFile/tls.keyFile (run `seavault tls setup`) or pass --tls-cert and --tls-key")
	}
	return resolved, nil
}

// logTLSStartup prints the resolved certificate's source, names, and expiry at
// listener startup, and warns when a certificate name is absent from the Host
// allowlist (I-T6) so a name that will 403 at the rebinding guard is visible
// before a client hits it. It never prints key material. resolved==none prints
// nothing (plaintext listener).
func logTLSStartup(out io.Writer, purpose string, resolved *tlsconfig.Resolved, allowedHosts []string) {
	if resolved == nil || resolved.Source == tlsconfig.SourceNone {
		return
	}
	names := "(none)"
	if len(resolved.Names) > 0 {
		names = strings.Join(resolved.Names, ", ")
	}
	fmt.Fprintf(out, "%s TLS: source=%s names=%s expires=%s\n",
		purpose, resolved.Source, names, resolved.NotAfter.UTC().Format(time.RFC3339))
	if resolved.SelfSigned {
		fmt.Fprintf(out, "%s TLS: %s\n", purpose, selfSignedTrustWarning)
	}
	for _, w := range resolved.Warnings {
		fmt.Fprintf(out, "%s TLS: %s\n", purpose, w)
	}
	for _, n := range resolved.Names {
		if net.ParseIP(strings.TrimSpace(n)) != nil {
			continue // an IP SAN is checked by the guard's loopback/allow rules
		}
		if hostInAllowlist(n, allowedHosts) {
			continue
		}
		if strings.Contains(n, "*") {
			// A wildcard SAN can never itself be an allowlist entry: the exact-match
			// rebinding guard drops wildcards (C5), so telling the operator to "add
			// it with --allow-host" would be a dead end (launch-allowlist-1). Point
			// them at the concrete names the wildcard covers instead.
			fmt.Fprintf(out, "%s TLS: warning: certificate name %q is a wildcard; the Host allowlist matches exact names only — add each concrete name a device will use (e.g. host%s) with --allow-host or tls.allowHosts\n", purpose, n, strings.TrimPrefix(strings.TrimSpace(n), "*"))
			continue
		}
		fmt.Fprintf(out, "%s TLS: warning: certificate name %q is not in the Host allowlist; requests with that Host will be refused — add it with --allow-host or tls.allowHosts\n", purpose, n)
	}
}

// hostInAllowlist reports whether name matches an allowlist entry exactly
// (case-insensitive). No wildcard expansion: the exact-match rebinding guard is
// authoritative (C5, I-T6).
func hostInAllowlist(name string, allowedHosts []string) bool {
	for _, h := range allowedHosts {
		if strings.EqualFold(strings.TrimSpace(h), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// buildLoopbackServer constructs the http.Server used by `serve` and `gui` with
// the Phase 0 header/idle timeouts: ReadHeaderTimeout bounds
// slowloris header dribbles and IdleTimeout bounds idle keep-alive connections.
// It sets no ReadTimeout (large uploads) and no WriteTimeout (large downloads and
// the GUI's SSE browser-session stream).
func buildLoopbackServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// listenErrorHint wraps a ListenAndServe/ListenAndServeTLS failure with a legible
// hint (, C5): now that `seavault gui` no longer kills other
// seavault processes, a second GUI or serve on the same address fails to bind,
// and the operator needs to know the port is already taken rather than see a raw
// "bind: address already in use". A nil error passes through as nil; the original
// error is wrapped so errors.Is/http.ErrServerClosed checks still work upstream.
func listenErrorHint(addr string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("could not listen on %s: %w. If another open-seavault-rclone GUI or serve is already running, open its link instead, or choose a different --addr", addr, err)
}

// printLaunchGuidance opens launchURL in the browser when openInBrowser is set
// and always prints the fallback line to out (C1, C1). When the
// injected open function reports an error it is surfaced to errOut instead of
// being discarded, so a headless / no-default-browser machine no longer strands
// the owner on an apparently-hung command. open is injected for testability.
func printLaunchGuidance(out, errOut io.Writer, launchURL string, openInBrowser bool, open func(string) error) {
	if openInBrowser {
		if err := open(launchURL); err != nil {
			fmt.Fprintf(errOut, "Could not open your browser automatically (%v). Copy the link above into your browser.\n", err)
		}
	}
	fmt.Fprintln(out, "If your browser did not open, copy the link above into your browser.")
}

// stdoutLooksRedirected reports whether stdout (described by fi) is NOT a
// character device, i.e. a file, pipe, or socket rather than a terminal. Serve
// uses it to warn that a freshly generated WebDAV credential is being written to
// a log/redirect (C5). Pure and portable: os.ModeCharDevice is
// defined on every OS.
func stdoutLooksRedirected(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeCharDevice == 0
}

// keychainUnavailableNote returns the one-line stderr note printed when the OS
// keychain was tried and returned an error before falling back (
// C4). A nil error yields the empty string (nothing to print). Only the first
// line of the error is used to keep the note to a single line.
func keychainUnavailableNote(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return fmt.Sprintf("OS keychain unavailable (%s); falling back to SEAVAULT_PASSWORD or the hidden prompt", msg)
}

// tlsReloadInterval overrides the hot-reloader poll interval for gui/serve. Zero
// (production) falls back to tlsconfig.DefaultPollInterval; the integration tests
// inject a short interval to drive a renewal swap deterministically. It is a test
// seam only.
var tlsReloadInterval time.Duration

// serveTestHook / guiTestHook, when non-nil, are invoked by cmdServe / cmdGUI
// with the live http.Server and its bound address just after the listener comes
// up, so an integration test can dial the real TLS listener and later Shutdown
// it (which lets the command return and cancels the reloader). Production nil.
var (
	serveTestHook func(srv *http.Server, addr string)
	guiTestHook   func(srv *http.Server, addr string)
)

// startTLSReloader constructs and runs the hot-reloader for a resolved TLS
// source so a renewed on-disk pair is served within the poll and serving.json is
// maintained at runtime (design §2/C11, I-T3). It is a no-op when resolved is nil
// or its source is none (nothing to reload). The reloader stops when ctx is
// cancelled (on server shutdown). Its log lines carry only path/name/time
// diagnostics — never key material — and are prefixed with the purpose.
//
// It returns a wait func the caller defers AFTER cancelling ctx: wait blocks
// until the reloader goroutine has fully returned, so the goroutine — and its
// serving.json write, which Run performs unconditionally at startup — is drained
// before the command returns. Without this join the startup write can land after
// the command returns and race a caller's teardown (e.g. a test's TempDir
// RemoveAll); no goroutine or file write outlives the listener it maintains.
func startTLSReloader(ctx context.Context, resolved *tlsconfig.Resolved, purpose string) (wait func()) {
	if resolved == nil || resolved.Source == tlsconfig.SourceNone {
		return func() {}
	}
	rl := resolved.Reloader(tlsconfig.ReloaderOptions{
		Interval: tlsReloadInterval,
		Logf: func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, purpose+" TLS: "+format+"\n", a...)
		},
	})
	if rl == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rl.Run(ctx)
	}()
	return func() { <-done }
}

// authLimitClock is the injected clock the limiter (lock/window expiry) and the
// disabled-since stamp / hourly re-warning read. Production is time.Now; the U4
// integration tests replace it with a controllable clock to drive lock expiry
// and the re-warning deterministically. It is a test seam only.
var authLimitClock = func() time.Time { return time.Now() }

// authLimitWarnEvery is how often the loud OFF warning re-emits while a disabled
// server runs (C7); authLimitWarnTick is how often the re-warn goroutine wakes to
// compare the injected clock. Tests shrink both to observe a re-emission quickly.
var (
	authLimitWarnEvery = time.Hour
	authLimitWarnTick  = time.Minute
)

// authLimitLogf receives the auth-limit operator messages: the per-lock line
// (C6), the startup OFF warning and its hourly re-emission (C7), and the
// non-loopback startup exposure line (§2.3). Production writes to stderr so an
// operator sees them; the integration tests capture the sink to assert content
// and prove no credential leaks (I-R2 / S1). It is a test seam.
var authLimitLogf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// resolveAuthLimitEnabled applies the --auth-limit flag over the persisted
// config: "" (absent) uses the config default (on unless auth.limits.enabled is
// false), "on"/"off" override it. An unrecognised value is an error.
func resolveAuthLimitEnabled(flagVal string, cfg appconfig.Config) (enabled, fromFlag bool, err error) {
	switch strings.ToLower(strings.TrimSpace(flagVal)) {
	case "":
		return cfg.Auth.Limits.IsEnabled(), false, nil
	case "on":
		return true, true, nil
	case "off":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("--auth-limit must be \"on\" or \"off\", got %q", flagVal)
	}
}

// parseAuthDur parses a normalized auth-limit duration string; an unparsable
// value yields 0, which authlimit.New re-normalizes to the default.
func parseAuthDur(s string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return d
}

// authLimitOffWarning composes the loud startup warning for a disabled limiter,
// always naming the flag (I-R4) and, for a persisted (config-file) disable,
// naming the date so a headless server left off after an incident says so (C7).
// It carries no credential.
func authLimitOffWarning(limits appconfig.AuthLimits, fromFlag, persisted bool) string {
	const base = "WARNING: authentication rate limiting is OFF — the GUI login and WebDAV auth are unthrottled and will not lock after repeated failed attempts."
	switch {
	case persisted && strings.TrimSpace(limits.DisabledSince) != "":
		return base + fmt.Sprintf(" Disabled since %s by auth.limits.enabled=false. Re-enable with --auth-limit on or set auth.limits.enabled=true.", limits.DisabledSince)
	case fromFlag:
		return base + " Disabled by --auth-limit off for this run. Re-enable by dropping --auth-limit off (or pass --auth-limit on)."
	default:
		return base + " Re-enable with --auth-limit on or set auth.limits.enabled=true."
	}
}

// startAuthLimit resolves the effective auth-limit state for a gui/serve run
// (design-u4 §2.2/§2.3, C7). When enabled it builds the limiter over the injected
// clock and returns it with the "on" status line. When disabled it returns a nil
// limiter (the surfaces skip all limiting, I-R4), emits the loud startup warning
// through authLimitLogf, records a disabled-since timestamp for a PERSISTED
// disable (updating *cfg and saving it, so `tls status`/settings can date the OFF
// state and re-enabling clears it), and starts a goroutine that re-emits the
// warning every authLimitWarnEvery on the injected clock. The returned stop func
// (always non-nil) halts that goroutine when the command returns.
func startAuthLimit(cfg *appconfig.Config, flagVal, purpose string) (lim *authlimit.Limiter, statusLine string, stop func(), err error) {
	stop = func() {}
	enabled, fromFlag, err := resolveAuthLimitEnabled(flagVal, *cfg)
	if err != nil {
		return nil, "", stop, err
	}
	limits := cfg.Auth.Limits
	if enabled {
		policy := authlimit.Policy{
			FailuresBeforeLock:        limits.FailuresBeforeLock,
			AccountFailuresBeforeLock: limits.AccountFailuresBeforeLock,
			Window:                    parseAuthDur(limits.Window),
			LockStart:                 parseAuthDur(limits.LockStart),
			LockMax:                   parseAuthDur(limits.LockMax),
			FailureDelay:              parseAuthDur(limits.FailureDelay),
			MaxKeys:                   limits.MaxKeys,
		}
		// Render the status line from the EFFECTIVE (on) state, never the raw
		// persisted config: when --auth-limit on overrides a persisted
		// enabled=false + disabledSince, the limiter IS running, so every readout
		// (the startup exposure line, /api/status, `tls status`, the settings page)
		// must read "auth limits: on (…)", not the stale "OFF since <date>"
		// (leakage-copy-1 / friction W3-5). And PERSIST the re-enable — set
		// enabled=true, clear disabledSince, and save — so a later FLAGLESS restart
		// (a systemd unit that just runs `seavault serve`) comes back protected, as
		// the docs promise `--auth-limit on` does (C7 / friction W2-3/W4-2). Persist
		// only when the persisted config actually disabled it, so a normal
		// on-by-default start writes nothing.
		effective := limits
		on := true
		effective.Enabled = &on
		effective.DisabledSince = ""
		if !cfg.Auth.Limits.IsEnabled() || strings.TrimSpace(cfg.Auth.Limits.DisabledSince) != "" {
			cfg.Auth.Limits.Enabled = &on
			cfg.Auth.Limits.DisabledSince = ""
			if saveErr := appconfig.Save(*cfg); saveErr != nil {
				authLimitLogf("auth-limit: could not persist the re-enabled state: %v", saveErr)
			}
		}
		return authlimit.New(policy, authLimitClock), effective.StatusLine(), stop, nil
	}

	// Disabled: build the effective (possibly dated) view for the status line.
	persisted := !cfg.Auth.Limits.IsEnabled() // the persisted config itself disables it
	effective := limits
	disabled := false
	effective.Enabled = &disabled
	if persisted {
		if strings.TrimSpace(effective.DisabledSince) == "" {
			stamp := authLimitClock().UTC().Format(time.RFC3339)
			effective.DisabledSince = stamp
			cfg.Auth.Limits.Enabled = &disabled
			cfg.Auth.Limits.DisabledSince = stamp
			if saveErr := appconfig.Save(*cfg); saveErr != nil {
				authLimitLogf("auth-limit: could not persist the disabled-since timestamp: %v", saveErr)
			}
		}
	} else {
		effective.DisabledSince = "" // a flag-only disable is not dated
	}
	statusLine = effective.StatusLine()

	warn := authLimitOffWarning(effective, fromFlag, persisted)
	authLimitLogf("%s", warn)

	stopCh := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(stopCh) }) }
	// Snapshot the seams (clock, sink, cadence) HERE — synchronously in the
	// command goroutine — and hand them to the re-warn goroutine, so the goroutine
	// never reads the mutable package-level seams a test rewrites at cleanup (they
	// are func/duration values; the captured clock closure still observes a test's
	// later time advances).
	go authLimitReWarn(warn, stopCh, authLimitClock, authLimitLogf, authLimitWarnEvery, authLimitWarnTick)
	return nil, statusLine, stop, nil
}

// authLimitReWarn re-emits the OFF warning every `every` of injected-clock time
// while a disabled server runs (C7), waking every `tick` to compare against
// `clock`. It returns when stop is closed (the command exiting). All time seams
// are passed in (not read from the globals) so the goroutine races with nothing.
func authLimitReWarn(warn string, stop <-chan struct{}, clock func() time.Time, logf func(string, ...any), every, tick time.Duration) {
	if tick <= 0 {
		tick = time.Minute
	}
	last := clock()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			now := clock()
			if now.Sub(last) >= every {
				logf("%s", warn)
				last = now
			}
		}
	}
}

// maybePrintExposureLine prints the one-line non-loopback exposure advisory
// (§2.3, friction A3-c5) for a bind reachable beyond this machine, naming the
// current auth-limit state so the operator sees the residual and the live
// protection at a glance. A loopback/localhost bind prints nothing.
func maybePrintExposureLine(addr, statusLine string) {
	if isLoopbackOrLocalhost(hostOf(addr)) {
		return
	}
	authLimitLogf("serving DECRYPTED content beyond this machine; prefer a VPN/Tailscale over an open LAN; %s", statusLine)
}

// defaultServeUser is the WebDAV Basic-auth username `serve` uses when --user is
// blank. It is public knowledge, so on a network-exposed bind it removes the
// "attacker must know a username" precondition on the per-account lockout lever
// (lockout-dos-2): anyone can drive the {basic,"",seavault} account ceiling.
const defaultServeUser = "seavault"

// maybeWarnDefaultServeUser warns, at startup, when `serve` binds a non-loopback
// address with the DEFAULT WebDAV username (lockout-dos-2, code half). Naming a
// non-default username with --user removes the precondition an attacker needs to
// aim the per-account ceiling at the owner's account from rotating sources. It is
// silent on a loopback bind (the account lever is not reachable off-box) and when
// the operator already chose a non-default --user. It names no credential.
func maybeWarnDefaultServeUser(addr, user string) {
	if isLoopbackOrLocalhost(hostOf(addr)) {
		return
	}
	if user != defaultServeUser {
		return
	}
	authLimitLogf("WARNING: serving beyond this machine with the DEFAULT WebDAV username %q; an attacker who assumes that public default can drive the per-account lockout against you from rotating sources — restart with --user NAME using a non-default username to remove that precondition", defaultServeUser)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8765", "local address for the WebDAV-compatible endpoint")
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	insecureBind := fs.Bool("insecure-bind", false, "allow binding to a non-loopback address (exposes decrypted content; not recommended)")
	user := fs.String("user", "seavault", "WebDAV Basic-auth username")
	passwordFile := fs.String("password-file", "", "read the WebDAV Basic-auth password from this file (trailing newline trimmed, must be non-empty)")
	quietCredentials := fs.Bool("quiet-credentials", false, "do not print the WebDAV password; requires --password-file or SEAVAULT_SERVE_PASSWORD")
	dropOSJunk := fs.Bool("drop-os-junk", false, "silently discard OS junk files (.DS_Store, Thumbs.db, ...) instead of storing them")
	tlsCert := fs.String("tls-cert", "", "serve WebDAV over HTTPS using this PEM certificate chain (leaf first); requires --tls-key")
	tlsKey := fs.String("tls-key", "", "the PEM private key matching --tls-cert")
	tlsUse := fs.Bool("tls", false, "serve WebDAV over HTTPS using the configured tls.certFile/tls.keyFile section")
	authLimit := fs.String("auth-limit", "", "rate-limit WebDAV Basic auth: on (default) or off (off is loud and unprotected; also settable via auth.limits.enabled)")
	var allowHost repeatableString
	fs.Var(&allowHost, "allow-host", "additional Host header value to accept besides loopback/localhost (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault serve [--addr 127.0.0.1:8765] [--user seavault] [--password-file PATH] [--quiet-credentials] [--allow-host NAME] [--tls-cert PATH --tls-key PATH | --tls] [--auth-limit on|off] [--drop-os-junk] [--no-keychain] [--insecure-bind] VAULT_DIR_OR_PROFILE")
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	authLimiter, authStatusLine, stopAuthLimit, err := startAuthLimit(&cfg, *authLimit, "serve")
	if err != nil {
		return err
	}
	defer stopAuthLimit()
	resolved, err := resolveServeTLS(*tlsCert, *tlsKey, *tlsUse, cfg, hostOf(*addr))
	if err != nil {
		return err
	}
	tlsOn := resolved != nil && resolved.Source != tlsconfig.SourceNone
	selfSigned := resolved != nil && resolved.SelfSigned
	warnings, err := ensureLoopbackBind(*addr, *insecureBind, tlsOn, selfSigned, certConfiguredFor(cfg))
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Printf("warning: %s\n", w)
	}
	serveEnvPassword := os.Getenv("SEAVAULT_SERVE_PASSWORD")
	credUser, credPassword, printCredentials, err := resolveServeCredentials(*user, *passwordFile, serveEnvPassword, *quietCredentials)
	if err != nil {
		return err
	}
	// The password was generated (not supplied) exactly when no source is set;
	// mirror resolveServeCredentials's source precedence.
	generatedPassword := strings.TrimSpace(*passwordFile) == "" && serveEnvPassword == ""
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForWrite(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	dav := localdav.New(v)
	dav.Credentials = &localdav.BasicCredentials{User: credUser, Password: credPassword}
	dav.AuthLimiter = authLimiter
	dav.AuthLogf = authLimitLogf
	dav.AllowedHosts = allowedHostsForBind(*addr, allowHost, cfg.TLS.AllowHosts)
	dav.DropOSJunk = *dropOSJunk
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	fmt.Printf("serving local WebDAV-compatible vault at %s://%s/\n", scheme, *addr)
	fmt.Println("bind is local by default; do not expose this listener on an untrusted network")
	maybePrintExposureLine(*addr, authStatusLine)
	maybeWarnDefaultServeUser(*addr, credUser)
	logTLSStartup(os.Stdout, "serve", resolved, dav.AllowedHosts)
	if printCredentials {
		fmt.Printf("WebDAV credentials: %s / %s\n", credUser, credPassword)
		fmt.Printf("URL: %s://%s:%s@%s/\n", scheme, credUser, credPassword, *addr)
		if generatedPassword {
			if fi, statErr := os.Stdout.Stat(); statErr == nil && stdoutLooksRedirected(fi) {
				fmt.Println("warning: this credential is being written to a non-terminal stdout (log/redirect); prefer --password-file with --quiet-credentials for daemons")
			}
		}
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return listenErrorHint(*addr, err)
	}
	// Start the TLS hot-reloader so a renewed pair is served within the poll and
	// serving.json is written for `tls status` (reload-not-wired-1). It stops when
	// this command returns (defer cancel), so no goroutine outlives the listener.
	reloadCtx, cancelReload := context.WithCancel(context.Background())
	waitReload := startTLSReloader(reloadCtx, resolved, "serve")
	defer func() { cancelReload(); waitReload() }()
	srv := buildLoopbackServer(*addr, dav)
	if serveTestHook != nil {
		serveTestHook(srv, ln.Addr().String())
	}
	return listenErrorHint(*addr, serveOn(ln, srv, resolved))
}

const guiAuthAccount = "seavault-gui-http-auth"

func cmdAppConfig(args []string) error {
	// sweep-docs-1 (C7): a --help anywhere prints the registry usage and runs
	// NOTHING — `app-config reset --help` must not delete the local config. (The
	// top-level dispatch also intercepts leaf --help, but this keeps the handler
	// self-protecting when called directly.)
	if hasHelpFlag(args) {
		if row, ok := topLevelCommand("app-config"); ok {
			renderCommandHelp(os.Stdout, row)
		}
		return nil
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: seavault app-config path | reset | reset-gui-login")
	}
	// registry-cli-2: only the documented sub-actions are accepted; the former
	// undocumented aliases (reset-config, clear-gui-login, reset-password) are
	// dropped so the accepted set matches the usage line the registry advertises.
	switch args[0] {
	case "path":
		p, err := appconfig.Path()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	case "reset":
		return resetLocalAppConfiguration(true)
	case "reset-gui-login":
		return resetLocalAppConfiguration(false)
	default:
		// An unknown sub-action is a usage error and exits 2, matching the group
		// dispatchers and the unknown top-level command (CLI-1). exitCodeError
		// carries the code; run() does not reprint it, so print the usage here.
		fmt.Fprintln(os.Stderr, "usage: seavault app-config path | reset | reset-gui-login")
		return &exitCodeError{code: 2, msg: fmt.Sprintf("unknown app-config subcommand %q", args[0])}
	}
}

func resetLocalAppConfiguration(resetAll bool) error {
	if resetAll {
		p, err := appconfig.Path()
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = keychain.Delete(guiAuthAccount)
		fmt.Printf("reset open-seavault-rclone local app configuration at %s\n", p)
		fmt.Println("vault data, saved vault locations, vault passwords, SSH keys, and remotes were not deleted")
		return nil
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cfg.GUI.Username = ""
	cfg.GUI.PasswordConfigured = false
	cfg.GUI.PasswordHash = ""
	if err := appconfig.Save(cfg); err != nil {
		return err
	}
	_ = keychain.Delete(guiAuthAccount)
	p, _ := appconfig.Path()
	fmt.Printf("reset open-seavault-rclone GUI login in %s\n", p)
	fmt.Println("restart open-seavault-rclone or reload the GUI; browser sessions are invalidated when the server restarts")
	return nil
}

func cmdGUI(args []string) error {
	// registry-cli-2: only the documented sub-actions are accepted; the former
	// undocumented aliases (reset, reset-password, clear-login) are dropped so the
	// accepted set matches the synopsis the registry advertises.
	if len(args) > 0 {
		switch args[0] {
		case "reset-config":
			return resetLocalAppConfiguration(true)
		case "reset-login":
			return resetLocalAppConfiguration(false)
		case "config-path":
			p, err := appconfig.Path()
			if err != nil {
				return err
			}
			fmt.Println(p)
			return nil
		}
	}
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "local address for the browser GUI")
	noOpen := fs.Bool("no-open", false, "do not open the browser automatically")
	exitOnBrowserClose := fs.Bool("exit-on-browser-close", true, "best-effort: stop the GUI after the browser page stops sending heartbeats; set --exit-on-browser-close=false to keep the server running")
	insecureBind := fs.Bool("insecure-bind", false, "allow binding to a non-loopback address (exposes decrypted content; not recommended)")
	tlsCert := fs.String("tls-cert", "", "serve the GUI over HTTPS using this PEM certificate chain (leaf first); requires --tls-key")
	tlsKey := fs.String("tls-key", "", "the PEM private key matching --tls-cert")
	authLimit := fs.String("auth-limit", "", "rate-limit the GUI login and vault open: on (default) or off (off is loud and unprotected; also settable via auth.limits.enabled)")
	var allowHost repeatableString
	fs.Var(&allowHost, "allow-host", "additional Host header value to accept besides loopback/localhost (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	initial := ""
	if fs.NArg() > 1 {
		return fmt.Errorf("usage: seavault gui [--addr 127.0.0.1:8787] [--no-open] [--allow-host NAME] [--tls-cert PATH --tls-key PATH] [--auth-limit on|off] [--insecure-bind] [VAULT_DIR_OR_PROFILE]")
	}
	if fs.NArg() == 1 {
		initial = fs.Arg(0)
	}
	//  (C5 /): do NOT terminate other seavault
	// processes here. The old TerminateExistingSeaVaultProcesses call SIGKILLed
	// EVERY process named "seavault", silently killing a running `seavault serve`
	// (a Finder/rclone mount) when the owner opened the GUI. A scoped
	// single-instance lock is; until then a second GUI on the same --addr
	// surfaces a legible bind failure via listenErrorHint below.
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	authLimiter, authStatusLine, stopAuthLimit, err := startAuthLimit(&cfg, *authLimit, "gui")
	if err != nil {
		return err
	}
	defer stopAuthLimit()
	// Resolve the serving certificate through the precedence chain (flags → the
	// shared tls section → the legacy gui.certFile → the self-signed floor when
	// gui.protocol is https → none). A configured full-but-mismatched pair fails
	// here with ErrKeyMismatch and binds nothing (C13).
	resolved, err := tlsconfig.Resolve(tlsconfig.Options{
		CertFlag: *tlsCert,
		KeyFlag:  *tlsKey,
		Cfg:      cfg,
		Purpose:  tlsconfig.PurposeGUI,
		BindHost: hostOf(*addr),
	})
	if err != nil {
		return err
	}
	tlsOn := resolved.Source != tlsconfig.SourceNone
	// gui auto-activates a configured cert (tlsOn is already true then), so
	// certConfigured only matters for the refusal path when no cert exists; pass
	// the real state for consistency with serve (polish-behaviour-1).
	warnings, err := ensureLoopbackBind(*addr, *insecureBind, tlsOn, resolved.SelfSigned, certConfiguredFor(cfg))
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Printf("warning: %s\n", w)
	}
	// Resolved state drives the server (C2): when a certificate resolved, the
	// in-memory protocol is https BEFORE the webui server is constructed, so the
	// session-cookie Secure attribute follows the resolved state, not the
	// persisted gui.protocol. There is no plaintext code path once tlsOn (C10).
	if tlsOn {
		cfg.GUI.Protocol = "https"
	}
	s, err := webui.NewWithConfig(initial, cfg)
	if err != nil {
		return err
	}
	s.TLSActive = tlsOn
	s.AllowedHosts = allowedHostsForBind(*addr, allowHost, cfg.TLS.AllowHosts)
	s.AuthLimiter = authLimiter
	s.AuthLogf = authLimitLogf
	s.AuthLimitStatus = authStatusLine
	// Pick up changes made to.seavault by an external sync client (e.g. the
	// Nextcloud desktop client) underneath this long-lived GUI server.
	stopWatcher := s.StartSyncWatcher(2 * time.Second)
	defer stopWatcher()
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	// Launch-link identity (C1, launch-allowlist-1): a non-loopback TLS bind
	// advertises the first confirmed CONCRETE name, so the link a person opens
	// from another device is a name the certificate is valid for and never a
	// wildcard. The confirmed names are the CLI --allow-host values merged with the
	// persisted tls.allowHosts — the concrete name the wizard recorded is used even
	// when this `gui` run passes no --allow-host of its own; loopback keeps its own
	// address.
	launchNames := append(append([]string{}, allowHost...), cfg.TLS.AllowHosts...)
	launchAddr := launchAddrForBind(*addr, tlsOn, launchNames, resolved.Names)
	launchURL := s.LaunchURL(scheme + "://" + launchAddr)
	// The no-session login hint carries the resolved launch address for BOTH
	// schemes (launch-hint-loopback-1): a plaintext listener on a non-default port
	// or a non-loopback interface must not tell the visitor to open the hardcoded
	// http://127.0.0.1:8787 — the hint is the address this server actually serves.
	s.LoginHintURL = scheme + "://" + launchAddr + "/?launch=…"
	fmt.Printf("serving local GUI at %s\n", launchURL)
	fmt.Println("open this exact launch link; a bare " + scheme + "://" + launchAddr + "/ no longer shows the app, and the launch secret rotates each launch, so bookmarks break by design")
	fmt.Println("bind is local by default; do not expose this listener on an untrusted network")
	maybePrintExposureLine(*addr, authStatusLine)
	logTLSStartup(os.Stdout, "gui", resolved, s.AllowedHosts)
	if *exitOnBrowserClose {
		s.EnableBrowserCloseShutdown(10 * time.Second)
		fmt.Println("exit-on-browser-close enabled; the GUI will stop shortly after the browser page closes")
	}
	printLaunchGuidance(os.Stdout, os.Stderr, launchURL, !*noOpen, openBrowser)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return listenErrorHint(*addr, err)
	}
	// Start the TLS hot-reloader so a renewed pair is served within the poll and
	// serving.json is written for `tls status` (reload-not-wired-1). It stops when
	// this command returns (defer cancel), covering both the serveErr and the
	// browser-close shutdown exits below.
	reloadCtx, cancelReload := context.WithCancel(context.Background())
	waitReload := startTLSReloader(reloadCtx, resolved, "gui")
	defer func() { cancelReload(); waitReload() }()
	srv := buildLoopbackServer(*addr, s)
	if guiTestHook != nil {
		guiTestHook(srv, ln.Addr().String())
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serveOn(ln, srv, resolved)
	}()
	select {
	case err := <-serveErr:
		if err == http.ErrServerClosed {
			return nil
		}
		return listenErrorHint(*addr, err)
	case <-s.ShutdownNotify():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		err := <-serveErr
		if err == http.ErrServerClosed {
			return nil
		}
		return listenErrorHint(*addr, err)
	}
}

// cmdTLS is the `seavault tls` command group (design §4): the interactive setup
// wizard plus the non-interactive companions use/status/check/reset. Every
// mutating command prints the status summary (C12); no command ever prints key
// material (I-T2).
func cmdTLS(args []string) error { return dispatchGroup("tls", execTLS, args) }

// execTLS is the tls group's leaf dispatcher. dispatchGroup (commands.go) has
// already rendered group help for a bare or `--help` invocation and rejected an
// unknown subcommand against the registry, so execTLS only ever sees a
// registered subcommand; H4 proves this switch and the registry never drift.
func execTLS(args []string) error {
	switch args[0] {
	case "setup":
		return cmdTLSSetup(args[1:])
	case "use":
		return cmdTLSUse(args[1:])
	case "status":
		return cmdTLSStatus(args[1:])
	case "check":
		return cmdTLSCheck(args[1:])
	case "reset":
		return cmdTLSReset(args[1:])
	default:
		return fmt.Errorf("%s", tlsUsage())
	}
}

func tlsUsage() string {
	return "usage: seavault tls setup | use --cert PATH --key PATH [--allow-host NAME] | status | check | reset"
}

// cmdTLSSetup runs the interactive wizard over the stdin prompter and the real
// tool seam.
func cmdTLSSetup(args []string) error {
	fs := flag.NewFlagSet("tls setup", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("tls setup takes no arguments")
	}
	return setup.RunTLSWizard(newStdinPrompter(), setup.DefaultTLSDeps())
}

// cmdTLSUse validates a cert/key pair and persists it to the shared tls section
// (clearing the legacy fields), then prints the status summary so the command
// that changes the configuration also reports it (C12). Nothing is persisted when
// validation fails.
func cmdTLSUse(args []string) error {
	fs := flag.NewFlagSet("tls use", flag.ExitOnError)
	cert := fs.String("cert", "", "path to the PEM certificate chain (leaf first)")
	key := fs.String("key", "", "path to the matching PEM private key")
	var allowHost repeatableString
	fs.Var(&allowHost, "allow-host", "exact Host name to admit at the rebinding guard (repeatable); defaults to the certificate's concrete DNS SANs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*cert) == "" || strings.TrimSpace(*key) == "" {
		return fmt.Errorf("tls use requires --cert PATH and --key PATH")
	}
	info, err := tlsconfig.Validate(*cert, *key)
	if err != nil {
		// Typed error (ErrKeyMismatch/ErrCertParse/ErrKeyParse); nothing persisted.
		return err
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cfg.TLS.CertFile = strings.TrimSpace(*cert)
	cfg.TLS.KeyFile = strings.TrimSpace(*key)
	cfg.TLS.AllowHosts = cleanAllowHostsCLI(allowHost, info.Names)
	cfg.GUI.Protocol = "https"
	cfg.GUI.CertFile = ""
	cfg.GUI.KeyFile = ""
	cfg.GUI.SelfSigned = false
	if err := appconfig.Save(cfg); err != nil {
		return err
	}
	saved, err := appconfig.Load()
	if err != nil {
		return err
	}
	writeTLSStatusSummary(os.Stdout, saved)
	return nil
}

// cmdTLSStatus prints the non-mutating status summary: source, names, expiry, days
// left, allowlist, key permissions, and the running-listener line from
// serving.json. It NEVER prints key material and never triggers the self-signed
// floor's generation.
func cmdTLSStatus(args []string) error {
	fs := flag.NewFlagSet("tls status", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	writeTLSStatusSummary(os.Stdout, cfg)
	return nil
}

// cmdTLSCheck validates the configured pair and exits non-zero on error (design
// §4). With nothing configured it reports so and exits 0 (nothing to validate).
func cmdTLSCheck(args []string) error {
	fs := flag.NewFlagSet("tls check", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cert, key, source := configuredPair(cfg)
	switch source {
	case tlsconfig.SourceNone:
		fmt.Println("tls check: no certificate configured (HTTP loopback / plaintext WebDAV); nothing to validate")
		return nil
	case tlsconfig.SourceSelfSigned:
		fmt.Println("tls check: self-signed floor — a certificate is generated when the GUI first starts over https")
		return nil
	}
	info, err := tlsconfig.Validate(cert, key)
	if err != nil {
		return err // exit 1
	}
	// An out-of-window leaf is a health-check failure, not a pass: the docs say
	// `tls check` "exits non-zero on any error — use it in a health check", and an
	// expired leaf is the single most important thing a health check must catch
	// (the Windows mount refuses it). Exit non-zero by default (A3-c6). Messages
	// name the certificate path and the times only — never key material (I-T2).
	now := time.Now()
	if now.After(info.NotAfter) {
		return fmt.Errorf("tls check: certificate expired on %s (%s)", info.NotAfter.UTC().Format(time.RFC3339), cert)
	}
	if now.Before(info.NotBefore) {
		return fmt.Errorf("tls check: certificate is not valid until %s (%s)", info.NotBefore.UTC().Format(time.RFC3339), cert)
	}
	// A still-valid leaf passes (exit 0); surface any soft warnings (expiring
	// soon, a group/world-readable key) so an operator sees them without failing.
	for _, w := range info.Warnings {
		fmt.Printf("tls check: warning: %s\n", w)
	}
	fmt.Printf("tls check: OK — %s\n", cert)
	return nil
}

// cmdTLSReset returns to the default state (HTTP loopback; no configured
// certificate): it clears the shared tls section and the legacy fields and sets
// gui.protocol=http, then prints the resulting status summary (C12).
func cmdTLSReset(args []string) error {
	fs := flag.NewFlagSet("tls reset", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cfg.TLS = appconfig.TLSSection{}
	cfg.GUI.Protocol = "http"
	cfg.GUI.CertFile = ""
	cfg.GUI.KeyFile = ""
	cfg.GUI.SelfSigned = false
	if err := appconfig.Save(cfg); err != nil {
		return err
	}
	fmt.Println("tls reset: returned to the default — HTTP on loopback, no configured certificate.")
	saved, err := appconfig.Load()
	if err != nil {
		return err
	}
	writeTLSStatusSummary(os.Stdout, saved)
	return nil
}

// configuredPair reports the winning configured cert/key pair and its source
// WITHOUT side effects (unlike tlsconfig.Resolve, it never triggers the
// self-signed floor's generation). A gui.protocol=https with no explicit pair is
// the self-signed floor (source self-signed, empty paths).
func configuredPair(cfg appconfig.Config) (cert, key string, source tlsconfig.Source) {
	switch {
	case strings.TrimSpace(cfg.TLS.CertFile) != "" && strings.TrimSpace(cfg.TLS.KeyFile) != "":
		return cfg.TLS.CertFile, cfg.TLS.KeyFile, tlsconfig.SourceConfig
	case strings.TrimSpace(cfg.GUI.CertFile) != "" && strings.TrimSpace(cfg.GUI.KeyFile) != "":
		return cfg.GUI.CertFile, cfg.GUI.KeyFile, tlsconfig.SourceLegacyGUI
	case strings.EqualFold(strings.TrimSpace(cfg.GUI.Protocol), "https"):
		return "", "", tlsconfig.SourceSelfSigned
	default:
		return "", "", tlsconfig.SourceNone
	}
}

// writeTLSStatusSummary prints the shared status summary consumed by `tls status`,
// `tls use`, and `tls reset` (C12). It reports the configured source, the
// certificate paths (never key bytes), names, expiry, days-left, self-signed
// classification (C7), any warnings, the allowlist, and the running-listener line
// from serving.json (C11). It performs no mutation.
func writeTLSStatusSummary(out io.Writer, cfg appconfig.Config) {
	cert, key, source := configuredPair(cfg)
	fmt.Fprintf(out, "tls source: %s\n", source)
	switch source {
	case tlsconfig.SourceConfig, tlsconfig.SourceLegacyGUI:
		info, err := tlsconfig.Validate(cert, key)
		if err != nil {
			fmt.Fprintf(out, "certificate: %s\ncertificate error: %v\n", cert, err)
		} else {
			fmt.Fprintf(out, "certificate: %s\n", cert)
			fmt.Fprintf(out, "private key: %s\n", key)
			names := "(none)"
			if len(info.Names) > 0 {
				names = strings.Join(info.Names, ", ")
			}
			fmt.Fprintf(out, "names: %s\n", names)
			fmt.Fprintf(out, "expires: %s (%d days left)\n", info.NotAfter.UTC().Format(time.RFC3339), daysUntil(info.NotAfter))
			selfSigned := info.SelfSigned || (source == tlsconfig.SourceLegacyGUI && cfg.GUI.SelfSigned)
			if selfSigned {
				fmt.Fprintf(out, "self-signed: yes — %s\n", selfSignedTrustWarning)
			}
			for _, w := range info.Warnings {
				fmt.Fprintf(out, "warning: %s\n", w)
			}
		}
	case tlsconfig.SourceSelfSigned:
		fmt.Fprintf(out, "self-signed floor: a self-signed certificate is generated when the GUI first starts over https — %s\n", selfSignedTrustWarning)
	case tlsconfig.SourceNone:
		fmt.Fprintln(out, "no certificate configured; the GUI stays on http loopback and WebDAV stays plaintext loopback")
	}
	allow := "(none)"
	if len(cfg.TLS.AllowHosts) > 0 {
		allow = strings.Join(cfg.TLS.AllowHosts, ", ")
	}
	fmt.Fprintf(out, "allowlist: %s\n", allow)
	if dir, err := tlsconfig.ServingDir(); err == nil {
		rs := tlsconfig.RunningListenerStatus(dir, time.Now())
		switch {
		case !rs.Present:
			fmt.Fprintln(out, "running listener: none seen")
		case rs.Stale:
			fmt.Fprintln(out, "running listener: no running listener seen in the last 2 days")
		default:
			fmt.Fprintf(out, "running listener: %d days left\n", rs.DaysLeft)
		}
	}
	// Auth rate-limit status (C7): the persisted view — "on (…)" or "OFF since
	// <date> — <remedy>" — so an operator reading `tls status` learns whether the
	// network-facing credential surfaces are protected.
	fmt.Fprintln(out, cfg.Auth.Limits.StatusLine())
}

// cleanAllowHostsCLI resolves the allowlist for `tls use`: the explicit
// --allow-host values when given, else the certificate's concrete DNS SANs. It
// trims, de-duplicates, and DROPS wildcards so a wildcard never enters the
// exact-match allowlist (C5).
func cleanAllowHostsCLI(explicit []string, certNames []string) []string {
	src := explicit
	if len(src) == 0 {
		src = certNames
	}
	seen := make(map[string]struct{})
	var out []string
	for _, h := range src {
		h = strings.TrimSpace(h)
		if h == "" || strings.Contains(h, "*") {
			continue
		}
		if _, dup := seen[strings.ToLower(h)]; dup {
			continue
		}
		seen[strings.ToLower(h)] = struct{}{}
		out = append(out, h)
	}
	return out
}

func daysUntil(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

func cmdMove(args []string) error {
	fs := flag.NewFlagSet("move", flag.ExitOnError)
	profileName := fs.String("profile", "", "saved vault name to update after moving")
	replace := fs.Bool("replace", false, "replace an existing destination directory")
	updateRemotes := fs.Bool("update-remotes", true, "update remote profiles that point at the old vault path")
	updateMatching := fs.Bool("update-matching-profiles", true, "update saved vault locations that point at the old vault path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: seavault move [--profile NAME] [--replace] [--update-remotes=true] SOURCE_VAULT_DIR_OR_PROFILE DEST_VAULT_DIR")
	}
	sourceArg := fs.Arg(0)
	destArg := fs.Arg(1)
	sourcePath, err := resolveVaultArg(sourceArg)
	if err != nil {
		return err
	}
	if *profileName == "" {
		if e, ok, err := profile.Resolve(sourceArg); err != nil {
			return err
		} else if ok {
			*profileName = e.Name
		}
	}
	res, err := vaultmove.Move(sourcePath, destArg, vaultmove.Options{ProfileName: *profileName, Replace: *replace, UpdateMatchingProfiles: *updateMatching, UpdateRemoteProfiles: *updateRemotes})
	if err != nil {
		return err
	}
	fmt.Printf("moved vault from %s to %s\n", res.SourcePath, res.DestinationPath)
	if res.UpdatedProfiles > 0 || res.UpdatedRemotes > 0 {
		fmt.Printf("updated %d saved vault location(s) and %d remote profile(s)\n", res.UpdatedProfiles, res.UpdatedRemotes)
	}
	for _, warning := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	return nil
}

func cmdProfile(args []string) error { return dispatchGroup("profile", execProfile, args) }

func execProfile(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault profile add [--save-password] NAME VAULT_DIR | save [--save-password] NAME VAULT_DIR | move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR | list [--status] | remove NAME")
	}
	switch args[0] {
	case "add", "save":
		fs := flag.NewFlagSet("profile "+args[0], flag.ExitOnError)
		savePassword := fs.Bool("save-password", false, "verify and store this vault password in the OS keychain")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: seavault profile %s [--save-password] NAME VAULT_DIR", args[0])
		}
		entry, err := profile.Add(fs.Arg(0), fs.Arg(1))
		if err != nil {
			return err
		}
		if *savePassword {
			cfg, err := vault.ReadConfig(entry.VaultPath)
			if err != nil {
				return err
			}
			password, err := readPasswordPrompt("Vault password to store in OS keychain: ")
			if err != nil {
				return err
			}
			if _, err := vault.Open(entry.VaultPath, password); err != nil {
				return fmt.Errorf("profile saved, but password did not open vault: %w", err)
			}
			if err := keychain.Set(cfg.VaultID, password); err != nil {
				return err
			}
			fmt.Printf("profile %s -> %s (password saved in OS keychain)\n", entry.Name, entry.VaultPath)
			return nil
		}
		fmt.Printf("profile %s -> %s\n", entry.Name, entry.VaultPath)
		return nil
	case "move":
		fs := flag.NewFlagSet("profile move", flag.ExitOnError)
		replace := fs.Bool("replace", false, "replace an existing destination directory")
		updateRemotes := fs.Bool("update-remotes", true, "update remote profiles that point at the old vault path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: seavault profile move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR")
		}
		res, err := vaultmove.MoveProfile(fs.Arg(0), fs.Arg(1), vaultmove.Options{Replace: *replace, UpdateRemoteProfiles: *updateRemotes})
		if err != nil {
			return err
		}
		fmt.Printf("moved saved vault %s from %s to %s\n", fs.Arg(0), res.SourcePath, res.DestinationPath)
		if res.UpdatedProfiles > 0 || res.UpdatedRemotes > 0 {
			fmt.Printf("updated %d saved vault location(s) and %d remote profile(s)\n", res.UpdatedProfiles, res.UpdatedRemotes)
		}
		for _, warning := range res.Warnings {
			fmt.Fprintln(os.Stderr, "warning:", warning)
		}
		return nil
	case "list":
		fs := flag.NewFlagSet("profile list", flag.ExitOnError)
		withStatus := fs.Bool("status", false, "include vault existence and keychain status")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("usage: seavault profile list [--status]")
		}
		entries, err := profile.Entries()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !*withStatus {
				fmt.Printf("%s\t%s\n", e.Name, e.VaultPath)
				continue
			}
			status, keychainStatus, recoveryStatus := "missing", "no keychain entry", ""
			if cfg, err := vault.ReadConfig(e.VaultPath); err == nil {
				status = "vault exists"
				if cfg.VaultID != "" {
					if p, err := keychain.Get(cfg.VaultID); err == nil && p != "" {
						keychainStatus = "keychain saved"
					}
				}
				// CLI-4: name the missing recovery key as a persistent surface. The
				// wrap-entry types are in the public config (no password needed); a
				// recovery key is always a recovery-type entry, so its absence — an
				// empty array included — is a keyless vault.
				recoveryStatus = "no recovery key — add one with `seavault recovery generate`"
				for _, we := range cfg.WrapEntries {
					if we.Type == vault.WrapTypeRecovery {
						recoveryStatus = "recovery key set"
						break
					}
				}
			}
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", e.Name, e.VaultPath, status, keychainStatus, recoveryStatus)
		}
		return nil
	case "remove", "rm":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault profile remove NAME")
		}
		// DOC-6: say what was removed instead of exiting silently. Resolve the path
		// first (best-effort) so the confirmation can name where the vault data was
		// left; the profile store, not the vault, is all that is removed.
		removedPath := ""
		if e, found, rerr := profile.Resolve(args[1]); rerr == nil && found {
			removedPath = e.VaultPath
		}
		if err := profile.Remove(args[1]); err != nil {
			return err
		}
		if removedPath != "" {
			fmt.Printf("removed profile %s (the vault data at %s was left in place)\n", args[1], removedPath)
		} else {
			fmt.Printf("removed profile %s\n", args[1])
		}
		return nil
	default:
		return fmt.Errorf("unknown profile command %q", args[0])
	}
}

// keychainStatusLine decides what `seavault keychain status` reports (friction
// ). getErr is the result of keychain.Get for the vault; serviceReachable
// is keychain.Check.Available. When Get succeeded, the entry exists. When Get
// failed but the service is reachable, the entry is simply absent (secret-tool
// exit 1 / macOS item-not-found), so it reports "no keychain entry for this
// vault" rather than the install-libsecret advice. Only when the service itself
// is unreachable is the failure real, and the caller surfaces getErr (which
// names the install/setup fix) and exits 1. Kept pure so it is testable on every
// OS through a fabricated (reachable, error) pair.
func keychainStatusLine(serviceReachable bool, getErr error) (line string, isErr bool) {
	if getErr == nil {
		return "OS keychain entry exists", false
	}
	if serviceReachable {
		return "no keychain entry for this vault", false
	}
	return getErr.Error(), true
}

// keychainDeleteReport composes what `seavault keychain delete` reports (DOCS-1),
// given the pre-delete lookup result (getErr; nil means an entry was found),
// whether the OS keychain service is reachable, and the delete outcome (delErr,
// only meaningful when an entry was found). It returns the plain operator line,
// whether that line is an error, and the raw backend detail to show ONLY under
// --debug. The plain line NEVER contains backend error text (the pre-U4 delete
// dumped a raw backend error when no entry existed), and no field ever carries a
// password. A missing entry with the service reachable is reported plainly and is
// NOT an error, so a delete that finds nothing to remove exits 0.
func keychainDeleteReport(vaultLabel string, getErr error, serviceReachable bool, delErr error) (line string, isErr bool, rawDetail string) {
	if getErr != nil {
		if serviceReachable {
			// The service answered and there is simply no entry: nothing to delete.
			return fmt.Sprintf("no keychain entry for %s", vaultLabel), false, ""
		}
		// The service could not be reached, so we cannot tell entry-or-not: a real
		// failure. The plain line names the situation; the raw backend error is the
		// --debug detail.
		return "could not reach the OS keychain to delete the entry", true, getErr.Error()
	}
	if delErr != nil {
		// An entry existed but the delete itself failed.
		return "could not delete the OS keychain entry", true, delErr.Error()
	}
	return "OS keychain entry deleted", false, ""
}

// cmdPassword implements `seavault password change`: rotate
// the vault password by rewrapping the same master||index bundle (no chunk or
// manifest rewrite) and refreshing the OS keychain entry when one exists.
func cmdPassword(args []string) error { return dispatchGroup("password", execPassword, args) }

func execPassword(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault password change [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE")
	}
	switch args[0] {
	case "change":
		return cmdPasswordChange(args[1:])
	default:
		return fmt.Errorf("unknown password subcommand %q; want: change", args[0])
	}
}

func cmdPasswordChange(args []string) error {
	fs := flag.NewFlagSet("password change", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the current password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup); re-TOFUs freshness protection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault password change [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	// Open with the CURRENT password (env, keychain, or prompt).
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	newPW, err := readNewVaultPassword()
	if err != nil {
		return err
	}
	if err := v.ChangePassword(newPW); err != nil {
		return err
	}
	refreshKeychainAfterRotation(v.ID(), newPW)
	fmt.Printf("password changed for %s (format epoch %d)\n", vaultPath, v.Config.FormatEpoch)
	return nil
}

// cmdRecovery implements `seavault recovery generate|redeem|revoke|list` (design
// ): the recovery-key lifecycle. generate mints a phrase with a
// mandatory read-back; redeem consumes a phrase to set a new password; revoke
// retires one entry; list shows the entry IDs to revoke.
func cmdRecovery(args []string) error { return dispatchGroup("recovery", execRecovery, args) }

func execRecovery(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault recovery generate|redeem|revoke|list VAULT_DIR_OR_PROFILE")
	}
	switch args[0] {
	case "generate":
		return cmdRecoveryGenerate(args[1:])
	case "redeem":
		return cmdRecoveryRedeem(args[1:])
	case "revoke":
		return cmdRecoveryRevoke(args[1:])
	case "list":
		return cmdRecoveryList(args[1:])
	default:
		return fmt.Errorf("unknown recovery subcommand %q; want: generate, redeem, revoke, list", args[0])
	}
}

// stdinIsInteractive reports whether standard input is a terminal (a character
// device). `recovery generate` and the last-key `recovery revoke` gate consult
// it: a freshly minted phrase is shown once and must be typed back at a live
// terminal, and destroying the last recovery key must be a deliberate
// interactive act — so a redirected/piped stdin (a script, a log capture) is
// refused (or forced to pass --yes). It is a package var so a test can drive the
// interactive path without a real PTY.
var stdinIsInteractive = func() bool {
	return stdinIsTTY()
}

// readRecoveryReadback reads the mandatory read-back for `recovery generate` from
// the terminal ONLY (design U2 §2.5 / review DOCS-1). Unlike `recovery redeem`,
// where SEAVAULT_RECOVERY_PHRASE lets an operator script a phrase they already
// hold, a phrase nobody has seen must not be confirmable by a script, so there is
// deliberately NO environment hook here. It is a package var so a test can supply
// a controlled read-back.
var readRecoveryReadback = func(prompt string) (string, error) {
	return passphrase.Read(prompt)
}

// recoveryEntryIDsCLI returns the IDs of a vault's recovery wrap entries in
// on-disk order (the appended one is last) — the input to the last-key revoke
// gate and to the device-local label lookup, mirroring webui's recoveryEntryIDs.
func recoveryEntryIDsCLI(v *vault.Vault) []string {
	ids := []string{}
	for _, ref := range v.WrapEntryRefs() {
		if ref.Type == vault.WrapTypeRecovery {
			ids = append(ids, ref.ID)
		}
	}
	return ids
}

// recordRecoveryLabelCLI writes the device-local label for the recovery entry
// just appended to v (design U2 §2.6, review cli-label-gap): the created date
// and this device's hostname, keyed by the entry's full ID. It returns the
// entry's stable 4-hex handle. Display-only and best-effort — a store failure is
// swallowed (the entry is already durable) and never fails the commit, mirroring
// webui's recordRecoveryLabel.
func recordRecoveryLabelCLI(v *vault.Vault) string {
	ids := recoveryEntryIDsCLI(v)
	if len(ids) == 0 {
		return ""
	}
	id := ids[len(ids)-1]
	host, _ := os.Hostname()
	_ = profile.SetRecoveryLabel(id, profile.RecoveryKeyLabel{
		Created: time.Now().Format("2006-01-02"),
		Device:  host,
	})
	return profile.Handle(id)
}

// confirmPromptDefault is confirmPrompt with an explicit default for an empty or
// closed-stdin answer, so the abandoned-card delete offer can default to the safe
// direction (delete a plaintext secret) the setup ceremony uses.
func confirmPromptDefault(prompt string, defaultYes bool) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return defaultYes, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultYes, nil
	}
}

func cmdRecoveryGenerate(args []string) error {
	fs := flag.NewFlagSet("recovery generate", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the current password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	save := fs.String("save", "", "also write the recovery card (24 words + compact form) to this file (0600); refused inside the vault folder, warned under a detected cloud-sync folder")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault recovery generate [--no-keychain] [--accept-rollback] [--save PATH] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	// DOCS-1 (make the v0.19 "interactive-only" claim TRUE): the read-back must be
	// typed at a live terminal, so refuse a non-interactive stdin BEFORE opening
	// the vault or emitting any phrase. A script or a redirect must never be able
	// to capture a freshly minted secret, and there is deliberately no environment
	// override for the read-back.
	if !stdinIsInteractive() {
		return errors.New("recovery generate needs an interactive terminal: the phrase is shown once and must be typed back to confirm it, so it will not run with input redirected from a file, pipe, or script (there is no environment override). Run it directly in a terminal")
	}
	// CLI-2 (design §2.5): validate a --save destination BEFORE minting, applying
	// the U1 save-path rules the setup ceremony uses. A path inside the vault
	// folder is refused outright (a plaintext master secret there would be uploaded
	// to the remote and defeat the encryption); a path under a detected cloud
	// provider root is allowed only after a second confirmation naming the risk.
	// Deciding up front means no phrase is minted if the target is unsafe.
	saveTarget := ""
	if strings.TrimSpace(*save) != "" {
		saveTarget = filepath.Clean(*save)
		if setup.PathInsideVault(saveTarget, vaultPath, runtime.GOOS) {
			return fmt.Errorf("refusing to save the recovery card to %s: that path is inside the vault folder. The recovery phrase is the master key; a plaintext copy inside the vault would be uploaded to your cloud/remote and defeat the encryption. Choose a location OUTSIDE the vault (a password manager, a USB key, or print it)", saveTarget)
		}
		home, _ := os.UserHomeDir()
		if prov, ok := setup.ProviderRootFor(saveTarget, home, runtime.GOOS); ok {
			ok2, cerr := confirmPrompt(fmt.Sprintf("Warning: %s is inside your %s folder, so the plaintext recovery card would be UPLOADED to your cloud in the clear — anyone with access to that cloud could unlock the vault. Save it there anyway? [y/N]: ", saveTarget, setup.DisplayName(prov)))
			if cerr != nil {
				return cerr
			}
			if !ok2 {
				return fmt.Errorf("did not save the recovery card; choose a location outside your sync folders (a password manager, a USB key, or print it)")
			}
		}
	}
	// CLI-4: `recovery generate` opens the vault, so it asks for the vault
	// password unless one is already available. Say so up front so the password
	// prompt is expected, not a surprise.
	fmt.Println("Note: recovery generate opens the vault, so you'll be asked for the vault password (unless it is saved in the OS keychain or set in SEAVAULT_PASSWORD).")
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	phrase, commit, err := v.PrepareRecovery()
	if err != nil {
		return err
	}
	fmt.Println("Recovery phrase — write it down and store it safely. It is shown ONCE and never stored.")
	// Show the 24 numbered words by DEFAULT (design U2 §2.5), with the base32
	// compact form beneath for people who prefer it (and for redeeming on a 0.17
	// client). The words are a pure re-encoding of the SAME secret.
	words, werr := vault.RecoveryPhraseWords(phrase)
	if werr == nil {
		fmt.Println()
		for i, w := range words {
			fmt.Printf("  %2d. %s\n", i+1, w)
		}
	}
	fmt.Println()
	fmt.Println("Compact form (base32) — the same key, for redeeming on a 0.17 client:")
	fmt.Println("    " + phrase)
	fmt.Println()
	// CLI-2 (C6): write the DRAFT card BEFORE the read-back gate, so the owner can
	// save/print the phrase while it is on screen. It is the SAME card the setup
	// ceremony writes (setup.RecoveryCardText), stamped DRAFT until the read-back
	// commits and written owner-only (0600).
	vaultName := filepath.Base(filepath.Clean(vaultPath))
	savedPath := ""
	if saveTarget != "" {
		card := setup.RecoveryCardText(vaultName, words, phrase, werr != nil, true)
		if werr2 := os.WriteFile(saveTarget, []byte(card), 0o600); werr2 != nil {
			return fmt.Errorf("could not write the recovery card to %s: %w", saveTarget, werr2)
		}
		savedPath = saveTarget
		fmt.Printf("saved the recovery card (DRAFT) to %s — it holds the plaintext recovery phrase, so anyone who can read it can unlock the vault. It was written owner-only (0600) BEFORE you confirm below, and is stamped DRAFT until you complete the read-back. Keep it safe, and delete it once the phrase is stored somewhere secure.\n", saveTarget)
	}
	// offerDeleteCard runs on any exit WITHOUT a committed key: it offers to delete
	// a card written before the gate (recovery-integration-2), defaulting to delete
	// (the safe direction for an abandoned plaintext secret).
	offerDeleteCard := func() {
		if savedPath == "" {
			return
		}
		del, derr := confirmPromptDefault(fmt.Sprintf("A recovery card was written to %s before the phrase was confirmed, but NO recovery key was added. It holds the plaintext phrase. Delete that file now? [Y/n]: ", savedPath), true)
		if derr == nil && del {
			if rerr := os.Remove(savedPath); rerr != nil {
				fmt.Fprintf(os.Stderr, "could not delete %s: %v — remove it by hand; it holds the plaintext recovery phrase.\n", savedPath, rerr)
			} else {
				fmt.Printf("deleted the abandoned recovery card %s.\n", savedPath)
			}
			return
		}
		fmt.Printf("kept %s — it holds the plaintext recovery phrase and was written before confirmation; delete it by hand once you no longer need it.\n", savedPath)
	}
	// MANDATORY read-back before commit: the owner re-enters the phrase, verified
	// against the in-memory value; a mismatch aborts with nothing written.
	// RecoveryPhraseCheck (not the boolean facade) surfaces the SPECIFIC typed
	// error, so a single mistyped word reads as a mistyped-word/checksum message
	// rather than a generic mismatch — and never leaks either phrase (§2.5, C1).
	// readRecoveryReadback reads from the terminal only (no env hook, DOCS-1).
	readback, err := readRecoveryReadback("Re-enter the recovery phrase to confirm: ")
	if err != nil {
		offerDeleteCard()
		return err
	}
	if cerr := vault.RecoveryPhraseCheck(phrase, readback); cerr != nil {
		offerDeleteCard()
		return fmt.Errorf("the re-entered phrase did not match (%w); nothing was written — run `recovery generate` again", cerr)
	}
	if err := commit(); err != nil {
		offerDeleteCard()
		return err
	}
	// cli-label-gap (design §2.6): record the device-local label (created date +
	// hostname) for the just-appended entry, keyed by its full ID. Best-effort.
	handle := recordRecoveryLabelCLI(v)
	// CLI-2 (C6): re-stamp the saved card as CONFIRMED now the key is durable. A
	// rewrite failure is non-fatal — the DRAFT card still holds the correct phrase.
	if savedPath != "" {
		confirmed := setup.RecoveryCardText(vaultName, words, phrase, werr != nil, false)
		if rerr := os.WriteFile(savedPath, []byte(confirmed), 0o600); rerr != nil {
			fmt.Fprintf(os.Stderr, "the recovery key was added, but the card file %s could not be re-stamped as confirmed (%v); it still holds the correct phrase.\n", savedPath, rerr)
		} else {
			fmt.Printf("re-stamped the recovery card %s as confirmed (the DRAFT marker is removed).\n", savedPath)
		}
	}
	if handle != "" {
		fmt.Printf("recovery key added (#%s)\n", handle)
	} else {
		fmt.Println("recovery key added")
	}
	return nil
}

// cliRedeemFailureDelay is the fixed throttle the single-shot CLI recovery
// redeem applies after a wrong phrase (design-u4 §2.2, C2/W2). It deliberately
// does NOT consult authlimit: a per-process, in-memory limiter protects nothing
// in a process that verifies at most one phrase before exiting.
const cliRedeemFailureDelay = 250 * time.Millisecond

func cmdRecoveryRedeem(args []string) error {
	fs := flag.NewFlagSet("recovery redeem", flag.ExitOnError)
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault recovery redeem [--accept-rollback] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	phrase, err := readRecoveryPhrasePrompt("Recovery phrase: ")
	if err != nil {
		return err
	}
	// A redeemer typed the phrase, so treat it as an interactive unlock (design
	// ); --accept-rollback still applies to a restored config.
	v, entryID, err := vault.OpenWithRecovery(vaultPath, phrase, vault.OpenOptions{AcceptRollback: *acceptRollback})
	if err != nil {
		// Fixed throttle on a wrong phrase (design-u4 §2.2, C2/W2): a single-shot CLI
		// process starts with an empty map and can never accumulate, so it uses a
		// plain fixed FailureDelay and holds NO rate-limiter reference — the GUI
		// redeem surface carries the limiter; this one deliberately does not.
		time.Sleep(cliRedeemFailureDelay)
		return err
	}
	if note := v.PreflightNote(); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	newPW, err := readNewVaultPassword()
	if err != nil {
		return err
	}
	if err := v.RedeemRecovery(entryID, newPW); err != nil {
		return err
	}
	refreshKeychainAfterRotation(v.ID(), newPW)
	fmt.Printf("recovery redeemed for %s: a new password is set and the recovery key was consumed (format epoch %d)\n", vaultPath, v.Config.FormatEpoch)
	return nil
}

func cmdRecoveryRevoke(args []string) error {
	fs := flag.NewFlagSet("recovery revoke", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the current password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	yes := fs.Bool("yes", false, "confirm revoking the LAST recovery key non-interactively (the vault would then have no recovery path)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: seavault recovery revoke [--no-keychain] [--accept-rollback] [--yes] VAULT_DIR_OR_PROFILE ENTRY_ID")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	entryID := fs.Arg(1)
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	// wiring-1 / CLI-5 (design §2.7, I-U4, matrix S1): revoking the vault's LAST
	// remaining recovery key destroys the only route back if the password is
	// forgotten. Gate it exactly as the GUI does (webui handleRecoveryRevoke): when
	// one or zero recovery keys remain, require an explicit confirmation that names
	// the consequence — an interactive y/N prompt, or --yes when stdin is not a
	// terminal. Without it, refuse and change NOTHING.
	if len(recoveryEntryIDsCLI(v)) <= 1 && !*yes {
		const consequence = "Revoking the last recovery key leaves the vault with no recovery path; a forgotten password cannot be recovered."
		if stdinIsInteractive() {
			ok, perr := confirmPrompt(consequence + " Revoke it anyway? [y/N]: ")
			if perr != nil {
				return perr
			}
			if !ok {
				return errors.New("the last recovery key was not revoked")
			}
		} else {
			return fmt.Errorf("refusing to revoke the last recovery key: %s Re-run with --yes to confirm non-interactively", consequence)
		}
	}
	if err := v.RevokeRecovery(entryID); err != nil {
		return err
	}
	// cli-label-gap / wordlist-labels-3: drop the device-local label so a revoked
	// key's hostname/date do not linger in the store. Best-effort, display-only.
	_ = profile.DeleteRecoveryLabel(entryID)
	fmt.Printf("revoked recovery entry %s\n", entryID)
	return nil
}

func cmdRecoveryList(args []string) error {
	fs := flag.NewFlagSet("recovery list", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the current password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault recovery list [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	// cli-label-gap (design §2.6 / C4): join the recovery entry IDs with this
	// device's label store and print each entry's stable 4-hex handle plus its
	// label-or-creation detail (falling back to the bare handle), followed by the
	// full entry ID revoke/redeem still need. A label-store read error degrades to
	// the bare IDs rather than failing the list.
	ids := recoveryEntryIDsCLI(v)
	if len(ids) == 0 {
		fmt.Fprintln(os.Stderr, "no recovery keys are registered for this vault")
		return nil
	}
	views, verr := profile.LabelledRecoveryKeys(ids)
	if verr != nil {
		for _, id := range ids {
			fmt.Println(id)
		}
		return nil
	}
	for _, view := range views {
		fmt.Printf("%s  (id %s)\n", view.Display(), view.ID)
	}
	return nil
}

// cmdVault implements `seavault vault seal-format|unseal-format VAULT` (design
// ): the operator's explicit end of the grace release and its
// reversal. seal-format retires open-seavault-rclone 0.16 and older by bumping the on-disk
// Version to 3 and raising MinReader to 3 in one MAC'd rewrite; unseal-format
// reverses it while no A3 directory-ID re-key has run.
func cmdVault(args []string) error { return dispatchGroup("vault", execVault, args) }

func execVault(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault vault seal-format|unseal-format [flags] VAULT_DIR_OR_PROFILE")
	}
	switch args[0] {
	case "seal-format":
		return cmdVaultSealFormat(args[1:])
	case "unseal-format":
		return cmdVaultUnsealFormat(args[1:])
	default:
		return fmt.Errorf("unknown vault subcommand %q; want: seal-format, unseal-format", args[0])
	}
}

func cmdVaultSealFormat(args []string) error {
	fs := flag.NewFlagSet("vault seal-format", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the vault password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	yes := fs.Bool("yes", false, "skip the interactive confirmation (for scripts that have already confirmed every device is upgraded)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault vault seal-format [--no-keychain] [--accept-rollback] [--yes] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	// Print whatever device signal exists BEFORE asking to confirm (
	// ), so the operator judges "every device upgraded" against the
	// inventory — or, when it is empty, sees the explicit no-telemetry warning.
	fmt.Fprint(os.Stderr, formatReaderSignal(v.ReaderInventory()))
	if !*yes {
		ok, err := confirmPrompt("Seal the vault format now? This retires open-seavault-rclone 0.16 and older for every device. [y/N]: ")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("seal-format aborted; nothing was changed")
		}
	}
	if err := v.SealFormat(); err != nil {
		return err
	}
	fmt.Printf("sealed %s: version %d, minReader %d — open-seavault-rclone 0.16 and older can no longer open it (format epoch %d)\n", vaultPath, v.Config.Version, v.Config.MinReader, v.Config.FormatEpoch)
	return nil
}

func cmdVaultUnsealFormat(args []string) error {
	fs := flag.NewFlagSet("vault unseal-format", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the vault password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault vault unseal-format [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	if err := v.UnsealFormat(); err != nil {
		return err
	}
	fmt.Printf("unsealed %s: version %d, minReader %d — open-seavault-rclone 0.16 and older can open it again (format epoch %d)\n", vaultPath, v.Config.Version, v.Config.MinReader, v.Config.FormatEpoch)
	return nil
}

// formatReaderSignal renders the device-local reader inventory seal-format shows
// before retiring older readers. A non-empty
// inventory lists each known DeviceID with the format level it reads and when it
// was last seen; an EMPTY inventory becomes the explicit no-telemetry warning,
// because the signal is device-local and cannot see a 0.16 peer (which records
// nothing) — the operator must not read "no devices listed" as "no other devices
// exist."
func formatReaderSignal(inv []vault.ReaderRecord) string {
	if len(inv) == 0 {
		return "open-seavault-rclone has no inventory of your other devices; sealing now will lock out any device still on 0.16 or older with no automatic recovery. Confirm every device is upgraded first.\n"
	}
	var b strings.Builder
	b.WriteString("Devices seen opening this vault through this app-data directory (device-local; a 0.16 peer records nothing and may be missing):\n")
	for _, r := range inv {
		b.WriteString(fmt.Sprintf("  %s  reads format %d  last seen %s\n", r.DeviceID, r.SupportedFormat, r.LastSeen))
	}
	b.WriteString("This list only covers devices that opened the vault through THIS device; a device missing here may still be on 0.16. Confirm every device is upgraded first.\n")
	return b.String()
}

// confirmPrompt reads a yes/no answer from stdin (the design: seal-format needs
// an interactive confirmation or --yes). Only an explicit y/yes confirms; a
// closed stdin (EOF, an unattended pipe) or any other answer declines, so a
// non-interactive caller that forgot --yes never accidentally seals.
func confirmPrompt(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		// EOF with nothing typed (closed stdin): a decline, not an error.
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func cmdKeychain(args []string) error { return dispatchGroup("keychain", execKeychain, args) }

func execKeychain(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault keychain store VAULT_DIR_OR_PROFILE | status VAULT_DIR_OR_PROFILE | delete VAULT_DIR_OR_PROFILE")
	}
	switch args[0] {
	case "store":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault keychain store VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(args[1])
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		password, err := readPasswordPrompt("Vault password to store in OS keychain: ")
		if err != nil {
			return err
		}
		if _, err := vault.Open(vaultPath, password); err != nil {
			return err
		}
		if err := keychain.Set(cfg.VaultID, password); err != nil {
			return err
		}
		fmt.Println("password stored in OS keychain")
		return nil
	case "status":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault keychain status VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(args[1])
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		_, getErr := keychain.Get(cfg.VaultID)
		line, isErr := keychainStatusLine(keychain.Check().Available, getErr)
		if isErr {
			// A genuine service failure (keychain unreachable, tools missing):
			// surface the original error, which names the install/setup fix, and
			// exit 1 as before.
			return getErr
		}
		fmt.Println(line)
		return nil
	case "delete", "remove", "rm":
		fs := flag.NewFlagSet("keychain delete", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		debug := fs.Bool("debug", false, "print the raw keychain backend error the plain summary omits")
		if err := fs.Parse(args[1:]); err != nil {
			return fmt.Errorf("usage: seavault keychain delete [--debug] VAULT_DIR_OR_PROFILE")
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: seavault keychain delete [--debug] VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(fs.Arg(0))
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		// Look the entry up BEFORE deleting so a missing entry is a plain line, not
		// a raw backend error (DOCS-1). keychainDeleteReport composes the operator
		// line and keeps every backend error string out of it; the raw detail is
		// shown only under --debug, and never carries any password (I-R2/I-S1).
		_, getErr := keychain.Get(cfg.VaultID)
		serviceReachable := keychain.Check().Available
		var delErr error
		if getErr == nil {
			delErr = keychain.Delete(cfg.VaultID)
		}
		line, isErr, rawDetail := keychainDeleteReport(vaultPath, getErr, serviceReachable, delErr)
		if isErr {
			fmt.Fprintln(os.Stderr, line)
			if *debug && rawDetail != "" {
				fmt.Fprintln(os.Stderr, "keychain error detail:", rawDetail)
			}
			return &exitCodeError{code: 1, msg: line}
		}
		fmt.Println(line)
		return nil
	default:
		return fmt.Errorf("unknown keychain command %q", args[0])
	}
}

func cmdRsync(args []string) error { return dispatchGroup("rsync", execRsync, args) }

func execRsync(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault rsync status|install|check-update|update|rollback|verify-runtime|path")
	}
	ctx := context.Background()
	installer := rsyncbin.NewInstaller()
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("rsync status", flag.ExitOnError)
		binary := fs.String("binary", "", "system rsync binary path or name; default searches PATH after managed rsync")
		check := fs.Bool("check-update", false, "also check latest upstream rsync source release")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		st := rsyncput.Inspect(ctx, *binary)
		if *check {
			st.Managed = installer.Status(ctx, true)
		}
		return printJSON(st)
	case "install":
		fs := flag.NewFlagSet("rsync install", flag.ExitOnError)
		ver := fs.String("version", "", "rsync version to register/install; default latest source release for runtime archive URLs")
		fromBinary := fs.String("from-binary", "", "register/copy an existing rsync-compatible binary into the managed runtime")
		offlineArchive := fs.String("offline-archive", "", "install from a local open-seavault-rclone rsync runtime zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		runtimeBase := fs.String("runtime-base-url", "", "base URL for open-seavault-rclone-built rsync runtime artifacts")
		buildID := fs.String("build-id", "", "optional runtime build identifier for provenance")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Install(ctx, rsyncbin.InstallOptions{Version: *ver, FromBinary: *fromBinary, OfflineArchive: *offlineArchive, OfflineSHA256: *offlineSHA, RuntimeBaseURL: *runtimeBase, BuildID: *buildID})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "check-update":
		li, err := installer.Latest(ctx)
		if printErr := printJSON(li); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "update":
		fs := flag.NewFlagSet("rsync update", flag.ExitOnError)
		ver := fs.String("version", "", "rsync version to install; default latest upstream source release")
		fromBinary := fs.String("from-binary", "", "register/copy an existing rsync-compatible binary into the managed runtime")
		offlineArchive := fs.String("offline-archive", "", "install from a local open-seavault-rclone rsync runtime zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		runtimeBase := fs.String("runtime-base-url", "", "base URL for open-seavault-rclone-built rsync runtime artifacts")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Update(ctx, rsyncbin.InstallOptions{Version: *ver, FromBinary: *fromBinary, OfflineArchive: *offlineArchive, OfflineSHA256: *offlineSHA, RuntimeBaseURL: *runtimeBase})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "rollback":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault rsync rollback")
		}
		m, err := rsyncbin.Rollback()
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "verify-runtime":
		m, err := rsyncbin.LoadManifest()
		if err == nil {
			err = rsyncbin.VerifyRuntime(m)
		}
		if err != nil {
			return err
		}
		fmt.Println("managed rsync runtime verified")
		return nil
	case "path":
		bin, err := rsyncbin.BinaryPath()
		if err != nil {
			return err
		}
		fmt.Println(bin)
		return nil
	default:
		return fmt.Errorf("unknown rsync command %q", args[0])
	}
}

func cmdRclone(args []string) error { return dispatchGroup("rclone", execRclone, args) }

func execRclone(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault rclone status|install|check-update|update|rollback|version|path|verify-runtime")
	}
	ctx := context.Background()
	installer := rclonebin.NewInstaller()
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("rclone status", flag.ExitOnError)
		check := fs.Bool("check-update", false, "also check the latest official rclone version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return printJSON(installer.Status(ctx, *check))
	case "install":
		fs := flag.NewFlagSet("rclone install", flag.ExitOnError)
		ver := fs.String("version", "", "rclone version to install; default latest stable")
		channel := fs.String("channel", "stable", "release channel: stable or beta")
		fromBinary := fs.String("from-binary", "", "register/copy an existing rclone-compatible binary into the managed runtime")
		offlineArchive := fs.String("offline-archive", "", "install from a local rclone zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		sig := fs.String("signature", "optional", "signature mode: optional, required, or skip")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Install(ctx, rclonebin.InstallOptions{Version: *ver, Channel: *channel, FromBinary: *fromBinary, OfflineArchive: *offlineArchive, OfflineSHA256: *offlineSHA, SignatureMode: *sig})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "check-update":
		fs := flag.NewFlagSet("rclone check-update", flag.ExitOnError)
		channel := fs.String("channel", "stable", "release channel")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		li, err := installer.Latest(ctx, *channel)
		if printErr := printJSON(li); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "update":
		fs := flag.NewFlagSet("rclone update", flag.ExitOnError)
		ver := fs.String("version", "", "rclone version to install; default latest")
		channel := fs.String("channel", "", "release channel")
		sig := fs.String("signature", "optional", "signature mode: optional, required, or skip")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := installer.Update(ctx, rclonebin.InstallOptions{Version: *ver, Channel: *channel, SignatureMode: *sig})
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "rollback":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault rclone rollback")
		}
		m, err := rclonebin.Rollback()
		if printErr := printJSON(m); printErr != nil && err == nil {
			err = printErr
		}
		return err
	case "version":
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		v, err := rclonebin.Version(ctx, bin)
		if err != nil {
			return err
		}
		fmt.Println(v)
		return nil
	case "path":
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		fmt.Println(bin)
		return nil
	case "verify-runtime":
		m, err := rclonebin.LoadManifest()
		if err != nil {
			return err
		}
		if err := rclonebin.VerifyRuntime(m); err != nil {
			return err
		}
		fmt.Println("managed rclone runtime verified")
		return nil
	default:
		return fmt.Errorf("unknown rclone command %q", args[0])
	}
}

func cmdRemote(args []string) error { return dispatchGroup("remote", execRemote, args) }

func execRemote(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault remote add|list|show|edit|delete|test|dry-run|push|pull|sync|check|config")
	}
	switch args[0] {
	case "add", "edit":
		fs := flag.NewFlagSet("remote "+args[0], flag.ExitOnError)
		backend := fs.String("backend", "", "rclone backend label, e.g. local, sftp, s3, b2, onedrive, webdav")
		typeName := fs.String("type", "rclone", "profile type: rclone or local")
		configPath := fs.String("config", "", "rclone config path, default app-managed config")
		transfers := fs.Int("transfers", 8, "parallel rclone transfers")
		checkers := fs.Int("checkers", 16, "parallel rclone checkers")
		fastList := fs.Bool("fast-list", true, "enable rclone --fast-list where supported")
		bandwidth := fs.String("bwlimit", "", "optional rclone bandwidth limit")
		allowSync := fs.Bool("allow-destructive-sync", false, "allow advanced destructive rclone sync for this profile")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 3 {
			return fmt.Errorf("usage: seavault remote %s [flags] NAME VAULT_DIR_OR_PROFILE RCLONE_REMOTE_PATH", args[0])
		}
		vaultPath, err := resolveVaultArg(fs.Arg(1))
		if err != nil {
			return err
		}
		p := remotes.DefaultProfile(fs.Arg(0), vaultPath, fs.Arg(2), *backend)
		p.Type = strings.ToLower(strings.TrimSpace(*typeName))
		p.Remote.Transfers = *transfers
		p.Remote.Checkers = *checkers
		p.Remote.FastList = *fastList
		p.Remote.BandwidthLimit = *bandwidth
		if *configPath != "" {
			cfg, err := remotes.ResolveConfigPath(*configPath)
			if err != nil {
				return err
			}
			p.Remote.RcloneConfigPath = cfg
		}
		p.Safety.AllowDestructiveSync = *allowSync
		entry, err := remotes.Add(p)
		if err != nil {
			return err
		}
		return printJSON(entry)
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault remote list")
		}
		entries, err := remotes.Entries()
		if err != nil {
			return err
		}
		for _, e := range entries {
			fmt.Printf("%s\t%s\t%s\t%s\n", e.Name, e.Type, e.Vault, e.Remote.RemotePath)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote show NAME")
		}
		p, ok, err := remotes.Get(args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("remote profile %q not found", args[1])
		}
		return printJSON(p)
	case "delete", "remove", "rm":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote delete NAME")
		}
		return remotes.Remove(args[1])
	case "test", "dry-run", "push", "pull", "check", "sync":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote %s NAME", args[0])
		}
		return runRemote(args[0], args[1])
	case "config":
		return cmdRemoteConfig(args[1:])
	default:
		return fmt.Errorf("unknown remote command %q", args[0])
	}
}

func runRemote(op, name string) error {
	ctx := context.Background()
	p, ok, err := remotes.Get(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("remote profile %q not found", name)
	}
	var res any
	if p.Type == "local" {
		t := localtransport.New(p)
		switch op {
		case "test":
			res, err = t.Test(ctx)
		case "dry-run":
			res, err = t.DryRunPush(ctx)
		case "push":
			res, err = t.Push(ctx, transport.Options{})
		case "pull":
			res, err = t.Pull(ctx, transport.Options{})
		case "check":
			res, err = t.Check(ctx)
		case "sync":
			res, err = t.Sync(ctx, transport.Options{})
		}
	} else {
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		t := rclonetransport.New(bin, p)
		switch op {
		case "test":
			res, err = t.Test(ctx)
		case "dry-run":
			res, err = t.DryRunPush(ctx)
		case "push":
			res, err = t.Push(ctx, transport.Options{})
		case "pull":
			res, err = t.Pull(ctx, transport.Options{})
		case "check":
			res, err = t.Check(ctx)
		case "sync":
			if !p.Safety.AllowDestructiveSync {
				return fmt.Errorf("destructive sync is disabled for %s; use push/pull/copy-safe flow or enable allowDestructiveSync after dry-run review", name)
			}
			return fmt.Errorf("destructive sync command is intentionally not automated; use copy-safe push/pull or vault-aware reconcile")
		}
	}
	if err != nil {
		if res != nil {
			_ = printJSON(res)
		}
		return err
	}
	return printJSON(res)
}

func cmdRemoteConfig(args []string) error {
	// sweep-docs-1 (C7): a --help anywhere in the nested invocation prints the
	// registry usage and runs NOTHING — `remote config create --help` must not
	// create rclone.conf. This runs BEFORE any sub-action dispatch below.
	if hasHelpFlag(args) {
		if row, ok := groupCommand("remote", "config"); ok {
			renderCommandHelp(os.Stdout, row)
		}
		return nil
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault remote config path|import|export-redacted|validate")
	}
	switch args[0] {
	case "path":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault remote config path")
		}
		fmt.Println(remotes.DefaultRcloneConfigPath())
		return nil
	case "import":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault remote config import SOURCE_RCLONE_CONF")
		}
		src, err := userpath.Abs(args[1])
		if err != nil {
			return err
		}
		dst := remotes.DefaultRcloneConfigPath()
		if err := copyFile(src, dst, 0o600); err != nil {
			return err
		}
		fmt.Println("imported rclone config to", dst)
		return nil
	case "export-redacted":
		if len(args) > 2 {
			return fmt.Errorf("usage: seavault remote config export-redacted [CONFIG_PATH]")
		}
		cfg := remotes.DefaultRcloneConfigPath()
		if len(args) == 2 {
			var err error
			cfg, err = userpath.Abs(args[1])
			if err != nil {
				return err
			}
		}
		data, err := os.ReadFile(cfg)
		if err != nil {
			return err
		}
		fmt.Println(remotes.RedactConfig(string(data)))
		return nil
	case "validate":
		bin, err := rclonebin.BinaryPath()
		if err != nil {
			return err
		}
		cfg := remotes.DefaultRcloneConfigPath()
		if len(args) == 2 {
			cfg, err = userpath.Abs(args[1])
			if err != nil {
				return err
			}
		} else if len(args) != 1 {
			return fmt.Errorf("usage: seavault remote config validate [CONFIG_PATH]")
		}
		out, err := exec.Command(bin, "--config", cfg, "config", "show").CombinedOutput()
		if err != nil {
			return fmt.Errorf("rclone config validate failed: %w: %s", err, strings.TrimSpace(remotes.RedactConfig(string(out))))
		}
		fmt.Println(remotes.RedactConfig(string(out)))
		return nil
	case "create":
		_, err := remotes.EnsureManagedConfig()
		if err != nil {
			return err
		}
		fmt.Println(remotes.DefaultRcloneConfigPath())
		return nil
	default:
		return fmt.Errorf("unknown remote config command %q", args[0])
	}
}

func cmdSSHKey(args []string) error { return dispatchGroup("ssh-key", execSSHKey, args) }

func execSSHKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: seavault ssh-key generate NAME | list | public PRIVATE_KEY_OR_NAME | import NAME PRIVATE_KEY")
	}
	ctx := context.Background()
	switch args[0] {
	case "generate":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault ssh-key generate NAME")
		}
		info, err := sshkeys.Generate(ctx, args[1])
		if err != nil {
			return err
		}
		return printJSON(info)
	case "import":
		if len(args) != 3 {
			return fmt.Errorf("usage: seavault ssh-key import NAME PRIVATE_KEY")
		}
		info, err := sshkeys.Import(args[1], args[2])
		if err != nil {
			return err
		}
		return printJSON(info)
	case "public":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault ssh-key public PRIVATE_KEY_OR_NAME")
		}
		pub, err := sshkeys.Public(args[1])
		if err != nil {
			return err
		}
		fmt.Println(pub)
		return nil
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: seavault ssh-key list")
		}
		keys, err := sshkeys.List()
		if err != nil {
			return err
		}
		return printJSON(keys)
	default:
		return fmt.Errorf("unknown ssh-key command %q", args[0])
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func resolveVaultArg(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("vault path or profile is required")
	}
	if !strings.ContainsAny(input, `/\\`) && !filepath.IsAbs(input) {
		if e, ok, err := profile.Resolve(input); err != nil {
			return "", err
		} else if ok {
			return e.VaultPath, nil
		}
	}
	return userpath.Abs(input)
}

// resolveVaultPasswordSource resolves the vault password AND whether the unlock
// is interactive. SEAVAULT_PASSWORD and the OS
// keychain are NON-interactive sources (an unattended process cannot read a
// warning, so a rollback must hard-refuse); the hidden prompt is interactive (a
// human is present). Precedence matches the historical readPasswordForVault:
// env, then keychain, then prompt.
func resolveVaultPasswordSource(vaultPath string, useKeychain bool) (password string, interactive bool, err error) {
	if p := os.Getenv("SEAVAULT_PASSWORD"); p != "" {
		return p, false, nil
	}
	if useKeychain {
		if cfg, cerr := vault.ReadConfig(vaultPath); cerr == nil && cfg.VaultID != "" {
			p, kerr := keychain.Get(cfg.VaultID)
			if kerr == nil && p != "" {
				return p, false, nil
			}
			//  C4: when the keychain was tried and errored, say so
			// before falling back instead of silently swallowing the error.
			if kerr != nil {
				fmt.Fprintln(os.Stderr, keychainUnavailableNote(kerr))
			}
		}
	}
	p, err := passphrase.Read("Vault password: ")
	if err != nil {
		return "", false, err
	}
	return p, true, nil
}

// readNewVaultPassword reads a NEW vault password for a rotation:
// a hidden prompt with confirmation, or SEAVAULT_NEW_PASSWORD for non-interactive
// scripting (kept separate from SEAVAULT_PASSWORD, which supplies the CURRENT
// secret, so the two never collide). It never consults SEAVAULT_PASSWORD.
func readNewVaultPassword() (string, error) {
	if p := os.Getenv("SEAVAULT_NEW_PASSWORD"); p != "" {
		return p, nil
	}
	p1, err := passphrase.Read("New vault password: ")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(p1) == "" {
		return "", errors.New("new password must not be empty")
	}
	p2, err := passphrase.Read("Confirm new vault password: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passwords do not match")
	}
	return p1, nil
}

// readRecoveryPhrasePrompt reads a recovery phrase for a redeem:
// SEAVAULT_RECOVERY_PHRASE for non-interactive scripting, else a hidden prompt.
// Unlike `recovery generate`, the phrase is a value the operator already holds,
// so an env override is appropriate here.
func readRecoveryPhrasePrompt(prompt string) (string, error) {
	if p := os.Getenv("SEAVAULT_RECOVERY_PHRASE"); p != "" {
		return p, nil
	}
	return passphrase.Read(prompt)
}

// refreshKeychainAfterRotation updates the OS keychain entry for a vault to a new
// secret ONLY when one already exists, so the next
// keychain-backed unlock does not fail with the retired password. A vault with no
// stored secret is left untouched; a keychain write failure is a non-fatal note.
func refreshKeychainAfterRotation(vaultID, newSecret string) {
	if vaultID == "" {
		return
	}
	if _, err := keychain.Get(vaultID); err != nil {
		return // no stored secret for this vault; nothing to refresh
	}
	if err := keychain.Set(vaultID, newSecret); err != nil {
		fmt.Fprintln(os.Stderr, "warning: the vault password changed but its OS keychain entry could not be updated:", err.Error())
		return
	}
	fmt.Fprintln(os.Stderr, "updated the OS keychain entry to the new password")
}

func readPasswordPrompt(prompt string) (string, error) {
	if p := os.Getenv("SEAVAULT_PASSWORD"); p != "" {
		return p, nil
	}
	return passphrase.Read(prompt)
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
