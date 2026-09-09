// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// command is one row of the seavault command registry: the single table that
// drives dispatch (run / dispatchGroup), usage(), every per-command --help, and
// group-level help. group is "" for a top-level command and the parent verb
// (e.g. "rclone") for a subcommand. aliases are accepted at dispatch but are not
// shown as their own help rows. A group PARENT is a top-level row (group == "")
// whose name is also the group of one or more subcommand rows; its handler routes
// through dispatchGroup and its usage line is generated from its children.
//
// commands is the ONE table §3.1 asks for: main() dispatches FROM it, usage()
// and each --help render FROM it, and H1/H4 iterate it. Adding or removing a
// dispatchable command is a single-line edit here that H4 forces the test suite
// to acknowledge.
type command struct {
	name     string
	group    string
	synopsis string
	// usage is the "seavault ..." invocation line with double-dash long flags
	// (no leading "usage:" prefix). Empty for a group parent, whose summary line
	// is generated from its children.
	usage   string
	aliases []string
	handler func(args []string) error
	// bespokeHelp marks a leaf whose handler renders its OWN richer --help block
	// (setup/verify/compact carry exit-code notes and a flag block). run() leaves
	// their --help to the handler; every other leaf's --help is rendered from the
	// registry row so it teaches the double-dash usage + synopsis (sweep-docs-2).
	bespokeHelp bool
}

// isHelpFlag reports whether tok is an explicit help request. It matches the
// forms the flag package honors so `seavault <group> <sub> --help` renders the
// registry entry instead of running the command (exit-code contract C7).
func isHelpFlag(tok string) bool {
	switch tok {
	case "-h", "-help", "--help":
		return true
	default:
		return false
	}
}

// hasHelpFlag reports whether any token in args is an explicit help request. A
// leaf --help intercept (sweep-docs-2) and the nested-leaf help guards in
// cmdRemoteConfig / cmdAppConfig (sweep-docs-1) use it so `<cmd> --help` renders
// usage and NEVER runs the command's action, wherever the flag appears.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if isHelpFlag(a) {
			return true
		}
	}
	return false
}

// run is the dispatcher main() delegates to. It returns the process exit code so
// it is testable without os.Exit (H5). It routes the top-level command FROM the
// registry: an explicit help request or a bare invocation prints usage and exits
// 0; an unknown command prints usage and exits 2; otherwise the matched row's
// handler runs and its error maps to the exit code (an *exitCodeError carries its
// own code and has already printed its human line, so run neither reprints nor
// forces 1).
func run(argv []string) int {
	// macOS Finder / LaunchServices double-click default (design §2.1): a .app
	// bundle launch carrying no real arguments (or only the legacy -psn_ argument)
	// opens the GUI with its defaults. A Terminal `seavault` with no arguments is
	// NOT a bundle launch, so finderLaunchActive is false and it still prints usage
	// (I-M3). Nothing new is registered in the command table (H4 stays green).
	if finderLaunchActive(argv) {
		return runFinderLaunchGUI()
	}
	if len(argv) == 0 {
		usage()
		return 2
	}
	name := argv[0]
	rest := argv[1:]
	if isHelpFlag(name) || name == "help" {
		fmt.Print(usageText())
		return 0
	}
	row, ok := topLevelCommand(name)
	if !ok {
		// Name the unrecognized verb before the usage wall (friction W3-1), so a
		// mistyped top-level command reads like an unknown SUBCOMMAND does
		// (dispatchGroup prints "error: unknown … subcommand …") instead of leaving
		// the operator to guess which token was rejected. Same exit code (2).
		fmt.Fprintf(os.Stderr, "error: unknown command %q; run \"seavault --help\"\n", name)
		usage()
		return 2
	}
	// Leaf --help renders from the registry (sweep-docs-2 / ADM-6): intercept
	// BEFORE the handler so `<cmd> --help` prints the double-dash usage line and
	// synopsis and exits 0, never the stdlib single-dash "Usage of <cmd>:" dump a
	// flag.ExitOnError set would print. Group parents route their own help through
	// dispatchGroup; the three leaves with a richer bespoke --help keep it.
	if !row.bespokeHelp && len(groupChildren(row.name)) == 0 && hasHelpFlag(rest) {
		renderCommandHelp(os.Stdout, row)
		return 0
	}
	if err := row.handler(rest); err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// dispatchGroup routes a group verb (rclone, remote, ...) FROM the registry. A
// bare group or an explicit --help prints the group's subcommand list and
// returns nil (exit 0, C7). An unknown subcommand prints the same list to stderr
// and returns an error (exit non-zero, C7). A recognized subcommand followed by
// --help renders that row and returns nil (exit 0). Otherwise exec — the group's
// own leaf dispatcher — runs the command unchanged. groupCommand is the single
// recognition gate, so the registry decides what is a valid subcommand while the
// leaf logic stays exactly where it was; H4 proves the registry and the leaf
// dispatcher never drift.
func dispatchGroup(group string, exec func([]string) error, args []string) error {
	if len(args) == 0 || isHelpFlag(args[0]) {
		renderGroupHelp(os.Stdout, group)
		return nil
	}
	sub := args[0]
	row, ok := groupCommand(group, sub)
	if !ok {
		renderGroupHelp(os.Stderr, group)
		// An unknown subcommand is a usage error and exits 2, the SAME code an
		// unknown top-level command yields (CLI-1): the two were inconsistent
		// before (top-level 2, subcommand 1). exitCodeError carries the code and
		// run() does not reprint it, so the reason line is emitted here.
		fmt.Fprintf(os.Stderr, "error: unknown %s subcommand %q; run \"seavault %s --help\"\n", group, sub, group)
		return &exitCodeError{code: 2, msg: fmt.Sprintf("unknown %s subcommand %q", group, sub)}
	}
	if len(args) > 1 && isHelpFlag(args[1]) {
		renderCommandHelp(os.Stdout, row)
		return nil
	}
	return exec(args)
}

// topLevelCommand finds a top-level row (group == "") by name or alias.
func topLevelCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.group != "" {
			continue
		}
		if c.name == name || containsString(c.aliases, name) {
			return c, true
		}
	}
	return command{}, false
}

// groupCommand finds a subcommand row within a group by name or alias.
func groupCommand(group, name string) (command, bool) {
	for _, c := range commands {
		if c.group != group {
			continue
		}
		if c.name == name || containsString(c.aliases, name) {
			return c, true
		}
	}
	return command{}, false
}

// groupChildren returns, in table order, the subcommand rows of a group. A
// non-empty result marks name as a group parent.
func groupChildren(group string) []command {
	var subs []command
	for _, c := range commands {
		if c.group == group {
			subs = append(subs, c)
		}
	}
	return subs
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// renderCommandHelp writes one command's --help block: its usage line and its
// synopsis, both drawn from the registry row (H1).
func renderCommandHelp(w io.Writer, c command) {
	fmt.Fprintf(w, "usage: %s\n\n%s\n", c.usage, c.synopsis)
}

// renderGroupHelp writes a group's help: the group synopsis, the generated
// summary line, and every subcommand with its synopsis (H1). It never errors on
// an unknown group name; it simply lists whatever children exist.
func renderGroupHelp(w io.Writer, group string) {
	subs := groupChildren(group)
	if parent, ok := topLevelCommand(group); ok && parent.synopsis != "" {
		fmt.Fprintf(w, "seavault %s — %s\n\n", group, parent.synopsis)
	} else {
		fmt.Fprintf(w, "seavault %s\n\n", group)
	}
	fmt.Fprintf(w, "usage: %s\n\nSubcommands:\n", groupSummaryLine(group))
	for _, c := range subs {
		fmt.Fprintf(w, "  %-16s %s\n", c.name, c.synopsis)
	}
	fmt.Fprintf(w, "\nRun \"seavault %s <subcommand> --help\" for one command's usage.\n", group)
}

// groupSummaryLine builds the one-line "seavault <group> a | b | c" summary from
// a group's child rows, so usage() and group help never drift from the table.
func groupSummaryLine(group string) string {
	subs := groupChildren(group)
	names := make([]string, len(subs))
	for i, c := range subs {
		names[i] = c.name
	}
	return "seavault " + group + " " + strings.Join(names, " | ")
}

// usage writes the top-level usage text to stderr (unchanged destination).
func usage() {
	fmt.Fprint(os.Stderr, usageText())
}

// usageText renders the top-level help FROM the registry: the version banner, one
// line per top-level command (a group parent collapses to its generated summary
// line), then the footer. TestUsageTextServeCredentialAndVersion pins the banner
// and the serve/WebDAV footer, so those substrings must survive here.
func usageText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "seavault %s\n\nCloud-folder client-side encrypted storage.\n\nUsage:\n", version)
	for _, c := range commands {
		if c.group != "" {
			continue // subcommands appear under their group's summary line
		}
		if len(groupChildren(c.name)) > 0 {
			fmt.Fprintf(&b, "  %s\n", groupSummaryLine(c.name))
			continue
		}
		fmt.Fprintf(&b, "  %s\n", c.usage)
	}
	b.WriteString(usageFooter)
	return b.String()
}

const usageFooter = `
VAULT_DIR is the encrypted folder. Put it inside any local cloud-sync directory.
Passwords are read from SEAVAULT_PASSWORD, then OS keychain, then a hidden prompt.
The serve command uses a separate WebDAV credential: SEAVAULT_SERVE_PASSWORD or --password-file (otherwise generated and printed once).
A bare "seavault gc" is a dry run: if it finds chunks it would reclaim, it writes an advisory to stderr and exits 3 (action required, not an error) so scripted callers detect that nothing was reclaimed without --confirm.
`

// commands is the seavault command registry. Order is display order for usage().
// Every dispatchable command appears exactly once, including the four that older
// usage() text omitted (rclone version / rclone path, remote sync / remote
// config) — the C3 completeness rows that H4 guards.
//
// It is populated in init() rather than as a var initializer because the group
// handlers it stores (cmdRclone, …) dispatch back through the table, which Go's
// static initialization-cycle check would otherwise reject.
var commands []command

func init() {
	commands = []command{
		// Top-level leaf commands.
		{name: "setup", bespokeHelp: true, synopsis: setupSynopsis(), usage: "seavault setup [--expert] [--no-keychain] [--profile NAME] [--no-open] | seavault setup --preset synced-folder|rclone|local --vault PATH [--remote NAME] [--allow-download] [--json]", handler: cmdSetup},
		{name: "init", synopsis: "Create a new encrypted vault in an empty directory.", usage: "seavault init [--kdf argon2id|scrypt|pbkdf2] [flags] VAULT_DIR", handler: cmdInit},
		{name: "put", synopsis: "Encrypt and store a file or folder into a vault.", usage: "seavault put [--method auto|native|managed-rsync|system-rsync|rsync] [flags] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]", handler: cmdPut},
		{name: "get", synopsis: "Decrypt and retrieve one stored path to a local file.", usage: "seavault get [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH", handler: cmdGet},
		{name: "export", synopsis: "Decrypt a subtree to a local folder or zip.", usage: "seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP", handler: cmdExport},
		{name: "list", synopsis: "List the encrypted contents of a vault.", usage: "seavault list [flags] VAULT_DIR_OR_PROFILE", handler: cmdList},
		{name: "remove", aliases: []string{"rm"}, synopsis: "Remove one stored path from a vault (chunks reclaimed by gc).", usage: "seavault remove [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH", handler: cmdRemove},
		{name: "verify", bespokeHelp: true, synopsis: verifySynopsis(), usage: "seavault verify [flags] VAULT_DIR_OR_PROFILE", handler: cmdVerify},
		{name: "gc", synopsis: "Reclaim unreferenced chunks; a bare run is a dry run (exits 3 if work is pending).", usage: "seavault gc [--confirm] [--fence 72h] [--json] [flags] VAULT_DIR_OR_PROFILE", handler: cmdGC},
		{name: "compact", bespokeHelp: true, synopsis: compactSynopsis(), usage: "seavault compact [--no-keychain] VAULT_DIR_OR_PROFILE", handler: cmdCompact},
		{name: "stats", synopsis: "Report vault size, chunk, and manifest statistics.", usage: "seavault stats [flags] VAULT_DIR_OR_PROFILE", handler: cmdStats},
		{name: "serve", synopsis: "Serve a vault over local WebDAV for a network drive mount.", usage: "seavault serve [--addr 127.0.0.1:8765] [--user seavault] [--password-file PATH] [--quiet-credentials] [--allow-host NAME] [--tls-cert PATH --tls-key PATH | --tls] [--auth-limit on|off] [--drop-os-junk] [flags] VAULT_DIR_OR_PROFILE", handler: cmdServe},
		{name: "gui", synopsis: "Run the local browser GUI; subcommands: reset-config, reset-login, config-path.", usage: "seavault gui [--addr 127.0.0.1:8787] [--no-open] [--exit-on-browser-close[=false]] [--allow-host NAME] [--tls-cert PATH --tls-key PATH] [--auth-limit on|off] [--insecure-bind] [VAULT_DIR_OR_PROFILE]", handler: cmdGUI},
		{name: "app-config", aliases: []string{"config"}, synopsis: "Inspect or reset this device's local app configuration.", usage: "seavault app-config path | reset | reset-gui-login", handler: cmdAppConfig},
		{name: "move", synopsis: "Move a vault directory and update saved locations and remotes.", usage: "seavault move [--profile NAME] [--replace] SOURCE_VAULT_DIR_OR_PROFILE DEST_VAULT_DIR", handler: cmdMove},
		{name: "version", synopsis: "Print the seavault version and exit.", usage: "seavault version", handler: cmdVersion},

		// Group parents (one per group; usage line generated from children).
		{name: "profile", synopsis: "Manage saved vault locations (a name bound to a path).", handler: cmdProfile},
		{name: "vault", synopsis: "Vault format lifecycle (raise or lower the reader floor).", handler: cmdVault},
		{name: "password", synopsis: "Vault password lifecycle.", handler: cmdPassword},
		{name: "recovery", synopsis: "Recovery-key lifecycle (mint, redeem, revoke, list).", handler: cmdRecovery},
		{name: "keychain", synopsis: "Manage a vault password's OS keychain entry.", handler: cmdKeychain},
		{name: "rclone", synopsis: "Manage the bundled rclone runtime.", handler: cmdRclone},
		{name: "rsync", synopsis: "Manage the bundled rsync runtime.", handler: cmdRsync},
		{name: "remote", synopsis: "Configure and drive rclone/local remote profiles.", handler: cmdRemote},
		{name: "ssh-key", synopsis: "Generate and manage SSH keys for SFTP remotes.", handler: cmdSSHKey},
		{name: "tls", synopsis: "Manage TLS certificates for the GUI and WebDAV (U3).", handler: cmdTLS},

		// profile subcommands.
		{group: "profile", name: "add", synopsis: "Save a vault location under a name.", usage: "seavault profile add [--save-password] NAME VAULT_DIR"},
		{group: "profile", name: "save", synopsis: "Alias of add: save a vault location under a name.", usage: "seavault profile save [--save-password] NAME VAULT_DIR"},
		{group: "profile", name: "move", synopsis: "Move a saved vault to a new path and update references.", usage: "seavault profile move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR"},
		{group: "profile", name: "list", synopsis: "List saved vault locations.", usage: "seavault profile list [--status]"},
		{group: "profile", name: "remove", aliases: []string{"rm"}, synopsis: "Forget a saved vault location (vault data is left in place).", usage: "seavault profile remove NAME"},

		// vault subcommands.
		{group: "vault", name: "seal-format", synopsis: "Raise the reader floor, retiring 0.16-and-older clients.", usage: "seavault vault seal-format [--no-keychain] [--accept-rollback] [--yes] VAULT_DIR_OR_PROFILE"},
		{group: "vault", name: "unseal-format", synopsis: "Reverse seal-format while no re-key has run.", usage: "seavault vault unseal-format [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE"},

		// password subcommands.
		{group: "password", name: "change", synopsis: "Change the vault password without rewriting chunks.", usage: "seavault password change [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE"},

		// recovery subcommands.
		{group: "recovery", name: "generate", synopsis: "Mint a recovery phrase (shown once, with a read-back).", usage: "seavault recovery generate [--no-keychain] [--accept-rollback] [--save PATH] VAULT_DIR_OR_PROFILE"},
		{group: "recovery", name: "redeem", synopsis: "Redeem a recovery phrase to set a new password.", usage: "seavault recovery redeem [--accept-rollback] VAULT_DIR_OR_PROFILE"},
		{group: "recovery", name: "revoke", synopsis: "Retire one recovery entry by its ID.", usage: "seavault recovery revoke [--no-keychain] [--accept-rollback] [--yes] VAULT_DIR_OR_PROFILE ENTRY_ID"},
		{group: "recovery", name: "list", synopsis: "List recovery entry IDs available to revoke.", usage: "seavault recovery list [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE"},

		// keychain subcommands.
		{group: "keychain", name: "store", synopsis: "Store a vault password in the OS keychain.", usage: "seavault keychain store VAULT_DIR_OR_PROFILE"},
		{group: "keychain", name: "status", synopsis: "Report whether a keychain entry exists for a vault.", usage: "seavault keychain status VAULT_DIR_OR_PROFILE"},
		{group: "keychain", name: "delete", aliases: []string{"remove", "rm"}, synopsis: "Delete a vault's OS keychain entry.", usage: "seavault keychain delete [--debug] VAULT_DIR_OR_PROFILE"},

		// rclone subcommands (version and path were omitted by older usage() — C3).
		{group: "rclone", name: "status", synopsis: "Report the managed rclone runtime status.", usage: "seavault rclone status [--check-update]"},
		{group: "rclone", name: "install", synopsis: "Install a managed rclone runtime.", usage: "seavault rclone install [--version V] [--channel stable|beta] [--from-binary PATH] [--offline-archive PATH] [--offline-sha256sums PATH] [--signature optional|required|skip]"},
		{group: "rclone", name: "check-update", synopsis: "Check the latest available rclone version.", usage: "seavault rclone check-update [--channel stable|beta]"},
		{group: "rclone", name: "update", synopsis: "Update the managed rclone runtime.", usage: "seavault rclone update [--version V] [--channel C] [--signature optional|required|skip]"},
		{group: "rclone", name: "rollback", synopsis: "Roll the managed rclone runtime back one version.", usage: "seavault rclone rollback"},
		{group: "rclone", name: "version", synopsis: "Print the managed rclone binary's version.", usage: "seavault rclone version"},
		{group: "rclone", name: "path", synopsis: "Print the managed rclone binary's path.", usage: "seavault rclone path"},
		{group: "rclone", name: "verify-runtime", synopsis: "Verify the managed rclone runtime against its manifest.", usage: "seavault rclone verify-runtime"},

		// rsync subcommands.
		{group: "rsync", name: "status", synopsis: "Report the rsync runtime status.", usage: "seavault rsync status [--binary PATH] [--check-update]"},
		{group: "rsync", name: "install", synopsis: "Install a managed rsync runtime.", usage: "seavault rsync install [--version V] [--from-binary PATH] [--offline-archive PATH] [--offline-sha256sums PATH] [--runtime-base-url URL] [--build-id ID]"},
		{group: "rsync", name: "check-update", synopsis: "Check the latest available rsync source release.", usage: "seavault rsync check-update"},
		{group: "rsync", name: "update", synopsis: "Update the managed rsync runtime.", usage: "seavault rsync update [--version V] [--from-binary PATH] [--offline-archive PATH] [--offline-sha256sums PATH] [--runtime-base-url URL]"},
		{group: "rsync", name: "rollback", synopsis: "Roll the managed rsync runtime back one version.", usage: "seavault rsync rollback"},
		{group: "rsync", name: "verify-runtime", synopsis: "Verify the managed rsync runtime against its manifest.", usage: "seavault rsync verify-runtime"},
		{group: "rsync", name: "path", synopsis: "Print the managed rsync binary's path.", usage: "seavault rsync path"},

		// remote subcommands (sync and config were omitted by older usage() — C3).
		{group: "remote", name: "add", synopsis: "Create a remote profile for a vault.", usage: "seavault remote add [--backend NAME] [--type rclone|local] [--config PATH] [--transfers N] [--checkers N] [--fast-list] [--bwlimit RATE] [--allow-destructive-sync] NAME VAULT_DIR_OR_PROFILE RCLONE_REMOTE_PATH"},
		{group: "remote", name: "edit", synopsis: "Update an existing remote profile.", usage: "seavault remote edit [--backend NAME] [--type rclone|local] [--config PATH] [--transfers N] [--checkers N] [--fast-list] [--bwlimit RATE] [--allow-destructive-sync] NAME VAULT_DIR_OR_PROFILE RCLONE_REMOTE_PATH"},
		{group: "remote", name: "list", synopsis: "List remote profiles.", usage: "seavault remote list"},
		{group: "remote", name: "show", synopsis: "Show one remote profile (secrets redacted).", usage: "seavault remote show NAME"},
		{group: "remote", name: "delete", aliases: []string{"remove", "rm"}, synopsis: "Delete a remote profile.", usage: "seavault remote delete NAME"},
		{group: "remote", name: "test", synopsis: "Test connectivity for a remote profile.", usage: "seavault remote test NAME"},
		{group: "remote", name: "dry-run", synopsis: "Preview a push without transferring anything.", usage: "seavault remote dry-run NAME"},
		{group: "remote", name: "push", synopsis: "Push the vault to its remote (copy-safe).", usage: "seavault remote push NAME"},
		{group: "remote", name: "pull", synopsis: "Pull the vault from its remote (copy-safe).", usage: "seavault remote pull NAME"},
		{group: "remote", name: "check", synopsis: "Compare local and remote without transferring.", usage: "seavault remote check NAME"},
		{group: "remote", name: "sync", synopsis: "Destructive one-way sync (guarded; refused unless enabled).", usage: "seavault remote sync NAME"},
		{group: "remote", name: "config", synopsis: "Inspect or import the rclone config file.", usage: "seavault remote config path | import SRC | export-redacted [PATH] | validate [PATH] | create"},

		// ssh-key subcommands.
		{group: "ssh-key", name: "generate", synopsis: "Generate a new SSH key.", usage: "seavault ssh-key generate NAME"},
		{group: "ssh-key", name: "import", synopsis: "Import an existing private key under a name.", usage: "seavault ssh-key import NAME PRIVATE_KEY"},
		{group: "ssh-key", name: "public", synopsis: "Print the public key for a stored or given key.", usage: "seavault ssh-key public PRIVATE_KEY_OR_NAME"},
		{group: "ssh-key", name: "list", synopsis: "List managed SSH keys.", usage: "seavault ssh-key list"},

		// tls subcommands (U3). Double-dash usage lines so H1/H4 cover them like
		// every other group; execTLS is the leaf dispatcher H4 diffs against.
		{group: "tls", name: "setup", synopsis: "Interactive wizard to serve the GUI/WebDAV over HTTPS.", usage: "seavault tls setup"},
		{group: "tls", name: "use", synopsis: "Validate and adopt a certificate/key pair for TLS.", usage: "seavault tls use --cert PATH --key PATH [--allow-host NAME]"},
		{group: "tls", name: "status", synopsis: "Report the configured certificate, expiry, and Host allowlist.", usage: "seavault tls status"},
		{group: "tls", name: "check", synopsis: "Validate the configured certificate; non-zero on any error.", usage: "seavault tls check"},
		{group: "tls", name: "reset", synopsis: "Return to the default: HTTP on loopback, no certificate.", usage: "seavault tls reset"},
	}
}

// cmdVersion prints the build version. It is a registry handler so `seavault
// version` dispatches from the table like every other command.
func cmdVersion(args []string) error {
	// registry-cli-3: reject stray arguments with a usage error (exit 2), matching
	// gc/list, instead of silently accepting them. `version --help` is handled by
	// run()'s leaf-help intercept before this runs, so only non-help junk reaches
	// here.
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: seavault version")
		return &exitCodeError{code: 2, msg: fmt.Sprintf("version takes no arguments; got %q", args[0])}
	}
	fmt.Println(version)
	return nil
}
