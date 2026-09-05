// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"bufio"
	"context"
	"crypto/rand"
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
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/importer"
	"github.com/alexdimarco/open-seavault-rclone/internal/keychain"
	"github.com/alexdimarco/open-seavault-rclone/internal/localdav"
	"github.com/alexdimarco/open-seavault-rclone/internal/passphrase"
	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/rsyncbin"
	"github.com/alexdimarco/open-seavault-rclone/internal/rsyncput"
	"github.com/alexdimarco/open-seavault-rclone/internal/sshkeys"
	"github.com/alexdimarco/open-seavault-rclone/internal/transport"
	localtransport "github.com/alexdimarco/open-seavault-rclone/internal/transport/local"
	rclonetransport "github.com/alexdimarco/open-seavault-rclone/internal/transport/rclone"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
	"github.com/alexdimarco/open-seavault-rclone/internal/vaultmove"
	"github.com/alexdimarco/open-seavault-rclone/internal/webui"
)

const version = "0.17.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "put":
		err = cmdPut(os.Args[2:])
	case "get":
		err = cmdGet(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "remove", "rm":
		err = cmdRemove(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "gc":
		err = cmdGC(os.Args[2:])
	case "compact":
		err = cmdCompact(os.Args[2:])
	case "stats":
		err = cmdStats(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "gui":
		err = cmdGUI(os.Args[2:])
	case "app-config", "config":
		err = cmdAppConfig(os.Args[2:])
	case "profile":
		err = cmdProfile(os.Args[2:])
	case "move":
		err = cmdMove(os.Args[2:])
	case "vault":
		err = cmdVault(os.Args[2:])
	case "password":
		err = cmdPassword(os.Args[2:])
	case "recovery":
		err = cmdRecovery(os.Args[2:])
	case "keychain":
		err = cmdKeychain(os.Args[2:])
	case "rclone":
		err = cmdRclone(os.Args[2:])
	case "rsync":
		err = cmdRsync(os.Args[2:])
	case "remote":
		err = cmdRemote(os.Args[2:])
	case "ssh-key":
		err = cmdSSHKey(os.Args[2:])
	case "version":
		fmt.Println(version)
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		// A command that wants a specific, non-1 process exit code (e.g. the gc
		// dry-run "action required" code 3) returns an
		// *exitCodeError. It carries its own exit code and has already written any
		// human message itself, so main neither prints "error:" nor forces exit 1.
		var ec *exitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
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
	password, _, err := resolveVaultPasswordSource(vaultPath, useKeychain)
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
	return v, nil
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
	// Surface the advisory lines (a source directory named like a SeaVault
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

// ensureLoopbackBind refuses a non-loopback listen address for endpoints that
// serve DECRYPTED vault content (the GUI and the WebDAV endpoint). Exposing
// those off localhost would let the network reach plaintext, so a non-loopback
// bind requires an explicit --insecure-bind override.
func ensureLoopbackBind(addr string, allowNonLoopback bool) error {
	if allowNonLoopback {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("refusing to bind %q: an empty host listens on all interfaces and would expose decrypted content; use 127.0.0.1 or pass --insecure-bind", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to bind %q: %q is not a loopback address, and this endpoint serves DECRYPTED content. Keep it on 127.0.0.1/localhost, or pass --insecure-bind to override (not recommended)", addr, host)
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
// values. See.
func allowedHostsForBind(addr string, extra []string) []string {
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
	return hosts
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
	return fmt.Errorf("could not listen on %s: %w. If another SeaVault GUI or serve is already running, open its link instead, or choose a different --addr", addr, err)
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
	var allowHost repeatableString
	fs.Var(&allowHost, "allow-host", "additional Host header value to accept besides loopback/localhost (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault serve [--addr 127.0.0.1:8765] [--user seavault] [--password-file PATH] [--quiet-credentials] [--allow-host NAME] [--drop-os-junk] [--no-keychain] [--insecure-bind] VAULT_DIR_OR_PROFILE")
	}
	if err := ensureLoopbackBind(*addr, *insecureBind); err != nil {
		return err
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
	dav.AllowedHosts = allowedHostsForBind(*addr, allowHost)
	dav.DropOSJunk = *dropOSJunk
	fmt.Printf("serving local WebDAV-compatible vault at http://%s/\n", *addr)
	fmt.Println("bind is local by default; do not expose this listener on an untrusted network")
	if printCredentials {
		fmt.Printf("WebDAV credentials: %s / %s\n", credUser, credPassword)
		fmt.Printf("URL: http://%s:%s@%s/\n", credUser, credPassword, *addr)
		if generatedPassword {
			if fi, statErr := os.Stdout.Stat(); statErr == nil && stdoutLooksRedirected(fi) {
				fmt.Println("warning: this credential is being written to a non-terminal stdout (log/redirect); prefer --password-file with --quiet-credentials for daemons")
			}
		}
	}
	srv := buildLoopbackServer(*addr, dav)
	return listenErrorHint(*addr, srv.ListenAndServe())
}

const guiAuthAccount = "seavault-gui-http-auth"

func cmdAppConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: seavault app-config path|reset|reset-gui-login")
	}
	switch args[0] {
	case "path":
		p, err := appconfig.Path()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	case "reset", "reset-config":
		return resetLocalAppConfiguration(true)
	case "reset-gui-login", "clear-gui-login", "reset-password":
		return resetLocalAppConfiguration(false)
	default:
		return fmt.Errorf("usage: seavault app-config path|reset|reset-gui-login")
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
		fmt.Printf("reset SeaVault local app configuration at %s\n", p)
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
	fmt.Printf("reset SeaVault GUI login in %s\n", p)
	fmt.Println("restart SeaVault or reload the GUI; browser sessions are invalidated when the server restarts")
	return nil
}

func cmdGUI(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "reset", "reset-config":
			return resetLocalAppConfiguration(true)
		case "reset-login", "reset-password", "clear-login":
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
	var allowHost repeatableString
	fs.Var(&allowHost, "allow-host", "additional Host header value to accept besides loopback/localhost (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	initial := ""
	if fs.NArg() > 1 {
		return fmt.Errorf("usage: seavault gui [--addr 127.0.0.1:8787] [--no-open] [--allow-host NAME] [--insecure-bind] [VAULT_DIR_OR_PROFILE]")
	}
	if err := ensureLoopbackBind(*addr, *insecureBind); err != nil {
		return err
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
	if strings.EqualFold(cfg.GUI.Protocol, "https") {
		host := *addr
		if h, _, splitErr := net.SplitHostPort(*addr); splitErr == nil {
			host = h
		}
		cfg, err = appconfig.EnsureSelfSignedCertificate(cfg, host)
		if err != nil {
			return err
		}
		if saveErr := appconfig.Save(cfg); saveErr != nil {
			return saveErr
		}
	}
	s, err := webui.NewWithConfig(initial, cfg)
	if err != nil {
		return err
	}
	s.AllowedHosts = allowedHostsForBind(*addr, allowHost)
	// Pick up changes made to.seavault by an external sync client (e.g. the
	// Nextcloud desktop client) underneath this long-lived GUI server.
	stopWatcher := s.StartSyncWatcher(2 * time.Second)
	defer stopWatcher()
	scheme := "http"
	if strings.EqualFold(cfg.GUI.Protocol, "https") {
		scheme = "https"
	}
	launchURL := s.LaunchURL(scheme + "://" + *addr)
	fmt.Printf("serving local GUI at %s\n", launchURL)
	fmt.Println("open this exact launch link; a bare " + scheme + "://" + *addr + "/ no longer shows the app, and the launch secret rotates each launch, so bookmarks break by design")
	fmt.Println("bind is local by default; do not expose this listener on an untrusted network")
	if *exitOnBrowserClose {
		s.EnableBrowserCloseShutdown(10 * time.Second)
		fmt.Println("exit-on-browser-close enabled; the GUI will stop shortly after the browser page closes")
	}
	printLaunchGuidance(os.Stdout, os.Stderr, launchURL, !*noOpen, openBrowser)
	srv := buildLoopbackServer(*addr, s)
	serveErr := make(chan error, 1)
	go func() {
		if scheme == "https" {
			serveErr <- srv.ListenAndServeTLS(cfg.GUI.CertFile, cfg.GUI.KeyFile)
			return
		}
		serveErr <- srv.ListenAndServe()
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

func cmdProfile(args []string) error {
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
			status, keychainStatus := "missing", "no keychain entry"
			if cfg, err := vault.ReadConfig(e.VaultPath); err == nil {
				status = "vault exists"
				if cfg.VaultID != "" {
					if p, err := keychain.Get(cfg.VaultID); err == nil && p != "" {
						keychainStatus = "keychain saved"
					}
				}
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", e.Name, e.VaultPath, status, keychainStatus)
		}
		return nil
	case "remove", "rm":
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault profile remove NAME")
		}
		return profile.Remove(args[1])
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

// cmdPassword implements `seavault password change`: rotate
// the vault password by rewrapping the same master||index bundle (no chunk or
// manifest rewrite) and refreshing the OS keychain entry when one exists.
func cmdPassword(args []string) error {
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
func cmdRecovery(args []string) error {
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

func cmdRecoveryGenerate(args []string) error {
	fs := flag.NewFlagSet("recovery generate", flag.ExitOnError)
	noKeychain := fs.Bool("no-keychain", false, "do not try the OS keychain for the current password")
	acceptRollback := fs.Bool("accept-rollback", false, "open a config older than this device last saw (a restore from backup)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: seavault recovery generate [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	phrase, commit, err := v.PrepareRecovery()
	if err != nil {
		return err
	}
	fmt.Println("Recovery phrase — write it down and store it safely. It is shown ONCE and never stored:")
	fmt.Println()
	fmt.Println("    " + phrase)
	fmt.Println()
	// MANDATORY read-back before commit: the owner
	// re-enters the phrase, verified against the in-memory value; a mismatch aborts
	// with nothing written.
	readback, err := readRecoveryPhrasePrompt("Re-enter the recovery phrase to confirm: ")
	if err != nil {
		return err
	}
	if !vault.RecoveryPhraseMatches(phrase, readback) {
		return fmt.Errorf("the re-entered phrase did not match; nothing was written — run `recovery generate` again")
	}
	if err := commit(); err != nil {
		return err
	}
	fmt.Println("recovery key added")
	return nil
}

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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: seavault recovery revoke [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE ENTRY_ID")
	}
	vaultPath, err := resolveVaultArg(fs.Arg(0))
	if err != nil {
		return err
	}
	v, err := openVaultForCLI(vaultPath, !*noKeychain, *acceptRollback)
	if err != nil {
		return err
	}
	if err := v.RevokeRecovery(fs.Arg(1)); err != nil {
		return err
	}
	fmt.Printf("revoked recovery entry %s\n", fs.Arg(1))
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
	count := 0
	for _, ref := range v.WrapEntryRefs() {
		if ref.Type == vault.WrapTypeRecovery {
			fmt.Println(ref.ID)
			count++
		}
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no recovery keys are registered for this vault")
	}
	return nil
}

// cmdVault implements `seavault vault seal-format|unseal-format VAULT` (design
// ): the operator's explicit end of the grace release and its
// reversal. seal-format retires SeaVault 0.16 and older by bumping the on-disk
// Version to 3 and raising MinReader to 3 in one MAC'd rewrite; unseal-format
// reverses it while no A3 directory-ID re-key has run.
func cmdVault(args []string) error {
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
		ok, err := confirmPrompt("Seal the vault format now? This retires SeaVault 0.16 and older for every device. [y/N]: ")
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
	fmt.Printf("sealed %s: version %d, minReader %d — SeaVault 0.16 and older can no longer open it (format epoch %d)\n", vaultPath, v.Config.Version, v.Config.MinReader, v.Config.FormatEpoch)
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
	fmt.Printf("unsealed %s: version %d, minReader %d — SeaVault 0.16 and older can open it again (format epoch %d)\n", vaultPath, v.Config.Version, v.Config.MinReader, v.Config.FormatEpoch)
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
		return "SeaVault has no inventory of your other devices; sealing now will lock out any device still on 0.16 or older with no automatic recovery. Confirm every device is upgraded first.\n"
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

func cmdKeychain(args []string) error {
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
		if len(args) != 2 {
			return fmt.Errorf("usage: seavault keychain delete VAULT_DIR_OR_PROFILE")
		}
		vaultPath, err := resolveVaultArg(args[1])
		if err != nil {
			return err
		}
		cfg, err := vault.ReadConfig(vaultPath)
		if err != nil {
			return err
		}
		if err := keychain.Delete(cfg.VaultID); err != nil {
			return err
		}
		fmt.Println("OS keychain entry deleted")
		return nil
	default:
		return fmt.Errorf("unknown keychain command %q", args[0])
	}
}

func cmdRsync(args []string) error {
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
		offlineArchive := fs.String("offline-archive", "", "install from a local SeaVault rsync runtime zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		runtimeBase := fs.String("runtime-base-url", "", "base URL for SeaVault-built rsync runtime artifacts")
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
		offlineArchive := fs.String("offline-archive", "", "install from a local SeaVault rsync runtime zip archive")
		offlineSHA := fs.String("offline-sha256sums", "", "SHA256SUMS file for --offline-archive")
		runtimeBase := fs.String("runtime-base-url", "", "base URL for SeaVault-built rsync runtime artifacts")
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

func cmdRclone(args []string) error {
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

func cmdRemote(args []string) error {
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

func cmdSSHKey(args []string) error {
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

func usage() {
	fmt.Fprint(os.Stderr, usageText())
}

func usageText() string {
	return fmt.Sprintf(`seavault %s

Cloud-folder client-side encrypted storage.

Usage:
  seavault init [flags] VAULT_DIR
  seavault put [--method auto|native|managed-rsync|system-rsync|rsync] [flags] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]
  seavault get [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH
  seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP
  seavault list [flags] VAULT_DIR_OR_PROFILE
  seavault remove [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH
  seavault verify [flags] VAULT_DIR_OR_PROFILE
  seavault gc [--confirm] [--fence 72h] [--json] [flags] VAULT_DIR_OR_PROFILE
  seavault compact [flags] VAULT_DIR_OR_PROFILE
  seavault stats [flags] VAULT_DIR_OR_PROFILE
  seavault serve [--addr 127.0.0.1:8765] [--user seavault] [--password-file PATH] [--quiet-credentials] [--allow-host NAME] [--drop-os-junk] [flags] VAULT_DIR_OR_PROFILE
  seavault gui [--addr 127.0.0.1:8787] [--no-open] [--allow-host NAME] [flags] [VAULT_DIR_OR_PROFILE]
  seavault gui reset-config | reset-login | config-path
  seavault app-config path | reset | reset-gui-login
  seavault profile add [--save-password] NAME VAULT_DIR
  seavault profile save [--save-password] NAME VAULT_DIR
  seavault profile move [--replace] [--update-remotes=true] NAME NEW_VAULT_DIR
  seavault move [--profile NAME] [--replace] SOURCE_VAULT_DIR_OR_PROFILE DEST_VAULT_DIR
  seavault profile list [--status]
  seavault profile remove NAME
  seavault password change [--no-keychain] [--accept-rollback] VAULT_DIR_OR_PROFILE
  seavault recovery generate | redeem | list VAULT_DIR_OR_PROFILE
  seavault recovery revoke VAULT_DIR_OR_PROFILE ENTRY_ID
  seavault vault seal-format [--yes] VAULT_DIR_OR_PROFILE
  seavault vault unseal-format VAULT_DIR_OR_PROFILE
  seavault keychain store VAULT_DIR_OR_PROFILE
  seavault keychain status VAULT_DIR_OR_PROFILE
  seavault keychain delete VAULT_DIR_OR_PROFILE
  seavault rclone status | install | check-update | update | rollback | verify-runtime
  seavault rsync status | install | check-update | update | rollback | verify-runtime | path
  seavault remote add NAME VAULT_DIR_OR_PROFILE RCLONE_REMOTE_PATH
  seavault remote list | show NAME | test NAME | dry-run NAME | push NAME | pull NAME | check NAME
  seavault ssh-key generate NAME | list | public NAME | import NAME PRIVATE_KEY

VAULT_DIR is the encrypted folder. Put it inside any local cloud-sync directory.
Passwords are read from SEAVAULT_PASSWORD, then OS keychain, then a hidden prompt.
The serve command uses a separate WebDAV credential: SEAVAULT_SERVE_PASSWORD or --password-file (otherwise generated and printed once).
A bare "seavault gc" is a dry run: if it finds chunks it would reclaim, it writes an advisory to stderr and exits 3 (action required, not an error) so scripted callers detect that nothing was reclaimed without --confirm.
`, version)
}
