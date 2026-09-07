// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclone

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/transport"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

type Runner interface {
	Run(ctx context.Context, args []string) (string, error)
	Path() string
}

type CommandRunner struct {
	Binary string
	Env    []string
}

func NewCommandRunner() (*CommandRunner, error) {
	p, err := rclonebin.BinaryPath()
	if err != nil {
		return nil, err
	}
	return &CommandRunner{Binary: p}, nil
}

func (r *CommandRunner) Path() string { return r.Binary }

func (r *CommandRunner) Run(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Env = append(os.Environ(), r.Env...)
	out, err := cmd.CombinedOutput()
	redacted := Redact(string(out))
	if err != nil {
		return redacted, fmt.Errorf("rclone %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(redacted))
	}
	return redacted, nil
}

type Backend struct {
	Profile remotes.Profile
	Runner  Runner
}

func New(binary string, p remotes.Profile) *Backend {
	return NewWithRunner(p, &CommandRunner{Binary: binary})
}

func NewManaged(p remotes.Profile) (*Backend, error) {
	r, err := NewCommandRunner()
	if err != nil {
		return nil, err
	}
	return NewWithRunner(p, r), nil
}

func NewWithRunner(p remotes.Profile, r Runner) *Backend {
	return &Backend{Profile: remotes.Normalize(p), Runner: r}
}

func (b *Backend) Validate(ctx context.Context) error {
	p := remotes.Normalize(b.Profile)
	if err := remotes.Validate(p); err != nil {
		return err
	}
	if b.Runner == nil {
		return errors.New("managed rclone runner is not configured")
	}
	if _, err := userpath.Abs(p.Vault); err != nil {
		return err
	}
	if strings.TrimSpace(p.Remote.RcloneConfigPath) != "" {
		if err := ensureConfigFile(p.Remote.RcloneConfigPath); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) Status(ctx context.Context) (transport.Status, error) {
	if err := b.Validate(ctx); err != nil {
		return transport.Status{OK: false, Message: err.Error()}, err
	}
	out, err := b.Runner.Run(ctx, []string{"version"})
	if err != nil {
		return transport.Status{OK: false, Message: err.Error()}, err
	}
	return transport.Status{OK: true, Message: firstLine(out)}, nil
}

func (b *Backend) DryRunPush(ctx context.Context) (transport.Result, error) {
	return b.Push(ctx, transport.Options{DryRun: true})
}

func (b *Backend) Push(ctx context.Context, opts transport.Options) (transport.Result, error) {
	return b.runSequence(ctx, transport.OperationPush, opts.DryRun, pushSequence(b.Profile))
}

func (b *Backend) Pull(ctx context.Context, opts transport.Options) (transport.Result, error) {
	return b.runSequence(ctx, transport.OperationPull, opts.DryRun, pullSequence(b.Profile))
}

func (b *Backend) Sync(ctx context.Context, opts transport.Options) (transport.Result, error) {
	start := time.Now().UTC().Format(time.RFC3339Nano)
	pull, err := b.Pull(ctx, opts)
	if err != nil {
		return pull, err
	}
	push, err := b.Push(ctx, opts)
	out := strings.TrimSpace(pull.Output + "\n" + push.Output)
	res := transport.Result{Operation: transport.OperationSync, OK: err == nil, DryRun: opts.DryRun, Commands: append(pull.Commands, push.Commands...), Output: out, StartedAt: start, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		res.Error = err.Error()
	}
	return res, err
}

func (b *Backend) Check(ctx context.Context) (transport.Result, error) {
	p := remotes.Normalize(b.Profile)
	src := localMeta(p.Vault)
	dst := remoteMeta(p.Remote.RemotePath, p.Vault)
	args := appendBaseArgs(p, []string{"check", src, dst, "--size-only", "--one-way"})
	return b.runSequence(ctx, transport.OperationCheck, false, [][]string{args})
}

func (b *Backend) Test(ctx context.Context) (transport.Result, error) {
	p := remotes.Normalize(b.Profile)
	seq := [][]string{{"version"}, appendBaseArgs(p, []string{"lsf", remoteMeta(p.Remote.RemotePath, p.Vault), "--max-depth", "1"})}
	return b.runSequence(ctx, transport.OperationTest, false, seq)
}

func (b *Backend) runSequence(ctx context.Context, op transport.Operation, dry bool, seq [][]string) (transport.Result, error) {
	start := time.Now().UTC().Format(time.RFC3339Nano)
	res := transport.Result{Operation: op, DryRun: dry, StartedAt: start}
	if err := b.Validate(ctx); err != nil {
		res.Error = err.Error()
		res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return res, err
	}
	var outputs []string
	for _, args := range seq {
		if dry && isTransferCommand(args) && !hasArg(args, "--dry-run") {
			args = append(args, "--dry-run")
		}
		cmd := transport.Command{Program: b.Runner.Path(), Args: redactArgs(args)}
		out, err := b.Runner.Run(ctx, args)
		cmd.Output = strings.TrimSpace(out)
		res.Commands = append(res.Commands, cmd)
		if strings.TrimSpace(out) != "" {
			outputs = append(outputs, strings.TrimSpace(out))
		}
		if err != nil {
			res.OK = false
			res.Error = err.Error()
			res.Output = strings.Join(outputs, "\n")
			res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			return res, err
		}
	}
	res.OK = true
	res.Output = strings.Join(outputs, "\n")
	res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return res, nil
}

func pushSequence(p remotes.Profile) [][]string {
	p = remotes.Normalize(p)
	root := remoteMeta(p.Remote.RemotePath, p.Vault)
	src := localMeta(p.Vault)
	seq := [][]string{}
	seq = append(seq, appendBaseArgs(p, []string{"mkdir", root}))
	seq = append(seq, appendBaseArgs(p, []string{"copy", filepath.Join(src, "objects", "chunks"), joinRemote(root, "objects/chunks")}))
	seq = append(seq, appendBaseArgs(p, []string{"copy", filepath.Join(src, "manifests"), joinRemote(root, "manifests")}))
	if dirExists(filepath.Join(src, "tombstones")) {
		seq = append(seq, appendBaseArgs(p, []string{"copy", filepath.Join(src, "tombstones"), joinRemote(root, "tombstones")}))
	}
	seq = append(seq, appendBaseArgs(p, []string{"copy", filepath.Join(src, vault.ConfigFileName), root}))
	return seq
}

func pullSequence(p remotes.Profile) [][]string {
	p = remotes.Normalize(p)
	root := remoteMeta(p.Remote.RemotePath, p.Vault)
	dst := localMeta(p.Vault)
	return [][]string{appendBaseArgs(p, []string{"copy", root, dst})}
}

func appendBaseArgs(p remotes.Profile, args []string) []string {
	p = remotes.Normalize(p)
	out := append([]string(nil), args...)
	if strings.TrimSpace(p.Remote.RcloneConfigPath) != "" {
		cfg, err := userpath.Abs(p.Remote.RcloneConfigPath)
		if err == nil {
			out = append(out, "--config", cfg)
		} else {
			out = append(out, "--config", p.Remote.RcloneConfigPath)
		}
	}
	out = append(out, "--log-format", "date,time,level,msg")
	if isTransferCommand(args) {
		out = append(out, "--transfers", fmt.Sprintf("%d", p.Remote.Transfers))
		out = append(out, "--checkers", fmt.Sprintf("%d", p.Remote.Checkers))
		out = append(out, "--stats", "1s")
		out = append(out, "--progress")
		if p.Remote.FastList {
			out = append(out, "--fast-list")
		}
		if strings.TrimSpace(p.Remote.BandwidthLimit) != "" {
			out = append(out, "--bwlimit", p.Remote.BandwidthLimit)
		}
	}
	return out
}

func isTransferCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "copy", "copyto", "sync", "check":
		return true
	default:
		return false
	}
}

// localMeta resolves the local vault's metadata directory, accepting BOTH the
// visible SeaVaultData and the legacy.seavault name.
func localMeta(root string) string {
	abs, err := userpath.Abs(root)
	if err == nil {
		root = abs
	}
	name, _, rerr := vault.ResolveMetaDir(root)
	if rerr != nil {
		name = vault.MetadataDirName
	}
	return filepath.Join(root, name)
}

// remoteMeta mirrors the local metadata directory name onto the remote path so a
// push/pull round-trips symmetrically for both layouts. localRoot
// supplies the resolved name; a remote path already ending in either metadata
// name is used as-is.
func remoteMeta(remote, localRoot string) string {
	r := strings.TrimSpace(remote)
	if r == "" {
		return r
	}
	name, _, err := vault.ResolveMetaDir(localRoot)
	if err != nil {
		name = vault.MetadataDirName
	}
	trim := strings.TrimRight(r, `/\`)
	for _, n := range vault.MetadataDirNames {
		if strings.HasSuffix(trim, "/"+n) || strings.HasSuffix(trim, "\\"+n) || strings.HasSuffix(trim, ":"+n) || trim == n {
			return trim
		}
	}
	return joinRemote(trim, name)
}

func joinRemote(base, elem string) string {
	base = strings.TrimRight(strings.TrimSpace(base), `/\`)
	elem = strings.TrimLeft(strings.ReplaceAll(elem, "\\", "/"), "/")
	if base == "" {
		return elem
	}
	return base + "/" + elem
}

func ensureConfigFile(path string) error {
	p, err := userpath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(p, []byte("# open-seavault-rclone managed rclone configuration\n"), 0o600)
	} else {
		return err
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func hasArg(args []string, arg string) bool {
	for _, a := range args {
		if a == arg {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return s
}

func Redact(s string) string {
	return rclonebin.RedactText(s)
}

func redactArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		lower := strings.ToLower(a)
		if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "pass") {
			if strings.Contains(a, "=") {
				parts := strings.SplitN(a, "=", 2)
				out[i] = parts[0] + "=[REDACTED]"
			} else if i+1 < len(out) {
				out[i+1] = "[REDACTED]"
			}
		}
	}
	return out
}
