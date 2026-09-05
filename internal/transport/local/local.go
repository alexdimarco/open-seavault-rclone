// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/transport"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

type Backend struct{ Profile remotes.Profile }

func New(p remotes.Profile) *Backend { return &Backend{Profile: remotes.Normalize(p)} }

func (b *Backend) Validate(ctx context.Context) error {
	if strings.TrimSpace(b.Profile.Vault) == "" || strings.TrimSpace(b.Profile.Remote.RemotePath) == "" {
		return fmt.Errorf("vault and remote path are required")
	}
	_, err := userpath.Abs(b.Profile.Vault)
	return err
}

func (b *Backend) Status(ctx context.Context) (transport.Status, error) {
	if err := b.Validate(ctx); err != nil {
		return transport.Status{OK: false, Message: err.Error()}, err
	}
	return transport.Status{OK: true, Message: "local copy backend ready"}, nil
}

func (b *Backend) Test(ctx context.Context) (transport.Result, error) {
	start := time.Now().UTC().Format(time.RFC3339Nano)
	err := os.MkdirAll(remoteMeta(b.Profile.Remote.RemotePath, b.Profile.Vault), 0o700)
	res := transport.Result{Operation: transport.OperationTest, OK: err == nil, StartedAt: start, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		res.Error = err.Error()
		return res, err
	}
	res.Output = "local target is writable"
	return res, nil
}

func (b *Backend) DryRunPush(ctx context.Context) (transport.Result, error) {
	return b.Push(ctx, transport.Options{DryRun: true})
}

func (b *Backend) Push(ctx context.Context, opts transport.Options) (transport.Result, error) {
	return b.copy(ctx, transport.OperationPush, localMeta(b.Profile.Vault), remoteMeta(b.Profile.Remote.RemotePath, b.Profile.Vault), opts.DryRun)
}

func (b *Backend) Pull(ctx context.Context, opts transport.Options) (transport.Result, error) {
	return b.copy(ctx, transport.OperationPull, remoteMeta(b.Profile.Remote.RemotePath, b.Profile.Vault), localMeta(b.Profile.Vault), opts.DryRun)
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
	start := time.Now().UTC().Format(time.RFC3339Nano)
	cmd := transport.Command{Program: "local", Args: []string{"compare", localMeta(b.Profile.Vault), remoteMeta(b.Profile.Remote.RemotePath, b.Profile.Vault)}}
	err := compareDirs(localMeta(b.Profile.Vault), remoteMeta(b.Profile.Remote.RemotePath, b.Profile.Vault))
	res := transport.Result{Operation: transport.OperationCheck, OK: err == nil, Commands: []transport.Command{cmd}, StartedAt: start, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		res.Error = err.Error()
		res.Output = err.Error()
	}
	return res, err
}

func (b *Backend) copy(ctx context.Context, op transport.Operation, src, dst string, dry bool) (transport.Result, error) {
	start := time.Now().UTC().Format(time.RFC3339Nano)
	cmd := transport.Command{Program: "local", Args: []string{"copy", src, dst}}
	if dry {
		cmd.Args = append([]string{"dry-run"}, cmd.Args...)
	}
	var err error
	if dry {
		_, err = os.Stat(src)
	} else {
		err = copyDir(ctx, src, dst)
	}
	res := transport.Result{Operation: op, OK: err == nil, DryRun: dry, Commands: []transport.Command{cmd}, StartedAt: start, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		res.Error = err.Error()
		res.Output = err.Error()
	} else if dry {
		res.Output = fmt.Sprintf("would copy %s to %s", src, dst)
	} else {
		res.Output = fmt.Sprintf("copied %s to %s", src, dst)
	}
	return res, err
}

// localMeta resolves the local vault's metadata directory, accepting BOTH the
// visible SeaVaultData and the legacy.seavault name.
func localMeta(root string) string {
	name, _, err := vault.ResolveMetaDir(root)
	if err != nil {
		name = vault.MetadataDirName
	}
	return filepath.Join(root, name)
}

// remoteMeta mirrors the local metadata directory name onto the remote path so a
// push/pull round-trips symmetrically for both the SeaVaultData and.seavault
// layouts. localRoot supplies the resolved name.
func remoteMeta(remote, localRoot string) string {
	name, _, err := vault.ResolveMetaDir(localRoot)
	if err != nil {
		name = vault.MetadataDirName
	}
	clean := filepath.Clean(remote)
	base := filepath.Base(clean)
	if base == "SeaVaultData" || base == vault.MetadataDirName {
		return clean
	}
	return filepath.Join(clean, name)
}

func copyDir(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func compareDirs(a, b string) error {
	return filepath.WalkDir(a, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(a, path)
		if err != nil {
			return err
		}
		ai, err := d.Info()
		if err != nil {
			return err
		}
		bi, err := os.Stat(filepath.Join(b, rel))
		if err != nil {
			return fmt.Errorf("missing remote object %s", rel)
		}
		if bi.Size() != ai.Size() {
			return fmt.Errorf("remote object size mismatch %s", rel)
		}
		return nil
	})
}
