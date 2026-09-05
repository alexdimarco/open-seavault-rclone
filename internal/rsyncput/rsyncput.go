// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncput

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/rsyncbin"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

const (
	MethodAuto         = "auto"
	MethodManagedRsync = "managed-rsync"
	MethodSystemRsync  = "system-rsync"
	MethodRsync        = "rsync" // backwards-compatible alias for system-rsync
	MethodNative       = "native"
)

type Options struct {
	Method      string
	RsyncBinary string
	KeepStaging bool
}

type Result struct {
	Method      string            `json:"method"`
	RsyncBinary string            `json:"rsyncBinary,omitempty"`
	RsyncOutput string            `json:"rsyncOutput,omitempty"`
	Results     []vault.PutResult `json:"results"`
	// Warnings carries the advisory lines the vault layer records for a put
	// : a source directory merely NAMED like a SeaVault metadata dir
	// (a second vault's SeaVaultData, a legacy.seavault in a backup tree) that
	// was imported as plain content rather than skipped. Dropping these here is
	//  — the operator sees per-file success with no advisory.
	Warnings []string `json:"warnings,omitempty"`
}

type Status struct {
	Available      bool            `json:"available"`
	Binary         string          `json:"binary,omitempty"`
	Version        string          `json:"version,omitempty"`
	Error          string          `json:"error,omitempty"`
	DefaultHint    string          `json:"defaultHint,omitempty"`
	Candidates     []string        `json:"candidates,omitempty"`
	OS             string          `json:"os,omitempty"`
	Managed        rsyncbin.Status `json:"managed"`
	Recommended    string          `json:"recommended"`
	NativeFallback bool            `json:"nativeFallback"`
}

// DefaultBinaryHint returns the most likely rsync executable path for this OS.
// It prefers the managed rsync runtime, then an executable currently on PATH,
// then common install locations.
func DefaultBinaryHint() string { return rsyncbin.DefaultBinaryHint() }

// CandidateBinaryPaths returns common rsync installation paths for user guidance.
func CandidateBinaryPaths() []string { return rsyncbin.CandidateBinaryPaths() }

func Inspect(ctx context.Context, binary string) Status {
	managed := rsyncbin.NewInstaller().Status(ctx, false)
	base := Status{DefaultHint: DefaultBinaryHint(), Candidates: CandidateBinaryPaths(), OS: runtime.GOOS, Managed: managed, NativeFallback: true, Recommended: "native"}
	if managed.Installed && managed.RuntimeOK {
		base.Available = true
		base.Binary = managed.BinaryPath
		base.Version = "rsync version " + managed.Version
		base.Recommended = MethodManagedRsync
		return base
	}
	bin, err := resolveSystemBinary(binary)
	if err != nil {
		base.Error = err.Error()
		return base
	}
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	base.Binary = bin
	if err != nil {
		base.Error = strings.TrimSpace(string(out))
		return base
	}
	base.Available = true
	base.Version = firstLine(string(out))
	base.Recommended = MethodSystemRsync
	return base
}

func PutPath(ctx context.Context, v *vault.Vault, sourcePath string, virtualPath string, opts Options) (Result, error) {
	// Refuse a source inside the encrypted metadata directory for EVERY method,
	// before any binary lookup: the guard must not depend on rsync being
	// installed (CI images have none), and the native path must not ingest
	// ciphertext or vault.json as user content either.
	if src, err := userpath.Abs(sourcePath); err == nil {
		if err := rejectMetadataSource(v.Root, src); err != nil {
			return Result{}, err
		}
	}
	originalMethod := strings.ToLower(strings.TrimSpace(opts.Method))
	method := normalizeMethod(opts.Method)
	switch method {
	case MethodNative:
		rep, err := v.PutPathReport(sourcePath, virtualPath)
		return Result{Method: MethodNative, Results: rep.Results, Warnings: rep.Warnings}, err
	case MethodManagedRsync:
		bin, err := rsyncbin.BinaryPath()
		if err != nil {
			return Result{}, err
		}
		return putViaRsync(ctx, v, sourcePath, virtualPath, opts, bin, MethodManagedRsync)
	case MethodSystemRsync:
		bin, err := resolveSystemBinary(opts.RsyncBinary)
		if err != nil {
			return Result{}, err
		}
		label := MethodSystemRsync
		if originalMethod == MethodRsync {
			label = MethodRsync
		}
		return putViaRsync(ctx, v, sourcePath, virtualPath, opts, bin, label)
	case MethodAuto:
		if bin, err := rsyncbin.BinaryPath(); err == nil {
			return putViaRsync(ctx, v, sourcePath, virtualPath, opts, bin, MethodManagedRsync)
		}
		if bin, err := resolveSystemBinary(opts.RsyncBinary); err == nil {
			return putViaRsync(ctx, v, sourcePath, virtualPath, opts, bin, MethodSystemRsync)
		}
		rep, putErr := v.PutPathReport(sourcePath, virtualPath)
		return Result{Method: MethodNative, Results: rep.Results, Warnings: rep.Warnings}, putErr
	default:
		return Result{}, fmt.Errorf("unsupported put method %q; use auto, native, managed-rsync, system-rsync, or rsync", opts.Method)
	}
}

func normalizeMethod(method string) string {
	method = strings.ToLower(strings.TrimSpace(method))
	switch method {
	case "", MethodAuto:
		return MethodAuto
	case MethodNative:
		return MethodNative
	case MethodManagedRsync, "managed", "app-rsync":
		return MethodManagedRsync
	case MethodSystemRsync, MethodRsync, "system":
		return MethodSystemRsync
	default:
		return method
	}
}

func putViaRsync(ctx context.Context, v *vault.Vault, sourcePath string, virtualPath string, opts Options, bin string, method string) (Result, error) {
	src, err := userpath.Abs(sourcePath)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(src)
	if err != nil {
		return Result{}, err
	}
	if err := rejectMetadataSource(v.Root, src); err != nil {
		return Result{}, err
	}
	tmp, err := os.MkdirTemp("", "seavault-rsync-put-*")
	if err != nil {
		return Result{}, err
	}
	if !opts.KeepStaging {
		defer os.RemoveAll(tmp)
	}

	// Exclude exactly THIS vault's own metadata directory, anchored to its relative
	// path within the source, rather than an unanchored any-depth name match
	// . A foreign metadata-named directory nested in the source is
	// therefore staged and imported as plain content (PutPath warns about it),
	// never silently dropped here.
	args := []string{"-a"}
	if rel, rerr := filepath.Rel(src, v.MetaRoot); rerr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "." {
		args = append(args, "--exclude", "/"+filepath.ToSlash(rel)+"/")
	}
	args = append(args,
		"--exclude", ".git/",
		src,
		tmp+string(os.PathSeparator),
	)
	cmd := exec.CommandContext(ctx, bin, args...)
	outBytes, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(outBytes))
	if err != nil {
		return Result{Method: method, RsyncBinary: bin, RsyncOutput: out}, fmt.Errorf("rsync staging failed: %w: %s", err, out)
	}

	staged := filepath.Join(tmp, filepath.Base(src))
	if _, err := os.Stat(staged); err != nil {
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		return Result{Method: method, RsyncBinary: bin, RsyncOutput: out}, fmt.Errorf("rsync staged %s was not found at %s", kind, staged)
	}
	rep, err := v.PutPathReport(staged, virtualPath)
	return Result{Method: method, RsyncBinary: bin, RsyncOutput: out, Results: rep.Results, Warnings: rep.Warnings}, err
}

func resolveSystemBinary(binary string) (string, error) {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "rsync"
	}
	if strings.ContainsAny(binary, `/\\`) {
		abs, err := userpath.Abs(binary)
		if err != nil {
			return "", err
		}
		if st, err := os.Stat(abs); err != nil {
			return "", err
		} else if st.IsDir() {
			return "", fmt.Errorf("rsync binary path %q is a directory", abs)
		}
		return abs, nil
	}
	p, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("system rsync was not found; use --method native or install managed rsync")
	}
	return p, nil
}

func rejectMetadataSource(vaultRoot, src string) error {
	root, err := userpath.Abs(vaultRoot)
	if err != nil {
		return err
	}
	// Refuse a source under EITHER metadata directory name of THIS vault (design
	// ): both the visible SeaVaultData and the legacy.seavault layout.
	for _, name := range vault.MetadataDirNames {
		meta := filepath.Join(root, name)
		rootRel, relErr := filepath.Rel(meta, src)
		if relErr == nil && rootRel != ".." && !strings.HasPrefix(rootRel, ".."+string(os.PathSeparator)) {
			return errors.New("refusing to put files from inside the encrypted vault metadata directory (" + name + ")")
		}
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
