// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

const (
	ModeAuto   = "auto"
	ModeRsync  = "rsync"
	ModeDirect = "direct"
)

type Options struct {
	Mode                string
	RsyncPath           string
	PreserveRootOnEmpty bool
}

type Report struct {
	Mode       string   `json:"mode"`
	UsedRsync  bool     `json:"usedRsync"`
	RsyncPath  string   `json:"rsyncPath,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Warning    string   `json:"warning,omitempty"`
	SourceKind string   `json:"sourceKind"`
}

type Result struct {
	Report  Report            `json:"report"`
	Results []vault.PutResult `json:"results"`
}

func Status(rsyncPath string) Report {
	bin, err := resolveRsync(rsyncPath)
	if err != nil {
		return Report{Mode: ModeRsync, UsedRsync: false, Warning: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	rep := Report{Mode: ModeRsync, UsedRsync: true, RsyncPath: bin, Command: []string{bin, "--version"}, Output: firstLine(string(out))}
	if err != nil {
		rep.Warning = strings.TrimSpace(fmt.Sprintf("%v: %s", err, out))
	}
	return rep
}

func PutPath(ctx context.Context, v *vault.Vault, sourcePath, virtualPath string, opts Options) (Result, error) {
	mode, err := normalizeMode(opts.Mode)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return Result{}, err
	}
	if mode == ModeDirect {
		res, err := putDirect(v, sourcePath, virtualPath, info, opts.PreserveRootOnEmpty)
		return Result{Report: Report{Mode: mode, UsedRsync: false, SourceKind: kind(info)}, Results: res}, err
	}
	bin, err := resolveRsync(opts.RsyncPath)
	if err != nil {
		if mode == ModeRsync {
			return Result{Report: Report{Mode: mode, UsedRsync: false, Warning: err.Error(), SourceKind: kind(info)}}, err
		}
		res, putErr := putDirect(v, sourcePath, virtualPath, info, opts.PreserveRootOnEmpty)
		warn := "rsync unavailable; used direct ingestion fallback: " + err.Error()
		return Result{Report: Report{Mode: mode, UsedRsync: false, Warning: warn, SourceKind: kind(info)}, Results: res}, putErr
	}
	res, rep, err := putViaRsync(ctx, v, bin, sourcePath, virtualPath, info, opts.PreserveRootOnEmpty)
	if err != nil {
		return Result{Report: rep}, err
	}
	return Result{Report: rep, Results: res}, nil
}

func PutDirectoryContents(ctx context.Context, v *vault.Vault, sourceDir, virtualBase string, opts Options) (Result, error) {
	mode, err := normalizeMode(opts.Mode)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(sourceDir)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("source %s is not a directory", sourceDir)
	}
	if mode == ModeDirect {
		res, err := v.PutDirectoryContents(sourceDir, virtualBase)
		return Result{Report: Report{Mode: mode, UsedRsync: false, SourceKind: "directory"}, Results: res}, err
	}
	bin, err := resolveRsync(opts.RsyncPath)
	if err != nil {
		if mode == ModeRsync {
			return Result{Report: Report{Mode: mode, UsedRsync: false, Warning: err.Error(), SourceKind: "directory"}}, err
		}
		res, putErr := v.PutDirectoryContents(sourceDir, virtualBase)
		warn := "rsync unavailable; used direct ingestion fallback: " + err.Error()
		return Result{Report: Report{Mode: mode, UsedRsync: false, Warning: warn, SourceKind: "directory"}, Results: res}, putErr
	}
	stage, err := os.MkdirTemp("", "seavault-rsync-ingest-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(stage)
	cmdArgs := []string{"-a", "--delete", ensureTrailingSep(sourceDir), ensureTrailingSep(stage)}
	out, runErr := runRsync(ctx, bin, cmdArgs)
	rep := Report{Mode: mode, UsedRsync: true, RsyncPath: bin, Command: append([]string{bin}, cmdArgs...), Output: strings.TrimSpace(out), SourceKind: "directory"}
	if runErr != nil {
		rep.Warning = strings.TrimSpace(out)
		return nilResult(rep), fmt.Errorf("rsync ingest staging failed: %w", runErr)
	}
	res, err := v.PutDirectoryContents(stage, virtualBase)
	return Result{Report: rep, Results: res}, err
}

func putViaRsync(ctx context.Context, v *vault.Vault, bin string, sourcePath, virtualPath string, info os.FileInfo, preserveRoot bool) ([]vault.PutResult, Report, error) {
	stageRoot, err := os.MkdirTemp("", "seavault-rsync-ingest-*")
	if err != nil {
		return nil, Report{}, err
	}
	defer os.RemoveAll(stageRoot)

	var args []string
	var stagedPath string
	if info.IsDir() {
		stagedPath = filepath.Join(stageRoot, "contents")
		if err := os.MkdirAll(stagedPath, 0o700); err != nil {
			return nil, Report{}, err
		}
		args = []string{"-a", "--delete", ensureTrailingSep(sourcePath), ensureTrailingSep(stagedPath)}
	} else {
		stagedPath = filepath.Join(stageRoot, filepath.Base(sourcePath))
		args = []string{"-a", sourcePath, ensureTrailingSep(stageRoot)}
	}
	out, runErr := runRsync(ctx, bin, args)
	rep := Report{Mode: ModeRsync, UsedRsync: true, RsyncPath: bin, Command: append([]string{bin}, args...), Output: strings.TrimSpace(out), SourceKind: kind(info)}
	if runErr != nil {
		rep.Warning = strings.TrimSpace(out)
		return nil, rep, fmt.Errorf("rsync ingest staging failed: %w", runErr)
	}
	if info.IsDir() {
		base := strings.TrimSpace(virtualPath)
		if base == "" && preserveRoot {
			base = filepath.Base(sourcePath)
		}
		res, err := v.PutDirectoryContents(stagedPath, base)
		return res, rep, err
	}
	res, err := v.PutPath(stagedPath, virtualPath)
	return res, rep, err
}

func putDirect(v *vault.Vault, sourcePath, virtualPath string, info os.FileInfo, preserveRoot bool) ([]vault.PutResult, error) {
	if info.IsDir() && !preserveRoot && strings.TrimSpace(virtualPath) == "" {
		return v.PutDirectoryContents(sourcePath, "")
	}
	return v.PutPath(sourcePath, virtualPath)
}

func runRsync(ctx context.Context, bin string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), ctx.Err()
	}
	return string(out), err
}

func resolveRsync(configured string) (string, error) {
	candidates := []string{}
	if strings.TrimSpace(configured) != "" {
		candidates = append(candidates, strings.TrimSpace(configured))
	}
	if env := strings.TrimSpace(os.Getenv("SEAVAULT_RSYNC")); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, "rsync")
	var last error
	for _, c := range candidates {
		if looksLikePath(c) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c, nil
			} else if err != nil {
				last = err
			} else {
				last = fmt.Errorf("%s is a directory", c)
			}
			continue
		}
		p, err := exec.LookPath(c)
		if err == nil {
			return p, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("rsync not found")
	}
	return "", fmt.Errorf("rsync binary not found; set SEAVAULT_RSYNC or pass --rsync-bin: %w", last)
}

func normalizeMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeRsync:
		return ModeRsync, nil
	case ModeDirect:
		return ModeDirect, nil
	default:
		return "", fmt.Errorf("unsupported ingest mode %q; use auto, rsync, or direct", mode)
	}
}

func looksLikePath(p string) bool {
	return filepath.IsAbs(p) || strings.Contains(p, "/") || strings.Contains(p, "\\")
}

func ensureTrailingSep(p string) string {
	if strings.HasSuffix(p, "/") || strings.HasSuffix(p, "\\") {
		return p
	}
	return p + string(os.PathSeparator)
}

func kind(info os.FileInfo) string {
	if info.IsDir() {
		return "directory"
	}
	return "file"
}

func nilResult(rep Report) Result { return Result{Report: rep} }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
