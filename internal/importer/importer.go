// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package importer

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/rsyncput"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

type Options struct {
	VirtualPath  string
	DryRun       bool
	Method       string
	RsyncBinary  string
	SkipExisting bool
}

type Progress struct {
	JobID         string    `json:"jobId,omitempty"`
	Status        string    `json:"status"`
	SourcePath    string    `json:"sourcePath"`
	VirtualPath   string    `json:"virtualPath"`
	CanonicalPath string    `json:"canonicalPath"`
	Method        string    `json:"method"`
	DryRun        bool      `json:"dryRun"`
	StartedAt     time.Time `json:"startedAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	FinishedAt    time.Time `json:"finishedAt,omitempty"`
	FilesScanned  int64     `json:"filesScanned"`
	FilesImported int64     `json:"filesImported"`
	FilesSkipped  int64     `json:"filesSkipped"`
	DirsScanned   int64     `json:"dirsScanned"`
	DirsCreated   int64     `json:"dirsCreated"`
	BytesScanned  int64     `json:"bytesScanned"`
	BytesImported int64     `json:"bytesImported"`
	Errors        int64     `json:"errors"`
	CurrentPath   string    `json:"currentPath,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
	Samples       []string  `json:"samples,omitempty"`
}

type Job struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	prog   Progress
}

var (
	jobsMu sync.Mutex
	jobs   = map[string]*Job{}
	nextID int64
)

func Start(ctx context.Context, v *vault.Vault, sourcePath string, opts Options) (*Job, error) {
	if strings.TrimSpace(sourcePath) == "" {
		return nil, fmt.Errorf("source path is required")
	}
	id := fmt.Sprintf("import-%d", atomic.AddInt64(&nextID, 1))
	ctx, cancel := context.WithCancel(ctx)
	now := time.Now().UTC()
	j := &Job{cancel: cancel, prog: Progress{JobID: id, Status: "queued", SourcePath: sourcePath, VirtualPath: opts.VirtualPath, Method: normalizeMethod(opts.Method), DryRun: opts.DryRun, StartedAt: now, UpdatedAt: now}}
	jobsMu.Lock()
	jobs[id] = j
	jobsMu.Unlock()
	go func() {
		res := ImportPath(ctx, v, sourcePath, opts, j.update)
		j.mu.Lock()
		j.prog = res
		j.prog.JobID = id
		j.mu.Unlock()
	}()
	return j, nil
}

func Get(id string) (*Job, bool) {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	j, ok := jobs[id]
	return j, ok
}

func (j *Job) Cancel() {
	if j == nil || j.cancel == nil {
		return
	}
	j.cancel()
}

func (j *Job) Progress() Progress {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.prog
}

func (j *Job) update(p Progress) {
	j.mu.Lock()
	defer j.mu.Unlock()
	p.JobID = j.prog.JobID
	j.prog = p
}

func ImportPath(ctx context.Context, v *vault.Vault, sourcePath string, opts Options, cb func(Progress)) Progress {
	method := normalizeMethod(opts.Method)
	now := time.Now().UTC()
	prog := Progress{Status: "running", SourcePath: sourcePath, VirtualPath: opts.VirtualPath, Method: method, DryRun: opts.DryRun, StartedAt: now, UpdatedAt: now}
	emit := func() {
		prog.UpdatedAt = time.Now().UTC()
		if cb != nil {
			cb(prog)
		}
	}
	finish := func(status string, err error) Progress {
		prog.Status = status
		if err != nil {
			prog.LastError = err.Error()
		}
		prog.FinishedAt = time.Now().UTC()
		emit()
		return prog
	}

	src, err := userpath.Abs(sourcePath)
	if err != nil {
		return finish("failed", err)
	}
	if err := preflight(method, opts.RsyncBinary); err != nil {
		return finish("failed", err)
	}
	info, err := os.Stat(src)
	if err != nil {
		return finish("failed", err)
	}
	base, err := baseVirtualPath(src, info, opts.VirtualPath)
	if err != nil {
		return finish("failed", err)
	}
	prog.SourcePath = src
	prog.CanonicalPath = base
	emit()
	if !info.IsDir() {
		return importOneFile(ctx, v, src, base, info, opts, prog, emit, finish)
	}
	if !opts.DryRun {
		if err := v.EnsureDirectory(base); err != nil {
			return finish("failed", err)
		}
		prog.DirsCreated++
	}
	metaRootAbs, _ := filepath.Abs(v.MetaRoot)
	err = filepath.WalkDir(src, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			prog.Errors++
			prog.LastError = walkErr.Error()
			emit()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" {
				return filepath.SkipDir
			}
			// Exclude exactly THIS vault's own metadata directory. A
			// foreign metadata-named directory is still filtered by the reserved-path
			// check below, keeping the bulk importer conservative.
			if abs, aerr := filepath.Abs(p); aerr == nil && abs == metaRootAbs {
				return filepath.SkipDir
			}
		}
		if vault.IsInternalVirtualPath(filepath.ToSlash(name)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			prog.FilesSkipped++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			prog.Errors++
			prog.LastError = err.Error()
			emit()
			return nil
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 || mode&os.ModeType != 0 && !mode.IsRegular() && !mode.IsDir() {
			prog.FilesSkipped++
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			prog.Errors++
			prog.LastError = err.Error()
			emit()
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		vp := path.Join(base, rel)
		if info.IsDir() {
			prog.DirsScanned++
			if !opts.DryRun {
				if err := v.EnsureDirectory(vp); err != nil {
					prog.Errors++
					prog.LastError = err.Error()
				} else {
					prog.DirsCreated++
				}
			}
			emit()
			return nil
		}
		prog.FilesScanned++
		prog.BytesScanned += info.Size()
		prog.CurrentPath = vp
		if opts.DryRun {
			addSample(&prog, vp)
			emit()
			return nil
		}
		if opts.SkipExisting {
			if rec, ok, err := v.FileInfo(vp); err == nil && ok && rec.Size == info.Size() {
				prog.FilesSkipped++
				emit()
				return nil
			}
		}
		if _, err := v.PutPath(p, vp); err != nil {
			prog.Errors++
			prog.LastError = err.Error()
		} else {
			prog.FilesImported++
			prog.BytesImported += info.Size()
			addSample(&prog, vp)
		}
		emit()
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return finish("cancelled", ctx.Err())
		}
		return finish("failed", err)
	}
	if prog.Errors > 0 {
		return finish("completed-with-errors", nil)
	}
	return finish("completed", nil)
}

func importOneFile(ctx context.Context, v *vault.Vault, src, vp string, info os.FileInfo, opts Options, prog Progress, emit func(), finish func(string, error) Progress) Progress {
	select {
	case <-ctx.Done():
		return finish("cancelled", ctx.Err())
	default:
	}
	prog.FilesScanned = 1
	prog.BytesScanned = info.Size()
	prog.CurrentPath = vp
	if opts.DryRun {
		addSample(&prog, vp)
		return finish("completed", nil)
	}
	if opts.SkipExisting {
		if rec, ok, err := v.FileInfo(vp); err == nil && ok && rec.Size == info.Size() {
			prog.FilesSkipped = 1
			return finish("completed", nil)
		}
	}
	if _, err := v.PutPath(src, vp); err != nil {
		prog.Errors = 1
		return finish("failed", err)
	}
	prog.FilesImported = 1
	prog.BytesImported = info.Size()
	addSample(&prog, vp)
	emit()
	return finish("completed", nil)
}

func baseVirtualPath(src string, info os.FileInfo, requested string) (string, error) {
	vp := strings.TrimSpace(requested)
	if vp == "" {
		vp = filepath.Base(src)
	}
	return vault.NormalizeContentPath(vp)
}

func normalizeMethod(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	if m == "" {
		return rsyncput.MethodNative
	}
	switch m {
	case rsyncput.MethodManagedRsync, rsyncput.MethodSystemRsync, rsyncput.MethodRsync:
		return m
	case "auto", rsyncput.MethodNative:
		return rsyncput.MethodNative
	default:
		return m
	}
}

func preflight(method, binary string) error {
	switch method {
	case rsyncput.MethodManagedRsync:
		st := rsyncput.Inspect(context.Background(), "")
		if !st.Managed.Installed || !st.Managed.RuntimeOK {
			return fmt.Errorf("managed rsync is not installed or failed verification; use native large import or install managed rsync")
		}
	case rsyncput.MethodSystemRsync, rsyncput.MethodRsync:
		st := rsyncput.Inspect(context.Background(), binary)
		if !st.Available {
			return fmt.Errorf("system rsync is not available: %s", st.Error)
		}
	}
	return nil
}

func addSample(p *Progress, vp string) {
	if len(p.Samples) < 10 {
		p.Samples = append(p.Samples, vp)
	}
}
