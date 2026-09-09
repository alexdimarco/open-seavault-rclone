// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

// Package bundlelaunch holds the pure, host-independent pieces of the macOS .app
// bundle launch behaviour (design §2.1, §2.2): detecting a Finder/LaunchServices
// launch, the 0600 rotate-once log sink that stands in for the stdout
// LaunchServices discards, and the single-instance lock a second double-click
// reads to re-open the already-running window. Every function is exercised on
// Linux CI through injected OS / env / executable-path values, so the
// darwin-only behaviour is proven off a Mac.
package bundlelaunch

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// RelaunchTokenHeader carries the app-data lock token on the loopback
// /api/relaunch call. Only a process holding the lock file's token may ask the
// running instance for its current launch link.
const RelaunchTokenHeader = "X-Seavault-Relaunch-Token"

// EnvBundleLaunch is the environment variable the bundle's Info.plist
// LSEnvironment sets to 1 so the process knows LaunchServices started it.
const EnvBundleLaunch = "SEAVAULT_BUNDLE_LAUNCH"

// Active reports whether this process is a macOS .app bundle launch: the target
// OS is darwin AND either LSEnvironment set SEAVAULT_BUNDLE_LAUNCH=1 or the
// executable lives under .../Contents/MacOS/. It is false on every non-darwin
// OS, so an env var a shell might inherit is ignored off a Mac (I-M3).
func Active(goos string, getenv func(string) string, execPath string) bool {
	if goos != "darwin" {
		return false
	}
	if getenv(EnvBundleLaunch) == "1" {
		return true
	}
	return strings.Contains(filepath.ToSlash(execPath), "/Contents/MacOS/")
}

// OnlyFinderArgs reports whether argv (os.Args[1:]) carries no real command:
// either it is empty, or it holds only the legacy -psn_<n> process-serial-number
// argument older Finder passed. Any real argument makes it false, so a Terminal
// user typing a subcommand is never diverted to the GUI.
func OnlyFinderArgs(argv []string) bool {
	switch len(argv) {
	case 0:
		return true
	case 1:
		return strings.HasPrefix(argv[0], "-psn_")
	default:
		return false
	}
}

// FinderLaunch reports whether run() should default to the gui command: a bundle
// launch (Active) carrying no real arguments (OnlyFinderArgs). A Terminal
// `seavault` with no arguments is NOT a FinderLaunch because Active is false, so
// it still prints usage (I-M3).
func FinderLaunch(goos string, getenv func(string) string, execPath string, argv []string) bool {
	return OnlyFinderArgs(argv) && Active(goos, getenv, execPath)
}

// Lock is the single-instance lock file's content: a random token authenticating
// the /api/relaunch call and the loopback port the running instance bound.
type Lock struct {
	Token string `json:"token"`
	Port  int    `json:"port"`
}

// NewToken returns a fresh 256-bit lock token as 64 lowercase hex characters.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// WriteLock writes l to path atomically with 0600 permissions (a temp file in the
// same directory, then rename). The caller resolves path under the app-data dir.
func WriteLock(path string, l Lock) error {
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gui.lock-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ReadLock reads and parses the lock file at path. A missing or malformed file
// returns an error; the caller treats any error as "no usable lock".
func ReadLock(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	var l Lock
	if err := json.Unmarshal(data, &l); err != nil {
		return Lock{}, err
	}
	return l, nil
}

// RemoveLock deletes the lock file, ignoring a missing file.
func RemoveLock(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

const defaultLogCap = 256 * 1024

// LogSink is the 0600, size-capped, rotate-once file a bundle launch writes its
// launch URL, grace-exit line and relaunch line to, because LaunchServices
// discards a bundle's stdout (design §2.2, C7, I-M8). It is the ONLY sink the
// launch URL — which carries the launch secret — is ever written to. A nil
// *LogSink is a no-op, so a Terminal launch (which constructs none) writes no
// file (I-M8).
type LogSink struct {
	path string
	max  int64
}

// NewLogSink returns a sink writing to path, rotating the current file to
// path+".1" once an append would push it past maxBytes. maxBytes <= 0 uses a
// default cap.
func NewLogSink(path string, maxBytes int64) *LogSink {
	if maxBytes <= 0 {
		maxBytes = defaultLogCap
	}
	return &LogSink{path: path, max: maxBytes}
}

// Path returns the sink's log-file path ("" for a nil sink).
func (s *LogSink) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Writeln appends line plus a newline to the log file, creating it and its parent
// 0600 / 0700, rotating the current file to path+".1" first when the append would
// push it past the cap. A nil sink is a no-op (a Terminal launch writes nothing).
func (s *LogSink) Writeln(line string) error {
	if s == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	entry := line + "\n"
	if fi, err := os.Stat(s.path); err == nil {
		if fi.Size()+int64(len(entry)) > s.max {
			// Rotate once: the current file becomes path+".1" (replacing any prior
			// rotation) and a fresh file starts. Rename keeps the 0600 mode.
			_ = os.Rename(s.path, s.path+".1")
		}
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	// Enforce 0600 even if a umask-relaxed create left it wider.
	_ = f.Chmod(0o600)
	if _, err := f.Write([]byte(entry)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
