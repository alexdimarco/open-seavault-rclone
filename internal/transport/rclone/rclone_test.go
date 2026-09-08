// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclone

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// rcloneLogFormatTokens is rclone's accepted --log-format token set (v1.74:
// "invalid choice … from: date, time, microseconds, UTC, longfile, shortfile,
// pid, nolevel, json"). It is the oracle the argv-hygiene test checks the
// wrapper's constructed --log-format value against, so a future edit that
// reintroduces a bogus token (the ADM-3 "level"/"msg" bug) is caught without a
// real binary.
var rcloneLogFormatTokens = map[string]bool{
	"date": true, "time": true, "microseconds": true, "UTC": true,
	"longfile": true, "shortfile": true, "pid": true, "nolevel": true, "json": true,
}

type fakeRunner struct{ args [][]string }

func (f *fakeRunner) Run(ctx context.Context, args []string) (string, error) {
	f.args = append(f.args, append([]string(nil), args...))
	return "ok", nil
}

func (f *fakeRunner) Path() string { return "/managed/rclone" }

func TestDryRunPushUsesCopyOnly(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	vaultRoot := t.TempDir()
	meta := filepath.Join(vaultRoot, vault.MetadataDirName)
	for _, d := range []string{filepath.Join(meta, "objects", "chunks"), filepath.Join(meta, "manifests")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(meta, vault.ConfigFileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := remotes.DefaultProfile("remote", vaultRoot, "remote:bucket/path", "s3")
	r := &fakeRunner{}
	b := NewWithRunner(p, r)
	res, err := b.DryRunPush(context.Background())
	if err != nil {
		t.Fatalf("DryRunPush failed: %v", err)
	}
	if !res.DryRun || !res.OK {
		t.Fatalf("unexpected result: %+v", res)
	}
	joined := flatten(r.args)
	if strings.Contains(joined, " sync ") {
		t.Fatalf("dry-run push must not use rclone sync: %s", joined)
	}
	if !strings.Contains(joined, "copy") || !strings.Contains(joined, "--dry-run") {
		t.Fatalf("expected copy with --dry-run: %s", joined)
	}
	if !strings.Contains(joined, vault.MetadataDirName) {
		t.Fatalf("expected remote.seavault path: %s", joined)
	}
}

func flatten(args [][]string) string {
	var parts []string
	for _, a := range args {
		parts = append(parts, strings.Join(a, " "))
	}
	return strings.Join(parts, " | ")
}

// logFormatValue returns the argument following the first --log-format in args,
// or "" if none is present.
func logFormatValue(args []string) (string, bool) {
	for i, a := range args {
		if a == "--log-format" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// ADM-3 argv hygiene (no binary): every --log-format the wrapper builds must
// carry ONLY tokens rclone accepts. The old "date,time,level,msg" smuggled the
// bogus "level"/"msg" tokens, which rclone rejects at flag-parse time, breaking
// every command that carries base args (lsf/copy/check/…). This asserts the
// constructed value on the real base-arg builder AND on the full Test sequence,
// so RemoteTest can actually reach a remote.
func TestBaseArgsLogFormatTokensAreValid(t *testing.T) {
	p := remotes.DefaultProfile("remote", t.TempDir(), "remote:bucket/path", "s3")

	// 1. Directly on the base-arg builder for a non-transfer command (lsf).
	base := appendBaseArgs(remotes.Normalize(p), []string{"lsf", "remote:bucket/path"})
	val, ok := logFormatValue(base)
	if !ok {
		t.Fatalf("appendBaseArgs must set --log-format; got %v", base)
	}
	if strings.TrimSpace(val) == "" {
		t.Fatal("the --log-format value must not be empty")
	}
	tokens := strings.Split(val, ",")
	if len(tokens) == 0 {
		t.Fatal("the --log-format value must carry at least one token")
	}
	for _, tok := range tokens {
		if !rcloneLogFormatTokens[strings.TrimSpace(tok)] {
			t.Fatalf("--log-format carries token %q which rclone does not accept (valid: %v); full value %q", tok, keysOf(rcloneLogFormatTokens), val)
		}
	}

	// 2. Through the full Test sequence (version + lsf) as it actually runs,
	// captured off a fake runner so no binary is needed. The lsf command MUST
	// carry a valid --log-format.
	meta := filepath.Join(p.Vault, vault.MetadataDirName)
	if err := os.MkdirAll(meta, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, vault.ConfigFileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	b := NewWithRunner(p, r)
	if _, err := b.Test(context.Background()); err != nil {
		t.Fatalf("Test with a fake runner must not error: %v", err)
	}
	sawLsf := false
	for _, args := range r.args {
		if len(args) == 0 || args[0] != "lsf" {
			continue
		}
		sawLsf = true
		val, ok := logFormatValue(args)
		if !ok {
			t.Fatalf("the Test-sequence lsf command must carry --log-format; got %v", args)
		}
		for _, tok := range strings.Split(val, ",") {
			if !rcloneLogFormatTokens[strings.TrimSpace(tok)] {
				t.Fatalf("the Test-sequence lsf --log-format carries invalid token %q (value %q)", tok, val)
			}
		}
	}
	if !sawLsf {
		t.Fatalf("the Test sequence must issue an lsf command; got %s", flatten(r.args))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ADM-3 stderr summary: a multi-line subprocess block (rclone's ~60-line usage
// dump on a flag-parse failure) is condensed to the first line, an elision
// marker, and a short tail — never pasted whole into an error. Short output is
// preserved.
func TestSummarizeOutput(t *testing.T) {
	if got := summarizeOutput(""); got != "" {
		t.Fatalf("empty output must summarise to empty; got %q", got)
	}
	short := "Error: invalid argument for --log-format"
	if got := summarizeOutput(short); got != short {
		t.Fatalf("short output must pass through unchanged; got %q", got)
	}

	var lines []string
	lines = append(lines, "Error: invalid argument \"date,time,level,msg\" for \"--log-format\" flag")
	for i := 0; i < 60; i++ {
		lines = append(lines, "  --some-flag   a usage line that would otherwise be dumped whole")
	}
	lines = append(lines, "Use \"rclone [command] --help\" for more information about a command.")
	full := strings.Join(lines, "\n")

	got := summarizeOutput(full)
	if strings.Count(got, "\n") != 0 {
		t.Fatalf("the summary must be a single line; got %q", got)
	}
	if gotLines := strings.Count(got, "usage line that would otherwise be dumped whole"); gotLines > 2 {
		t.Fatalf("the summary must not carry the whole usage block (found %d body lines); got %q", gotLines, got)
	}
	if !strings.Contains(got, "invalid argument") {
		t.Fatalf("the summary must keep the first (diagnostic) line; got %q", got)
	}
	if !strings.Contains(got, "more lines omitted") {
		t.Fatalf("the summary must state that lines were omitted; got %q", got)
	}
	if len(got) >= len(full) {
		t.Fatalf("the summary must be shorter than the full block (%d vs %d)", len(got), len(full))
	}
}

// ADM-3 real binary: when a real rclone is discoverable, prove the actual flag
// behaviour — the wrapper's "date,time" parses and lists, while the old
// "date,time,level,msg" is rejected at flag parse. Skipped (not failed) when no
// rclone is present, so CI without a runtime relies on the argv-hygiene test
// above. Confirmed locally against rclone v1.74.0.
func TestRealRcloneAcceptsWrapperLogFormat(t *testing.T) {
	bin := findRealRclone(t)
	if bin == "" {
		t.Skip("no real rclone binary discoverable; the argv-hygiene test covers the token set")
	}
	listDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(listDir, "a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The value the wrapper builds must parse and list.
	good := exec.Command(bin, "lsf", ":local:"+listDir, "--max-depth", "1", "--log-format", "date,time")
	if out, err := good.CombinedOutput(); err != nil {
		t.Fatalf("real rclone rejected the wrapper's --log-format date,time: %v\n%s", err, out)
	}
	// The old bogus token set must be rejected — this is the ADM-3 bug made
	// concrete against the real binary.
	bad := exec.Command(bin, "lsf", ":local:"+listDir, "--max-depth", "1", "--log-format", "date,time,level,msg")
	if out, err := bad.CombinedOutput(); err == nil {
		t.Fatalf("real rclone unexpectedly accepted date,time,level,msg — the ADM-3 premise no longer holds; out=%s", out)
	}
}

// findRealRclone returns a path to a runnable rclone, or "" to skip. It checks
// PATH first, then the managed runtime the real (unmocked) app home records.
func findRealRclone(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("rclone"); err == nil {
		return p
	}
	if p, err := rclonebin.BinaryPath(); err == nil {
		if _, statErr := os.Stat(p); statErr == nil {
			return p
		}
	}
	return ""
}

// ADM-3 stderr (real process): CommandRunner.Run embeds a SUMMARY of a failing
// subprocess's output in its error — the first line, an elision marker and a
// short tail — never the whole block (which for rclone is a ~60-line usage
// dump). Uses a real POSIX shell to emit a long failing output; skipped on
// Windows where /bin/sh is absent (the Run wrapper is identical there and the
// summarizeOutput unit test covers the logic).
func TestCommandRunnerBoundsErrorOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell to emit a long failing output")
	}
	r := &CommandRunner{Binary: "/bin/sh"}
	script := `i=0; while [ $i -lt 60 ]; do echo "usage line $i"; i=$((i+1)); done; echo final; exit 3`
	out, err := r.Run(context.Background(), []string{"-c", script})
	if err == nil {
		t.Fatal("a non-zero exit must surface an error")
	}
	msg := err.Error()
	// The summarised error is a single line; the un-summarised full block would
	// carry the subprocess's ~60 newlines. (Counting a body token is unreliable
	// here because the echoed command args in the error also contain it.)
	if n := strings.Count(msg, "\n"); n != 0 {
		t.Fatalf("the error must be a single summarised line, not the whole %d-newline block; msg=%q", n, msg)
	}
	if !strings.Contains(msg, "more lines omitted") {
		t.Fatalf("the error must state that lines were omitted; msg=%q", msg)
	}
	// The full output is still available in the returned string for the detailed
	// log/output sink (only the ERROR is summarised).
	if strings.Count(out, "usage line") < 60 {
		t.Fatalf("the returned output string must keep the full block; got %q", out)
	}
}
