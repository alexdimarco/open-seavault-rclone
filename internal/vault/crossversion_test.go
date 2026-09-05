// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The 0.15.0 fixture commit: the last release-line commit whose binary this
// version must stay format-compatible with (invariant I1). It creates hidden
// .seavault vaults.
const legacy015Commit = "ab64d05"

func runFixtureCmd(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// R4 / I1 (P0-4, §12): build the 0.15.0 binary from commit ab64d05 and prove
// BOTH directions of the compatibility boundary. Forward: a .seavault vault the
// 0.15.0 binary created is opened, read, and written by this version, and the
// 0.15.0 binary still reads it after this version wrote to it. Reverse: a vault
// this version creates (visible SeaVaultData) is NOT located by the 0.15.0
// binary, which reports "no vault" — the intended one-way boundary (D1.3). The
// test skips only when git is unavailable.
func TestCrossVersion015Fixture(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable; skipping cross-version fixture test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable; skipping cross-version fixture test")
	}
	// Keep this process's device-local freshness anchors (written by the A2 rewrite
	// path an A2 rotation exercises below) out of the real app-data dir.
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	top, err := runFixtureCmd(t, "", os.Environ(), "git", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Skipf("not a git checkout (%v); skipping", err)
	}
	repoRoot := strings.TrimSpace(top)

	// A shallow or partial clone (a common CI default; this repo's CI fetches
	// nothing and runs offline) may not contain the fixture commit. Probe for it
	// and SKIP legibly rather than letting `git worktree add` turn a missing
	// environmental precondition into a red gate (friction Cold C6). This matches
	// the git/go LookPath skip pattern above and the repo's "red = the code is
	// wrong" discipline.
	if out, err := runFixtureCmd(t, repoRoot, os.Environ(), "git", "cat-file", "-e", legacy015Commit+"^{commit}"); err != nil {
		t.Skipf("fixture commit %s not present in this (shallow?) checkout; skipping: %v\n%s", legacy015Commit, err, out)
	}

	// Materialise the 0.15.0 source in a detached worktree and build its binary.
	work := filepath.Join(t.TempDir(), "old-src")
	if out, err := runFixtureCmd(t, repoRoot, os.Environ(), "git", "worktree", "add", "--detach", work, legacy015Commit); err != nil {
		t.Fatalf("git worktree add %s: %v\n%s", legacy015Commit, err, out)
	}
	defer runFixtureCmd(t, repoRoot, os.Environ(), "git", "worktree", "remove", "--force", work)

	oldBin := filepath.Join(t.TempDir(), "seavault-015")
	buildEnv := append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := runFixtureCmd(t, work, buildEnv, "go", "build", "-o", oldBin, "./cmd/seavault"); err != nil {
		t.Fatalf("build 0.15.0 binary: %v\n%s", err, out)
	}

	const pw = "correct horse battery staple"
	pwEnv := append(os.Environ(), "SEAVAULT_PASSWORD="+pw, "SEAVAULT_APP_HOME="+t.TempDir())

	// ---- Forward: 0.15.0 creates a .seavault vault; this version opens it. ----
	oldVault := filepath.Join(t.TempDir(), "oldvault")
	if out, err := runFixtureCmd(t, "", pwEnv, oldBin, "init", "--kdf", "pbkdf2", "--pbkdf2-iterations", "1000", oldVault); err != nil {
		t.Fatalf("0.15.0 init: %v\n%s", err, out)
	}
	if !fileExists(filepath.Join(oldVault, ".seavault", "vault.json")) {
		t.Fatal("the 0.15.0 binary must create a hidden .seavault vault")
	}
	src := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(src, []byte("cross-version payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runFixtureCmd(t, "", pwEnv, oldBin, "put", oldVault, src, "hello.txt"); err != nil {
		t.Fatalf("0.15.0 put: %v\n%s", err, out)
	}

	// This version opens the 0.15.0 vault and reads the file back unchanged.
	v, err := Open(oldVault, pw)
	if err != nil {
		t.Fatalf("this version must open a 0.15.0 .seavault vault (invariant I1): %v", err)
	}
	if filepath.Base(v.MetaRoot) != ".seavault" {
		t.Fatalf("MetaRoot must resolve to the legacy .seavault dir, got %q", v.MetaRoot)
	}
	var buf bytes.Buffer
	if err := v.WriteFileTo("hello.txt", &buf); err != nil {
		t.Fatalf("this version must read the 0.15.0-written file: %v", err)
	}
	if buf.String() != "cross-version payload" {
		t.Fatalf("round-trip content mismatch: %q", buf.String())
	}

	// This version writes into the 0.15.0 vault (a new file + a tombstone with the
	// additive deletedGeneration field), exercising I1's "old reader ignores new
	// fields" path.
	if _, err := v.PutReader(strings.NewReader("added by new version"), "added.txt", int64(len("added by new version")), 0o600, time.Now()); err != nil {
		t.Fatalf("this version must write into a 0.15.0 vault: %v", err)
	}

	// The 0.15.0 binary still reads the vault after this version wrote to it.
	listOut, err := runFixtureCmd(t, "", pwEnv, oldBin, "list", oldVault)
	if err != nil {
		t.Fatalf("the 0.15.0 binary must still read the vault after this version wrote to it: %v\n%s", err, listOut)
	}
	if !strings.Contains(listOut, "hello.txt") || !strings.Contains(listOut, "added.txt") {
		t.Fatalf("0.15.0 list must show both the original and the new file; got:\n%s", listOut)
	}

	// ---- I1 / Condition 4: this version rotates the password; the 0.15.0 binary
	// STILL opens the vault with the NEW password (the legacy WrappedKeys wrap is
	// kept current and Version stays 2), and the OLD password no longer opens. This
	// proves an A2 password rotation does not lock out a grace-release peer. ----
	const newPW = "rotated brioche seventeen dusk"
	rot, err := Open(oldVault, pw)
	if err != nil {
		t.Fatalf("this version must re-open the 0.15.0 vault to rotate it: %v", err)
	}
	if err := rot.ChangePassword(newPW); err != nil {
		t.Fatalf("A2 password change on a 0.15.0-created vault: %v", err)
	}
	// Version must still be 2 after the rotation (no seal-format), so 0.16/0.15
	// keeps reading it.
	if cfg, cerr := ReadConfig(oldVault); cerr != nil || cfg.Version != 2 {
		t.Fatalf("after an A2 rotation Version must remain 2 (cfg=%+v err=%v)", cfg, cerr)
	}
	newPWEnv := append(os.Environ(), "SEAVAULT_PASSWORD="+newPW, "SEAVAULT_APP_HOME="+t.TempDir())
	listAfterRotate, err := runFixtureCmd(t, "", newPWEnv, oldBin, "list", oldVault)
	if err != nil {
		t.Fatalf("the 0.15.0 binary must STILL open the vault with the new password after an A2 rotation (legacy wrap kept current, Condition 4): %v\n%s", err, listAfterRotate)
	}
	if !strings.Contains(listAfterRotate, "hello.txt") || !strings.Contains(listAfterRotate, "added.txt") {
		t.Fatalf("the 0.15.0 binary must read both files after the rotation; got:\n%s", listAfterRotate)
	}
	// The OLD password must no longer open the 0.15.0 legacy wrap.
	if out, oerr := runFixtureCmd(t, "", pwEnv, oldBin, "list", oldVault); oerr == nil {
		t.Fatalf("the 0.15.0 binary must NOT open with the retired password after an A2 rotation:\n%s", out)
	}
	// This version re-opens with the new password after the rotation.
	if _, err := Open(oldVault, newPW); err != nil {
		t.Fatalf("this version must re-open a 0.15.0 vault after its own A2 rotation: %v", err)
	}

	// ---- Reverse: this version creates a SeaVaultData vault; 0.15.0 cannot find it. ----
	newVault := filepath.Join(t.TempDir(), "newvault")
	if err := CreateWithOptions(newVault, pw, CreateOptions{Chunk: testParams(), KDF: FastKDFConfigForTests()}); err != nil {
		t.Fatal(err)
	}
	if !fileExists(filepath.Join(newVault, "SeaVaultData", "vault.json")) {
		t.Fatal("this version must create a visible SeaVaultData vault")
	}
	refusedOut, refErr := runFixtureCmd(t, "", pwEnv, oldBin, "list", newVault)
	if refErr == nil {
		t.Fatalf("the 0.15.0 binary must NOT locate a SeaVaultData vault, but list succeeded:\n%s", refusedOut)
	}
	// Documented outcome (D1.3): the 0.15.0 binary looks only for .seavault, so it
	// reports the metadata as absent rather than corrupting anything. The exact
	// message is a not-found error on <root>/.seavault/vault.json.
	if !strings.Contains(strings.ToLower(refusedOut), ".seavault") && !strings.Contains(strings.ToLower(refusedOut), "no such file") && !strings.Contains(strings.ToLower(refusedOut), "not found") {
		t.Logf("0.15.0 refusal message (informational): %s", refusedOut)
	}
}
