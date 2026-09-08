// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/setup"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// TestEnsureLoopbackBind verifies the GUI/WebDAV listeners (which serve
// decrypted content) refuse non-loopback binds unless explicitly overridden.
func TestEnsureLoopbackBind(t *testing.T) {
	allowed := []string{"127.0.0.1:8787", "localhost:8765", "[::1]:8787", "127.0.0.1:0"}
	for _, a := range allowed {
		if err := ensureLoopbackBind(a, false); err != nil {
			t.Fatalf("expected %q to be allowed: %v", a, err)
		}
	}
	rejected := []string{"0.0.0.0:8787", ":8787", "192.168.1.5:8787", "example.com:8787"}
	for _, a := range rejected {
		if err := ensureLoopbackBind(a, false); err == nil {
			t.Fatalf("expected %q to be rejected", a)
		}
		if err := ensureLoopbackBind(a, true); err != nil {
			t.Fatalf("expected %q to be allowed with --insecure-bind override: %v", a, err)
		}
	}
}

// TestResolveServeCredentials covers the password-source precedence
// (--password-file > SEAVAULT_SERVE_PASSWORD > generated), the generated-password
// shape, and the --quiet-credentials rules (error without a source; suppress the
// echo with a source). Regression (cmd half). Every row is asserted.
func TestResolveServeCredentials(t *testing.T) {
	dir := t.TempDir()
	fileWins := filepath.Join(dir, "pw-file-wins")
	if err := os.WriteFile(fileWins, []byte("filepass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileCRLF := filepath.Join(dir, "pw-file-crlf")
	if err := os.WriteFile(fileCRLF, []byte("crlfpass\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	type row struct {
		name          string
		user          string
		passwordFile  string
		env           string
		quiet         bool
		wantUser      string
		wantPassword  string // "" means "assert generated shape" when wantGenerated is true
		wantGenerated bool
		wantPrintIt   bool
		wantErr       bool
		errMentions   []string
	}
	rows := []row{
		{name: "file wins over env", user: "seavault", passwordFile: fileWins, env: "envpass", quiet: false, wantUser: "seavault", wantPassword: "filepass", wantPrintIt: true},
		{name: "file trailing CRLF trimmed", user: "seavault", passwordFile: fileCRLF, env: "", quiet: false, wantUser: "seavault", wantPassword: "crlfpass", wantPrintIt: true},
		{name: "env wins over generated", user: "custom", passwordFile: "", env: "envpass", quiet: false, wantUser: "custom", wantPassword: "envpass", wantPrintIt: true},
		{name: "generated 32 chars printIt true", user: "seavault", passwordFile: "", env: "", quiet: false, wantUser: "seavault", wantGenerated: true, wantPrintIt: true},
		{name: "quiet without source errors naming both sources", user: "seavault", passwordFile: "", env: "", quiet: true, wantErr: true, errMentions: []string{"--password-file", "SEAVAULT_SERVE_PASSWORD"}},
		{name: "quiet with env printIt false", user: "seavault", passwordFile: "", env: "envpass", quiet: true, wantUser: "seavault", wantPassword: "envpass", wantPrintIt: false},
		{name: "quiet with file printIt false", user: "seavault", passwordFile: fileWins, env: "", quiet: true, wantUser: "seavault", wantPassword: "filepass", wantPrintIt: false},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			user, password, printIt, err := resolveServeCredentials(r.user, r.passwordFile, r.env, r.quiet)
			if r.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got user=%q password=%q printIt=%v", user, password, printIt)
				}
				for _, m := range r.errMentions {
					if !strings.Contains(err.Error(), m) {
						t.Fatalf("error %q does not mention %q", err.Error(), m)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user != r.wantUser {
				t.Fatalf("user = %q, want %q", user, r.wantUser)
			}
			if r.wantGenerated {
				if len(password) != 32 {
					t.Fatalf("generated password %q has length %d, want 32", password, len(password))
				}
				// base64url without padding: no '+', '/', or '=' characters.
				if strings.ContainsAny(password, "+/=") {
					t.Fatalf("generated password %q is not base64url without padding", password)
				}
			} else if password != r.wantPassword {
				t.Fatalf("password = %q, want %q", password, r.wantPassword)
			}
			if printIt != r.wantPrintIt {
				t.Fatalf("printIt = %v, want %v", printIt, r.wantPrintIt)
			}
		})
	}
}

// TestResolveServeCredentialsGeneratedUnique guards against a fixed/stub password:
// two generated passwords must differ.
func TestResolveServeCredentialsGeneratedUnique(t *testing.T) {
	_, a, _, err := resolveServeCredentials("seavault", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	_, b, _, err := resolveServeCredentials("seavault", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || b == "" {
		t.Fatalf("generated passwords must be non-empty (a=%q b=%q)", a, b)
	}
	if a == b {
		t.Fatalf("two generated passwords are identical (%q); expected random", a)
	}
}

// TestBuildLoopbackServer asserts the header/idle timeouts are armed on the
// http.Server used by serve and gui. Regression (cmd half).
func TestBuildLoopbackServer(t *testing.T) {
	handler := localdavHandlerStub{}
	srv := buildLoopbackServer("127.0.0.1:0", handler)
	if srv.Addr != "127.0.0.1:0" {
		t.Fatalf("Addr = %q, want 127.0.0.1:0", srv.Addr)
	}
	if srv.Handler == nil {
		t.Fatal("Handler is nil")
	}
	if srv.ReadHeaderTimeout == 0 {
		t.Fatal("ReadHeaderTimeout is zero; slowloris header dribbles are unbounded")
	}
	if srv.IdleTimeout == 0 {
		t.Fatal("IdleTimeout is zero; idle keep-alive connections are unbounded")
	}
}

type localdavHandlerStub struct{}

func (localdavHandlerStub) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {}

// TestListenErrorHint (, C5): now that `seavault gui` no
// longer SIGKILLs other seavault processes, a second listener on a bound address
// fails to bind, and the operator must be told the port is taken. A real bind
// conflict is provoked by pre-binding the port, then wrapped with the hint.
func TestListenErrorHint(t *testing.T) {
	if err := listenErrorHint("127.0.0.1:0", nil); err != nil {
		t.Fatalf("listenErrorHint(nil) = %v, want nil", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	// buildLoopbackServer(addr).ListenAndServe cannot bind the in-use addr and
	// returns immediately with the bind error.
	bindErr := buildLoopbackServer(addr, localdavHandlerStub{}).ListenAndServe()
	if bindErr == nil {
		t.Fatal("expected ListenAndServe to fail binding an in-use address")
	}
	hinted := listenErrorHint(addr, bindErr)
	if hinted == nil {
		t.Fatal("listenErrorHint returned nil for a real bind failure")
	}
	msg := hinted.Error()
	if !strings.Contains(msg, "already running") {
		t.Fatalf("hint %q does not mention another instance already running", msg)
	}
	if !strings.Contains(msg, addr) {
		t.Fatalf("hint %q does not name the bind address %q", msg, addr)
	}
	if !errors.Is(hinted, bindErr) {
		t.Fatal("hint must wrap the original error so upstream errors.Is checks still work")
	}
}

// TestPrintLaunchGuidance (C1, C1): the fallback line is always
// printed to stdout, and an openBrowser failure is surfaced to stderr instead of
// being discarded. open is injected to drive both paths.
func TestPrintLaunchGuidance(t *testing.T) {
	const fallback = "If your browser did not open, copy the link above into your browser."

	// open error path: stdout fallback AND a stderr failure line.
	var out, errOut bytes.Buffer
	printLaunchGuidance(&out, &errOut, "http://127.0.0.1:8787/?launch=x", true, func(string) error {
		return errors.New("xdg-open missing")
	})
	if !strings.Contains(out.String(), fallback) {
		t.Fatalf("stdout missing fallback line: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "Could not open your browser automatically (xdg-open missing)") {
		t.Fatalf("stderr missing open-failure line: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "Copy the link above into your browser.") {
		t.Fatalf("stderr missing copy hint: %q", errOut.String())
	}

	// open success path: stdout fallback, no stderr, open called once with the URL.
	out.Reset()
	errOut.Reset()
	called := 0
	gotURL := ""
	printLaunchGuidance(&out, &errOut, "http://127.0.0.1:8787/?launch=y", true, func(u string) error {
		called++
		gotURL = u
		return nil
	})
	if called != 1 {
		t.Fatalf("open called %d times, want 1", called)
	}
	if gotURL != "http://127.0.0.1:8787/?launch=y" {
		t.Fatalf("open received URL %q, want the launch URL", gotURL)
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr must be empty when open succeeds: %q", errOut.String())
	}
	if !strings.Contains(out.String(), fallback) {
		t.Fatalf("stdout missing fallback line on success: %q", out.String())
	}

	// no-open path (--no-open): open is not called, fallback still printed.
	out.Reset()
	errOut.Reset()
	called = 0
	printLaunchGuidance(&out, &errOut, "http://127.0.0.1:8787/?launch=z", false, func(string) error {
		called++
		return nil
	})
	if called != 0 {
		t.Fatalf("open must not be called when openInBrowser is false, called %d times", called)
	}
	if !strings.Contains(out.String(), fallback) {
		t.Fatalf("stdout missing fallback line with --no-open: %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr must be empty with --no-open: %q", errOut.String())
	}
}

type fakeFileInfo struct{ mode os.FileMode }

func (f fakeFileInfo) Name() string       { return "stdout" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// TestStdoutLooksRedirected (C5): a character device is a terminal
// (not redirected); everything else (regular file, pipe) is a redirect/log. Every
// row asserted.
func TestStdoutLooksRedirected(t *testing.T) {
	type row struct {
		name string
		mode os.FileMode
		want bool
	}
	rows := []row{
		{"character device terminal", os.ModeCharDevice, false},
		{"device with char bit", os.ModeDevice | os.ModeCharDevice, false},
		{"regular file redirect", 0, true},
		{"regular file with perms", 0o644, true},
		{"named pipe", os.ModeNamedPipe, true},
		{"socket", os.ModeSocket, true},
	}
	if len(rows) == 0 {
		t.Fatal("empty stdoutLooksRedirected table exercises nothing")
	}
	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			if got := stdoutLooksRedirected(fakeFileInfo{mode: r.mode}); got != r.want {
				t.Fatalf("stdoutLooksRedirected(mode=%v) = %v, want %v", r.mode, got, r.want)
			}
		})
		asserted++
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

// TestKeychainUnavailableNote (C4): a nil error prints nothing; a
// real error yields a single-line note naming the fallback. Every row asserted.
func TestKeychainUnavailableNote(t *testing.T) {
	if s := keychainUnavailableNote(nil); s != "" {
		t.Fatalf("nil error must yield no note, got %q", s)
	}
	type row struct {
		name         string
		err          error
		wantContains []string
		wantAbsent   []string
	}
	rows := []row{
		{
			name:         "single line",
			err:          errors.New("Secret Service lookup failed; install libsecret-tools"),
			wantContains: []string{"OS keychain unavailable", "Secret Service lookup failed", "falling back to SEAVAULT_PASSWORD or the hidden prompt"},
		},
		{
			name:         "multiline uses first line only",
			err:          errors.New("first line\nsecond line"),
			wantContains: []string{"OS keychain unavailable", "first line", "falling back to"},
			wantAbsent:   []string{"second line", "\n\n"},
		},
	}
	if len(rows) == 0 {
		t.Fatal("empty keychainUnavailableNote table exercises nothing")
	}
	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			got := keychainUnavailableNote(r.err)
			if got == "" {
				t.Fatal("expected a non-empty note for a non-nil error")
			}
			for _, c := range r.wantContains {
				if !strings.Contains(got, c) {
					t.Fatalf("note %q missing %q", got, c)
				}
			}
			for _, a := range r.wantAbsent {
				if strings.Contains(got, a) {
					t.Fatalf("note %q should not contain %q", got, a)
				}
			}
		})
		asserted++
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

// TestUsageTextServeCredentialAndVersion (items 5 and 7): the top-level usage
// footer documents serve's separate WebDAV credential, and the reported version
// is bumped to 0.16.0.
func TestUsageTextServeCredentialAndVersion(t *testing.T) {
	txt := usageText()
	if txt == "" {
		t.Fatal("usageText is empty")
	}
	for _, want := range []string{"separate WebDAV credential", "SEAVAULT_SERVE_PASSWORD", "--password-file"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("usage footer missing %q:\n%s", want, txt)
		}
	}
	if !strings.Contains(txt, "seavault "+version) {
		t.Fatalf("usage does not report version %s:\n%s", version, txt)
	}
}

// (cmd leg): cmdInit enforces the KDF strength floor before it
//
// prompts for a password. A below-floor request is refused with an error naming
// the floor and creates no vault; a minimum-compliant request succeeds.
func TestCmdInitEnforcesKDFFloor(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")

	weak := filepath.Join(t.TempDir(), "weak")
	err := cmdInit([]string{"--kdf", "pbkdf2", "--pbkdf2-iterations", "1", weak})
	if err == nil {
		t.Fatal("cmdInit must refuse a pbkdf2 iteration count below the floor")
	}
	if !strings.Contains(err.Error(), "600000") {
		t.Fatalf("refusal must name the pbkdf2 floor, got %v", err)
	}
	if _, statErr := os.Stat(weak); !os.IsNotExist(statErr) {
		t.Fatalf("no vault should be created when the KDF is refused (stat err=%v)", statErr)
	}

	ok := filepath.Join(t.TempDir(), "ok")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", ok}); err != nil {
		t.Fatalf("a minimum-compliant argon2id request must be accepted, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ok, ".seavault", "vault.json")); statErr != nil {
		if _, statErr2 := os.Stat(filepath.Join(ok, "SeaVaultData", "vault.json")); statErr2 != nil {
			t.Fatalf("expected a created vault at %s (%v / %v)", ok, statErr, statErr2)
		}
	}
}

//	(CLI): `gc --confirm` writes deletion intents for the unreferenced chunks
//
// left by a delete and removes nothing before the fence; `gc --json` emits a
// parseable report that lists the pending intents.
func TestCmdGCConfirmWritesIntentsAndJSON(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	const pw = "correct horse battery staple"

	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", vaultPath}); err != nil {
		t.Fatalf("init: %v", err)
	}
	v, err := vault.Open(vaultPath, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("payload data here for chunking"), "doc.txt", 30, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("doc.txt"); err != nil {
		t.Fatal(err)
	}

	chunksDir := filepath.Join(v.MetaRoot, "objects", "chunks")
	intentsDir := filepath.Join(v.MetaRoot, vault.GCIntentDirName)
	chunksBefore := countFilesUnder(t, chunksDir)
	if chunksBefore == 0 {
		t.Fatal("expected the deleted file's chunks to remain on disk before GC")
	}

	out, err := captureStdout(t, func() error { return cmdGC([]string{"--no-keychain", "--confirm", vaultPath}) })
	if err != nil {
		t.Fatalf("gc --confirm: %v", err)
	}
	if !strings.Contains(out, "intents written:") {
		t.Fatalf("confirm output should report intents written, got:\n%s", out)
	}
	if n := countFilesUnder(t, intentsDir); n == 0 {
		t.Fatal("gc --confirm must write at least one deletion intent")
	}
	if n := countFilesUnder(t, chunksDir); n != chunksBefore {
		t.Fatalf("gc --confirm must not remove fresh chunks before the fence (before %d, after %d)", chunksBefore, n)
	}

	out, err = captureStdout(t, func() error { return cmdGC([]string{"--no-keychain", "--json", vaultPath}) })
	if err != nil {
		t.Fatalf("gc --json: %v", err)
	}
	var rep struct {
		Confirm bool `json:"confirm"`
		Fence   string
		Pending []struct {
			ChunkID string `json:"chunkId"`
		} `json:"pending"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("gc --json must emit valid JSON: %v\n%s", err, out)
	}
	if rep.Confirm {
		t.Fatal("a dry-run json report must have confirm=false")
	}
	if rep.Fence == "" {
		t.Fatal("gc --json must report the fence")
	}
	if len(rep.Pending) == 0 {
		t.Fatal("the dry-run json report should list the intents the confirm run wrote")
	}
}

// Regression for (design
// /): a hostile sync server that deletes every manifest under an intact
// vault.json while keeping the live-file chunks must NOT be able to drive the CLI
// `gc --confirm` into queueing and deleting those surviving chunks. Every CLI gc
// invocation re-Opens the vault (Open -> EnsureContentLayout); if that resurrected
// the content-marker manifest, the loaded index would be non-empty and
// gcRefusalGate's `len(idx.Files) != 0` early return would silently defeat the
// wiped-store refusal. This exercises the exact CLI/production sequence
// (cmdGC -> vault.Open -> GarbageCollect); the package-level
// TestGCRefusesWipedManifestStore, which calls GarbageCollect on an already-open
// *Vault and never re-Opens, does not cover this path.
func TestCmdGCRefusesWipedManifestStore(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	const pw = "correct horse battery staple"

	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", vaultPath}); err != nil {
		t.Fatalf("init: %v", err)
	}
	v, err := vault.Open(vaultPath, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("payload data here for chunking"), "doc.txt", 30, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	manifestsDir := filepath.Join(v.MetaRoot, vault.ManifestDirName)
	chunksDir := filepath.Join(v.MetaRoot, "objects", "chunks")
	intentsDir := filepath.Join(v.MetaRoot, vault.GCIntentDirName)

	// HOSTILE sync server: delete every manifest (content marker included) under an
	// intact vault.json, leaving the live file's chunks orphaned on disk.
	if err := os.RemoveAll(manifestsDir); err != nil {
		t.Fatal(err)
	}
	chunksBefore := countFilesUnder(t, chunksDir)
	if chunksBefore == 0 {
		t.Fatal("precondition: the live file's chunks must remain on disk")
	}

	// The real CLI path: cmdGC re-Opens the vault (EnsureContentLayout) before
	// GarbageCollect. A wiped store must be refused, writing and removing nothing.
	_, gcErr := captureStdout(t, func() error { return cmdGC([]string{"--no-keychain", "--confirm", vaultPath}) })
	if !errors.Is(gcErr, vault.ErrGCRefused) {
		t.Fatalf("gc --confirm on a wiped manifest store must return ErrGCRefused, got %v", gcErr)
	}
	if n := countFilesUnder(t, chunksDir); n != chunksBefore {
		t.Fatalf("a refused gc must remove no chunks; before %d, after %d", chunksBefore, n)
	}
	if n := countFilesUnder(t, intentsDir); n != 0 {
		t.Fatalf("a refused gc must write no deletion intents; got %d", n)
	}
	// Open of a wiped store must NOT resurrect the content-marker manifest:
	// re-creating it is exactly what would mask the wipe from the refusal gate.
	if n := countFilesUnder(t, manifestsDir); n != 0 {
		t.Fatalf("gc's Open of a wiped store must not resurrect any manifest; got %d", n)
	}
}

func countFilesUnder(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String(), runErr
}

// captureOutputs runs fn with os.Stdout and os.Stderr redirected to pipes and
// returns what each received. Writers are closed before the pipes are drained,
// so the captured payloads must stay well under the OS pipe buffer.
func captureOutputs(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	rErr, wErr, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	os.Stdout, os.Stderr = wOut, wErr
	runErr := fn()
	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout, os.Stderr = origOut, origErr
	var outBuf, errBuf bytes.Buffer
	if _, e := outBuf.ReadFrom(rOut); e != nil {
		t.Fatal(e)
	}
	if _, e := errBuf.ReadFrom(rErr); e != nil {
		t.Fatal(e)
	}
	return outBuf.String(), errBuf.String(), runErr
}

// Tombstone for (review): the
// Open-time preflight note for a legacy.seavault vault under a sync-client
// folder was set on the vault (vault.go openNote) and surfaced by the GUI
// (webui handleOpen -> v.PreflightNote), but NO CLI Open command surfaced it.
// A CLI user who opens a legacy vault stored under Nextcloud/Dropbox/etc must see
// the same one-line note the GUI shows on Open. This drives the exact
// production sequence: cmdList -> vault.Open -> v.PreflightNote.
func TestCmdOpenSurfacesLegacyPreflightNoteUnderSyncFolder(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	const pw = "correct horse battery staple"

	// A vault root whose path carries a known sync-client segment (matcher).
	root := filepath.Join(t.TempDir(), "Nextcloud", "vault")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", root}); err != nil {
		t.Fatalf("init: %v", err)
	}
	// The Open-time note this root must produce (the short Owner-C2 note, not
	// the create-time one); a vacuous pass (empty note) is a bug.
	want := vault.LegacyOpenPreflightNote(root)
	if want == "" {
		t.Fatal("precondition: a legacy vault under a Nextcloud segment must produce a non-empty Open preflight note")
	}

	// Seed a file so `list` has real stdout to print alongside the note.
	v, err := vault.Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("hello preflight"), "f.txt", 15, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Control: a new vault keeps its data in the visible SeaVaultData dir and so is
	// NOT legacy; opening it via the CLI must emit no preflight note.
	newMeta := filepath.Join(root, "SeaVaultData")
	if _, statErr := os.Stat(filepath.Join(newMeta, "vault.json")); statErr != nil {
		t.Fatalf("init should create a visible SeaVaultData metadata dir: %v", statErr)
	}
	_, stderrNew, err := captureOutputs(t, func() error { return cmdList([]string{"--no-keychain", root}) })
	if err != nil {
		t.Fatalf("list (SeaVaultData): %v", err)
	}
	if strings.Contains(stderrNew, want) {
		t.Fatalf("a non-legacy SeaVaultData vault must not emit the preflight note on CLI open; stderr:\n%s", stderrNew)
	}

	// Make it a legacy vault: rename the visible dir to the hidden.seavault name a
	// 0.15.0 client would have created.
	if err := os.Rename(newMeta, filepath.Join(root, vault.MetadataDirName)); err != nil {
		t.Fatalf("rename to legacy.seavault: %v", err)
	}

	stdout, stderrLegacy, err := captureOutputs(t, func() error { return cmdList([]string{"--no-keychain", root}) })
	if err != nil {
		t.Fatalf("list (legacy.seavault): %v", err)
	}
	if !strings.Contains(stderrLegacy, want) {
		t.Fatalf("`seavault list` of a legacy.seavault vault under a sync folder must surface the preflight note on stderr.\nstderr:\n%s", stderrLegacy)
	}
	// The note is advisory: it must go to stderr, never contaminate the stdout file
	// listing a caller may parse.
	if strings.Contains(stdout, want) {
		t.Fatalf("the preflight note must not be written to stdout (it would corrupt the file listing); stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "content/f.txt") {
		t.Fatalf("list stdout should still contain the file listing; got:\n%s", stdout)
	}
}

func manifestNameSet(t *testing.T, dir string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".manifest") {
			out[p] = struct{}{}
		}
		return nil
	})
	return out
}

// buildConcurrentConflict stages a genuine causal conflict on disk for
// virtualPath: two DIFFERENT device installations each write
// the path without seeing the other, so their manifests carry disjoint vector
// clocks and reconcile as CONCURRENT — kept as one canonical winner plus one
// *.conflict-* entry — rather than one cleanly superseding the other (which a
// same-device re-edit now does). Device A writes bodyA; its manifest is then
// hidden so device B writes an independent bodyB to the same path; A's manifest
// is restored alongside B's as a sync-client conflicted copy. It leaves
// SEAVAULT_APP_HOME pointing at device B's home and returns the manifests dir.
func buildConcurrentConflict(t *testing.T, vaultPath, pw, virtualPath, bodyA, bodyB string) string {
	t.Helper()
	homeA, homeB := t.TempDir(), t.TempDir()

	t.Setenv("SEAVAULT_APP_HOME", homeA)
	vA, err := vault.Open(vaultPath, pw)
	if err != nil {
		t.Fatalf("open device A: %v", err)
	}
	manifestsDir := filepath.Join(vA.MetaRoot, "manifests")
	before := manifestNameSet(t, manifestsDir)
	if _, err := vA.PutReader(strings.NewReader(bodyA), virtualPath, int64(len(bodyA)), 0o600, time.Now()); err != nil {
		t.Fatalf("device A put: %v", err)
	}
	var docManifest string
	for p := range manifestNameSet(t, manifestsDir) {
		if _, ok := before[p]; !ok {
			docManifest = p
		}
	}
	if docManifest == "" {
		t.Fatal("could not locate device A's manifest for the path")
	}
	loserBytes, err := os.ReadFile(docManifest)
	if err != nil {
		t.Fatal(err)
	}
	// Hide device A's manifest so device B writes an independent version.
	if err := os.Remove(docManifest); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SEAVAULT_APP_HOME", homeB)
	vB, err := vault.Open(vaultPath, pw)
	if err != nil {
		t.Fatalf("open device B: %v", err)
	}
	if _, err := vB.PutReader(strings.NewReader(bodyB), virtualPath, int64(len(bodyB)), 0o600, time.Now()); err != nil {
		t.Fatalf("device B put: %v", err)
	}
	// Restore device A's version as a sync-client conflicted copy next to B's.
	sibling := strings.TrimSuffix(docManifest, ".manifest") + ".sync-conflict.manifest"
	if err := os.WriteFile(sibling, loserBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestsDir
}

// (cmd leg): `seavault gc` is a dry run that prints the
//
// compaction plan (conflict copies to materialise, temp orphans) and writes
// nothing; `seavault compact` applies it and is idempotent.
func TestCmdGCDryRunAndCompact(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	const pw = "correct horse battery staple"

	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", vaultPath}); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Build a GENUINE pending conflict on disk: under the A2
	// vector clock a same-device re-edit is cleanly superseded, so a real conflict
	// needs two DIFFERENT devices editing without seeing each other (disjoint
	// clocks → concurrent → kept as one canonical + one conflict).
	manifestsDir := buildConcurrentConflict(t, vaultPath, pw, "doc.txt", "v1 device A", "v2 device B")

	manifestsBeforeDry := len(manifestNameSet(t, manifestsDir))
	out, errOut, err := captureOutputs(t, func() error { return cmdGC([]string{"--no-keychain", vaultPath}) })
	// Friction: a bare dry run that found an actionable plan (here a conflict
	// to materialise) must exit 3 with an advisory on stderr, not exit 0 silently.
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Fatalf("a dry run with pending work must return exit code 3, got %v", err)
	}
	if !strings.Contains(errOut, "gc: dry run") || !strings.Contains(errOut, "pass --confirm") {
		t.Fatalf("dry run must write the advisory to stderr, got:\n%s", errOut)
	}
	if !strings.Contains(out, "conflict copies to materialise: 1") {
		t.Fatalf("gc dry run should list one pending conflict, got:\n%s", out)
	}
	if !strings.Contains(out, "content/doc.txt.conflict-") {
		t.Fatalf("gc dry run should name the conflict path, got:\n%s", out)
	}
	if !strings.Contains(out, "dry run: nothing was changed") {
		t.Fatalf("gc without --confirm must announce a dry run, got:\n%s", out)
	}
	if got := len(manifestNameSet(t, manifestsDir)); got != manifestsBeforeDry {
		t.Fatalf("gc dry run must not change the manifests on disk (before %d, after %d)", manifestsBeforeDry, got)
	}

	out, err = captureStdout(t, func() error { return cmdCompact([]string{"--no-keychain", vaultPath}) })
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if !strings.Contains(out, "conflict copies materialised: 1") {
		t.Fatalf("compact should materialise one conflict, got:\n%s", out)
	}

	out, err = captureStdout(t, func() error { return cmdCompact([]string{"--no-keychain", vaultPath}) })
	if err != nil {
		t.Fatalf("second compact: %v", err)
	}
	if !strings.Contains(out, "conflict copies materialised: 0") {
		t.Fatalf("a second compact must be a no-op, got:\n%s", out)
	}
}

// TestGCDryRunAdvisory: the helper that turns a completed gc
// report into the one-line stderr advisory and the process exit code. A dry run
// that found something actionable (unreferenced chunks, pending intents, or a
// non-empty compaction plan) yields the advisory and exit code 3; a dry run with
// nothing to do, and every --confirm run, yield ("", 0). Every row asserted.
func TestGCDryRunAdvisory(t *testing.T) {
	type row struct {
		name         string
		report       vault.GCReport
		wantCode     int
		wantContains []string
	}
	rows := []row{
		{
			name:     "confirm run never advises",
			report:   vault.GCReport{Confirm: true, Candidates: []string{"a", "b"}, CandidateBytes: 40},
			wantCode: 0,
		},
		{
			name:     "dry run nothing to do is silent exit 0",
			report:   vault.GCReport{Confirm: false},
			wantCode: 0,
		},
		{
			name:         "dry run with unreferenced chunks advises exit 3",
			report:       vault.GCReport{Confirm: false, Candidates: []string{"a", "b"}, CandidateBytes: 54074},
			wantCode:     3,
			wantContains: []string{"gc: dry run", "2 chunk(s)", "54074 bytes", "pass --confirm", "scripted callers must add --confirm"},
		},
		{
			name:         "dry run with only pending intents advises exit 3",
			report:       vault.GCReport{Confirm: false, Pending: []vault.PendingIntent{{ChunkID: "x"}}},
			wantCode:     3,
			wantContains: []string{"gc: dry run", "0 chunk(s)", "pass --confirm"},
		},
		{
			name:         "dry run with only a compact conflict advises exit 3",
			report:       vault.GCReport{Confirm: false, Compact: &vault.CompactReport{Conflicts: []string{"content/doc.txt.conflict-x"}}},
			wantCode:     3,
			wantContains: []string{"gc: dry run", "pass --confirm"},
		},
		{
			name:         "dry run with only superseded manifests advises exit 3",
			report:       vault.GCReport{Confirm: false, Compact: &vault.CompactReport{RemovedManifests: 2}},
			wantCode:     3,
			wantContains: []string{"gc: dry run"},
		},
		{
			name:         "dry run with only tmp orphans advises exit 3",
			report:       vault.GCReport{Confirm: false, Compact: &vault.CompactReport{TmpOrphans: []string{"objects/chunks/xx/foo.tmp-1"}}},
			wantCode:     3,
			wantContains: []string{"gc: dry run"},
		},
		{
			name:     "dry run with an empty compact plan is silent exit 0",
			report:   vault.GCReport{Confirm: false, Compact: &vault.CompactReport{}},
			wantCode: 0,
		},
	}
	if len(rows) == 0 {
		t.Fatal("empty gcDryRunAdvisory table exercises nothing")
	}
	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			msg, code := gcDryRunAdvisory(r.report)
			if code != r.wantCode {
				t.Fatalf("exit code = %d, want %d (msg %q)", code, r.wantCode, msg)
			}
			if r.wantCode == 0 {
				if msg != "" {
					t.Fatalf("exit code 0 must carry no advisory, got %q", msg)
				}
			} else {
				if msg == "" {
					t.Fatalf("exit code %d must carry a non-empty advisory", code)
				}
				for _, c := range r.wantContains {
					if !strings.Contains(msg, c) {
						t.Fatalf("advisory %q missing %q", msg, c)
					}
				}
			}
			asserted++
		})
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

// TestClampFence (C5): the helper mirrors vault.GarbageCollect's
// fence clamping and reports a one-line notice exactly when the requested fence
// was changed. Every row asserted.
func TestClampFence(t *testing.T) {
	type row struct {
		name         string
		requested    time.Duration
		wantFence    time.Duration
		wantNotice   bool
		wantContains []string
	}
	rows := []row{
		{name: "default 72h unchanged", requested: 72 * time.Hour, wantFence: 72 * time.Hour, wantNotice: false},
		{name: "exactly the 1h minimum unchanged", requested: time.Hour, wantFence: time.Hour, wantNotice: false},
		{name: "above minimum unchanged", requested: 2 * time.Hour, wantFence: 2 * time.Hour, wantNotice: false},
		{name: "30m raised to 1h with notice", requested: 30 * time.Minute, wantFence: time.Hour, wantNotice: true, wantContains: []string{"30m", "1h", "minimum"}},
		{name: "1s raised to 1h with notice", requested: time.Second, wantFence: time.Hour, wantNotice: true, wantContains: []string{"1s", "1h"}},
		{name: "zero selects the default with notice", requested: 0, wantFence: vault.GCFenceDefault, wantNotice: true, wantContains: []string{"default"}},
		{name: "negative selects the default with notice", requested: -5 * time.Minute, wantFence: vault.GCFenceDefault, wantNotice: true, wantContains: []string{"default"}},
	}
	if len(rows) == 0 {
		t.Fatal("empty clampFence table exercises nothing")
	}
	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			fence, notice := clampFence(r.requested)
			if fence != r.wantFence {
				t.Fatalf("effective fence = %s, want %s", fence, r.wantFence)
			}
			if r.wantNotice {
				if notice == "" {
					t.Fatalf("expected a clamp notice for requested %s", r.requested)
				}
				for _, c := range r.wantContains {
					if !strings.Contains(notice, c) {
						t.Fatalf("notice %q missing %q", notice, c)
					}
				}
			} else if notice != "" {
				t.Fatalf("requested %s must be used as-is with no notice, got %q", r.requested, notice)
			}
			asserted++
		})
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

// TestExportMappingLines (C6): the (original -> written)
// mapping the CLI prints. A real export lists only the sanitised/disambiguated
// entries (silence when every file kept its name); a dry run lists every planned
// destination and flags the renamed ones.
func TestExportMappingLines(t *testing.T) {
	destRoot := filepath.Join(t.TempDir(), "dest")
	res := vault.ExportResult{
		DestPath: destRoot,
		Entries: []vault.ExportEntry{
			{Path: "content/a.txt", DestPath: filepath.Join(destRoot, "a.txt")},
			{Path: "content/a:b.txt", DestPath: filepath.Join(destRoot, "a_b.txt")},
			{Path: "content/CON.txt", DestPath: filepath.Join(destRoot, "_CON.txt")},
		},
	}

	// Real export: only the two renamed entries, under a header; the unchanged
	// a.txt is not listed.
	real := exportMappingLines(res, false)
	if len(real) == 0 {
		t.Fatal("a real export with renamed entries must produce mapping lines")
	}
	realJoined := strings.Join(real, "\n")
	for _, want := range []string{"renamed on export", "content/a:b.txt -> a_b.txt", "content/CON.txt -> _CON.txt"} {
		if !strings.Contains(realJoined, want) {
			t.Fatalf("real-export mapping missing %q:\n%s", want, realJoined)
		}
	}
	if strings.Contains(realJoined, "content/a.txt ->") {
		t.Fatalf("a real export must not list the unchanged entry:\n%s", realJoined)
	}

	// Dry run: every planned entry listed; the renamed ones flagged.
	dry := exportMappingLines(res, true)
	dryJoined := strings.Join(dry, "\n")
	for _, want := range []string{"planned destinations", "content/a.txt -> a.txt", "content/a:b.txt -> a_b.txt (renamed)", "content/CON.txt -> _CON.txt (renamed)"} {
		if !strings.Contains(dryJoined, want) {
			t.Fatalf("dry-run mapping missing %q:\n%s", want, dryJoined)
		}
	}
	if strings.Contains(dryJoined, "content/a.txt -> a.txt (renamed)") {
		t.Fatalf("the unchanged entry must not be flagged renamed:\n%s", dryJoined)
	}

	// A real export whose files all kept their names prints nothing extra.
	clean := vault.ExportResult{
		DestPath: destRoot,
		Entries:  []vault.ExportEntry{{Path: "content/a.txt", DestPath: filepath.Join(destRoot, "a.txt")}},
	}
	if lines := exportMappingLines(clean, false); len(lines) != 0 {
		t.Fatalf("a clean real export must print no mapping lines, got %v", lines)
	}

	// ZIP entries share the archive DestPath and are never flagged renamed.
	zipRes := vault.ExportResult{
		Zip:      true,
		DestPath: filepath.Join(destRoot, "export.zip"),
		Entries:  []vault.ExportEntry{{Path: "content/a:b.txt", DestPath: filepath.Join(destRoot, "export.zip")}},
	}
	if exportEntryRenamed(zipRes, zipRes.Entries[0]) {
		t.Fatal("a ZIP entry must never be flagged renamed")
	}
}

// TestKeychainStatusLine (C6): a reachable service with no entry
// reports "no keychain entry for this vault" (not the install advice); an
// unreachable service surfaces the original error. Every row asserted.
func TestKeychainStatusLine(t *testing.T) {
	getErr := errors.New("Secret Service lookup failed; install libsecret-tools or use SEAVAULT_PASSWORD: exit status 1")
	type row struct {
		name      string
		reachable bool
		getErr    error
		wantLine  string
		wantIsErr bool
	}
	rows := []row{
		{name: "entry exists", reachable: true, getErr: nil, wantLine: "OS keychain entry exists", wantIsErr: false},
		{name: "entry exists even if check pessimistic", reachable: false, getErr: nil, wantLine: "OS keychain entry exists", wantIsErr: false},
		{name: "reachable but no entry", reachable: true, getErr: getErr, wantLine: "no keychain entry for this vault", wantIsErr: false},
		{name: "unreachable service surfaces the error", reachable: false, getErr: getErr, wantLine: getErr.Error(), wantIsErr: true},
	}
	if len(rows) == 0 {
		t.Fatal("empty keychainStatusLine table exercises nothing")
	}
	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			line, isErr := keychainStatusLine(r.reachable, r.getErr)
			if line != r.wantLine {
				t.Fatalf("line = %q, want %q", line, r.wantLine)
			}
			if isErr != r.wantIsErr {
				t.Fatalf("isErr = %v, want %v", isErr, r.wantIsErr)
			}
			asserted++
		})
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

// TestSubcommandSynopses (C5): compact/verify --help carry a
// one-line synopsis, and writeSubcommandUsage renders the usage line, the
// synopsis, and the flag defaults into the FlagSet's output.
func TestSubcommandSynopses(t *testing.T) {
	if s := compactSynopsis(); s == "" || !strings.Contains(s, "chunk") || !strings.Contains(s, "gc") {
		t.Fatalf("compactSynopsis must describe compact and point to gc for chunk space, got %q", s)
	}
	if s := verifySynopsis(); s == "" || !strings.Contains(s, "chunk") || !strings.Contains(s, "pending") {
		t.Fatalf("verifySynopsis must describe verify and its pending-intent listing, got %q", s)
	}

	var buf bytes.Buffer
	fs := flag.NewFlagSet("compact", flag.ContinueOnError)
	fs.SetOutput(&buf)
	fs.Bool("no-keychain", false, "do not try the OS keychain")
	writeSubcommandUsage(fs, "usage: seavault compact [--no-keychain] VAULT_DIR_OR_PROFILE", compactSynopsis())
	out := buf.String()
	for _, want := range []string{"usage: seavault compact", compactSynopsis(), "-no-keychain"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered compact usage missing %q:\n%s", want, out)
		}
	}
}

// TestCmdVaultSealUnsealFormat drives the CLI seal-format/unseal-format path
// : seal-format --yes prints the device signal
// and bumps the on-disk Version to 3 / MinReader to 3; unseal-format restores
// Version 2 / MinReader 2; and seal-format with no --yes and a closed stdin
// aborts without changing anything.
func TestCmdVaultSealUnsealFormat(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")

	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", vaultPath}); err != nil {
		t.Fatalf("init: %v", err)
	}

	// seal-format --yes: prints the device signal to stderr and seals.
	stdout, stderr, err := captureOutputs(t, func() error {
		return cmdVault([]string{"seal-format", "--yes", "--no-keychain", vaultPath})
	})
	if err != nil {
		t.Fatalf("seal-format --yes: %v", err)
	}
	if !strings.Contains(stdout, "sealed") || !strings.Contains(stdout, "version 3") {
		t.Fatalf("seal-format must report the seal, got stdout:\n%s", stdout)
	}
	// This device opened the vault at init and again for the seal, so the device
	// signal must list it as an A2 (format-3) reader, not the no-inventory warning.
	if !strings.Contains(stderr, "reads format 3") {
		t.Fatalf("seal-format must print the device signal (this device reads format 3), got stderr:\n%s", stderr)
	}
	if cfg, cerr := vault.ReadConfig(vaultPath); cerr != nil || cfg.Version != 3 || cfg.MinReader != 3 {
		t.Fatalf("seal-format must persist Version=3 MinReader=3 (cfg=%+v err=%v)", cfg, cerr)
	}

	// unseal-format: restores the grace-release Version/MinReader.
	stdout, _, err = captureOutputs(t, func() error {
		return cmdVault([]string{"unseal-format", "--no-keychain", vaultPath})
	})
	if err != nil {
		t.Fatalf("unseal-format: %v", err)
	}
	if !strings.Contains(stdout, "unsealed") || !strings.Contains(stdout, "version 2") {
		t.Fatalf("unseal-format must report the reversal, got stdout:\n%s", stdout)
	}
	if cfg, cerr := vault.ReadConfig(vaultPath); cerr != nil || cfg.Version != 2 || cfg.MinReader != 2 {
		t.Fatalf("unseal-format must restore Version=2 MinReader=2 (cfg=%+v err=%v)", cfg, cerr)
	}

	// seal-format with no --yes and a closed stdin declines (a non-interactive
	// caller that forgot --yes must not accidentally seal).
	origStdin := os.Stdin
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	_ = w.Close() // immediate EOF
	os.Stdin = r
	_, _, err = captureOutputs(t, func() error {
		return cmdVault([]string{"seal-format", "--no-keychain", vaultPath})
	})
	os.Stdin = origStdin
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("seal-format without --yes and a closed stdin must abort, got %v", err)
	}
	if cfg, cerr := vault.ReadConfig(vaultPath); cerr != nil || cfg.Version != 2 {
		t.Fatalf("an aborted seal-format must not change the vault (cfg=%+v err=%v)", cfg, cerr)
	}
}

// TestFormatReaderSignal covers both the review display branches: an EMPTY
// inventory becomes the explicit no-telemetry warning (the operator must not read
// silence as "no other devices"); a non-empty one lists each device and its
// reader format level.
func TestFormatReaderSignal(t *testing.T) {
	if s := formatReaderSignal(nil); !strings.Contains(s, "no inventory of your other devices") {
		t.Fatalf("an empty inventory must render the no-telemetry warning, got %q", s)
	}
	s := formatReaderSignal([]vault.ReaderRecord{{DeviceID: "abc123", SupportedFormat: 3, Version: 2, LastSeen: "2026-09-04T00:00:00Z"}})
	if !strings.Contains(s, "abc123") || !strings.Contains(s, "format 3") {
		t.Fatalf("a non-empty inventory must list the device and its format, got %q", s)
	}
	if strings.Contains(s, "no inventory of your other devices") {
		t.Fatalf("a non-empty inventory must not render the no-telemetry warning, got %q", s)
	}
}

// TestPutRatchetsConfigMACThenDetectsForgery is the tombstone for finding
// .
// EnsureConfigMAC — the ConfigMAC ratchet — was defined (internal/vault/configmac.go)
// but never invoked by any production command, so a vault created by `init` and
// used only via put/get NEVER acquired a configTag. The common grace-release
// vault was therefore left permanently on TOFU: config forgery (VaultID /
// ChunkParams / KDF / wrap edits) went completely undetected because there was no
// tag to verify against — 's core scenario failed in the shipped binary. This
// test drives the real CLI: `put` is a write-capable command, so per it MUST
// opportunistically ratchet a tag on the first such open; a subsequent
// MAC-covered, unwrap-independent forgery (chunk.minSize) must then be caught as
// ErrConfigTampered. Before the fix the tag is absent (the first assertion fires)
// and the forgery is silently accepted (exit 0).
func TestPutRatchetsConfigMACThenDetectsForgery(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	const pw = "correct horse battery staple"
	t.Setenv("SEAVAULT_PASSWORD", pw)

	vaultPath := filepath.Join(t.TempDir(), "vaultC")
	if err := cmdInit([]string{"--kdf", "argon2id", "--argon2-time", "2", "--argon2-memory", "19456", "--argon2-parallelism", "1", vaultPath}); err != nil {
		t.Fatalf("init: %v", err)
	}
	cfgPath := filepath.Join(vaultPath, "SeaVaultData", "vault.json")

	// A fresh init writes no tag: the grace-release vault stays on TOFU until a
	// write-capable open ratchets one.
	if tag := readConfigTagForTest(t, cfgPath); tag != "" {
		t.Fatalf("init must not write a configTag (TOFU until first write-capable open), got %q", tag)
	}

	// put is a write-capable command: it MUST ratchet a ConfigTag.
	src := filepath.Join(t.TempDir(), "f3.txt")
	if err := os.WriteFile(src, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error {
		return cmdPut([]string{"--no-keychain", vaultPath, src, "/f3.txt"})
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if tag := readConfigTagForTest(t, cfgPath); tag == "" {
		t.Fatal("a write-capable `put` did not ratchet a ConfigTag; the grace-release vault is left permanently on TOFU and config forgery is undetectable")
	}

	// Act as the hostile config server: forge a MAC-covered, unwrap-independent
	// field (chunk.minSize) directly in vault.json. The ratcheted tag no longer
	// verifies, so the next open must hard-refuse.
	forgeConfigMinSizeForTest(t, cfgPath, 512)

	_, _, err := captureOutputs(t, func() error {
		return cmdList([]string{"--no-keychain", vaultPath})
	})
	if !errors.Is(err, vault.ErrConfigTampered) {
		t.Fatalf("forging a MAC-covered field after `put` must be caught as ErrConfigTampered, got %v", err)
	}
}

// readConfigTagForTest returns the configTag string from a vault.json, or "" when
// the field is absent. It reads through a RawMessage map so the rest of the
// config is untouched (used by forgeConfigMinSizeForTest to preserve the tag).
func readConfigTagForTest(t *testing.T, cfgPath string) string {
	t.Helper()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	raw, ok := m["configTag"]
	if !ok {
		return ""
	}
	var tag string
	if err := json.Unmarshal(raw, &tag); err != nil {
		t.Fatalf("parse configTag: %v", err)
	}
	return tag
}

// forgeConfigMinSizeForTest rewrites chunk.minSize in vault.json while leaving
// every other field (including the configTag) byte-identical, mimicking a hostile
// config server that edits a MAC-covered field offline.
func forgeConfigMinSizeForTest(t *testing.T, cfgPath string, minSize int) {
	t.Helper()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	var chunk map[string]json.RawMessage
	if err := json.Unmarshal(m["chunk"], &chunk); err != nil {
		t.Fatalf("parse chunk params: %v", err)
	}
	enc, err := json.Marshal(minSize)
	if err != nil {
		t.Fatal(err)
	}
	chunk["minSize"] = enc
	chunkEnc, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	m["chunk"] = chunkEnc
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// canonBase32Len counts the base32 (A-Z, 2-7) characters in s, ignoring dashes
// and spaces. A minted recovery phrase canonicalises to exactly 52; prose does
// not, so this recognises a leaked phrase anywhere in captured output.
func canonBase32Len(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			n++
		}
	}
	return n
}

// outputHasRecoveryPhrase reports whether any single line of out canonicalises to
// the 52-character recovery-phrase length using only base32 characters, dashes
// and spaces — i.e. a recovery phrase was printed.
func outputHasRecoveryPhrase(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		only := true
		for _, r := range line {
			switch {
			case r >= 'A' && r <= 'Z', r >= '2' && r <= '7', r == '-', r == ' ':
			default:
				only = false
			}
		}
		if only && canonBase32Len(line) == 52 {
			return true
		}
	}
	return false
}

func countRecoveryEntriesCLI(t *testing.T, vaultDir string) int {
	t.Helper()
	cfg, err := vault.ReadConfig(vaultDir)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	n := 0
	for _, e := range cfg.WrapEntries {
		if e.Type == vault.WrapTypeRecovery {
			n++
		}
	}
	return n
}

// T3 (I-S1/I-S3): a non-interactive `setup --preset synced-folder` reads the
// password from SEAVAULT_PASSWORD only, creates the vault, writes NO recovery
// entry, prints the remedy, and never prints a recovery phrase. With no
// SEAVAULT_PASSWORD it refuses (typed), reading nothing from argv.
func TestCmdSetupNonInteractiveSyncedFolder(t *testing.T) {
	const pw = "correct horse battery staple"

	t.Run("with SEAVAULT_PASSWORD", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		t.Setenv("SEAVAULT_PASSWORD", pw)
		vaultDir := filepath.Join(t.TempDir(), "MyVault")

		out, err := captureStdout(t, func() error {
			return cmdSetup([]string{"--preset", "synced-folder", "--vault", vaultDir, "--no-keychain"})
		})
		if err != nil {
			t.Fatalf("preset synced-folder must succeed: %v", err)
		}
		if _, oerr := vault.Open(vaultDir, pw); oerr != nil {
			t.Fatalf("the vault must be created and open with the SEAVAULT_PASSWORD value: %v", oerr)
		}
		if n := countRecoveryEntriesCLI(t, vaultDir); n != 0 {
			t.Fatalf("a non-interactive run must write NO recovery entry (I-S3); got %d", n)
		}
		if !strings.Contains(out, "recovery generate") {
			t.Fatalf("the summary must print the recovery remedy; got:\n%s", out)
		}
		if outputHasRecoveryPhrase(out) {
			t.Fatalf("a non-interactive run must never print a recovery phrase; got:\n%s", out)
		}
		if strings.Contains(out, pw) {
			t.Fatalf("the summary must not carry the password; got:\n%s", out)
		}
	})

	t.Run("without SEAVAULT_PASSWORD refuses", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
		os.Unsetenv("SEAVAULT_PASSWORD")
		vaultDir := filepath.Join(t.TempDir(), "MyVault")

		err := cmdSetup([]string{"--preset", "synced-folder", "--vault", vaultDir, "--no-keychain"})
		if err == nil {
			t.Fatal("a non-interactive run with no SEAVAULT_PASSWORD must refuse")
		}
		if !strings.Contains(err.Error(), "SEAVAULT_PASSWORD") {
			t.Fatalf("the refusal must name SEAVAULT_PASSWORD; got %v", err)
		}
		if _, statErr := os.Stat(vaultDir); !os.IsNotExist(statErr) {
			t.Fatalf("no vault may be created when the password is absent; stat err=%v", statErr)
		}
	})
}

// T14 CLI half (C11): `setup --preset rclone` without --allow-download is refused
// with the offline install options named, before any password is read (so a
// password is never taken from argv) and with nothing created.
func TestCmdSetupRclonePresetRequiresAllowDownload(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	os.Unsetenv("SEAVAULT_PASSWORD") // the refusal must not depend on a password
	vaultDir := filepath.Join(t.TempDir(), "MyVault")

	err := cmdSetup([]string{"--preset", "rclone", "--vault", vaultDir, "--remote", "myremote"})
	if err == nil {
		t.Fatal("`setup --preset rclone` without --allow-download must be refused")
	}
	for _, want := range []string{"--allow-download", "--offline-archive", "--from-binary"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name the offline option %q; got %v", want, err)
		}
	}
	if _, statErr := os.Stat(vaultDir); !os.IsNotExist(statErr) {
		t.Fatalf("nothing may be created when the rclone preset is refused; stat err=%v", statErr)
	}
}

// TestSetupSynopsis asserts the `setup --help` synopsis exists, names the wizard
// and the non-interactive SEAVAULT_PASSWORD path, and renders through the shared
// usage writer (so the --help wiring is exercised).
func TestSetupSynopsis(t *testing.T) {
	s := setupSynopsis()
	if s == "" || !strings.Contains(s, "wizard") || !strings.Contains(s, "SEAVAULT_PASSWORD") {
		t.Fatalf("setupSynopsis must describe the wizard and the SEAVAULT_PASSWORD preset path, got %q", s)
	}
	var buf bytes.Buffer
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(&buf)
	fs.Bool("expert", false, "x")
	writeSubcommandUsage(fs, "usage: seavault setup [--expert]", s)
	out := buf.String()
	for _, want := range []string{"usage: seavault setup", s, "-expert"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered setup usage missing %q:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// U1 fix tranche (Fixer B): CLI-5, CLI-6/DOC-5, ADM-1, ADM-3, ADM-5, ADM-6,
// preset-noninteractive-2. Tests live here (package main); the CLI-5 production
// change lives in internal/setup (RunInteractive is the shared wizard flow).
// ---------------------------------------------------------------------------

// scriptPrompter is a queue-driven setup.Prompter for driving RunInteractive in
// tests (design §3.2 "scripted prompter"). Each method dequeues its next answer
// and records what was Shown; an exhausted queue returns an error so a
// mis-scripted flow fails loudly instead of hanging. secretCalls counts password
// prompts so a test can prove the password step was (not) reached.
type scriptPrompter struct {
	selects     []int
	confirms    []bool
	texts       []string
	secrets     []string
	shown       []string
	secretCalls int
}

func (p *scriptPrompter) Select(_ string, _ []setup.Option, def int) (int, error) {
	if len(p.selects) == 0 {
		return def, fmt.Errorf("scriptPrompter: no Select answer queued")
	}
	v := p.selects[0]
	p.selects = p.selects[1:]
	return v, nil
}

func (p *scriptPrompter) Confirm(_ string, def bool) (bool, error) {
	if len(p.confirms) == 0 {
		return def, fmt.Errorf("scriptPrompter: no Confirm answer queued")
	}
	v := p.confirms[0]
	p.confirms = p.confirms[1:]
	return v, nil
}

func (p *scriptPrompter) Text(_, def string) (string, error) {
	if len(p.texts) == 0 {
		return def, fmt.Errorf("scriptPrompter: no Text answer queued")
	}
	v := p.texts[0]
	p.texts = p.texts[1:]
	return v, nil
}

func (p *scriptPrompter) Secret(_ string) (string, error) {
	p.secretCalls++
	if len(p.secrets) == 0 {
		return "", fmt.Errorf("scriptPrompter: no Secret answer queued")
	}
	v := p.secrets[0]
	p.secrets = p.secrets[1:]
	return v, nil
}

func (p *scriptPrompter) Show(msg string)   { p.shown = append(p.shown, msg) }
func (p *scriptPrompter) shownText() string { return strings.Join(p.shown, "\n") }

// TestSetupInteractiveOpenExistingVault (CLI-5): when the chosen location already
// holds a vault, the wizard offers to open it IMMEDIATELY — before the password
// and the rest of the ceremony are spent. Accepting "open it now" finishes without
// ever asking for a password.
func TestSetupInteractiveOpenExistingVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	existDir := filepath.Join(home, "already", "MyVault")
	if err := vault.CreateWithOptions(existDir, "pw-existing", vault.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pr := &scriptPrompter{
		texts:    []string{existDir}, // step 1: where should the vault live?
		confirms: []bool{true},       // "A vault already exists ... Open it now?" -> yes
	}
	res, err := setup.RunInteractive(pr, setup.DefaultDeps(), setup.RunOptions{
		Home:       home,
		NoKeychain: true,
		NoOpen:     true,
		// OpenApp nil -> the affordance prints the command instead of launching.
	})
	if err != nil {
		t.Fatalf("choosing 'open it now' must not error: %v", err)
	}
	if pr.secretCalls != 0 {
		t.Fatalf("the password step must be SKIPPED when the location already holds a vault (CLI-5); Secret was called %d times", pr.secretCalls)
	}
	if !strings.Contains(pr.shownText(), "seavault gui") {
		t.Fatalf("the open affordance must name `seavault gui`; shown:\n%s", pr.shownText())
	}
	_ = res
}

// TestSetupInteractiveLeftoversRemoveAndRetry (CLI-5): interrupted-setup leftovers
// (a non-empty dir with no vault.json) are caught right after the location is
// chosen; the wizard offers remove-and-retry, then proceeds to build the vault.
func TestSetupInteractiveLeftoversRemoveAndRetry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	target := filepath.Join(home, "vault", "MyVault")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "stray.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "leftovers-pass"
	pr := &scriptPrompter{
		texts:    []string{target},
		confirms: []bool{true, false}, // remove leftovers -> yes; recovery -> defer
		selects:  []int{2},            // cloud: local-only
		secrets:  []string{pw, pw},    // password + confirm
	}
	res, err := setup.RunInteractive(pr, setup.DefaultDeps(), setup.RunOptions{
		Home:       home,
		NoKeychain: true,
		NoOpen:     true,
	})
	if err != nil {
		t.Fatalf("remove-and-retry must complete the setup: %v", err)
	}
	if pr.secretCalls != 2 {
		t.Fatalf("after removing leftovers the flow must proceed to the password step; Secret called %d times", pr.secretCalls)
	}
	if _, oerr := vault.Open(target, pw); oerr != nil {
		t.Fatalf("a working vault must exist at the target after remove-and-retry: %v", oerr)
	}
	if _, statErr := os.Stat(filepath.Join(target, "stray.tmp")); !os.IsNotExist(statErr) {
		t.Fatalf("the leftover file must be gone after remove-and-retry; stat err=%v", statErr)
	}
	_ = res
}

// TestSetupInteractiveProfileCollisionSuffixed (CLI-5 / C3): a resolved profile
// name that already points at a DIFFERENT vault is caught before the password; the
// wizard offers a suffixed name and registers the NEW vault under it, leaving the
// original profile untouched (C3: register under a new name, not silently repoint).
func TestSetupInteractiveProfileCollisionSuffixed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	otherDir := filepath.Join(home, "other", "MyVault-other")
	if err := vault.CreateWithOptions(otherDir, "pw-other", vault.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Add("MyVault", otherDir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "new", "MyVault") // basename "MyVault" collides
	const pw = "suffix-pass"
	pr := &scriptPrompter{
		texts:    []string{target},
		confirms: []bool{true, false}, // "register as MyVault-2?" -> yes; recovery -> defer
		selects:  []int{2},            // cloud: local-only
		secrets:  []string{pw, pw},
	}
	res, err := setup.RunInteractive(pr, setup.DefaultDeps(), setup.RunOptions{
		Home:       home,
		NoKeychain: true,
		NoOpen:     true,
	})
	if err != nil {
		t.Fatalf("the suffixed-name affordance must complete: %v", err)
	}
	if res.ProfileName != "MyVault-2" {
		t.Fatalf("the new vault must register under the suffixed name; got %q", res.ProfileName)
	}
	if e, found, _ := profile.Resolve("MyVault"); !found || filepath.Clean(e.VaultPath) != filepath.Clean(otherDir) {
		t.Fatalf("the original MyVault profile must be untouched (-> %s); got found=%v %q", otherDir, found, e.VaultPath)
	}
	if e, found, _ := profile.Resolve("MyVault-2"); !found || filepath.Clean(e.VaultPath) != filepath.Clean(target) {
		t.Fatalf("MyVault-2 must point at the new vault %s; got found=%v %q", target, found, e.VaultPath)
	}
}

// TestSetupFailureLines (CLI-6/DOC-5): on a failed setup the operator is told the
// vault was created (when it was) and sees the step-branched CloudNote, each at
// most once (the CloudNote must never be printed twice).
func TestSetupFailureLines(t *testing.T) {
	note := "the vault and profile were created, but the remote did not verify: boom. Fix it and run `seavault remote test r`."
	res := setup.Result{VaultID: "vid", VaultDir: "/x/MyVault", ProfileName: "MyVault", CloudNote: note}
	lines := setupFailureLines(res)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "/x/MyVault") || !strings.Contains(joined, "created") {
		t.Fatalf("a built-then-failed setup must name the created vault; got %q", joined)
	}
	if strings.Count(joined, note) != 1 {
		t.Fatalf("the CloudNote must appear exactly once; got %d in %q", strings.Count(joined, note), joined)
	}
	if got := setupFailureLines(setup.Result{}); len(got) != 0 {
		t.Fatalf("a result with nothing built yields no reassurance lines; got %v", got)
	}
	only := setupFailureLines(setup.Result{VaultID: "v", VaultDir: "/d", ProfileName: "p"})
	if len(only) != 1 || !strings.Contains(only[0], "/d") {
		t.Fatalf("a built vault with no CloudNote yields exactly the created line; got %v", only)
	}
}

// TestSetupPresetIdempotentRerun (ADM-5): a --preset run whose --vault already
// holds a matching vault is an idempotent no-op — it reports the existing vault
// and exits 0, so a provisioning loop is safe to re-run.
func TestSetupPresetIdempotentRerun(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	vaultDir := filepath.Join(t.TempDir(), "MyVault")

	if err := cmdSetup([]string{"--preset", "local", "--vault", vaultDir, "--no-keychain"}); err != nil {
		t.Fatalf("first run must succeed: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return cmdSetup([]string{"--preset", "local", "--vault", vaultDir, "--no-keychain"})
	})
	if err != nil {
		t.Fatalf("an idempotent re-run must exit 0 (err nil); got %v", err)
	}
	if !strings.Contains(out, "already exists") {
		t.Fatalf("the re-run must report the existing vault; got:\n%s", out)
	}
}

// TestSetupPresetRerunProfileMismatch (ADM-5): an existing vault at --vault whose
// requested profile name already points at a DIFFERENT vault is a genuine
// mismatch — it keeps a non-zero exit (distinct from the exit-0 match) and changes
// nothing.
func TestSetupPresetRerunProfileMismatch(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	const pw = "correct horse battery staple"
	t.Setenv("SEAVAULT_PASSWORD", pw)
	dirA := filepath.Join(t.TempDir(), "A")
	dirB := filepath.Join(t.TempDir(), "B")
	if err := cmdSetup([]string{"--preset", "local", "--vault", dirA, "--no-keychain", "--profile", "shared"}); err != nil {
		t.Fatalf("seed run A must succeed: %v", err)
	}
	if err := vault.CreateWithOptions(dirB, pw, vault.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	err := cmdSetup([]string{"--preset", "local", "--vault", dirB, "--no-keychain", "--profile", "shared"})
	if err == nil {
		t.Fatal("a vault at --vault whose profile name points elsewhere must NOT exit 0")
	}
	if !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("the mismatch must be handled by the idempotent-rerun path (naming 'nothing was changed'); got %v", err)
	}
	if e, _, _ := profile.Resolve("shared"); filepath.Clean(e.VaultPath) != filepath.Clean(dirA) {
		t.Fatalf("the mismatch must not repoint the profile; shared -> %q", e.VaultPath)
	}
}

// TestSetupPresetJSONOutput (ADM-1): --preset --json emits the machine-readable
// Result fields and no secret; prose stays the default.
func TestSetupPresetJSONOutput(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	const pw = "correct horse battery staple"
	t.Setenv("SEAVAULT_PASSWORD", pw)
	vaultDir := filepath.Join(t.TempDir(), "MyVault")

	out, err := captureStdout(t, func() error {
		return cmdSetup([]string{"--preset", "local", "--vault", vaultDir, "--no-keychain", "--json"})
	})
	if err != nil {
		t.Fatalf("json preset run must succeed: %v", err)
	}
	var got setupResultJSON
	if jerr := json.Unmarshal([]byte(out), &got); jerr != nil {
		t.Fatalf("--json output must be a single JSON document: %v\n%s", jerr, out)
	}
	if got.VaultID == "" {
		t.Fatalf("json must carry a vaultID; got:\n%s", out)
	}
	if filepath.Clean(got.VaultDir) != filepath.Clean(vaultDir) {
		t.Fatalf("json vaultDir mismatch: %q", got.VaultDir)
	}
	if got.Profile != "MyVault" {
		t.Fatalf("json profile mismatch: %q", got.Profile)
	}
	if got.Cloud != "local" {
		t.Fatalf("json cloud mismatch: %q", got.Cloud)
	}
	if got.RecoveryCreated {
		t.Fatal("a preset run never creates a recovery key (I-S3)")
	}
	if strings.Contains(out, pw) {
		t.Fatalf("json output must never carry the password")
	}

	prose, perr := captureStdout(t, func() error {
		return cmdSetup([]string{"--preset", "local", "--vault", filepath.Join(t.TempDir(), "V2"), "--no-keychain"})
	})
	if perr != nil {
		t.Fatal(perr)
	}
	if strings.HasPrefix(strings.TrimSpace(prose), "{") {
		t.Fatalf("prose must be the default without --json; got:\n%s", prose)
	}
}

// TestSetupHelpDoubleDashAndExitCodes (ADM-6 + ADM-3): `setup --help` prints the
// double-dash long flag forms (matching the usage line), documents the exit-code
// contract, and states the rclone-remote precondition.
func TestSetupHelpDoubleDashAndExitCodes(t *testing.T) {
	var buf bytes.Buffer
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(&buf)
	registerSetupFlags(fs)
	writeSetupUsage(fs)
	out := buf.String()

	for _, want := range []string{"--expert", "--preset", "--vault", "--remote", "--allow-download", "--no-keychain", "--profile", "--no-open", "--json"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup --help must list the long flag %q; got:\n%s", want, out)
		}
	}
	// The flag BLOCK (not just the usage line) renders double-dash: the usage line
	// spells flags as "[--expert]", so a two-space "  --expert" appears only in the
	// rendered flag block.
	if !strings.Contains(out, "  --expert") {
		t.Fatalf("the flag block must render double-dash long forms; got:\n%s", out)
	}
	for _, want := range []string{"Exit codes:", "idempotent re-run", "setup failed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup --help must document the exit-code contract (%q); got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "ALREADY EXISTS") || !strings.Contains(out, "rclone config") {
		t.Fatalf("setup --help must state --remote must already exist in each machine's rclone config (ADM-3); got:\n%s", out)
	}
}

// TestSetupPresetRecoveryRemedyShellQuoted (preset-noninteractive-2, main.go half):
// the printed recovery-skip remedy shell-quotes a profile name with spaces so the
// command pastes as a single argument.
func TestSetupPresetRecoveryRemedyShellQuoted(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	const pw = "correct horse battery staple"
	t.Setenv("SEAVAULT_PASSWORD", pw)
	vaultDir := filepath.Join(t.TempDir(), "My Vault") // spaced basename -> spaced profile

	out, err := captureStdout(t, func() error {
		return cmdSetup([]string{"--preset", "local", "--vault", vaultDir, "--no-keychain"})
	})
	if err != nil {
		t.Fatalf("preset run must succeed: %v", err)
	}
	if !strings.Contains(out, "recovery generate 'My Vault'") {
		t.Fatalf("the recovery remedy must shell-quote a spaced profile name; got:\n%s", out)
	}
	if strings.Contains(out, "recovery generate My Vault") {
		t.Fatalf("the remedy must not interpolate the spaced name raw; got:\n%s", out)
	}
}
