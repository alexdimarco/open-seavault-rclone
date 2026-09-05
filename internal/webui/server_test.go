// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

func TestMain(m *testing.M) {
	appHome, err := os.MkdirTemp("", "seavault-webui-test-home-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("SEAVAULT_APP_HOME", appHome)
	code := m.Run()
	_ = os.RemoveAll(appHome)
	os.Exit(code)
}

// newTestSession inserts a GUI session into s and returns the cookie that names
// it. Every GUI request (except the Host-guard probe and the launch redemption)
// now needs one; the shared helpers attach one automatically. See.
func newTestSession(s *Server, loggedIn bool) *http.Cookie {
	id, err := randomToken()
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.authSessions[id] = session{expires: time.Now().Add(sessionTTL), loggedIn: loggedIn, cookieIssued: time.Now()}
	s.mu.Unlock()
	return &http.Cookie{Name: guiSessionCookie, Value: id}
}

// authReq attaches a loopback Host and a fresh logged-in session cookie to req,
// as every non-launch request from the live GUI page carries.
func authReq(s *Server, req *http.Request) *http.Request {
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, true))
	return req
}

func postJSON(t *testing.T, s *Server, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SeaVault-Token", s.token)
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func getJSON(t *testing.T, s *Server, path string, dst any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if dst != nil {
		if err := json.Unmarshal(rr.Body.Bytes(), dst); err != nil {
			t.Fatalf("decode %s: %v body=%s", path, err, rr.Body.String())
		}
	}
	return rr.Code
}

func TestIndexUsesResponsiveCrossBrowserLayout(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index failed: %d", rr.Code)
	}
	html := rr.Body.String()
	checks := []string{
		`<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">`,
		`class="app-shell"`,
		`class="result-panel"`,
		`aria-live="polite"`,
		`grid-template-columns: minmax(0, 1fr) minmax(340px, 420px)`,
		`@media (max-width: 1180px)`,
		`@media (max-width: 720px)`,
		`* { box-sizing: border-box; }`,
		`input, select, textarea { width: 100%;`,
		`class="table-wrap"`,
		`id="compatWarning"`,
		`id="vaultSelect"`,
		`id="availableVaults"`,
		`Save vault location/password`,
		`webkitdirectory directory multiple`,
		`selected folder name is already included`,
		`id="fileSummary"`,
		`id="folderSummary"`,
		`Import local path`,
		`Browser-selected folders cannot fill this field`,
		`value="`,
		`The browser could not reach the local SeaVault GUI service`,
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Fatalf("responsive GUI markup missing %q", want)
		}
	}
}

func TestSavedVaultStatusListsProfiledVault(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "alpha")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          "passphrase",
		"profile":           "alpha",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	if len(status.AvailableVaults) != 1 {
		t.Fatalf("expected one saved vault, got %#v", status.AvailableVaults)
	}
	got := status.AvailableVaults[0]
	if got.Name != "alpha" || got.VaultPath != vaultPath || !got.Open || got.Status != "open" {
		t.Fatalf("unexpected vault status: %#v", got)
	}
}

func TestInitCreatesAndOpensVault(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          "passphrase",
		"profile":           "",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	if !status.Open || status.VaultPath != vaultPath {
		t.Fatalf("expected open vault at %q, got %#v", vaultPath, status)
	}
}

func TestInitExpandsTildePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         "~/Nextcloud/seavault",
		"password":          "passphrase",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	want := filepath.Join(home, "Nextcloud", "seavault")
	if !status.Open || status.VaultPath != want {
		t.Fatalf("expected open vault at %q, got %#v", want, status)
	}
}

func TestOpenAcceptsOlderCreateFormPayload(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	initResp := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          "passphrase",
		"profile":           "",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if initResp.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", initResp.Code, initResp.Body.String())
	}
	_ = postJSON(t, s, "/api/close", map[string]any{})
	openResp := postJSON(t, s, "/api/open", map[string]any{
		"vaultPath":    vaultPath,
		"password":     "passphrase",
		"profile":      "work-cloud",
		"kdf":          "scrypt",
		"savePassword": false,
		"useKeychain":  false,
	})
	if openResp.Code != http.StatusOK {
		t.Fatalf("open failed: %d %s", openResp.Code, openResp.Body.String())
	}
}

func TestInitRejectsSlashUserPathBeforeMkdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only path shape")
	}
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         "/user/alex/Nextcloud/seavault",
		"password":          "passphrase",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Use ~/Nextcloud/seavault") {
		t.Fatalf("unexpected error: %s", rr.Body.String())
	}
}

func initOpenTestVault(t *testing.T, s *Server) string {
	t.Helper()
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath":         vaultPath,
		"password":          "passphrase",
		"kdf":               "argon2id",
		"argon2Time":        2,
		"argon2MemoryKiB":   19456,
		"argon2Parallelism": 1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	return vaultPath
}

func TestBrowserFolderUploadPreservesRelativePaths(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", "browser-root"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("relpaths", "folder/nested/a.txt"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("files", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("folder upload")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-SeaVault-Token", s.token)
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", rr.Code, rr.Body.String())
	}
	var files struct {
		Files []fileDTO `json:"files"`
	}
	if code := getJSON(t, s, "/api/files", &files); code != http.StatusOK {
		t.Fatalf("files failed: %d", code)
	}
	if len(files.Files) != 1 || files.Files[0].Path != "content/browser-root/folder/nested/a.txt" {
		t.Fatalf("unexpected files: %#v", files.Files)
	}
}

func TestUploadPathUsesRsync(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not available")
	}
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	src := filepath.Join(t.TempDir(), "source-dir")
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "nested", "a.txt"), []byte("rsync gui"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := postJSON(t, s, "/api/upload-path", map[string]any{
		"sourcePath":  src,
		"virtualPath": "local-rsync",
		"method":      "rsync",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("upload path failed: %d %s", rr.Code, rr.Body.String())
	}
	var files struct {
		Files []fileDTO `json:"files"`
	}
	if code := getJSON(t, s, "/api/files", &files); code != http.StatusOK {
		t.Fatalf("files failed: %d", code)
	}
	if len(files.Files) != 1 || files.Files[0].Path != "content/local-rsync/nested/a.txt" {
		t.Fatalf("unexpected files: %#v", files.Files)
	}
}

func TestRcloneRemoteAndSSHKeyAPIs(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if code := getJSON(t, s, "/api/rclone/status", &st); code != http.StatusOK {
		t.Fatalf("rclone status failed: %d", code)
	}
	vaultPath := filepath.Join(t.TempDir(), "vault")
	remotePath := filepath.Join(t.TempDir(), "remote")
	rr := postJSON(t, s, "/api/remote", map[string]any{
		"name":       "local-copy",
		"type":       "local",
		"vaultPath":  vaultPath,
		"remotePath": remotePath,
		"backend":    "local",
		"transfers":  2,
		"checkers":   4,
		"fastList":   false,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("remote save failed: %d %s", rr.Code, rr.Body.String())
	}
	var rem map[string]any
	if code := getJSON(t, s, "/api/remotes", &rem); code != http.StatusOK {
		t.Fatalf("remote list failed: %d", code)
	}
	rr = postJSON(t, s, "/api/ssh-keys", map[string]any{"name": "gui"})
	if rr.Code != http.StatusOK {
		t.Fatalf("ssh key generate failed: %d %s", rr.Code, rr.Body.String())
	}
	var pub map[string]string
	if code := getJSON(t, s, "/api/ssh-key-public?name=gui_ed25519", &pub); code != http.StatusOK {
		t.Fatalf("ssh key public failed: %d", code)
	}
	if !strings.HasPrefix(pub["publicKey"], "ssh-ed25519 ") {
		t.Fatalf("unexpected public key: %q", pub["publicKey"])
	}
}

func TestExportAPIPlansAndExportsFolder(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", "docs/"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("files", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("export me")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-SeaVault-Token", s.token)
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", rr.Code, rr.Body.String())
	}
	dest := filepath.Join(t.TempDir(), "export")
	rr = postJSON(t, s, "/api/export", map[string]any{"virtualPath": "docs", "destPath": dest, "overwrite": "fail", "dryRun": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("export dry-run failed: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dry-run created destination, err=%v", err)
	}
	rr = postJSON(t, s, "/api/export", map[string]any{"virtualPath": "docs", "destPath": dest, "overwrite": "fail"})
	if rr.Code != http.StatusOK {
		t.Fatalf("export failed: %d %s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "export me" {
		t.Fatalf("exported file = %q", string(got))
	}
}

func TestRsyncStatusAPI(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if code := getJSON(t, s, "/api/rsync/status?binary=definitely-not-rsync", &st); code != http.StatusOK {
		t.Fatalf("rsync status failed: %d", code)
	}
	if available, _ := st["available"].(bool); available {
		t.Fatalf("expected fake rsync to be unavailable: %#v", st)
	}
	if st["defaultHint"] == "" || st["os"] == "" {
		t.Fatalf("expected rsync status to include OS/default hint: %#v", st)
	}
}

func TestVaultMoveAPIUpdatesSavedProfile(t *testing.T) {
	appHome := filepath.Join(t.TempDir(), "app")
	t.Setenv("SEAVAULT_APP_HOME", appHome)
	root := t.TempDir()
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "old-vault")
	dst := filepath.Join(root, "new-vault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": src,
		"password":  "passphrase",
		"profile":   "move-me",
		"kdf":       "pbkdf2",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = postJSON(t, s, "/api/vault-move", map[string]any{
		"profileName":          "move-me",
		"destinationPath":      dst,
		"updateRemoteProfiles": true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("move failed: %d %s", rr.Code, rr.Body.String())
	}
	metaName, _, resErr := vault.ResolveMetaDir(dst)
	if resErr != nil {
		t.Fatalf("resolve destination metadata: %v", resErr)
	}
	if _, err := os.Stat(filepath.Join(dst, metaName, "vault.json")); err != nil {
		t.Fatalf("destination metadata missing: %v", err)
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	found := false
	for _, v := range status.AvailableVaults {
		if v.Name == "move-me" {
			found = true
			if filepath.Clean(v.VaultPath) != filepath.Clean(dst) {
				t.Fatalf("profile path not moved: %s", v.VaultPath)
			}
		}
	}
	if !found {
		t.Fatal("moved profile not found in status")
	}
}

func davRequest(t *testing.T, s *Server, method, virtualPath string, body *bytes.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	urlPath := "/dav/" + s.davToken + "/" + strings.TrimPrefix(strings.ReplaceAll(virtualPath, "\\", "/"), "/")
	req := httptest.NewRequest(method, urlPath, body)
	// The embedded localdav server enforces a loopback Host allowlist; drive it
	// under a loopback Host as a real GUI client would. /dav uses the distinct
	// davToken, not the CSRF token. A session cookie is attached
	// so the flow also holds when a GUI password is configured.
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, true))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func TestIntegratedWebDAVFileManagerSmoke(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	filesReq := authReq(s, httptest.NewRequest(http.MethodGet, "/files/", nil))
	filesRR := httptest.NewRecorder()
	s.ServeHTTP(filesRR, filesReq)
	if filesRR.Code != http.StatusOK {
		t.Fatalf("/files failed: %d", filesRR.Code)
	}
	html := filesRR.Body.String()
	for _, want := range []string{"WebDAV file manager", "davPropfind", "PROPFIND", "Drop files here", "copyDavURL", "webdavStatusBox", "Select current folder"} {
		if !strings.Contains(html, want) {
			t.Fatalf("/files markup missing %q", want)
		}
	}

	rr := davRequest(t, s, http.MethodPut, "docs/a.txt", bytes.NewReader([]byte("alpha")), nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("PUT failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "MKCOL", "empty-folder", nil, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("MKCOL failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "MKCOL", "content/explicit-empty", nil, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("MKCOL under content failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodDelete, "content", nil, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected protected content delete rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "COPY", "", nil, map[string]string{"Destination": "/dav/" + s.davToken + "/root-copy"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected root COPY rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "PROPFIND", "", nil, map[string]string{"Depth": "1"})
	if rr.Code != 207 {
		t.Fatalf("PROPFIND root failed: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "/content/") {
		t.Fatalf("PROPFIND root did not include content folder: %s", rr.Body.String())
	}
	rr = davRequest(t, s, "PROPFIND", "docs", nil, map[string]string{"Depth": "1"})
	if rr.Code != 207 || !strings.Contains(rr.Body.String(), "a.txt") {
		t.Fatalf("PROPFIND nested failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodGet, "docs/a.txt", nil, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "alpha" {
		t.Fatalf("GET failed: %d %q", rr.Code, rr.Body.String())
	}
	if cache := rr.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("GET missing no-store header: %q", cache)
	}
	rr = davRequest(t, s, "COPY", "docs/a.txt", nil, map[string]string{"Destination": "/dav/" + s.davToken + "/docs/b.txt"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("COPY failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "MOVE", "docs/b.txt", nil, map[string]string{"Destination": "/dav/" + s.davToken + "/docs/c.txt"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("MOVE failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodGet, "docs/c.txt", nil, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "alpha" {
		t.Fatalf("GET moved failed: %d %q", rr.Code, rr.Body.String())
	}
	// Export ZIP now goes through a single-use ticket: the CSRF
	// token no longer rides in the download URL.
	ticketRR := postJSON(t, s, "/api/export-zip/ticket", map[string]any{"path": "docs"})
	if ticketRR.Code != http.StatusOK {
		t.Fatalf("export ticket failed: %d %s", ticketRR.Code, ticketRR.Body.String())
	}
	var ticketResp struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(ticketRR.Body.Bytes(), &ticketResp); err != nil {
		t.Fatalf("decode ticket: %v body=%s", err, ticketRR.Body.String())
	}
	if ticketResp.Ticket == "" {
		t.Fatalf("empty export ticket: %s", ticketRR.Body.String())
	}
	rr = httptest.NewRecorder()
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/api/export-zip?ticket="+ticketResp.Ticket, nil))
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("ZIP download failed: %d content-type=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodDelete, "docs/c.txt", nil, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE failed: %d %s", rr.Code, rr.Body.String())
	}
}

func TestIntegratedWebDAVSecurityControls(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	badReq := httptest.NewRequest("PROPFIND", "/dav/not-the-token/", nil)
	badReq.Host = "127.0.0.1"
	badRR := httptest.NewRecorder()
	s.ServeHTTP(badRR, badReq)
	if badRR.Code != http.StatusForbidden {
		t.Fatalf("expected token rejection, got %d", badRR.Code)
	}

	rr := davRequest(t, s, http.MethodPut, ".SeAvAuLt/evil", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected case-insensitive.seavault rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodPut, ".seavault/evil", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected.seavault rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodPut, "../evil", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected traversal rejection, got %d %s", rr.Code, rr.Body.String())
	}

	rr = postJSON(t, s, "/api/webdav", map[string]any{"readOnly": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("set readonly failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodPut, "docs/readonly.txt", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected readonly write rejection, got %d %s", rr.Code, rr.Body.String())
	}

	oldToken := s.token
	rr = postJSON(t, s, "/api/close", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("close failed: %d %s", rr.Code, rr.Body.String())
	}
	if s.token == oldToken {
		t.Fatal("expected token rotation on close")
	}
	closedReq := httptest.NewRequest("PROPFIND", "/dav/"+s.davToken+"/", nil)
	closedReq.Host = "127.0.0.1"
	closedRR := httptest.NewRecorder()
	s.ServeHTTP(closedRR, closedReq)
	if closedRR.Code != http.StatusConflict {
		t.Fatalf("expected WebDAV stopped when vault closes, got %d", closedRR.Code)
	}
}

func TestGuiAuthShowsLoginLandingAndProtectsAPI(t *testing.T) {
	s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	// DEVIATION (/ step 4): with a GUI password set, GET / WITHOUT a
	// session is now the static 403 page, not the login form. The old assertion
	// (auth-off/landing showed the login page without a session) contradicted the
	// new "everything needs a session" rule, so it is inverted here.
	noSess := httptest.NewRequest(http.MethodGet, "/", nil)
	noSess.Host = "127.0.0.1"
	noSessRR := httptest.NewRecorder()
	s.ServeHTTP(noSessRR, noSess)
	if noSessRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for / without a session, got %d", noSessRR.Code)
	}
	if strings.Contains(noSessRR.Body.String(), "SeaVault login") {
		t.Fatalf("no-session page must not be the login form: %q", noSessRR.Body.String())
	}

	// A non-loggedIn session (as launch redemption creates when a password is
	// set) renders the login page at /.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, false))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login landing failed: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "SeaVault login") {
		t.Fatalf("expected login landing page, got %q", rr.Body.String())
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	apiReq.Host = "127.0.0.1"
	apiReq.AddCookie(newTestSession(s, false))
	apiRR := httptest.NewRecorder()
	s.ServeHTTP(apiRR, apiReq)
	if apiRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected API to return 401, got %d %s", apiRR.Code, apiRR.Body.String())
	}
}

func TestGuiAuthSessionAllowsIndexAndLogoutClearsSession(t *testing.T) {
	s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := newTestSession(s, true)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated index failed: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Logout") {
		t.Fatalf("expected logout link in authenticated UI")
	}

	logoutReq := httptest.NewRequest(http.MethodGet, "/logout", nil)
	logoutReq.Host = "127.0.0.1"
	logoutReq.AddCookie(cookie)
	logoutRR := httptest.NewRecorder()
	s.ServeHTTP(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", logoutRR.Code)
	}
	if _, ok := s.authSessions[cookie.Value]; ok {
		t.Fatalf("logout did not remove server-side session")
	}
	if got := logoutRR.Header().Get("Clear-Site-Data"); got == "" {
		t.Fatalf("logout should ask the browser to clear local site data")
	}
}

func TestHelpPageAccessibleWithAuthEnabled(t *testing.T) {
	s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/help", nil)
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, false))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("help page failed: %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "SeaVault help") || !strings.Contains(body, "Settings page") || !strings.Contains(body, "Reset password/config") {
		t.Fatalf("help page missing expected content: %q", body)
	}
}

// getResetNonce fetches the /reset-config page (which mints a fresh nonce) and
// extracts the hidden nonce input value.
func getResetNonce(t *testing.T, s *Server, cookie *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/reset-config", nil)
	req.Host = "127.0.0.1"
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("reset page failed: %d", rr.Code)
	}
	m := resetNoncePattern.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatalf("reset page missing nonce input: %s", rr.Body.String())
	}
	return m[1]
}

var resetNoncePattern = regexp.MustCompile(`name="nonce"[^>]*value="([0-9a-fA-F]+)"`)

func TestResetConfigClearsGuiAuthAndConfig(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "https", Username: "alex", PasswordConfigured: true}, Log: appconfig.LogConfig{MaxEntries: 77, Persist: true}}
	if err := appconfig.Save(cfg); err != nil {
		t.Fatal(err)
	}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	cookie := newTestSession(s, true)

	// DEVIATION (/D5): a bare POST confirm=RESET no longer resets. The reset
	// must carry a nonce minted by the GET page, so drive the page-then-post flow.
	nonce := getResetNonce(t, s, cookie)
	form := url.Values{"confirm": {"RESET"}, "nonce": {nonce}}
	req := httptest.NewRequest(http.MethodPost, "/reset-config", strings.NewReader(form.Encode()))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("reset failed: %d %s", rr.Code, rr.Body.String())
	}
	if s.guiAuthEnabled() {
		t.Fatalf("GUI auth should be disabled after reset")
	}
	if len(s.authSessions) != 0 {
		t.Fatalf("reset should clear server-side sessions")
	}
	if got := rr.Header().Get("Clear-Site-Data"); got == "" {
		t.Fatalf("reset should ask the browser to clear local site data")
	}
	loaded, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GUI.Username != "" || loaded.GUI.PasswordConfigured || loaded.GUI.Protocol != "http" || loaded.Log.MaxEntries != appconfig.Default().Log.MaxEntries {
		t.Fatalf("config was not reset to defaults: %+v", loaded)
	}
}

func TestResetConfigRequiresNonceAndSameSite(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}, Log: appconfig.LogConfig{MaxEntries: 55}}
	if err := appconfig.Save(cfg); err != nil {
		t.Fatal(err)
	}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	cookie := newTestSession(s, true)

	post := func(form url.Values, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/reset-config", strings.NewReader(form.Encode()))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr
	}

	// confirm=RESET but NO nonce -> config intact.
	post(url.Values{"confirm": {"RESET"}}, nil)
	if !s.guiAuthEnabled() {
		t.Fatalf("reset without a nonce wiped the config")
	}

	// valid nonce but a cross-site fetch -> config intact.
	nonce := getResetNonce(t, s, cookie)
	post(url.Values{"confirm": {"RESET"}, "nonce": {nonce}}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if !s.guiAuthEnabled() {
		t.Fatalf("cross-site reset wiped the config")
	}

	// a fresh nonce, same-origin -> resets.
	nonce = getResetNonce(t, s, cookie)
	post(url.Values{"confirm": {"RESET"}, "nonce": {nonce}}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if s.guiAuthEnabled() {
		t.Fatalf("same-origin reset with a valid nonce should have wiped the config")
	}
}

// TestHostGuardRejectsForeignHost covers the webui half of:
// a foreign Host is rejected on the app, the API and the WebDAV mount, while
// loopback names and the configured extra Host are accepted for both / and /dav.
func TestHostGuardRejectsForeignHost(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	s.AllowedHosts = []string{"vault.lan"}

	get := func(host, target string) int {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Host = host
		req.AddCookie(newTestSession(s, true))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr.Code
	}
	propfind := func(host string) int {
		req := httptest.NewRequest("PROPFIND", "/dav/"+s.davToken+"/", nil)
		req.Host = host
		req.Header.Set("Depth", "1")
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := get("evil.example", "/"); code != http.StatusForbidden {
		t.Fatalf("/ under evil Host = %d, want 403", code)
	}
	if code := get("evil.example", "/api/status"); code != http.StatusForbidden {
		t.Fatalf("/api/status under evil Host = %d, want 403", code)
	}
	if code := propfind("evil.example"); code != http.StatusForbidden {
		t.Fatalf("/dav under evil Host = %d, want 403", code)
	}
	for _, host := range []string{"127.0.0.1:8787", "localhost", "[::1]:8787"} {
		if code := get(host, "/"); code != http.StatusOK {
			t.Fatalf("/ under %q = %d, want 200", host, code)
		}
	}
	if code := get("vault.lan", "/"); code != http.StatusOK {
		t.Fatalf("/ under vault.lan = %d, want 200", code)
	}
	if code := propfind("vault.lan"); code != http.StatusMultiStatus {
		t.Fatalf("/dav under vault.lan = %d, want 207", code)
	}
	if code := propfind("127.0.0.1"); code != http.StatusMultiStatus {
		t.Fatalf("/dav under loopback = %d, want 207", code)
	}
}

// TestLaunchSecretCreatesSession covers: / without a
// session is a 403 page that never leaks the CSRF token; ?redeemed=1 shows the
// cookie-blocked variant; a wrong launch secret is 403; the right one sets a
// session cookie and 302s to /?redeemed=1, after which / renders.
func TestLaunchSecretCreatesSession(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	noSess := httptest.NewRequest(http.MethodGet, "/", nil)
	noSess.Host = "127.0.0.1"
	noSessRR := httptest.NewRecorder()
	s.ServeHTTP(noSessRR, noSess)
	if noSessRR.Code != http.StatusForbidden {
		t.Fatalf("/ without session = %d, want 403", noSessRR.Code)
	}
	if strings.Contains(noSessRR.Body.String(), s.token) {
		t.Fatalf("no-session page leaked the CSRF token")
	}

	redeemed := httptest.NewRequest(http.MethodGet, "/?redeemed=1", nil)
	redeemed.Host = "127.0.0.1"
	redRR := httptest.NewRecorder()
	s.ServeHTTP(redRR, redeemed)
	if redRR.Code != http.StatusForbidden {
		t.Fatalf("/?redeemed=1 = %d, want 403", redRR.Code)
	}
	if !strings.Contains(redRR.Body.String(), "not storing") {
		t.Fatalf("expected the cookie-blocked message, got %q", redRR.Body.String())
	}

	wrong := httptest.NewRequest(http.MethodGet, "/?launch=wrong", nil)
	wrong.Host = "127.0.0.1"
	wrongRR := httptest.NewRecorder()
	s.ServeHTTP(wrongRR, wrong)
	if wrongRR.Code != http.StatusForbidden {
		t.Fatalf("/?launch=wrong = %d, want 403", wrongRR.Code)
	}

	right := httptest.NewRequest(http.MethodGet, "/?launch="+s.launchSecret, nil)
	right.Host = "127.0.0.1"
	rightRR := httptest.NewRecorder()
	s.ServeHTTP(rightRR, right)
	if rightRR.Code != http.StatusFound {
		t.Fatalf("/?launch=right = %d, want 302", rightRR.Code)
	}
	if loc := rightRR.Header().Get("Location"); loc != "/?redeemed=1" {
		t.Fatalf("launch redirect Location = %q, want /?redeemed=1", loc)
	}
	var sess *http.Cookie
	for _, c := range rightRR.Result().Cookies() {
		if c.Name == guiSessionCookie && c.Value != "" {
			sess = c
		}
	}
	if sess == nil {
		t.Fatalf("launch redemption set no session cookie")
	}
	idx := httptest.NewRequest(http.MethodGet, "/", nil)
	idx.Host = "127.0.0.1"
	idx.AddCookie(sess)
	idxRR := httptest.NewRecorder()
	s.ServeHTTP(idxRR, idx)
	if idxRR.Code != http.StatusOK {
		t.Fatalf("index with launch session = %d, want 200", idxRR.Code)
	}
}

// TestDistinctWebDAVAndExportTokens covers: the CSRF token is not
// a WebDAV token, the davToken is; the legacy ?token= export form is gone; the
// ticket flow works exactly once.
func TestDistinctWebDAVAndExportTokens(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	if putRR := davRequest(t, s, http.MethodPut, "docs/z.txt", bytes.NewReader([]byte("zzz")), nil); putRR.Code != http.StatusCreated {
		t.Fatalf("seed PUT = %d %s", putRR.Code, putRR.Body.String())
	}

	propfind := func(token string) int {
		req := httptest.NewRequest("PROPFIND", "/dav/"+token+"/", nil)
		req.Host = "127.0.0.1"
		req.Header.Set("Depth", "1")
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := propfind(s.token); code != http.StatusForbidden {
		t.Fatalf("/dav with CSRF token = %d, want 403", code)
	}
	if code := propfind(s.davToken); code != http.StatusMultiStatus {
		t.Fatalf("/dav with davToken = %d, want 207", code)
	}

	legacy := httptest.NewRequest(http.MethodGet, "/api/export-zip?token="+s.token+"&path=docs", nil)
	legacy.Host = "127.0.0.1"
	legacy.AddCookie(newTestSession(s, true))
	legacyRR := httptest.NewRecorder()
	s.ServeHTTP(legacyRR, legacy)
	if legacyRR.Code != http.StatusForbidden {
		t.Fatalf("/api/export-zip?token= = %d, want 403", legacyRR.Code)
	}

	ticketRR := postJSON(t, s, "/api/export-zip/ticket", map[string]any{"path": "docs"})
	if ticketRR.Code != http.StatusOK {
		t.Fatalf("ticket mint = %d %s", ticketRR.Code, ticketRR.Body.String())
	}
	var tr struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(ticketRR.Body.Bytes(), &tr); err != nil {
		t.Fatalf("decode ticket: %v", err)
	}
	if tr.Ticket == "" {
		t.Fatalf("empty ticket: %s", ticketRR.Body.String())
	}

	first := httptest.NewRequest(http.MethodGet, "/api/export-zip?ticket="+tr.Ticket, nil)
	first.Host = "127.0.0.1"
	first.AddCookie(newTestSession(s, true))
	firstRR := httptest.NewRecorder()
	s.ServeHTTP(firstRR, first)
	if firstRR.Code != http.StatusOK || firstRR.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("first ticket use = %d ct=%q", firstRR.Code, firstRR.Header().Get("Content-Type"))
	}

	second := httptest.NewRequest(http.MethodGet, "/api/export-zip?ticket="+tr.Ticket, nil)
	second.Host = "127.0.0.1"
	second.AddCookie(newTestSession(s, true))
	secondRR := httptest.NewRecorder()
	s.ServeHTTP(secondRR, second)
	if secondRR.Code != http.StatusForbidden {
		t.Fatalf("second ticket use = %d, want 403", secondRR.Code)
	}
}

// TestLogSaveRejectedByForeignHost covers: a POST with a
// valid CSRF token but a foreign Host is 403 and writes nothing.
func TestLogSaveRejectedByForeignHost(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "evil.log")
	payload, err := json.Marshal(map[string]any{"path": logPath, "text": "should not be written"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/log/save", bytes.NewReader(payload))
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SeaVault-Token", s.token)
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("log/save under evil Host = %d, want 403", rr.Code)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("log file was written despite the foreign Host: err=%v", err)
	}
}

// TestBrowserHeartbeatExtendsExpiringSession covers the webui half of
// : a session one second from expiry is slid forward 12h by a
// heartbeat, because the session check refreshes the TTL before dispatch.
func TestBrowserHeartbeatExtendsExpiringSession(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.authSessions[id] = session{expires: time.Now().Add(time.Second), loggedIn: true}
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/browser-heartbeat", nil)
	req.Host = "127.0.0.1"
	req.AddCookie(&http.Cookie{Name: guiSessionCookie, Value: id})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("heartbeat = %d, want 200", rr.Code)
	}
	s.mu.Lock()
	got := s.authSessions[id]
	s.mu.Unlock()
	if time.Until(got.expires) < 11*time.Hour {
		t.Fatalf("heartbeat did not extend the session: expires in %v", time.Until(got.expires))
	}
}

// TestBrowserSessionDropsTokenQuery covers: the browser-session SSE stream
// authenticates by the session cookie alone; it no longer requires ?token= and
// no longer 403s when the query is absent.
func TestBrowserSessionDropsTokenQuery(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the stream loop returns as soon as it sees a done context
	req := httptest.NewRequest(http.MethodGet, "/api/browser-session", nil).WithContext(ctx)
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("browser-session without ?token = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("browser-session content-type = %q, want text/event-stream", ct)
	}
}

// insertSession inserts a GUI session with a controlled cookieIssued/expires and
// returns the cookie naming it, so the cookie-re-issue behaviour can be
// driven with a deliberately stale or fresh browser cookie.
func insertSession(t *testing.T, s *Server, loggedIn bool, expires, issued time.Time) *http.Cookie {
	t.Helper()
	id, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.authSessions[id] = session{expires: expires, loggedIn: loggedIn, cookieIssued: issued}
	s.mu.Unlock()
	return &http.Cookie{Name: guiSessionCookie, Value: id}
}

// TestSessionCookieReissuedAsServerTTLSlides covers:
// sessionOf slides the server-side expiry on every gated request, but the browser
// cookie's Expires was written once at launch and never re-issued, so an actively
// used tab was force-expired by the browser at launch+12h. A gated request on a
// session whose cookie is at least an hour old must now re-issue Set-Cookie with a
// fresh Expires; a just-issued cookie must not be re-issued; the Secure flag must
// track the GUI protocol.
func TestSessionCookieReissuedAsServerTTLSlides(t *testing.T) {
	now := time.Now()

	t.Run("stale cookie is re-issued and the server TTL moves", func(t *testing.T) {
		s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
		if err != nil {
			t.Fatal(err)
		}
		cookie := insertSession(t, s, true, now.Add(3*time.Hour), now.Add(-2*time.Hour))
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.Host = "127.0.0.1"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("/api/status = %d, want 200", rr.Code)
		}
		var set *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == guiSessionCookie {
				set = c
			}
		}
		if set == nil {
			t.Fatalf("a 2h-old session cookie was not re-issued on a gated request")
		}
		if set.Value != cookie.Value {
			t.Fatalf("re-issued cookie value = %q, want the same session id %q", set.Value, cookie.Value)
		}
		if d := time.Until(set.Expires); d < 11*time.Hour {
			t.Fatalf("re-issued cookie Expires only %v ahead, want >= 11h", d)
		}
		s.mu.Lock()
		got := s.authSessions[cookie.Value]
		s.mu.Unlock()
		if d := time.Until(got.expires); d < 11*time.Hour {
			t.Fatalf("server-side expiry not slid: %v ahead", d)
		}
	})

	t.Run("a just-issued cookie is not re-issued", func(t *testing.T) {
		s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
		if err != nil {
			t.Fatal(err)
		}
		cookie := insertSession(t, s, true, now.Add(3*time.Hour), now)
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.Host = "127.0.0.1"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("/api/status = %d, want 200", rr.Code)
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == guiSessionCookie {
				t.Fatalf("a freshly-issued session cookie was re-issued unnecessarily")
			}
		}
	})

	t.Run("re-issued cookie carries Secure when the GUI protocol is https", func(t *testing.T) {
		s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "https"}})
		if err != nil {
			t.Fatal(err)
		}
		cookie := insertSession(t, s, true, now.Add(3*time.Hour), now.Add(-2*time.Hour))
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.Host = "127.0.0.1"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("/api/status = %d, want 200", rr.Code)
		}
		var set *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == guiSessionCookie {
				set = c
			}
		}
		if set == nil {
			t.Fatalf("a stale session cookie was not re-issued under https")
		}
		if !set.Secure {
			t.Fatalf("re-issued cookie is missing the Secure flag under https")
		}
	})
}

// TestWebDAVStatusFlagsNativeClientsAndNote covers (the design
// step 3): with a GUI password set, /dav additionally requires a login cookie no
// native client can present, so the copied WebDAV URL 401s for Finder/Explorer/
// rclone. /api/webdav must report nativeClients=false and a note pointing at
// seavault serve; with no GUI password it reports nativeClients=true and no note;
// the index page wires the flag into the copy affordance.
func TestWebDAVStatusFlagsNativeClientsAndNote(t *testing.T) {
	authS, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, authS)
	var authWD struct {
		Running       bool   `json:"running"`
		NativeClients bool   `json:"nativeClients"`
		Note          string `json:"note"`
	}
	if code := getJSON(t, authS, "/api/webdav", &authWD); code != http.StatusOK {
		t.Fatalf("/api/webdav (auth) = %d", code)
	}
	if !authWD.Running {
		t.Fatalf("expected a running WebDAV mount after opening a vault")
	}
	if authWD.NativeClients {
		t.Fatalf("nativeClients should be false with a GUI password set")
	}
	if !strings.Contains(authWD.Note, "seavault serve") {
		t.Fatalf("note should point at seavault serve, got %q", authWD.Note)
	}

	openS, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, openS)
	var openWD struct {
		NativeClients bool   `json:"nativeClients"`
		Note          string `json:"note"`
	}
	if code := getJSON(t, openS, "/api/webdav", &openWD); code != http.StatusOK {
		t.Fatalf("/api/webdav (no auth) = %d", code)
	}
	if !openWD.NativeClients {
		t.Fatalf("nativeClients should be true with no GUI password")
	}
	if openWD.Note != "" {
		t.Fatalf("note should be empty with no GUI password, got %q", openWD.Note)
	}

	idxRR := httptest.NewRecorder()
	openS.ServeHTTP(idxRR, authReq(openS, httptest.NewRequest(http.MethodGet, "/", nil)))
	if idxRR.Code != http.StatusOK {
		t.Fatalf("index = %d", idxRR.Code)
	}
	if !strings.Contains(idxRR.Body.String(), "nativeClients") {
		t.Fatalf("index JS does not reference nativeClients")
	}
}

// TestNoSessionPageStatesPlainRecovery covers: the no-session 403
// page names the plain-language recovery step for an icon-launched owner.
func TestNoSessionPageStatesPlainRecovery(t *testing.T) {
	s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("/ without session = %d, want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Close this tab and start SeaVault again; it will open the app for you.") {
		t.Fatalf("no-session page missing the plain-language recovery line: %s", rr.Body.String())
	}
}

// TestResetConfigSuccessLinksBackToApp covers: after a successful
// reset the primary button links back into the app through a fresh launch
// redemption (sessions were cleared, so /login -> / would 403). The launch secret
// must appear ONLY on the success page, never on the initial/failure page.
func TestResetConfigSuccessLinksBackToApp(t *testing.T) {
	cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}}
	if err := appconfig.Save(cfg); err != nil {
		t.Fatal(err)
	}
	s, err := NewWithConfig("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	cookie := newTestSession(s, true)

	initReq := httptest.NewRequest(http.MethodGet, "/reset-config", nil)
	initReq.Host = "127.0.0.1"
	initReq.AddCookie(cookie)
	initRR := httptest.NewRecorder()
	s.ServeHTTP(initRR, initReq)
	if initRR.Code != http.StatusOK {
		t.Fatalf("reset page = %d", initRR.Code)
	}
	if strings.Contains(initRR.Body.String(), s.launchSecret) {
		t.Fatalf("the initial reset page leaked the launch secret")
	}
	if strings.Contains(initRR.Body.String(), "Back to SeaVault") {
		t.Fatalf("the initial reset page should offer Back to login, not Back to SeaVault")
	}

	nonce := getResetNonce(t, s, cookie)
	form := url.Values{"confirm": {"RESET"}, "nonce": {nonce}}
	req := httptest.NewRequest(http.MethodPost, "/reset-config", strings.NewReader(form.Encode()))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("reset = %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/?launch="+s.launchSecret) {
		t.Fatalf("reset success page did not link through the launch URL: %s", body)
	}
	if !strings.Contains(body, "Back to SeaVault") {
		t.Fatalf("reset success page missing the Back to SeaVault label")
	}
}

// POST /api/compact requires a session and a matching CSRF
// token, runs Vault.Compact, and returns the report. A pure load performed by
// the sync watcher (ReloadIfChanged) or any read materialises nothing on disk;
// only the explicit /api/compact call does.
func TestApiCompactMaterialisesConflictWithSessionAndCSRF(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	v := s.vault
	if v == nil {
		t.Fatal("expected an open vault after init")
	}

	// Build a GENUINE pending conflict on disk behind the vault's back (design
	// ): under the A2 vector clock a same-device re-edit is cleanly
	// superseded, so a real conflict needs two DIFFERENT devices editing the path
	// without seeing each other (disjoint clocks → concurrent → one canonical plus
	// one *.conflict-* entry).
	canonicalSource, loserSource := stageConcurrentConflict(t, s, "doc.txt", "passphrase", "v1 device A", "v2 device B")

	// A state-changing POST without the CSRF token is refused before any work.
	noToken := httptest.NewRequest(http.MethodPost, "/api/compact", strings.NewReader("{}"))
	noToken.Host = "127.0.0.1"
	noToken.Header.Set("Content-Type", "application/json")
	noToken.AddCookie(newTestSession(s, true))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, noToken)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("compact without CSRF token must be forbidden, got %d %s", rr.Code, rr.Body.String())
	}

	// The passive sync-watcher path (ReloadIfChanged) and a forced reload write
	// nothing: the losing copy stays on disk until an explicit compaction.
	if _, err := v.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(loserSource); err != nil {
		t.Fatalf("a reload must not remove the losing manifest copy: %v", err)
	}

	// The authorized POST runs Compact and returns the report.
	rr = postJSON(t, s, "/api/compact", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("compact failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK     bool `json:"ok"`
		Report struct {
			Conflicts        []string `json:"conflicts"`
			RemovedManifests int      `json:"removedManifests"`
			TmpOrphans       []string `json:"tmpOrphans"`
		} `json:"report"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode compact response: %v body=%s", err, rr.Body.String())
	}
	if !resp.OK || len(resp.Report.Conflicts) != 1 {
		t.Fatalf("compact should materialise exactly one conflict, got %#v", resp.Report)
	}
	if !strings.HasPrefix(resp.Report.Conflicts[0], "content/doc.txt.conflict-") {
		t.Fatalf("unexpected conflict path %q", resp.Report.Conflicts[0])
	}
	// Compact actually applied the plan on disk (not a dry run): the LOSER's source
	// manifest is removed and re-materialised at the conflict name. Which of the
	// two concurrent copies loses is content-key-chosen (never filename-chosen,
	// ), so exactly one of the two original sources survives — the
	// winner keeps its file, the loser's is gone.
	_, canonExists := os.Stat(canonicalSource)
	_, sibExists := os.Stat(loserSource)
	if (canonExists == nil) == (sibExists == nil) {
		t.Fatalf("compact must remove exactly one of the two concurrent sources; canonical present=%v sibling present=%v", canonExists == nil, sibExists == nil)
	}
}

func manifestFileSet(t *testing.T, dir string) map[string]struct{} {
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

// stageConcurrentConflict stages a genuine causal conflict on disk for the
// server's open vault: a SECOND device installation edits
// virtualPath without seeing this device, so the two manifests carry disjoint
// vector clocks and reconcile as CONCURRENT — kept as one canonical winner plus
// one *.conflict-* entry — instead of one cleanly superseding the other (which a
// same-device re-edit now does). It returns the two on-disk source manifest
// paths (device B's at the canonical name, device A's restored as a sync-client
// conflicted copy); after a compaction exactly one of them survives (the winner
// keeps its file, the loser's is removed and re-materialised at a conflict name),
// which winner being content-key-chosen, not filename-chosen.
func stageConcurrentConflict(t *testing.T, s *Server, virtualPath, pw, bodyA, bodyB string) (canonical, sibling string) {
	t.Helper()
	v := s.vault
	if v == nil {
		t.Fatal("stageConcurrentConflict needs an open server vault")
	}
	manifestsDir := filepath.Join(v.MetaRoot, "manifests")
	before := manifestFileSet(t, manifestsDir)
	orig := os.Getenv("SEAVAULT_APP_HOME")

	// Device A (a distinct installation) writes its version, then we hide its
	// manifest so this device (B) writes an independent one to the same path.
	homeA := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", homeA)
	vA, err := vault.Open(v.Root, pw)
	if err != nil {
		t.Fatalf("open device A: %v", err)
	}
	if _, err := vA.PutReader(strings.NewReader(bodyA), virtualPath, int64(len(bodyA)), 0o600, time.Now()); err != nil {
		t.Fatalf("device A put: %v", err)
	}
	var docManifest string
	for p := range manifestFileSet(t, manifestsDir) {
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
	if err := os.Remove(docManifest); err != nil {
		t.Fatal(err)
	}

	// Back to this device (the server's cached id) for the concurrent write.
	t.Setenv("SEAVAULT_APP_HOME", orig)
	if _, err := v.PutReader(strings.NewReader(bodyB), virtualPath, int64(len(bodyB)), 0o600, time.Now()); err != nil {
		t.Fatalf("device B put: %v", err)
	}
	sibling = strings.TrimSuffix(docManifest, ".manifest") + ".sync-conflict.manifest"
	if err := os.WriteFile(sibling, loserBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return docManifest, sibling
}

// --- STAGE B: fenced GUI gc, warning banner, pending-deletion
// and conflict visibility, and scoped upload-error hint (A1).

// metaFingerprint hashes every file under root (relative path, size, mtime, and
// content) so a test can assert a code path wrote NOTHING in the metadata dir.
func metaFingerprint(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s|%d|%d|%x", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano(), sum))
		return nil
	})
	if err != nil {
		t.Fatalf("fingerprint walk %s: %v", root, err)
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

// countFilesWithSuffix counts files under dir whose name ends in suffix (a
// missing dir counts as zero).
func countFilesWithSuffix(t *testing.T, dir, suffix string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count %s in %s: %v", suffix, dir, err)
	}
	return n
}

// makeGCCandidate puts a file and deletes it, leaving one unreferenced but
// present chunk — exactly the gc candidate the fenced two-phase collection acts
// on. It uses only the public vault API so the webui package can build it.
func makeGCCandidate(t *testing.T, v *vault.Vault) {
	t.Helper()
	body := "reclaimable-bytes-for-gc"
	if _, err := v.PutReader(strings.NewReader(body), "gc-doc.txt", int64(len(body)), 0o600, time.Now()); err != nil {
		t.Fatalf("put gc candidate: %v", err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	var target string
	for p := range files {
		if strings.HasSuffix(p, "gc-doc.txt") {
			target = p
		}
	}
	if target == "" {
		t.Fatalf("could not locate the put file to delete; files=%v", files)
	}
	if _, err := v.RemovePath(target); err != nil {
		t.Fatalf("delete gc candidate: %v", err)
	}
}

// POST /api/gc is gated by the session (a missing session is 403, before
// any gc work) and only accepts POST (a GET is 405).
func TestApiGCRequiresSessionAndPostMethod(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	noSess := httptest.NewRequest(http.MethodPost, "/api/gc", strings.NewReader(`{"confirm":false}`))
	noSess.Host = "127.0.0.1"
	noSess.Header.Set("Content-Type", "application/json")
	noSess.Header.Set("X-SeaVault-Token", s.token)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, noSess)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("/api/gc without a session must be 403, got %d %s", rr.Code, rr.Body.String())
	}

	get := authReq(s, httptest.NewRequest(http.MethodGet, "/api/gc", nil))
	getRR := httptest.NewRecorder()
	s.ServeHTTP(getRR, get)
	if getRR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/gc must be 405, got %d %s", getRR.Code, getRR.Body.String())
	}
}

// confirm=false is a dry run — it returns the unreferenced-chunk
// candidates and writes NOTHING in the metadata dir (fingerprint unchanged).
func TestApiGCDryRunReturnsCandidatesWithoutWriting(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	v := s.vault
	makeGCCandidate(t, v)

	before := metaFingerprint(t, v.MetaRoot)
	rr := postJSON(t, s, "/api/gc", map[string]any{"confirm": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("gc dry-run failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK             bool   `json:"ok"`
		Confirm        bool   `json:"confirm"`
		Candidates     int    `json:"candidates"`
		CandidateBytes int64  `json:"candidateBytes"`
		Fence          string `json:"fence"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode gc dry-run response: %v body=%s", err, rr.Body.String())
	}
	if !resp.OK || resp.Confirm {
		t.Fatalf("dry-run must be ok and not confirm: %#v", resp)
	}
	if resp.Candidates < 1 || resp.CandidateBytes < 1 {
		t.Fatalf("dry-run must report the unreferenced candidate (count %d, bytes %d)", resp.Candidates, resp.CandidateBytes)
	}
	if after := metaFingerprint(t, v.MetaRoot); after != before {
		t.Fatalf("dry-run must write NOTHING in the metadata dir; fingerprint changed (%s -> %s)", before, after)
	}
}

// confirm=true writes deletion intents but removes NOTHING before the
// fence has elapsed (the intent, first-seen record, and chunk mtime are all
// young), and the chunk objects survive.
func TestApiGCConfirmWritesIntentsRemovesNothingBeforeFence(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	v := s.vault
	makeGCCandidate(t, v)

	chunksDir := filepath.Join(v.MetaRoot, "objects", "chunks")
	intentsDir := filepath.Join(v.MetaRoot, vault.GCIntentDirName)
	chunksBefore := countFilesWithSuffix(t, chunksDir, ".chunk")
	if chunksBefore < 1 {
		t.Fatalf("expected at least one chunk on disk before gc, got %d", chunksBefore)
	}

	rr := postJSON(t, s, "/api/gc", map[string]any{"confirm": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("gc confirm failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK           bool  `json:"ok"`
		Confirm      bool  `json:"confirm"`
		Queued       int   `json:"queued"`
		Removed      int   `json:"removed"`
		RemovedBytes int64 `json:"removedBytes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode gc confirm response: %v body=%s", err, rr.Body.String())
	}
	if !resp.OK || !resp.Confirm {
		t.Fatalf("confirm response must be ok and confirm: %#v", resp)
	}
	if resp.Queued < 1 {
		t.Fatalf("confirm must queue at least one deletion intent, got %d", resp.Queued)
	}
	if resp.Removed != 0 || resp.RemovedBytes != 0 {
		t.Fatalf("confirm before the fence must remove nothing, got removed=%d bytes=%d", resp.Removed, resp.RemovedBytes)
	}
	if got := countFilesWithSuffix(t, intentsDir, ".intent"); got < 1 {
		t.Fatalf("confirm must write a deletion intent, found %d intent files", got)
	}
	if got := countFilesWithSuffix(t, chunksDir, ".chunk"); got != chunksBefore {
		t.Fatalf("confirm before the fence must NOT remove chunk objects: before=%d after=%d", chunksBefore, got)
	}
}

// a sub-1h fence is clamped up to the 1h minimum and the
// response explains the clamp (parity with the CLI fence notice).
func TestApiGCClampsSubHourFenceInResponse(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	rr := postJSON(t, s, "/api/gc", map[string]any{"confirm": false, "fence": "30m"})
	if rr.Code != http.StatusOK {
		t.Fatalf("gc with a 30m fence failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Fence       string `json:"fence"`
		FenceNotice string `json:"fenceNotice"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode gc response: %v body=%s", err, rr.Body.String())
	}
	if resp.Fence != vault.GCFenceMin.String() {
		t.Fatalf("a 30m fence must be clamped to the 1h minimum in the response, got %q", resp.Fence)
	}
	if !strings.Contains(resp.FenceNotice, "minimum") {
		t.Fatalf("the response must explain the clamp, got fenceNotice=%q", resp.FenceNotice)
	}
}

// /C2: the index page carries a visible warnings banner element and the
// JS feeds res.warnings from init/open into it (not only into the JSON dump).
func TestIndexSurfacesWarningsBanner(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index failed: %d", rr.Code)
	}
	html := rr.Body.String()
	for _, want := range []string{
		`id="noticeBanner"`,
		`function showNotices`,
		`res.warnings`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("warnings-banner wiring missing %q", want)
		}
	}
}

// the Verify report renders a pending-deletions line from
// report.pendingIntents (GUI parity with the CLI's pending-gc-intents line).
func TestIndexVerifyReportShowsPendingDeletions(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index failed: %d", rr.Code)
	}
	html := rr.Body.String()
	for _, want := range []string{
		`report.pendingIntents`,
		`Pending deletions in flight`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("verify pending-deletions wiring missing %q", want)
		}
	}
}

// a conflict entry carries conflictOf in the /api/files listing, and
// the WebDAV file table renders a "conflict copy of <original>" badge from it.
func TestConflictEntrySurfacesInListingAndDavBadge(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	v := s.vault

	// Build a GENUINE pending sync-conflict on disk behind the vault's back
	// : two DIFFERENT devices edit doc.txt without seeing each
	// other, so the copies carry disjoint vector clocks and reconcile as
	// concurrent (a same-device re-edit would be cleanly superseded, no conflict).
	stageConcurrentConflict(t, s, "doc.txt", "passphrase", "v1 device A", "v2 device B")
	// A pure load surfaces the conflict entry (no compaction needed).
	if err := v.ReloadIndex(); err != nil {
		t.Fatal(err)
	}

	var listing struct {
		Files []struct {
			Path       string `json:"path"`
			ConflictOf string `json:"conflictOf"`
		} `json:"files"`
	}
	if code := getJSON(t, s, "/api/files", &listing); code != http.StatusOK {
		t.Fatalf("/api/files returned %d", code)
	}
	found := false
	for _, f := range listing.Files {
		if strings.HasPrefix(f.Path, "content/doc.txt.conflict-") {
			found = true
			if f.ConflictOf != "content/doc.txt" {
				t.Fatalf("conflict entry must carry conflictOf=content/doc.txt, got %q", f.ConflictOf)
			}
		}
	}
	if !found {
		t.Fatalf("expected a conflict entry in the /api/files listing; got %+v", listing.Files)
	}

	// The WebDAV table renders a conflict badge from the conflictOf data.
	idxReq := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	idxRR := httptest.NewRecorder()
	s.ServeHTTP(idxRR, idxReq)
	html := idxRR.Body.String()
	for _, want := range []string{`conflict copy of `, `conflictOf`} {
		if !strings.Contains(html, want) {
			t.Fatalf("WebDAV conflict-badge wiring missing %q", want)
		}
	}
}

// the large-folder ingest hint is only composed onto size/limit upload
// errors, not name-validation errors — the browser-upload catch routes its
// message through composeUploadError instead of unconditionally appending it.
func TestUploadErrorHintScopedToSizeLimits(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := authReq(s, httptest.NewRequest(http.MethodGet, "/", nil))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index failed: %d", rr.Code)
	}
	html := rr.Body.String()
	for _, want := range []string{
		`function composeUploadError`,
		`function isLikelySizeLimitError`,
		`composeUploadError(e.message)`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("scoped upload-error wiring missing %q", want)
		}
	}
	if strings.Contains(html, `showError('Upload failed', e.message +`) {
		t.Fatal("the large-folder hint is still appended unconditionally to every browser-upload error")
	}
}

// TestGUIRecoveryRedeemWorksWhenLockedOut is the tombstone for: the
// GUI recovery-redeem must work in the locked-out state it exists for (an owner
// who forgot the password cannot open the vault first). Before the fix
// handleRecoveryRedeem required s.vault != nil and returned 409 "no vault is open"
// — the one state the panel is for. OpenWithRecovery opens via the phrase alone,
// so redeem now takes a vault path and needs no prior unlock.
func TestGUIRecoveryRedeemWorksWhenLockedOut(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := initOpenTestVault(t, s)

	rr := postJSON(t, s, "/api/recovery/generate", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", rr.Code, rr.Body.String())
	}
	var gen struct {
		Phrase string `json:"phrase"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode generate: %v (%s)", err, rr.Body.String())
	}
	if gen.Phrase == "" {
		t.Fatal("generate must return the recovery phrase")
	}
	if rr := postJSON(t, s, "/api/recovery/commit", map[string]any{"readback": gen.Phrase}); rr.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rr.Code, rr.Body.String())
	}

	// The locked-out state the panel exists for: no vault open, no session path.
	s.mu.Lock()
	s.vault = nil
	s.vaultPath = ""
	s.mu.Unlock()

	rr = postJSON(t, s, "/api/recovery/redeem", map[string]any{
		"vaultPath":   vaultPath,
		"phrase":      gen.Phrase,
		"newPassword": "a brand new vault password",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("redeem when locked out must succeed, got %d %s", rr.Code, rr.Body.String())
	}
	s.mu.Lock()
	reopened := s.vault != nil
	s.mu.Unlock()
	if !reopened {
		t.Fatal("a successful locked-out redeem must install the reopened vault")
	}
}
