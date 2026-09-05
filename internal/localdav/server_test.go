// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package localdav

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// newTestVault creates a fresh vault with the fast test KDF and tiny chunk
// params (so even small files split into several chunks), opens it, and returns
// the open handle.
func newTestVault(t *testing.T) *vault.Vault {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "correct horse battery staple"
	opts := vault.CreateOptions{
		Chunk: vault.ChunkParams{MinSize: 64, AvgSize: 128, MaxSize: 256},
		KDF:   vault.FastKDFConfigForTests(),
	}
	if err := vault.CreateWithOptions(root, pw, opts); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// putFile stores data at the given user path (bypassing the WebDAV surface).
func putFile(t *testing.T, v *vault.Vault, vp string, data []byte) {
	t.Helper()
	if _, err := v.PutReader(bytes.NewReader(data), vp, int64(len(data)), 0o600, time.Unix(1700000000, 0).UTC()); err != nil {
		t.Fatalf("PutReader(%q): %v", vp, err)
	}
}

// req builds a request with a loopback Host so it survives the Host guard.
func req(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Host = "127.0.0.1"
	return r
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	return rr
}

func chunksDir(v *vault.Vault) string {
	return filepath.Join(v.MetaRoot, "objects", "chunks")
}

// ---- R1: seavault serve authentication -------------------------------------

func TestBasicAuthRequiredAndEnforced(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/a.txt", []byte("alpha"))
	s := &Server{Vault: v, Credentials: &BasicCredentials{User: "seavault", Password: "s3cret-pw"}}

	// Unauthenticated GET/PROPFIND/PUT -> 401 with the WWW-Authenticate challenge.
	for _, tc := range []struct {
		name, method, target string
		body                 io.Reader
	}{
		{"GET", http.MethodGet, "/docs/a.txt", nil},
		{"PROPFIND", "PROPFIND", "/", nil},
		{"PUT", http.MethodPut, "/docs/new.txt", strings.NewReader("x")},
	} {
		rr := serve(s, req(tc.method, tc.target, tc.body))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated: code=%d want 401", tc.name, rr.Code)
		}
		if got := rr.Header().Get("WWW-Authenticate"); got != `Basic realm="SeaVault", charset="UTF-8"` {
			t.Fatalf("%s WWW-Authenticate=%q", tc.name, got)
		}
	}

	// Wrong password -> 401.
	bad := req(http.MethodGet, "/docs/a.txt", nil)
	bad.SetBasicAuth("seavault", "wrong")
	if rr := serve(s, bad); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: code=%d want 401", rr.Code)
	}

	// Correct credentials -> the verb is served.
	for _, tc := range []struct {
		name, method, target string
		body                 io.Reader
		want                 int
	}{
		{"GET", http.MethodGet, "/docs/a.txt", nil, http.StatusOK},
		{"PROPFIND", "PROPFIND", "/", nil, 207},
		{"PUT", http.MethodPut, "/docs/created.txt", strings.NewReader("y"), http.StatusCreated},
	} {
		r := req(tc.method, tc.target, tc.body)
		r.SetBasicAuth("seavault", "s3cret-pw")
		if rr := serve(s, r); rr.Code != tc.want {
			t.Fatalf("%s authenticated: code=%d want %d body=%s", tc.name, rr.Code, tc.want, rr.Body.String())
		}
	}
}

// ---- R2: Host allowlist (localdav half) ------------------------------------

func TestHostGuard(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/a.txt", []byte("alpha"))

	s := &Server{Vault: v}
	// evil host -> 403 on GET and PROPFIND, with the remedy body.
	for _, method := range []string{http.MethodGet, "PROPFIND"} {
		r := httptest.NewRequest(method, "/docs/a.txt", nil)
		r.Host = "evil.example"
		rr := serve(s, r)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s evil.example: code=%d want 403", method, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "unexpected Host header") {
			t.Fatalf("%s 403 body missing remedy: %q", method, rr.Body.String())
		}
	}

	// Loopback identities are allowed.
	for _, host := range []string{"127.0.0.1", "127.0.0.1:8787", "localhost", "localhost:8787", "[::1]", "[::1]:8787"} {
		r := httptest.NewRequest(http.MethodGet, "/docs/a.txt", nil)
		r.Host = host
		if rr := serve(s, r); rr.Code != http.StatusOK {
			t.Fatalf("Host %q: code=%d want 200", host, rr.Code)
		}
	}

	// AllowedHosts entry is accepted; other names still rejected.
	s2 := &Server{Vault: v, AllowedHosts: []string{"vault.lan"}}
	r := httptest.NewRequest(http.MethodGet, "/docs/a.txt", nil)
	r.Host = "vault.lan"
	if rr := serve(s2, r); rr.Code != http.StatusOK {
		t.Fatalf("AllowedHosts vault.lan: code=%d want 200", rr.Code)
	}
	r = httptest.NewRequest("PROPFIND", "/", nil)
	r.Host = "evil.example"
	if rr := serve(s2, r); rr.Code != http.StatusForbidden {
		t.Fatalf("AllowedHosts server, evil.example: code=%d want 403", rr.Code)
	}
	// The remedy body names the extra allowed host.
	r = httptest.NewRequest(http.MethodGet, "/docs/a.txt", nil)
	r.Host = "nope.example"
	rr := serve(s2, r)
	if !strings.Contains(rr.Body.String(), "vault.lan") {
		t.Fatalf("403 body should name the extra allowed host: %q", rr.Body.String())
	}
}

// ---- R6: Range reads via ServeContent --------------------------------------

func TestRangeAndHeadViaServeContent(t *testing.T) {
	v := newTestVault(t)
	data := []byte("abcdefghij0123456789") // 20 bytes
	putFile(t, v, "docs/data.bin", data)
	s := &Server{Vault: v}

	// Range: bytes=5-9 -> 206 with an exact 5-byte slice and Content-Range.
	r := req(http.MethodGet, "/docs/data.bin", nil)
	r.Header.Set("Range", "bytes=5-9")
	rr := serve(s, r)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("Range GET: code=%d want 206", rr.Code)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 5-9/20" {
		t.Fatalf("Content-Range=%q want bytes 5-9/20", got)
	}
	if body := rr.Body.String(); body != "fghij" {
		t.Fatalf("Range body=%q want %q", body, "fghij")
	}

	// Plain GET advertises byte ranges and returns the whole file.
	rr = serve(s, req(http.MethodGet, "/docs/data.bin", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("plain GET: code=%d want 200", rr.Code)
	}
	if got := rr.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Fatalf("Accept-Ranges=%q want bytes", got)
	}
	if rr.Body.String() != string(data) {
		t.Fatalf("plain GET body mismatch")
	}

	// HEAD sets Content-Length and returns no body.
	rr = serve(s, req(http.MethodHead, "/docs/data.bin", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("HEAD: code=%d want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Length"); got != "20" {
		t.Fatalf("HEAD Content-Length=%q want 20", got)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("HEAD body should be empty, got %d bytes", rr.Body.Len())
	}
}

func TestPendingChunkYields409(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/data.bin", []byte("abcdefghij0123456789"))
	if err := os.RemoveAll(chunksDir(v)); err != nil {
		t.Fatal(err)
	}
	s := &Server{Vault: v}
	rr := serve(s, req(http.MethodGet, "/docs/data.bin", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("pending chunk GET: code=%d want 409", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not fully synced yet") {
		t.Fatalf("409 body=%q", rr.Body.String())
	}
}

// ---- R8: COPY honours Overwrite --------------------------------------------

func TestCopyOverwriteSemantics(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/a.txt", []byte("alpha"))
	putFile(t, v, "docs/dst.txt", []byte("OLD"))
	s := &Server{Vault: v}

	// Overwrite: F onto an existing dst -> 412 and dst unchanged.
	r := req("COPY", "/docs/a.txt", nil)
	r.Header.Set("Destination", "/docs/dst.txt")
	r.Header.Set("Overwrite", "F")
	if rr := serve(s, r); rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("COPY Overwrite F onto existing: code=%d want 412", rr.Code)
	}
	rr := serve(s, req(http.MethodGet, "/docs/dst.txt", nil))
	if rr.Body.String() != "OLD" {
		t.Fatalf("dst changed after a refused overwrite: %q", rr.Body.String())
	}

	// Overwrite: T onto an existing dst -> 204 and dst replaced.
	r = req("COPY", "/docs/a.txt", nil)
	r.Header.Set("Destination", "/docs/dst.txt")
	r.Header.Set("Overwrite", "T")
	if rr := serve(s, r); rr.Code != http.StatusNoContent {
		t.Fatalf("COPY Overwrite T onto existing: code=%d want 204", rr.Code)
	}
	rr = serve(s, req(http.MethodGet, "/docs/dst.txt", nil))
	if rr.Body.String() != "alpha" {
		t.Fatalf("dst not replaced by overwrite: %q", rr.Body.String())
	}

	// New destination -> 201.
	r = req("COPY", "/docs/a.txt", nil)
	r.Header.Set("Destination", "/docs/new.txt")
	if rr := serve(s, r); rr.Code != http.StatusCreated {
		t.Fatalf("COPY to a new dst: code=%d want 201", rr.Code)
	}
}

// ---- R9: MKCOL missing parent / MOVE of a marker-only dir ------------------

func TestMkcolMissingParent409(t *testing.T) {
	v := newTestVault(t)
	s := &Server{Vault: v}
	rr := serve(s, req("MKCOL", "/missing/sub", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("MKCOL under a missing parent: code=%d want 409", rr.Code)
	}
	// A MKCOL directly under the workspace root succeeds.
	if rr := serve(s, req("MKCOL", "/top", nil)); rr.Code != http.StatusCreated {
		t.Fatalf("MKCOL top-level: code=%d want 201", rr.Code)
	}
}

func TestMoveMarkerOnlyDirectory(t *testing.T) {
	v := newTestVault(t)
	if err := v.EnsureDirectory("emptydir"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Vault: v}

	r := req("MOVE", "/emptydir", nil)
	r.Header.Set("Destination", "/moveddir")
	if rr := serve(s, r); rr.Code != http.StatusCreated {
		t.Fatalf("MOVE of a marker-only dir: code=%d want 201", rr.Code)
	}
	// Source is gone.
	if rr := serve(s, req("PROPFIND", "/emptydir", nil)); rr.Code != http.StatusNotFound {
		t.Fatalf("source dir should be gone after MOVE: code=%d", rr.Code)
	}
	// Destination is present.
	if rr := serve(s, req("PROPFIND", "/moveddir", nil)); rr.Code != 207 {
		t.Fatalf("destination dir should exist after MOVE: code=%d", rr.Code)
	}
}

// ---- R10: PROPFIND Depth: infinity -----------------------------------------

func TestPropfindDepthInfinityForbidden(t *testing.T) {
	v := newTestVault(t)
	s := &Server{Vault: v}
	r := req("PROPFIND", "/", nil)
	r.Header.Set("Depth", "infinity")
	rr := serve(s, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("PROPFIND Depth infinity: code=%d want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "propfind-finite-depth") {
		t.Fatalf("403 body missing propfind-finite-depth: %q", rr.Body.String())
	}
	// Absent Depth still behaves as Depth: 1.
	if rr := serve(s, req("PROPFIND", "/", nil)); rr.Code != 207 {
		t.Fatalf("PROPFIND absent depth: code=%d want 207", rr.Code)
	}
}

// ---- R11: opt-in OS junk dropping ------------------------------------------

func TestDropOSJunk(t *testing.T) {
	// DropOSJunk on: PUT is a no-op 201; DELETE 204; GET 404; nothing stored.
	v := newTestVault(t)
	s := &Server{Vault: v, DropOSJunk: true}
	if rr := serve(s, req(http.MethodPut, "/.DS_Store", strings.NewReader("junk"))); rr.Code != http.StatusCreated {
		t.Fatalf("DropOSJunk PUT: code=%d want 201", rr.Code)
	}
	entries, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	for p := range entries {
		if filepath.Base(p) == ".DS_Store" {
			t.Fatalf(".DS_Store was stored despite DropOSJunk: %q", p)
		}
	}
	if rr := serve(s, req(http.MethodGet, "/.DS_Store", nil)); rr.Code != http.StatusNotFound {
		t.Fatalf("DropOSJunk GET junk: code=%d want 404", rr.Code)
	}
	if rr := serve(s, req(http.MethodDelete, "/.DS_Store", nil)); rr.Code != http.StatusNoContent {
		t.Fatalf("DropOSJunk DELETE junk: code=%d want 204", rr.Code)
	}

	// DropOSJunk off (default): the junk file is stored like any other file.
	v2 := newTestVault(t)
	s2 := &Server{Vault: v2}
	if rr := serve(s2, req(http.MethodPut, "/.DS_Store", strings.NewReader("junk"))); rr.Code != http.StatusCreated {
		t.Fatalf("default PUT junk: code=%d want 201", rr.Code)
	}
	entries2, err := v2.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for p := range entries2 {
		if filepath.Base(p) == ".DS_Store" {
			stored = true
		}
	}
	if !stored {
		t.Fatal("default policy should store .DS_Store")
	}
}

// ---- R12: write-inactivity deadline armed on the stream --------------------

// deadlineRecorder is an httptest recorder that also satisfies the
// SetWriteDeadline seam used by http.ResponseController, recording how many
// times the deadline is (re)armed.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu       sync.Mutex
	setCalls int
}

func (d *deadlineRecorder) SetWriteDeadline(time.Time) error {
	d.mu.Lock()
	d.setCalls++
	d.mu.Unlock()
	return nil
}

func (d *deadlineRecorder) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.setCalls
}

func TestWriteDeadlineArmedPerWrite(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/data.bin", []byte("abcdefghij0123456789"))
	s := &Server{Vault: v}

	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.ServeHTTP(rec, req(http.MethodGet, "/docs/data.bin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: code=%d want 200", rec.Code)
	}
	if rec.calls() < 1 {
		t.Fatalf("SetWriteDeadline was armed %d times, want >=1", rec.calls())
	}
}

// ---- R16: read-inactivity deadline armed on the PUT body -------------------

// readDeadlineRecorder is the PUT-side counterpart to deadlineRecorder (R12):
// an httptest recorder that also satisfies the SetReadDeadline seam used by
// http.ResponseController, recording how many times the read deadline is
// (re)armed as the request body is consumed. handlePut wraps r.Body in a
// deadlineReader whose Read first calls SetReadDeadline via
// http.NewResponseController(w), so a stalled/slow uploader is cut after
// bodyInactivity (design D6.2, pre-code Condition C2). Without that wrap this
// seam is never touched and calls() stays 0.
type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	mu       sync.Mutex
	setCalls int
}

func (d *readDeadlineRecorder) SetReadDeadline(time.Time) error {
	d.mu.Lock()
	d.setCalls++
	d.mu.Unlock()
	return nil
}

func (d *readDeadlineRecorder) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.setCalls
}

// TestReadDeadlineArmedPerRead is the tombstone for the PUT half of D6.2/C2:
// a PUT whose uploader stalls has its read deadline armed as the body is read.
// Neutralize by dropping the deadlineReader wrap in handlePut (pass r.Body
// straight to PutReader) and this fails with calls()==0.
func TestReadDeadlineArmedPerRead(t *testing.T) {
	v := newTestVault(t)
	s := &Server{Vault: v}

	// A multi-chunk body (>1 KiB against the tiny test chunk params) so the
	// body is read in several passes; the deadline must be (re)armed each time.
	data := bytes.Repeat([]byte("abcdefghij0123456789"), 64)
	rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.ServeHTTP(rec, req(http.MethodPut, "/docs/upload.bin", bytes.NewReader(data)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT: code=%d want 201 body=%s", rec.Code, rec.Body.String())
	}
	if rec.calls() < 1 {
		t.Fatalf("SetReadDeadline was armed %d times, want >=1", rec.calls())
	}

	// The bytes must actually have landed through the wrapped reader: read the
	// file back so the assertion above cannot pass on a short-circuited body.
	rr := serve(s, req(http.MethodGet, "/docs/upload.bin", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("readback GET: code=%d want 200", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), data) {
		t.Fatalf("stored bytes differ: got %d bytes want %d", rr.Body.Len(), len(data))
	}
}

// ---- R14: a streaming GET does not block a concurrent PROPFIND -------------

// blockingRecorder blocks the first body Write until release is closed, after
// signalling started.
type blockingRecorder struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingRecorder) Write(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.started)
		<-b.release
	})
	return b.ResponseRecorder.Write(p)
}

func TestStreamingGetDoesNotBlockPropfind(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/data.bin", []byte("abcdefghij0123456789"))
	s := &Server{Vault: v}

	block := &blockingRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		started:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	getDone := make(chan struct{})
	go func() {
		defer close(getDone)
		s.ServeHTTP(block, req(http.MethodGet, "/docs/data.bin", nil))
	}()

	select {
	case <-block.started:
	case <-time.After(2 * time.Second):
		t.Fatal("GET never reached the streaming write")
	}

	// While the GET is paused mid-write, a PROPFIND must complete.
	propDone := make(chan int, 1)
	go func() {
		rr := serve(s, req("PROPFIND", "/", nil))
		propDone <- rr.Code
	}()
	select {
	case code := <-propDone:
		if code != 207 {
			t.Fatalf("PROPFIND during a paused GET: code=%d want 207", code)
		}
	case <-time.After(2 * time.Second):
		close(block.release)
		t.Fatal("PROPFIND blocked behind a streaming GET")
	}

	close(block.release)
	<-getDone
}

// ---- R15: presence/stat cache and shared chunk cache -----------------------

// withOpenCounter wraps the presence-checking open seam and returns a pointer
// to the number of stat sweeps performed.
func withOpenCounter(t *testing.T) *int {
	t.Helper()
	orig := openReaderAtFn
	n := 0
	openReaderAtFn = func(v *vault.Vault, vp string) (*vault.FileReader, error) {
		n++
		return orig(v, vp)
	}
	t.Cleanup(func() { openReaderAtFn = orig })
	return &n
}

func TestHeadAndNotModifiedSkipStatSweep(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/data.bin", []byte("abcdefghij0123456789"))
	files, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	rec := files["content/docs/data.bin"]
	etag := etagForRecord("content/docs/data.bin", rec)

	// Delete every chunk: HEAD and a 304 must still succeed, proving neither
	// touches the chunk objects.
	if err := os.RemoveAll(chunksDir(v)); err != nil {
		t.Fatal(err)
	}
	s := &Server{Vault: v}

	cnt := withOpenCounter(t)
	if rr := serve(s, req(http.MethodHead, "/docs/data.bin", nil)); rr.Code != http.StatusOK {
		t.Fatalf("HEAD after chunk removal: code=%d want 200", rr.Code)
	}
	if *cnt != 0 {
		t.Fatalf("HEAD performed %d stat sweeps, want 0", *cnt)
	}

	r := req(http.MethodGet, "/docs/data.bin", nil)
	r.Header.Set("If-None-Match", etag)
	if rr := serve(s, r); rr.Code != http.StatusNotModified {
		t.Fatalf("conditional GET: code=%d want 304", rr.Code)
	}
	if *cnt != 0 {
		t.Fatalf("304 path performed %d stat sweeps, want 0", *cnt)
	}
}

func TestTwoRangeGetsStatOnce(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/data.bin", []byte("abcdefghij0123456789"))
	s := &Server{Vault: v}

	cnt := withOpenCounter(t)
	r := req(http.MethodGet, "/docs/data.bin", nil)
	r.Header.Set("Range", "bytes=0-4")
	if rr := serve(s, r); rr.Code != http.StatusPartialContent {
		t.Fatalf("first Range GET: code=%d want 206", rr.Code)
	}
	r = req(http.MethodGet, "/docs/data.bin", nil)
	r.Header.Set("Range", "bytes=5-9")
	if rr := serve(s, r); rr.Code != http.StatusPartialContent {
		t.Fatalf("second Range GET: code=%d want 206", rr.Code)
	}
	if *cnt != 1 {
		t.Fatalf("two Range GETs within 10s performed %d stat sweeps, want 1", *cnt)
	}
}

func TestSecondGetServedFromChunkCache(t *testing.T) {
	v := newTestVault(t)
	data := []byte("abcdefghij0123456789the quick brown fox jumps over")
	putFile(t, v, "docs/data.bin", data)
	s := &Server{Vault: v}

	// First GET warms the server's shared chunk cache.
	rr := serve(s, req(http.MethodGet, "/docs/data.bin", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != string(data) {
		t.Fatalf("warm-up GET: code=%d body=%q", rr.Code, rr.Body.String())
	}

	// Remove every chunk object from disk. A second GET within the presence
	// window must still return the full file, proving every chunk came from the
	// in-memory cache and nothing was re-read/decrypted from disk.
	if err := os.RemoveAll(chunksDir(v)); err != nil {
		t.Fatal(err)
	}
	rr = serve(s, req(http.MethodGet, "/docs/data.bin", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("cache-served GET: code=%d want 200", rr.Code)
	}
	if rr.Body.String() != string(data) {
		t.Fatalf("cache-served GET body mismatch: %q", rr.Body.String())
	}
}

// A small guard so a future refactor that empties the junk list is caught.
func TestIsMountJunkTable(t *testing.T) {
	junk := []string{".DS_Store", "._resource", ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems", ".localized", "desktop.ini", "Thumbs.db", "__MACOSX"}
	notJunk := []string{"a.txt", "DS_Store", "notes.md", "photo.jpg"}
	for _, n := range junk {
		if !isMountJunk(n) {
			t.Fatalf("isMountJunk(%q)=false, want true", n)
		}
	}
	for _, n := range notJunk {
		if isMountJunk(n) {
			t.Fatalf("isMountJunk(%q)=true, want false", n)
		}
	}
}

// chunkObjectPath returns the on-disk path of a chunk object, mirroring the
// vault's internal layout (objects/chunks/<id[:2]>/<id>.chunk).
func chunkObjectPath(v *vault.Vault, id string) string {
	prefix := id
	if len(prefix) > 2 {
		prefix = id[:2]
	}
	return filepath.Join(v.MetaRoot, "objects", "chunks", prefix, id+".chunk")
}

// TestStalePresentTornGetYields409 is the IC-2 tombstone: a warm GET caches a
// "present" verdict for 10s; if a chunk object is then removed on disk while its
// plaintext is NOT resident in the ChunkCache (ChunkCacheBytes: 1), a second GET
// within the window must NOT trust the stale verdict and serve a torn 200 (a
// full Content-Length committed by http.ServeContent, then a short body when the
// missing chunk's ReadAt fails). It must instead re-verify the bytes it is about
// to serve and return the clean 409 the presence pre-check exists to produce.
func TestStalePresentTornGetYields409(t *testing.T) {
	v := newTestVault(t)
	// A multi-chunk file so removing the last chunk leaves a torn tail.
	data := make([]byte, 4000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	putFile(t, v, "docs/big.bin", data)

	// ChunkCacheBytes: 1 => no chunk (>= 64 B) is ever retained, so the second
	// GET must re-read from disk rather than being masked by the chunk cache.
	s := &Server{Vault: v, ChunkCacheBytes: 1}

	// Warm GET: 200, full body, Content-Length == size. Caches presence=present.
	rr := serve(s, req(http.MethodGet, "/docs/big.bin", nil))
	if rr.Code != http.StatusOK || rr.Body.Len() != len(data) {
		t.Fatalf("warm GET: code=%d body=%d want 200 and %d bytes", rr.Code, rr.Body.Len(), len(data))
	}

	// Externally remove the last chunk object (simulating a sync/GC removal).
	files, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	rec := files["content/docs/big.bin"]
	if len(rec.Chunks) < 2 {
		t.Fatalf("test needs a multi-chunk file, got %d chunks", len(rec.Chunks))
	}
	last := rec.Chunks[len(rec.Chunks)-1]
	if err := os.Remove(chunkObjectPath(v, last.ID)); err != nil {
		t.Fatal(err)
	}

	// Second GET within the 10s presence window: must be a clean 409, never a
	// 200 whose Content-Length over-promises the truncated body.
	rr = serve(s, req(http.MethodGet, "/docs/big.bin", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("stale-present torn GET returned 200 with Content-Length=%q but only %d of %d bytes delivered; want 409",
			rr.Header().Get("Content-Length"), rr.Body.Len(), len(data))
	}
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale-present torn GET: code=%d want 409", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not fully synced yet") {
		t.Fatalf("409 body=%q", rr.Body.String())
	}
}

// ---- IC-3: the GET response ETag must describe the bytes it validates -------

// TestGetEtagMatchesServedGeneration is the IC-3 tombstone. handleGet derives
// the response ETag from its AllEntries snapshot (generation G1) but opens the
// reader in a second, independent index snapshot. A same-path overwrite landing
// between the two makes http.ServeContent serve the NEW generation's bytes under
// the OLD generation's ETag; a resuming client whose If-Range equals that stale
// validator then gets a 206 of new content stitched onto previously fetched old
// bytes under a matching validator. The fix binds the response ETag to the
// reader's own record so the validator always describes the bytes it labels. We
// drive the race deterministically through the exact production open seam the
// cache-miss path calls: the wrapper commits generation G2 just before the real
// open runs.
func TestGetEtagMatchesServedGeneration(t *testing.T) {
	v := newTestVault(t)
	const vp = "content/docs/race.bin"
	putFile(t, v, "docs/race.bin", bytes.Repeat([]byte("A"), 20)) // generation G1

	files, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	etagG1 := etagForRecord(vp, files[vp])

	// Inject the same-path overwrite (generation G2, different size) between the
	// handler's AllEntries snapshot and the reader open, via the seam the
	// production cache-miss path calls.
	orig := openReaderAtFn
	openReaderAtFn = func(vv *vault.Vault, p string) (*vault.FileReader, error) {
		putFile(t, vv, "docs/race.bin", bytes.Repeat([]byte("B"), 40)) // generation G2
		return orig(vv, p)
	}
	t.Cleanup(func() { openReaderAtFn = orig })

	s := &Server{Vault: v}

	// A resuming client presents the G1 validator it fetched earlier.
	r := req(http.MethodGet, "/docs/race.bin", nil)
	r.Header.Set("Range", "bytes=5-9")
	r.Header.Set("If-Range", etagG1)
	rr := serve(s, r)

	// The reader served generation-2 bytes (all 'B'): confirm the race fired so
	// this test can never pass vacuously.
	body := rr.Body.Bytes()
	if len(body) == 0 || bytes.IndexByte(body, 'A') != -1 {
		t.Fatalf("expected generation-2 bytes ('B' only) in body, got %q (code=%d)", body, rr.Code)
	}

	// The validator the served generation actually deserves.
	files2, err := v.AllEntries()
	if err != nil {
		t.Fatal(err)
	}
	etagG2 := etagForRecord(vp, files2[vp])
	if etagG1 == etagG2 {
		t.Fatal("overwrite did not change the ETag; test cannot distinguish generations")
	}

	// The response labels generation-2 bytes, so its ETag must be the
	// generation-2 validator, never the stale generation-1 one the handler
	// snapshotted.
	got := rr.Header().Get("ETag")
	if got == etagG1 {
		t.Fatalf("IC-3: response served generation-2 bytes %q under the stale generation-1 ETag %s; "+
			"an If-Range resume would stitch new content onto old bytes under a matching validator", body, etagG1)
	}
	if got != etagG2 {
		t.Fatalf("IC-3: response ETag %q matches neither the served generation-2 record etag %s; "+
			"the validator must describe the bytes it labels", got, etagG2)
	}
}
