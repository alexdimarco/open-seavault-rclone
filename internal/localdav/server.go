// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package localdav

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/authlimit"
	"github.com/alexdimarco/open-seavault-rclone/internal/loopback"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// bodyInactivity is the per-request inactivity deadline applied to a streaming
// GET body (each Write) and a PUT body (each Read). A client that neither reads
// nor writes for this long has its connection closed; a slow-but-progressing
// transfer is never cut. See.
const bodyInactivity = 60 * time.Second

// presenceTTL is how long a successful/pending OpenReaderAt presence sweep is
// cached per (path, generation) so a scrubbing Range client pays the per-chunk
// stat sweep at most once per window. See the design step 4.
const presenceTTL = 10 * time.Second

// defaultChunkCacheBytes is the size of the lazily created shared chunk cache
// when neither ChunkCache nor ChunkCacheBytes is set. See.
const defaultChunkCacheBytes = 64 << 20

// defaultMaxStreams bounds concurrent streaming GET bodies when MaxStreams is
// unset. See.
const defaultMaxStreams = 8

type Server struct {
	Vault    *vault.Vault
	ReadOnly bool
	Prefix   string

	// AllowedHosts are extra Host names (besides loopback addresses and
	// "localhost") that ServeHTTP accepts. See.
	AllowedHosts []string
	// Credentials, when non-nil, require HTTP Basic authentication on every
	// request (OPTIONS included). See.
	Credentials *BasicCredentials
	// AuthLimiter, when non-nil (and Credentials is set), rate-limits and locks
	// the Basic-auth surface (design-u4 §2.2, surface "basic"): a locked peer is
	// denied BEFORE the constant-time compare with 429 + Retry-After and NO
	// WWW-Authenticate (so a client stops re-prompting), a failed compare is
	// throttled by FailureDelay and then answered 401 as before, and a match
	// resets the peer. It is nil for the GUI's per-request /dav servers, which are
	// session-gated rather than Basic-authenticated. See.
	AuthLimiter *authlimit.Limiter
	// AuthLogf, when non-nil, receives the one-line operator lock message when the
	// Basic surface locks a peer (C6); it never carries a credential. cmd serve
	// points it at the auth-limit log sink. Nil discards the line.
	AuthLogf func(format string, args ...any)
	// DropOSJunk, when true, makes the server silently no-op filesystem cruft
	// (.DS_Store and friends) instead of storing it. See.
	DropOSJunk bool
	// MaxStreams bounds concurrent streaming GET bodies (0 => defaultMaxStreams).
	// Ignored when StreamSem is non-nil (the shared semaphore already carries a
	// capacity).
	MaxStreams int
	// StreamSem, when non-nil, is the streaming-GET semaphore this Server uses
	// instead of lazily minting a private one. A caller that constructs a fresh
	// Server per request (the GUI's handleWebDAV) passes one shared semaphore so
	// the MaxStreams cap stays GLOBAL across requests rather than resetting to a
	// full budget on every request. See the design and.
	StreamSem chan struct{}
	// ChunkCache is the shared decrypted-chunk cache attached to every reader. If
	// nil, the server lazily creates one of ChunkCacheBytes bytes.
	ChunkCache *vault.ChunkCache
	// ChunkCacheBytes sizes the lazily created chunk cache (0 => 64 MiB).
	ChunkCacheBytes int64
	// Presence, when non-nil, is the shared (path, generation) presence-sweep
	// cache this Server uses instead of lazily minting a private one. A caller
	// that constructs a fresh Server per request (the GUI's handleWebDAV) passes
	// one shared cache so the "stat once per 10 s window" optimization stays
	// GLOBAL across requests: without it every throwaway Server starts with an
	// empty presence map and re-runs the full per-chunk stat sweep on every Range
	// GET. Scope it to one open vault (a caller swapping vaults must hand a fresh
	// cache) since the key is not vault-qualified. See the design and finding
	// IC-1.
	Presence *PresenceCache

	// mu serialises the compound (snapshot-then-mutate) verbs DELETE/MKCOL/
	// MOVE/COPY. GET/HEAD/PROPFIND/OPTIONS/PUT do NOT take it.
	mu sync.Mutex

	presenceOnce sync.Once
	presenceLazy *PresenceCache

	streamOnce sync.Once
	streamSem  chan struct{}

	cacheOnce sync.Once
}

// PresenceCache is a 10 s cache of the per-(path, generation) presence-sweep
// result (present, or ErrChunksPending) so a scrubbing client issuing many
// Range GETs pays the per-chunk stat sweep once. It is safe for concurrent use.
// A Server lazily mints a private one; the GUI mount, which builds a fresh
// Server per /dav request, holds one shared cache and injects it via
// Server.Presence so the sweep result binds across requests. The
// key is (path, generation) and is NOT vault-qualified, so a shared cache must
// be scoped to a single open vault. See.
type PresenceCache struct {
	mu      sync.Mutex
	entries map[presenceKey]presenceEntry
}

// NewPresenceCache returns an empty shared presence cache.
func NewPresenceCache() *PresenceCache {
	return &PresenceCache{entries: make(map[presenceKey]presenceEntry)}
}

// get returns the cached entry for key and whether it is still fresh at now.
func (c *PresenceCache) get(key presenceKey, now time.Time) (presenceEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.entries[key]
	return ent, ok && now.Before(ent.expires)
}

// store records the sweep result for key with a fresh presenceTTL window.
func (c *PresenceCache) store(key presenceKey, now time.Time, pending bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[presenceKey]presenceEntry)
	}
	c.entries[key] = presenceEntry{expires: now.Add(presenceTTL), pending: pending}
}

// BasicCredentials are the HTTP Basic user/password that a standalone
// localdav.Server requires when non-nil.
type BasicCredentials struct {
	User     string
	Password string
}

type presenceKey struct {
	path string
	gen  int64
}

type presenceEntry struct {
	expires time.Time
	pending bool // the presence sweep found a missing chunk (ErrChunksPending)
}

// openReaderAtFn is the seam localdav tests wrap to count presence-checking
// opens (each does exactly one per-chunk stat sweep). Production leaves it as
// the default.
var openReaderAtFn = func(v *vault.Vault, vp string) (*vault.FileReader, error) {
	return v.OpenReaderAt(vp)
}

func New(v *vault.Vault) *Server {
	return &Server{Vault: v}
}

func (s *Server) maxStreams() int {
	if s.MaxStreams > 0 {
		return s.MaxStreams
	}
	return defaultMaxStreams
}

func (s *Server) sem() chan struct{} {
	if s.StreamSem != nil {
		return s.StreamSem
	}
	s.streamOnce.Do(func() { s.streamSem = make(chan struct{}, s.maxStreams()) })
	return s.streamSem
}

// acquireStream blocks for a streaming slot or returns false if the client goes
// away first.
func (s *Server) acquireStream(ctx context.Context) bool {
	sem := s.sem()
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) releaseStream() { <-s.sem() }

func (s *Server) chunkCache() *vault.ChunkCache {
	s.cacheOnce.Do(func() {
		if s.ChunkCache != nil {
			return
		}
		bytesCap := s.ChunkCacheBytes
		if bytesCap <= 0 {
			bytesCap = defaultChunkCacheBytes
		}
		s.ChunkCache = vault.NewChunkCache(bytesCap)
	})
	return s.ChunkCache
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !loopback.HostAllowed(r.Host, s.AllowedHosts) {
		http.Error(w, hostForbiddenBody(r.Host, s.AllowedHosts), http.StatusForbidden)
		return
	}

	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if s.Credentials != nil && !s.authorizeBasic(w, r) {
		return
	}

	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, LOCK, UNLOCK")
		w.WriteHeader(http.StatusNoContent)
	case "PROPFIND":
		s.handlePropfind(w, r)
	case http.MethodGet, http.MethodHead:
		s.handleGet(w, r)
	case http.MethodPut:
		if s.rejectReadOnly(w) {
			return
		}
		s.handlePut(w, r)
	case http.MethodDelete:
		if s.rejectReadOnly(w) {
			return
		}
		s.handleDelete(w, r)
	case "MKCOL":
		if s.rejectReadOnly(w) {
			return
		}
		s.handleMkcol(w, r)
	case "MOVE":
		if s.rejectReadOnly(w) {
			return
		}
		s.handleCopyMove(w, r, true)
	case "COPY":
		if s.rejectReadOnly(w) {
			return
		}
		s.handleCopyMove(w, r, false)
	case "LOCK":
		s.handleLock(w, r)
	case "UNLOCK":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not implemented", http.StatusNotImplemented)
	}
}

// hostForbiddenBody is the 403 body naming the remedy.
func hostForbiddenBody(rawHost string, extra []string) string {
	allowed := "loopback addresses, localhost"
	if len(extra) > 0 {
		allowed += ", " + strings.Join(extra, ", ")
	}
	return fmt.Sprintf("forbidden: unexpected Host header %q; allowed: %s; start with --allow-host NAME to add one", rawHost, allowed)
}

// authorizeBasic gates a Basic-authenticated request. It returns true when the
// request may proceed and has already written the response otherwise.
//
// A request with NO Basic header is the client's first probe: it is answered
// with the WWW-Authenticate challenge (401) and does NOT touch the limiter — the
// challenge is a prompt, not a credential guess, so a well-behaved client's
// initial unauthenticated request never burns a failure. Once credentials are
// presented, the limiter (when configured) runs BEFORE the constant-time compare
// (design-u4 §2.2, I-R1): a locked peer gets 429 + Retry-After with NO
// WWW-Authenticate; a wrong credential is throttled by FailureDelay and then
// answered 401 with the challenge as before; a match resets the peer.
func (s *Server) authorizeBasic(w http.ResponseWriter, r *http.Request) bool {
	user, _, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="open-seavault-rclone", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	if s.AuthLimiter == nil {
		if s.credentialsMatch(r) {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="open-seavault-rclone", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	att, allowed, retryAfter := s.AuthLimiter.Attempt(authlimit.SurfaceBasic, r.RemoteAddr, user)
	if !allowed {
		// Locked: deny before the compare. No WWW-Authenticate (so the client
		// stops re-prompting for a password it cannot currently use).
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		http.Error(w, "too many failed authentication attempts; retry after the lock expires", http.StatusTooManyRequests)
		return false
	}
	if s.credentialsMatch(r) {
		att.Success()
		return true
	}
	att.Fail()
	if s.AuthLogf != nil {
		for _, line := range att.LockLines() {
			s.AuthLogf("%s", line)
		}
	}
	if d := s.AuthLimiter.FailureDelay(); d > 0 {
		time.Sleep(d)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="open-seavault-rclone", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
	return false
}

// retryAfterSeconds converts a lock/throttle duration to a whole-seconds
// Retry-After value, rounding up so a sub-second remainder never truncates to 0
// (a "retry in 0 seconds" would invite an immediate re-lock). A non-positive
// duration yields 1.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return secs
}

// credentialsMatch compares the request's Basic credentials against the
// configured ones. Both fields are hashed with SHA-256 first so the
// constant-time compare also compares lengths in constant time.
func (s *Server) credentialsMatch(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	wantUser := sha256.Sum256([]byte(s.Credentials.User))
	gotUser := sha256.Sum256([]byte(user))
	wantPass := sha256.Sum256([]byte(s.Credentials.Password))
	gotPass := sha256.Sum256([]byte(pass))
	userOK := subtle.ConstantTimeCompare(wantUser[:], gotUser[:]) == 1
	passOK := subtle.ConstantTimeCompare(wantPass[:], gotPass[:]) == 1
	return userOK && passOK
}

func (s *Server) rejectReadOnly(w http.ResponseWriter) bool {
	if !s.ReadOnly {
		return false
	}
	http.Error(w, "this WebDAV view is read-only", http.StatusForbidden)
	return true
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.DropOSJunk && vp != "" && isMountJunk(path.Base(vp)) {
		http.NotFound(w, r)
		return
	}

	// Snapshot the record set (under the vault's own lock, not s.mu) so a
	// concurrent streaming GET never blocks PROPFIND.
	files, err := s.Vault.AllEntries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rec, isFile := files[vp]
	if !isFile || vault.IsInternalVirtualPath(vp) {
		// Directory (or root) => HTML listing, as today. Anything else => 404.
		if vp == "" || directoryExists(files, vp) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method == http.MethodHead {
				return
			}
			_ = writeDirectoryHTML(w, s, files, vp)
			return
		}
		http.NotFound(w, r)
		return
	}

	// Step 2: conditional 304 with no stat sweep and no chunk reads.
	etag := etagForRecord(vp, rec)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Step 3: HEAD returns headers only, doing zero chunk work.
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", rec.Size))
		if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
			w.Header().Set("Last-Modified", t.UTC().Format(http.TimeFormat))
		}
		return
	}

	// Step 4: open a decrypting reader, honouring the cached presence result.
	// Scope the (re-)verification to the bytes this request will actually serve
	// so a fresh "present" cache hit still catches a chunk removed since the
	// sweep (IC-2) without re-statting the whole file on every Range GET.
	off, length := servedByteRange(r, rec.Size)
	fr, err := s.openFileReader(vp, rec, off, length)
	if err != nil {
		if errors.Is(err, vault.ErrChunksPending) {
			http.Error(w, "file is not fully synced yet", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer fr.Close()

	// Step 5: let http.ServeContent own Content-Length/Range/Last-Modified.
	// Re-derive the validator from the reader's OWN record rather than the
	// AllEntries snapshot taken at the top: openFileReader re-loads the index, so
	// a same-path overwrite (new generation, last-writer-wins) landing between the
	// two snapshots would otherwise label the new generation's bytes/Size/ModTime
	// with the old generation's ETag. http.ServeContent uses the header ETag for
	// If-Range/If-None-Match, so a stale validator that still matched a resuming
	// client's If-Range would stitch new content onto previously fetched old bytes
	// . Binding the ETag to fr keeps validator and bytes in the same
	// generation; in the common no-overwrite case fr's record equals rec, so this
	// is the identical value.
	etag = etagForReader(vp, fr)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", etag)
	dw := &deadlineResponseWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: bodyInactivity}
	if !s.acquireStream(r.Context()) {
		return
	}
	defer s.releaseStream()
	http.ServeContent(dw, r, path.Base(vp), fr.ModTime(), io.NewSectionReader(fr, 0, fr.Size()))
}

// openFileReader opens a reader for vp, using a 10 s per-(path, generation)
// cache of the presence-sweep result so repeated Range GETs skip the whole-file
// stat sweep. On a cache miss it performs the sweep (via openReaderAtFn).
// On a fresh "present" hit it opens without the sweep but re-verifies, on disk,
// the chunks in [off, off+length) that the shared chunk cache cannot serve, so a
// chunk removed since the sweep yields a clean ErrChunksPending (→ 409) instead
// of a torn 200. off/length name the byte range the request will
// serve (0, rec.Size for a whole-file GET).
func (s *Server) openFileReader(vp string, rec vault.FileRecord, off, length int64) (*vault.FileReader, error) {
	key := presenceKey{path: vp, gen: rec.Generation}
	now := time.Now()
	cache := s.presence()

	if ent, fresh := cache.get(key, now); fresh {
		if ent.pending {
			return nil, vault.ErrChunksPending
		}
		fr, err := s.Vault.OpenReaderAtWithOptions(vp, vault.OpenReaderAtOptions{SkipPresenceCheck: true})
		if err != nil {
			return nil, err
		}
		fr.Cache = s.chunkCache()
		if verr := fr.VerifyChunkPresence(off, length); verr != nil {
			fr.Close()
			if errors.Is(verr, vault.ErrChunksPending) {
				// The file is torn: downgrade the stale "present" verdict so
				// subsequent GETs fast-path to 409 rather than re-detecting it.
				cache.store(key, now, true)
			}
			return nil, verr
		}
		return fr, nil
	}

	fr, err := openReaderAtFn(s.Vault, vp)
	if err == nil {
		cache.store(key, now, false)
		fr.Cache = s.chunkCache()
		return fr, nil
	}
	if errors.Is(err, vault.ErrChunksPending) {
		cache.store(key, now, true)
	}
	return nil, err
}

// servedByteRange returns the byte range [off, off+length) that http.ServeContent
// will actually read for r on a file of size bytes. It returns the whole file
// (0, size) unless the request carries exactly one simple, fully-closed byte
// range and no If-Range header — either of which can make ServeContent send the
// whole file or several disjoint regions — so a caller re-verifying presence
// never under-checks the bytes that will be sent.
func servedByteRange(r *http.Request, size int64) (off, length int64) {
	if r.Method == http.MethodHead {
		return 0, 0
	}
	spec := strings.TrimSpace(r.Header.Get("Range"))
	if spec == "" || r.Header.Get("If-Range") != "" {
		return 0, size
	}
	const prefix = "bytes="
	if !strings.HasPrefix(spec, prefix) {
		return 0, size
	}
	spec = spec[len(prefix):]
	if strings.ContainsRune(spec, ',') { // multiple ranges: verify the whole file
		return 0, size
	}
	dash := strings.IndexByte(spec, '-')
	if dash <= 0 || dash == len(spec)-1 { // suffix ("-N") or open-ended ("A-")
		return 0, size
	}
	a, err1 := strconv.ParseInt(strings.TrimSpace(spec[:dash]), 10, 64)
	b, err2 := strconv.ParseInt(strings.TrimSpace(spec[dash+1:]), 10, 64)
	if err1 != nil || err2 != nil || a < 0 || b < a || a >= size {
		return 0, size
	}
	if b >= size {
		b = size - 1
	}
	return a, b - a + 1
}

// presence resolves the presence-sweep cache: the shared one when the caller
// injected Server.Presence (the GUI mount, so the sweep result binds across the
// fresh-per-request Servers —), otherwise a per-Server lazy cache.
func (s *Server) presence() *PresenceCache {
	if s.Presence != nil {
		return s.Presence
	}
	s.presenceOnce.Do(func() { s.presenceLazy = NewPresenceCache() })
	return s.presenceLazy
}

// deadlineResponseWriter re-arms the connection's write deadline before each
// body Write so a stalled reader is cut after bodyInactivity, while a
// progressing transfer is never cut. ErrNotSupported (httptest recorders) is
// ignored so tests still work.
type deadlineResponseWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
	d  time.Duration
}

func (dw *deadlineResponseWriter) Write(p []byte) (int, error) {
	if err := dw.rc.SetWriteDeadline(time.Now().Add(dw.d)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	return dw.ResponseWriter.Write(p)
}

// deadlineReader re-arms the connection's read deadline before each body Read.
type deadlineReader struct {
	r  io.Reader
	rc *http.ResponseController
	d  time.Duration
}

func (dr *deadlineReader) Read(p []byte) (int, error) {
	if err := dr.rc.SetReadDeadline(time.Now().Add(dr.d)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	return dr.r.Read(p)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if vp == "" {
		http.Error(w, "cannot PUT to vault root", http.StatusBadRequest)
		return
	}
	if s.DropOSJunk && isMountJunk(path.Base(vp)) {
		// Silently accept without storing: the client believes it wrote the file.
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		return
	}
	// No s.mu: Vault.PutReader is safe for concurrent callers.
	_, existed, _ := s.Vault.FileInfo(vp)
	// Creating a NEW reserved-segment path is refused at the boundary with a
	// clean 400; overwriting an EXISTING reserved path a peer or
	// legacy client created still works.
	if !existed && vault.ReservedContentSegment(vp) {
		http.Error(w, fmt.Sprintf("reserved virtual path %q is not allowed", vp), http.StatusBadRequest)
		return
	}
	size := r.ContentLength
	if size < 0 {
		size = -1
	}
	body := io.Reader(&deadlineReader{r: r.Body, rc: http.NewResponseController(w), d: bodyInactivity})
	if _, err := s.Vault.PutReader(body, vp, size, 0o600, time.Now().UTC()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.DropOSJunk && vp != "" && isMountJunk(path.Base(vp)) {
		// The junk file was never stored; report a successful delete.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.Vault.RemovePath(vp); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMkcol(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if vp == "" {
		http.Error(w, "root collection already exists; use content/ as the writable workspace", http.StatusMethodNotAllowed)
		return
	}
	if s.DropOSJunk && isMountJunk(path.Base(vp)) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		return
	}
	if requestHasBody(r) {
		http.Error(w, "MKCOL does not accept a request body", http.StatusUnsupportedMediaType)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exists, err := s.Vault.DirectoryExists(vp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if exists {
		http.Error(w, "collection already exists", http.StatusMethodNotAllowed)
		return
	}
	// A NEW reserved-segment collection cannot be created; an
	// existing one short-circuits at the "already exists" check above.
	if vault.ReservedContentSegment(vp) {
		http.Error(w, fmt.Sprintf("reserved virtual path %q is not allowed", vp), http.StatusBadRequest)
		return
	}
	if parent := path.Dir(vp); !isWorkspaceRoot(parent) {
		parentExists, err := s.Vault.DirectoryExists(parent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !parentExists {
			http.Error(w, "parent collection does not exist", http.StatusConflict)
			return
		}
	}
	if err := s.Vault.EnsureDirectory(vp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// isWorkspaceRoot reports whether a path.Dir result names the always-present
// content workspace root (or nothing), so a MKCOL directly under it needs no
// parent-existence check.
func isWorkspaceRoot(parent string) bool {
	return parent == "" || parent == "." || parent == vault.ContentRootName
}

// requestHasBody reports whether the request carries a non-empty body, without
// consuming a body it must preserve (MKCOL never needs the bytes).
func requestHasBody(r *http.Request) bool {
	if r.ContentLength > 0 {
		return true
	}
	if r.Body == nil {
		return false
	}
	var one [1]byte
	n, _ := io.ReadFull(r.Body, one[:])
	return n > 0
}

func (s *Server) handleCopyMove(w http.ResponseWriter, r *http.Request, move bool) {
	src, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	destination := strings.TrimSpace(r.Header.Get("Destination"))
	if destination == "" {
		http.Error(w, "Destination header is required", http.StatusBadRequest)
		return
	}
	dst, err := s.virtualPathFromDestination(destination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if dst == "" || src == "" {
		http.Error(w, "invalid source or destination", http.StatusBadRequest)
		return
	}
	// The destination is a create target: a reserved-segment name cannot be
	// created. Moving or copying an EXISTING reserved source OUT to
	// an ordinary name is still allowed, so this gates only the destination
	// .
	if vault.ReservedContentSegment(dst) {
		http.Error(w, fmt.Sprintf("reserved virtual path %q is not allowed", dst), http.StatusBadRequest)
		return
	}
	if move && (dst == src || strings.HasPrefix(dst+"/", src+"/")) {
		http.Error(w, "cannot move a path into itself", http.StatusBadRequest)
		return
	}

	overwrite := strings.TrimSpace(r.Header.Get("Overwrite"))
	if overwrite == "" {
		overwrite = "T"
	}
	if overwrite != "T" && overwrite != "F" {
		http.Error(w, "Overwrite must be T or F", http.StatusBadRequest)
		return
	}
	depth := strings.TrimSpace(r.Header.Get("Depth"))
	if move && depth == "0" {
		http.Error(w, "MOVE with Depth 0 is not allowed", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := s.Vault.AllEntries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, srcIsFile := files[src]
	srcIsFile = srcIsFile && !vault.IsInternalVirtualPath(src)
	srcIsDir := !srcIsFile && directoryExists(files, src)
	if !srcIsFile && !srcIsDir {
		http.Error(w, "source path not found", http.StatusNotFound)
		return
	}
	_, dstIsFile := files[dst]
	dstIsFile = dstIsFile && !vault.IsInternalVirtualPath(dst)
	dstIsDir := directoryExists(files, dst)
	dstExists := dstIsFile || dstIsDir

	if overwrite == "F" && dstExists {
		http.Error(w, "destination exists and Overwrite is F", http.StatusPreconditionFailed)
		return
	}

	// COPY of a collection with Depth: 0 creates only the collection.
	if !move && srcIsDir && depth == "0" {
		if dstIsFile { // type change: replace the file with a collection
			if _, err := s.Vault.RemovePath(dst); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := s.Vault.EnsureDirectory(dst); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeCopyMoveStatus(w, dstExists)
		return
	}

	// Overwrite onto an existing destination: a plain file->file overwrite is
	// the in-place atomic PutReader (no pre-delete); a type change or a
	// collection->collection overwrite removes the destination first (RFC 4918
	// .4).
	if dstExists {
		typeChange := (srcIsFile && dstIsDir) || (srcIsDir && dstIsFile)
		collToColl := srcIsDir && dstIsDir
		if typeChange || collToColl {
			if _, err := s.Vault.RemovePath(dst); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	if _, err := s.copyPath(src, dst); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if move {
		if _, err := s.Vault.RemovePath(src); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeCopyMoveStatus(w, dstExists)
}

func writeCopyMoveStatus(w http.ResponseWriter, existed bool) {
	if existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Server) copyPath(src, dst string) (int, error) {
	files, err := s.Vault.AllEntries()
	if err != nil {
		return 0, err
	}
	if vault.IsInternalVirtualPath(src) || vault.IsInternalVirtualPath(dst) {
		return 0, fmt.Errorf("reserved paths cannot be copied")
	}
	if rec, ok := files[src]; ok && !vault.IsInternalVirtualPath(src) {
		return 1, s.copyFile(src, dst, rec)
	}
	if !directoryExists(files, src) {
		return 0, fmt.Errorf("source path %q not found", src)
	}
	if err := s.Vault.EnsureDirectory(dst); err != nil {
		return 0, err
	}
	prefix := src
	if prefix != "" {
		prefix += "/"
	}
	count := 0
	keys := make([]string, 0, len(files))
	for p := range files {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			keys = append(keys, p)
		}
	}
	sort.Strings(keys)
	for _, p := range keys {
		rel := p
		if prefix != "" {
			rel = strings.TrimPrefix(p, prefix)
		}
		if rel == "" {
			continue
		}
		if vault.IsDirectoryMarkerPath(p) {
			dirRel := strings.TrimSuffix(rel, "/"+vault.DirectoryMarkerName)
			if dirRel == vault.DirectoryMarkerName {
				dirRel = ""
			}
			if err := s.Vault.EnsureDirectory(path.Join(dst, dirRel)); err != nil {
				return count, err
			}
			continue
		}
		destPath := path.Join(dst, rel)
		if err := s.copyFile(p, destPath, files[p]); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *Server) copyFile(src, dst string, rec vault.FileRecord) error {
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := s.Vault.WriteFileTo(src, pw)
		_ = pw.CloseWithError(err)
		errc <- err
	}()
	modTime := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
		modTime = t
	}
	_, putErr := s.Vault.PutReader(pr, dst, rec.Size, rec.Mode, modTime)
	writeErr := <-errc
	if putErr != nil {
		return putErr
	}
	return writeErr
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery/></D:prop>`))
}

func (s *Server) handlePropfind(w http.ResponseWriter, r *http.Request) {
	vp, err := s.requestVirtualPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.DropOSJunk && vp != "" && isMountJunk(path.Base(vp)) {
		http.NotFound(w, r)
		return
	}
	depth := strings.TrimSpace(r.Header.Get("Depth"))
	if strings.EqualFold(depth, "infinity") {
		w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>`))
		return
	}
	if depth == "" {
		depth = "1"
	}
	// No s.mu: AllEntries snapshots under the vault's own lock.
	files, err := s.Vault.AllEntries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	responses, ok := propfindResponses(files, vp, depth, s.basePrefix())
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write([]byte(`<D:multistatus xmlns:D="DAV:">`))
	for _, resp := range responses {
		writeResponse(w, resp)
	}
	_, _ = w.Write([]byte(`</D:multistatus>`))
}

// etagMatches reports whether an If-None-Match header value matches etag. It
// accepts "*", a comma-separated list, and weak ("W/") validators.
func etagMatches(inm, etag string) bool {
	inm = strings.TrimSpace(inm)
	if inm == "*" {
		return true
	}
	for _, part := range strings.Split(inm, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == etag {
			return true
		}
	}
	return false
}

// isMountJunk reports whether base is filesystem cruft the client's OS creates
// automatically (Finder/Explorer/Spotlight metadata). See.
func isMountJunk(base string) bool {
	if strings.HasPrefix(base, "._") {
		return true
	}
	switch base {
	case ".DS_Store", ".Spotlight-V100", ".Trashes", ".fseventsd",
		".TemporaryItems", ".localized", "desktop.ini", "Thumbs.db", "__MACOSX":
		return true
	}
	return false
}

type responseInfo struct {
	Href    string
	IsDir   bool
	Size    int64
	ModTime string
	ETag    string
}

func propfindResponses(files map[string]vault.FileRecord, vp string, depth string, base string) ([]responseInfo, bool) {
	vp = strings.Trim(vp, "/")
	var out []responseInfo
	if rec, ok := files[vp]; ok && !vault.IsInternalVirtualPath(vp) {
		out = append(out, responseInfo{Href: href(base, vp, false), IsDir: false, Size: rec.Size, ModTime: rec.ModTime, ETag: etagForRecord(vp, rec)})
		return out, true
	}

	if !directoryExists(files, vp) {
		return nil, false
	}
	out = append(out, responseInfo{Href: href(base, vp, true), IsDir: true})
	if depth == "0" {
		return out, true
	}

	prefix := vp
	if prefix != "" {
		prefix += "/"
	}
	childDirs := map[string]bool{}
	var childFiles []responseInfo
	for p, rec := range files {
		if prefix != "" && !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p
		if prefix != "" {
			rest = strings.TrimPrefix(p, prefix)
		}
		if rest == "" {
			continue
		}
		if vault.IsDirectoryMarkerPath(p) {
			dirRest := strings.TrimSuffix(rest, "/"+vault.DirectoryMarkerName)
			if dirRest == vault.DirectoryMarkerName {
				continue
			}
			if dirRest != "" {
				first := dirRest
				if slash := strings.Index(first, "/"); slash >= 0 {
					first = first[:slash]
				}
				childDirs[path.Join(vp, first)] = true
			}
			continue
		}
		if vault.IsInternalVirtualPath(p) {
			continue
		}
		if slash := strings.Index(rest, "/"); slash >= 0 {
			childDirs[path.Join(vp, rest[:slash])] = true
			continue
		}
		childFiles = append(childFiles, responseInfo{Href: href(base, path.Join(vp, rest), false), IsDir: false, Size: rec.Size, ModTime: rec.ModTime, ETag: etagForRecord(path.Join(vp, rest), rec)})
	}
	var dirs []string
	for d := range childDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		out = append(out, responseInfo{Href: href(base, d, true), IsDir: true})
	}
	sort.Slice(childFiles, func(i, j int) bool { return childFiles[i].Href < childFiles[j].Href })
	out = append(out, childFiles...)
	return out, true
}

func directoryExists(files map[string]vault.FileRecord, vp string) bool {
	if vp == "" {
		return true
	}
	if _, ok := files[path.Join(vp, vault.DirectoryMarkerName)]; ok {
		return true
	}
	prefix := strings.TrimSuffix(vp, "/") + "/"
	for p := range files {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func (s *Server) requestVirtualPath(r *http.Request) (string, error) {
	p, err := url.PathUnescape(r.URL.Path)
	if err != nil {
		return "", err
	}
	base := s.basePrefix()
	if base != "" && strings.HasPrefix(p, base) {
		p = strings.TrimPrefix(p, base)
	}
	p = strings.TrimPrefix(p, "/")
	return cleanDAVVirtualPath(p)
}

func (s *Server) virtualPathFromDestination(destination string) (string, error) {
	p := destination
	if u, err := url.Parse(destination); err == nil && u.Path != "" {
		p = u.Path
	}
	p, err := url.PathUnescape(p)
	if err != nil {
		return "", err
	}
	base := s.basePrefix()
	if base != "" && strings.HasPrefix(p, base) {
		p = strings.TrimPrefix(p, base)
	}
	p = strings.TrimPrefix(p, "/")
	return cleanDAVVirtualPath(p)
}

func cleanDAVVirtualPath(input string) (string, error) {
	if strings.Trim(strings.ReplaceAll(input, "\\", "/"), "/ ") == "" {
		return "", nil
	}
	vp, err := vault.NormalizeContentPath(input)
	if err != nil {
		return "", err
	}
	if vault.IsInternalVirtualPath(vp) {
		return "", fmt.Errorf("reserved vault internals are not exposed through WebDAV")
	}
	return vp, nil
}

func (s *Server) basePrefix() string {
	p := strings.TrimSpace(s.Prefix)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func href(base, vp string, dir bool) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		base = ""
	}
	if vp == "" {
		if base == "" {
			return "/"
		}
		return base + "/"
	}
	h := "/" + url.PathEscape(vp)
	h = strings.ReplaceAll(h, "%2F", "/")
	if dir && !strings.HasSuffix(h, "/") {
		h += "/"
	}
	return base + h
}

func writeResponse(w http.ResponseWriter, ri responseInfo) {
	var b bytes.Buffer
	b.WriteString(`<D:response><D:href>`)
	xmlEscape(&b, ri.Href)
	b.WriteString(`</D:href><D:propstat><D:prop>`)
	if ri.IsDir {
		b.WriteString(`<D:resourcetype><D:collection/></D:resourcetype>`)
	} else {
		b.WriteString(`<D:resourcetype/>`)
		b.WriteString(`<D:getcontentlength>`)
		b.WriteString(fmt.Sprintf("%d", ri.Size))
		b.WriteString(`</D:getcontentlength>`)
		if ri.ETag != "" {
			b.WriteString(`<D:getetag>`)
			xmlEscape(&b, ri.ETag)
			b.WriteString(`</D:getetag>`)
		}
	}
	if ri.ModTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, ri.ModTime); err == nil {
			b.WriteString(`<D:getlastmodified>`)
			b.WriteString(t.UTC().Format(http.TimeFormat))
			b.WriteString(`</D:getlastmodified>`)
		}
	}
	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
	_, _ = w.Write(b.Bytes())
}

func writeDirectoryHTML(w io.Writer, s *Server, files map[string]vault.FileRecord, vp string) error {
	items, ok := propfindResponses(files, vp, "1", s.basePrefix())
	if !ok {
		return fmt.Errorf("directory not found")
	}
	_, _ = io.WriteString(w, "<!doctype html><meta charset=\"utf-8\"><title>open-seavault-rclone WebDAV</title><h1>open-seavault-rclone WebDAV</h1><ul>")
	for _, item := range items {
		if item.Href == href(s.basePrefix(), vp, true) {
			continue
		}
		label := path.Base(strings.TrimSuffix(item.Href, "/"))
		if item.IsDir {
			label += "/"
		}
		_, _ = fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`, htmlEscape(item.Href), htmlEscape(label))
	}
	_, _ = io.WriteString(w, "</ul>")
	return nil
}

func etagForRecord(vp string, rec vault.FileRecord) string {
	return fmt.Sprintf("\"%x-%x-%d\"", len(vp), rec.Generation, rec.Size)
}

// etagForReader builds the same opaque validator as etagForRecord but from an
// open reader's own snapshot, so the ETag encodes the exact generation and byte
// length http.ServeContent will serve. It exists so handleGet can bind the GET
// response validator to the bytes it actually streams instead of to an earlier,
// independent index snapshot.
func etagForReader(vp string, fr *vault.FileReader) string {
	return fmt.Sprintf("\"%x-%x-%d\"", len(vp), fr.Generation(), fr.Size())
}

func htmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func xmlEscape(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}
