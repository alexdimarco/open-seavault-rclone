// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

// ErrChunksPending reports that OpenReaderAt found at least one of a file's
// chunk objects missing on disk (typically a file whose chunks have not
// finished syncing from a cloud remote). It wraps os.ErrNotExist so callers can
// test with errors.Is(err, os.ErrNotExist) as well as
// errors.Is(err, ErrChunksPending).
var ErrChunksPending = fmt.Errorf("one or more chunks are not present yet: %w", os.ErrNotExist)

// loadChunkFn is the seam used by (*FileReader).ReadAt to decrypt a covering
// chunk. It wraps (*Vault).loadChunk (which authenticates and recovers
// sync-conflict copies). Tests replace it to count how many chunks a read
// decrypts; production code leaves it as the default.
var loadChunkFn = func(v *Vault, ref ChunkRef) ([]byte, error) { return v.loadChunk(ref) }

// OpenReaderAtOptions tunes OpenReaderAtWithOptions.
type OpenReaderAtOptions struct {
	// SkipPresenceCheck opens the reader without stat-ing every chunk object
	// first. The open then always succeeds (given a live record), and any
	// missing chunk surfaces only from the ReadAt that needs it. The default
	// (false) performs the presence pre-check and returns ErrChunksPending when
	// a chunk object is absent, which callers such as localdav need because
	// http.ServeContent commits a 200 status before the first read.
	SkipPresenceCheck bool
}

// FileReader is a random-access, decrypting reader over one vault file. It
// implements io.ReaderAt. A FileReader snapshots the file's chunk list at open
// time, so a concurrent overwrite of the same virtual path does not change the
// chunk list mid-read.
//
// FileReader keeps a one-chunk cache (a Range read typically walks forward) and,
// when Cache is set, consults a shared ChunkCache before decrypting and fills it
// after. It never decrypts chunks outside the requested byte range.
type FileReader struct {
	// Cache, when non-nil, is a shared decrypted-chunk cache consulted before
	// loadChunk and filled after. Set it after construction and before the first
	// ReadAt. It is safe for concurrent use across FileReaders.
	Cache *ChunkCache

	v       *Vault
	rec     FileRecord
	offsets []int64 // prefix sums, len == len(rec.Chunks)+1; offsets[0]==0
	size    int64
	modTime time.Time

	// mu guards the one-chunk cache and closed flag so ReadAt honours the
	// io.ReaderAt contract of tolerating parallel calls on one reader.
	mu          sync.Mutex
	cachedIdx   int // index of the chunk held in cachedChunk, or -1
	cachedChunk []byte
	closed      bool
}

// OpenReaderAt opens a decrypting random-access reader for virtualPath. It
// snapshots the file record under the vault lock, then stats every chunk object
// (canonical name only) and returns ErrChunksPending if any is absent.
func (v *Vault) OpenReaderAt(virtualPath string) (*FileReader, error) {
	return v.OpenReaderAtWithOptions(virtualPath, OpenReaderAtOptions{})
}

// OpenReaderAtWithOptions is OpenReaderAt with tunable behaviour; see
// OpenReaderAtOptions.
func (v *Vault) OpenReaderAtWithOptions(virtualPath string, opts OpenReaderAtOptions) (*FileReader, error) {
	// FileInfo loads the index under v.mu and returns an owned (deep-copied)
	// record, so the snapshot cannot change mid-read.
	rec, ok, err := v.FileInfo(virtualPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("virtual path %q not found: %w", virtualPath, os.ErrNotExist)
	}

	if !opts.SkipPresenceCheck {
		for _, ref := range rec.Chunks {
			if _, serr := os.Stat(v.chunkPath(ref.ID)); serr != nil {
				if errors.Is(serr, os.ErrNotExist) {
					return nil, ErrChunksPending
				}
				return nil, serr
			}
		}
	}

	offsets := make([]int64, len(rec.Chunks)+1)
	for i, ref := range rec.Chunks {
		offsets[i+1] = offsets[i] + int64(ref.Size)
	}

	var mt time.Time
	if rec.ModTime != "" {
		if t, perr := time.Parse(time.RFC3339Nano, rec.ModTime); perr == nil {
			mt = t
		}
	}

	return &FileReader{
		v:         v,
		rec:       rec,
		offsets:   offsets,
		size:      offsets[len(offsets)-1],
		modTime:   mt,
		cachedIdx: -1,
	}, nil
}

// ReadAt implements io.ReaderAt: it fills p with bytes starting at off,
// returning io.EOF only when the end of the file is reached. A read entirely at
// or past EOF returns (0, io.EOF).
func (f *FileReader) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("vault: ReadAt on closed FileReader")
	}
	if off < 0 {
		return 0, errors.New("vault: ReadAt: negative offset")
	}
	if off >= f.size {
		return 0, io.EOF
	}
	n := 0
	pos := off
	for n < len(p) && pos < f.size {
		ci := f.chunkIndexFor(pos)
		chunk, err := f.chunkAtLocked(ci)
		if err != nil {
			return n, err
		}
		within := pos - f.offsets[ci]
		copied := copy(p[n:], chunk[within:])
		n += copied
		pos += int64(copied)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// chunkIndexFor returns the index of the chunk covering absolute offset pos,
// which must satisfy 0 <= pos < f.size.
func (f *FileReader) chunkIndexFor(pos int64) int {
	// Smallest i in [0, numChunks) with offsets[i+1] > pos.
	return sort.Search(len(f.offsets)-1, func(i int) bool {
		return f.offsets[i+1] > pos
	})
}

// chunkAtLocked returns the decrypted plaintext of chunk ci, consulting the
// one-chunk cache, then the shared cache, then decrypting. f.mu must be held.
func (f *FileReader) chunkAtLocked(ci int) ([]byte, error) {
	if f.cachedIdx == ci && f.cachedChunk != nil {
		return f.cachedChunk, nil
	}
	ref := f.rec.Chunks[ci]
	if f.Cache != nil {
		if pt, ok := f.Cache.Get(ref.ID); ok {
			f.cachedIdx = ci
			f.cachedChunk = pt
			return pt, nil
		}
	}
	pt, err := loadChunkFn(f.v, ref)
	if err != nil {
		return nil, err
	}
	f.cachedIdx = ci
	f.cachedChunk = pt
	if f.Cache != nil {
		f.Cache.Put(ref.ID, pt)
	}
	return pt, nil
}

// Size returns the file's plaintext length in bytes.
func (f *FileReader) Size() int64 { return f.size }

// ModTime returns the file's recorded modification time (zero if unparseable).
func (f *FileReader) ModTime() time.Time { return f.modTime }

// Generation returns the index generation of the record this reader snapshotted
// at open time. A caller that binds a response validator (e.g. an HTTP ETag) to
// its own earlier index snapshot uses this to re-derive the validator from the
// generation whose bytes the reader actually serves, closing the window where a
// same-path overwrite between the two snapshots would label new bytes with the
// old generation's validator (localdav).
func (f *FileReader) Generation() int64 { return f.rec.Generation }

// Close releases the reader's one-chunk cache. It is idempotent.
func (f *FileReader) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.cachedChunk = nil
	f.cachedIdx = -1
	return nil
}

// VerifyChunkPresence stats the on-disk object for every chunk that covers the
// byte range [off, off+length) and whose plaintext the reader's Cache cannot
// serve, returning ErrChunksPending if any such object is absent (and any other
// stat error verbatim). It lets a caller that opened with SkipPresenceCheck
// re-close, for exactly the bytes it is about to serve, the torn-read window a
// stale cached "present" verdict would otherwise leave open: a chunk removed
// after the presence sweep (external sync or GC) surfaces as a clean
// ErrChunksPending here instead of truncating an already-committed 200 in
// http.ServeContent. Chunks resident in Cache are not stat-ed:
// they are served from memory regardless of the on-disk object. A caller wanting
// the whole file re-verified passes off=0, length=Size.
func (f *FileReader) VerifyChunkPresence(off, length int64) error {
	if off < 0 {
		off = 0
	}
	if length <= 0 || off >= f.size {
		return nil
	}
	end := off + length
	if end > f.size {
		end = f.size
	}
	lo := f.chunkIndexFor(off)
	hi := f.chunkIndexFor(end - 1)
	for ci := lo; ci <= hi; ci++ {
		ref := f.rec.Chunks[ci]
		if f.Cache != nil {
			if _, ok := f.Cache.Get(ref.ID); ok {
				continue
			}
		}
		if _, err := os.Stat(f.v.chunkPath(ref.ID)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return ErrChunksPending
			}
			return err
		}
	}
	return nil
}

// ReadRange decrypts length bytes of virtualPath starting at off and writes them
// to w. A negative length reads from off to the end of the file. It is a thin
// wrapper over OpenReaderAt.
func (v *Vault) ReadRange(virtualPath string, off, length int64, w io.Writer) error {
	fr, err := v.OpenReaderAt(virtualPath)
	if err != nil {
		return err
	}
	defer fr.Close()
	if length < 0 {
		length = fr.Size() - off
		if length < 0 {
			length = 0
		}
	}
	_, err = io.Copy(w, io.NewSectionReader(fr, off, length))
	return err
}

// ChunkCache is a byte-bounded LRU of decrypted chunk plaintext keyed by chunk
// ID. A chunk ID is a keyed content hash, so a cached plaintext is correct for
// every file that references it; entries are evicted by byte pressure, never
// invalidated by path. ChunkCache is safe for concurrent use.
type ChunkCache struct {
	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List // front == most-recently-used
	items    map[string]*list.Element
}

type chunkCacheEntry struct {
	id   string
	data []byte
}

// NewChunkCache returns a ChunkCache bounded to maxBytes of decrypted plaintext.
func NewChunkCache(maxBytes int64) *ChunkCache {
	return &ChunkCache{
		maxBytes: maxBytes,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

// Get returns the cached plaintext for id and marks it most-recently-used.
func (c *ChunkCache) Get(id string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[id]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*chunkCacheEntry).data, true
}

// Put inserts plaintext for id, evicting least-recently-used entries until the
// cache is within its byte bound. A chunk larger than maxBytes is never stored.
// The slice is retained (not copied); callers must not mutate cached plaintext.
func (c *ChunkCache) Put(id string, data []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[id]; ok {
		// Content-addressed: the plaintext for a given id is invariant, so keep
		// the existing entry and just refresh its recency.
		c.ll.MoveToFront(el)
		return
	}
	sz := int64(len(data))
	if sz > c.maxBytes {
		return
	}
	el := c.ll.PushFront(&chunkCacheEntry{id: id, data: data})
	c.items[id] = el
	c.curBytes += sz
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*chunkCacheEntry)
		c.ll.Remove(back)
		delete(c.items, ent.id)
		c.curBytes -= int64(len(ent.data))
	}
}
