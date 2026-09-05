// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pseudoRandomBytes returns n deterministic, well-varied bytes so the
// content-defined chunker splits an input of a few KB into many small chunks
// under testParams {64,128,256}.
func pseudoRandomBytes(n int) []byte {
	b := make([]byte, n)
	x := uint32(0x12345678)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

const readerTestModUnix = 1700000000

// newReaderTestVault creates a fresh vault, stores an 8 KiB file at
// docs/data.bin, and returns the open vault plus the original bytes.
func newReaderTestVault(t *testing.T) (*Vault, []byte) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	const pw = "correct horse battery staple"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	data := pseudoRandomBytes(8192)
	mt := time.Unix(readerTestModUnix, 0).UTC()
	if _, err := v.PutReader(bytes.NewReader(data), "docs/data.bin", int64(len(data)), 0o600, mt); err != nil {
		t.Fatal(err)
	}
	return v, data
}

// withChunkLoadCounter installs a counting wrapper around loadChunkFn (the test
// hook) and returns a pointer to the number of decrypt-loads performed. It is
// restored on cleanup.
func withChunkLoadCounter(t *testing.T) *int {
	t.Helper()
	orig := loadChunkFn
	n := 0
	loadChunkFn = func(v *Vault, ref ChunkRef) ([]byte, error) {
		n++
		return orig(v, ref)
	}
	t.Cleanup(func() { loadChunkFn = orig })
	return &n
}

// coveringChunks reports how many chunks (given prefix-sum offsets, len =
// numChunks+1) overlap the byte range [off, off+length). It mirrors exactly the
// set of chunks ReadAt must decrypt for that range.
func coveringChunks(offsets []int64, off, length int64) int {
	end := off + length
	count := 0
	for i := 0; i+1 < len(offsets); i++ {
		if offsets[i] < end && offsets[i+1] > off {
			count++
		}
	}
	return count
}

func TestFileReaderReadAt(t *testing.T) {
	v, data := newReaderTestVault(t)
	fr, err := v.OpenReaderAt("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Close()

	size := fr.Size()
	if size != int64(len(data)) {
		t.Fatalf("Size = %d, want %d", size, len(data))
	}
	offs := fr.offsets
	if len(offs) < 5 {
		t.Fatalf("expected the file to split into many chunks, got %d", len(offs)-1)
	}
	firstBoundary := offs[1]
	midBoundary := offs[len(offs)/2]

	type row struct {
		name   string
		off    int64
		length int64
	}
	rows := []row{
		{"from-start", 0, 100},
		{"cross-boundary", firstBoundary - 10, 40},
		{"exactly-at-boundary", midBoundary, 50},
		{"to-eof", size - 10, 10},
		{"at-eof", size, 8},
		{"past-eof", size + 16, 8},
		{"zero-length", 100, 0},
		{"whole-file", 0, size},
	}
	if len(rows) == 0 {
		t.Fatal("empty ReadAt table exercises nothing")
	}

	asserted := 0
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			buf := make([]byte, r.length)
			n, err := fr.ReadAt(buf, r.off)

			var wantN int
			var wantErr error
			var wantBytes []byte
			switch {
			case r.off >= size:
				wantN, wantErr = 0, io.EOF
			default:
				avail := size - r.off
				if r.length <= avail {
					wantN, wantErr = int(r.length), nil
				} else {
					wantN, wantErr = int(avail), io.EOF
				}
				wantBytes = data[r.off : r.off+int64(wantN)]
			}
			if n != wantN {
				t.Fatalf("ReadAt(off=%d,len=%d) n=%d, want %d", r.off, r.length, n, wantN)
			}
			if err != wantErr {
				t.Fatalf("ReadAt(off=%d,len=%d) err=%v, want %v", r.off, r.length, err, wantErr)
			}
			if wantN > 0 && !bytes.Equal(buf[:n], wantBytes) {
				t.Fatalf("ReadAt(off=%d,len=%d) returned wrong bytes", r.off, r.length)
			}
		})
		asserted++
	}
	if asserted != len(rows) {
		t.Fatalf("asserted %d rows, table has %d", asserted, len(rows))
	}
}

func TestFileReaderChunkLoadCountEqualsCoveringChunks(t *testing.T) {
	v, data := newReaderTestVault(t)
	fr, err := v.OpenReaderAt("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Close()

	offs := fr.offsets
	if len(offs) < 8 {
		t.Fatalf("need many chunks for this test, got %d", len(offs)-1)
	}
	// A mid-file range that starts inside chunk 2 and ends on a later boundary.
	off := offs[2] + 5
	end := offs[len(offs)-3]
	length := end - off
	if length <= 0 {
		t.Fatalf("bad range: off=%d end=%d", off, end)
	}
	want := coveringChunks(offs, off, length)
	if want < 2 {
		t.Fatalf("test must span multiple chunks, spans %d", want)
	}

	cnt := withChunkLoadCounter(t)
	buf := make([]byte, length)
	n, err := fr.ReadAt(buf, off)
	if err != nil {
		t.Fatalf("ReadAt err = %v", err)
	}
	if int64(n) != length {
		t.Fatalf("short read: n=%d want %d", n, length)
	}
	if !bytes.Equal(buf, data[off:off+length]) {
		t.Fatal("ReadAt returned wrong bytes for mid-file range")
	}
	if *cnt != want {
		t.Fatalf("decrypted %d chunks, want exactly the %d covering chunks", *cnt, want)
	}
}

func TestFileReaderReadAtLoadsNoChunksOutsideRange(t *testing.T) {
	v, _ := newReaderTestVault(t)
	fr, err := v.OpenReaderAt("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Close()

	// Reading a single byte in the middle must decrypt exactly one chunk.
	offs := fr.offsets
	mid := offs[len(offs)/2] + 1
	cnt := withChunkLoadCounter(t)
	buf := make([]byte, 1)
	if _, err := fr.ReadAt(buf, mid); err != nil {
		t.Fatal(err)
	}
	if *cnt != 1 {
		t.Fatalf("single-byte read decrypted %d chunks, want 1", *cnt)
	}
}

func TestFileReaderErrChunksPending(t *testing.T) {
	v, _ := newReaderTestVault(t)
	rec, ok, err := v.FileInfo("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(rec.Chunks) == 0 {
		t.Fatalf("record not found or has no chunks: ok=%v chunks=%d", ok, len(rec.Chunks))
	}
	victim := v.chunkPath(rec.Chunks[0].ID)
	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}

	_, err = v.OpenReaderAt("docs/data.bin")
	if err == nil {
		t.Fatal("OpenReaderAt should fail when a chunk file is absent")
	}
	if !errors.Is(err, ErrChunksPending) {
		t.Fatalf("want ErrChunksPending, got %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ErrChunksPending must wrap os.ErrNotExist, got %v", err)
	}
}

func TestFileReaderSkipPresenceCheck(t *testing.T) {
	v, _ := newReaderTestVault(t)
	rec, ok, err := v.FileInfo("docs/data.bin")
	if err != nil || !ok {
		t.Fatalf("FileInfo: ok=%v err=%v", ok, err)
	}
	victim := v.chunkPath(rec.Chunks[0].ID)
	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}

	fr, err := v.OpenReaderAtWithOptions("docs/data.bin", OpenReaderAtOptions{SkipPresenceCheck: true})
	if err != nil {
		t.Fatalf("SkipPresenceCheck should open despite the missing chunk, got %v", err)
	}
	defer fr.Close()

	// The first chunk backs the start of the file; reading it must now fail.
	buf := make([]byte, fr.offsets[1])
	if _, rerr := fr.ReadAt(buf, 0); rerr == nil {
		t.Fatal("ReadAt over a removed chunk should fail")
	}
}

func TestFileReaderModTimeAndClose(t *testing.T) {
	v, data := newReaderTestVault(t)
	fr, err := v.OpenReaderAt("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(readerTestModUnix, 0).UTC()
	if !fr.ModTime().Equal(want) {
		t.Fatalf("ModTime = %v, want %v", fr.ModTime(), want)
	}
	if fr.Size() != int64(len(data)) {
		t.Fatalf("Size = %d, want %d", fr.Size(), len(data))
	}
	if err := fr.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if _, err := fr.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("ReadAt after Close should fail")
	}
}

func TestReadRange(t *testing.T) {
	v, data := newReaderTestVault(t)
	var buf bytes.Buffer
	off, length := int64(200), int64(1500)
	if err := v.ReadRange("docs/data.bin", off, length, &buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), data[off:off+length]) {
		t.Fatalf("ReadRange returned %d bytes, want the range [%d,%d)", buf.Len(), off, off+length)
	}
}

func TestChunkCacheHitYieldsZeroLoads(t *testing.T) {
	v, data := newReaderTestVault(t)
	cache := NewChunkCache(1 << 20)

	fr1, err := v.OpenReaderAt("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	fr1.Cache = cache
	buf1 := make([]byte, fr1.Size())
	if _, err := fr1.ReadAt(buf1, 0); err != nil {
		t.Fatalf("warm-up read: %v", err)
	}
	if !bytes.Equal(buf1, data) {
		t.Fatal("warm-up read returned wrong bytes")
	}
	fr1.Close()

	fr2, err := v.OpenReaderAt("docs/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	fr2.Cache = cache
	defer fr2.Close()

	cnt := withChunkLoadCounter(t)
	buf2 := make([]byte, fr2.Size())
	if _, err := fr2.ReadAt(buf2, 0); err != nil {
		t.Fatalf("warm-cache read: %v", err)
	}
	if !bytes.Equal(buf2, data) {
		t.Fatal("warm-cache read returned wrong bytes")
	}
	if *cnt != 0 {
		t.Fatalf("warm-cache read decrypted %d chunks, want 0", *cnt)
	}
}

func TestChunkCacheEvictsByBytes(t *testing.T) {
	// Pure insertion-order eviction: capacity holds two 100-byte chunks.
	c := NewChunkCache(250)
	c.Put("a", make([]byte, 100))
	c.Put("b", make([]byte, 100))
	c.Put("cc", make([]byte, 100)) // 300 > 250 -> evict LRU "a"
	if _, ok := c.Get("a"); ok {
		t.Fatal("a should have been evicted by byte pressure")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("b should still be cached")
	}
	if _, ok := c.Get("cc"); !ok {
		t.Fatal("cc should still be cached")
	}

	// Recency promotion: a Get moves an entry to most-recently-used.
	c2 := NewChunkCache(250)
	c2.Put("a", make([]byte, 100))
	c2.Put("b", make([]byte, 100))
	if _, ok := c2.Get("a"); !ok { // promote a; b is now LRU
		t.Fatal("a should be present before eviction")
	}
	c2.Put("cc", make([]byte, 100)) // evict LRU "b"
	if _, ok := c2.Get("b"); ok {
		t.Fatal("b was least-recently-used and should be evicted")
	}
	if _, ok := c2.Get("a"); !ok {
		t.Fatal("a was promoted and should survive")
	}
}

func TestChunkCacheOversizeNotStored(t *testing.T) {
	c := NewChunkCache(50)
	c.Put("big", make([]byte, 100)) // larger than the whole cache
	if _, ok := c.Get("big"); ok {
		t.Fatal("a chunk larger than maxBytes must never be stored")
	}
}
