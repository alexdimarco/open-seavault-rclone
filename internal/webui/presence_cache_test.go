// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// hideChunks renames the open vault's chunk-object directory aside so the
// presence sweep sees every chunk missing (a torn/not-yet-synced file). The
// returned restore func moves them back. It returns the chunk directory path so
// callers can key off it.
func hideChunks(t *testing.T, s *Server) (restore func()) {
	t.Helper()
	chunks := filepath.Join(s.vault.MetaRoot, "objects", "chunks")
	aside := chunks + ".aside"
	if err := os.Rename(chunks, aside); err != nil {
		t.Fatalf("hide chunks: %v", err)
	}
	restored := false
	return func() {
		if restored {
			return
		}
		restored = true
		if err := os.Rename(aside, chunks); err != nil {
			t.Fatalf("restore chunks: %v", err)
		}
	}
}

// TestWebDAVPresenceSweepBoundAcrossRequests is the IC-1 tombstone (presence
// half; the streaming-semaphore half is OA-1).
//
// handleWebDAV builds a fresh localdav.Server on every /dav request. The
// (path, generation) presence-sweep cache that lets a scrubbing client "stat
// once per 10 s window" is a field on that Server. If each
// throwaway Server mints its own presence cache, the sweep result binds
// NOTHING across requests: every Range GET re-runs the full per-chunk stat
// sweep and the optimization is void for /dav.
//
// The test drives the presence result across two /dav requests. A first Range
// GET on a torn file (chunks hidden) records a PENDING sweep result and returns
// 409. The chunks then reappear. Within the 10 s presence window a second /dav
// GET must be answered from the SHARED cached pending result (409) — proving
// the sweep bound across requests. Before the fix (per-request localdav.Server
// with a private presence cache) the second GET re-sweeps, sees the chunks now
// present, and returns 206, so the test fails.
func TestWebDAVPresenceSweepBoundAcrossRequests(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	// A non-empty file so it owns at least one chunk object on disk.
	body := bytes.Repeat([]byte("y"), 4096)
	if rr := davRequest(t, s, http.MethodPut, "docs/pending.bin", bytes.NewReader(body), nil); rr.Code != http.StatusCreated {
		t.Fatalf("PUT setup: code=%d want 201 (%s)", rr.Code, rr.Body.String())
	}

	restore := hideChunks(t, s)

	// First /dav Range GET: the sweep finds the chunk objects missing -> 409,
	// and the pending result is recorded in the presence cache keyed by
	// (path, generation).
	first := davRequest(t, s, http.MethodGet, "docs/pending.bin", nil, map[string]string{"Range": "bytes=0-3"})
	if first.Code != http.StatusConflict {
		restore()
		t.Fatalf("first Range GET on torn file: code=%d want 409 (%s)", first.Code, first.Body.String())
	}

	// Chunks reappear (sync completed). Within the presence window the second
	// /dav GET must be answered from the SHARED cached pending sweep.
	restore()
	second := davRequest(t, s, http.MethodGet, "docs/pending.bin", nil, map[string]string{"Range": "bytes=0-3"})
	if second.Code != http.StatusConflict {
		t.Fatalf("second /dav GET within the presence window: code=%d want 409 (served from the cached pending sweep). A 206 means the per-request localdav.Server minted its own presence cache and the sweep did not bind across requests (IC-1)", second.Code)
	}
}

// TestWebDAVPresenceCacheResetOnVaultReopen guards the vault-scoping that makes
// the shared presence cache safe: sharing presence results across /dav requests
// must NOT leak a previous vault view's cached sweep into a freshly (re)opened
// vault. Closing and reopening the SAME vault preserves each file's generation,
// so the presence key is identical; a stale pending entry from the old view,
// still inside its 10 s window, would otherwise answer 409 for a file that is
// now fully present. The GUI's shared presence cache is scoped to the open
// vault and resets when the vault pointer changes.
func TestWebDAVPresenceCacheResetOnVaultReopen(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := initOpenTestVault(t, s)

	body := bytes.Repeat([]byte("z"), 4096)
	if rr := davRequest(t, s, http.MethodPut, "docs/reopen.bin", bytes.NewReader(body), nil); rr.Code != http.StatusCreated {
		t.Fatalf("PUT setup: code=%d want 201 (%s)", rr.Code, rr.Body.String())
	}

	restore := hideChunks(t, s)
	// Cache a pending presence result for (path, generation) under this vault.
	if rr := davRequest(t, s, http.MethodGet, "docs/reopen.bin", nil, map[string]string{"Range": "bytes=0-3"}); rr.Code != http.StatusConflict {
		restore()
		t.Fatalf("GET on torn file: code=%d want 409 (%s)", rr.Code, rr.Body.String())
	}
	restore()

	// Close and reopen the SAME vault. The reopened index preserves the file's
	// generation, so the presence key is identical to the cached pending entry.
	if rr := postJSON(t, s, "/api/close", map[string]any{}); rr.Code != http.StatusOK {
		t.Fatalf("close: code=%d (%s)", rr.Code, rr.Body.String())
	}
	if rr := postJSON(t, s, "/api/open", map[string]any{"vaultPath": vaultPath, "password": "passphrase"}); rr.Code != http.StatusOK {
		t.Fatalf("reopen: code=%d (%s)", rr.Code, rr.Body.String())
	}

	// The fresh vault view must sweep anew and serve the present file.
	got := davRequest(t, s, http.MethodGet, "docs/reopen.bin", nil, map[string]string{"Range": "bytes=0-3"})
	if got.Code != http.StatusPartialContent {
		t.Fatalf("GET after vault reopen: code=%d want 206. A 409 means the shared presence cache served a stale pending sweep from the previous vault view (presence cache not reset on vault change)", got.Code)
	}
}

// TestWebDAVRepeatedRangeGetsAmortizeStatSweep is the
// tombstone: the PRESENT-path half of the shared presence-sweep cache on the
// GUI /dav leg (the pending-path half is TestWebDAVPresenceSweepBoundAcross-
// Requests above).
//
// handleWebDAV builds a fresh localdav.Server per /dav request. the design
// step 4 promises a scrubbing / media-preview client (the T5 workload) issuing
// many Range GETs against a fully-synced file "pays the stat sweep once": the
// first GET runs the whole-file per-chunk os.Stat sweep and records a PRESENT
// verdict in the (path, generation) presence cache; a later GET within the 10 s
// window skips that whole-file sweep and only re-verifies, for the bytes it is
// about to serve, the chunks the shared chunk cache cannot already supply
// (IC-2). If the presence cache were minted per request every
// Range GET would re-run the full sweep and the amortization would be void
// for /dav -- exactly the file-manager media-preview workload.
//
// The stat-counter seam lives in the localdav package and is out of reach from
// a webui test, so the amortization is observed through handleWebDAV directly:
// warm the shared chunk + presence caches with a first Range GET, then make
// every chunk object VANISH from disk. A second Range GET within the window
// must still return 206 -- the present-path skips the whole-file sweep and
// serves the requested bytes from the shared chunk cache, so nothing on disk is
// stat-ed. Before IC-1 (per-request presence cache) the second GET is a cache
// miss, re-runs the full sweep, finds the chunk objects gone, and returns 409.
func TestWebDAVRepeatedRangeGetsAmortizeStatSweep(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	// A single-chunk file (20 KiB is well under the 2 MiB min chunk size), so
	// the requested Range and the whole file share one chunk object.
	body := bytes.Repeat([]byte("scrub"), 4096)
	if rr := davRequest(t, s, http.MethodPut, "media/clip.bin", bytes.NewReader(body), nil); rr.Code != http.StatusCreated {
		t.Fatalf("PUT setup: code=%d want 201 (%s)", rr.Code, rr.Body.String())
	}

	// First Range GET: runs the whole-file stat sweep, records a PRESENT sweep
	// in the shared (path, generation) presence cache, and warms the shared
	// chunk cache for the bytes it serves.
	first := davRequest(t, s, http.MethodGet, "media/clip.bin", nil, map[string]string{"Range": "bytes=0-15"})
	if first.Code != http.StatusPartialContent {
		t.Fatalf("first Range GET: code=%d want 206 (%s)", first.Code, first.Body.String())
	}

	// Every chunk object vanishes from disk. A shared presence cache lets the
	// second GET take the fast present-path: it skips the whole-file sweep and
	// serves the requested bytes from the shared chunk cache warmed above, so
	// VerifyChunkPresence stat-checks nothing on disk.
	restore := hideChunks(t, s)
	defer restore()

	second := davRequest(t, s, http.MethodGet, "media/clip.bin", nil, map[string]string{"Range": "bytes=0-15"})
	if second.Code != http.StatusPartialContent {
		t.Fatalf("second Range GET within the presence window: code=%d want 206 (served without re-running the whole-file stat sweep). A 409 means the per-request localdav.Server minted its own presence cache, so every Range GET re-pays the full stat sweep and the amortization is void for /dav", second.Code)
	}
	if got := second.Body.Len(); got != 16 {
		t.Fatalf("second Range GET served %d bytes, want 16", got)
	}
}
