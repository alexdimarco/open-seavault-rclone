// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingDavWriter signals on its first body Write and parks there until it is
// released, pinning a streaming /dav GET inside the localdav stream semaphore's
// critical section so a second concurrent GET's contention is observable.
type blockingDavWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingDavWriter) Write(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.started)
		<-b.release
	})
	return b.ResponseRecorder.Write(p)
}

func davGetReq(t *testing.T, s *Server, virtualPath string) *http.Request {
	t.Helper()
	urlPath := "/dav/" + s.davToken + "/" + strings.TrimPrefix(virtualPath, "/")
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	// The embedded localdav server enforces a loopback Host allowlist; drive it
	// under a loopback Host, with a logged-in session cookie, as a GUI client
	// would. /dav authenticates with the davToken (design D4.1).
	req.Host = "127.0.0.1"
	req.AddCookie(newTestSession(s, true))
	return req
}

// TestWebDAVStreamSemaphoreIsGlobalAcrossRequests is the OA-1 tombstone.
//
// handleWebDAV builds a fresh localdav.Server on every /dav request. The
// streaming-GET semaphore that is supposed to cap concurrent decrypt streams
// (bounding read-path memory, design §12 "proven by construction") is a field
// on that Server. If each throwaway Server mints its own semaphore, the cap is
// per-request, not global: N concurrent authenticated Range GETs each get a
// fresh full budget and decrypt chunks simultaneously.
//
// The test pins the GUI's shared stream budget to a single slot, parks one
// authenticated /dav GET inside the streaming body, and asserts a second
// concurrent /dav GET cannot enter the streaming body until the first releases.
// Before the fix (handleWebDAV does not thread the shared semaphore into the
// per-request localdav.Server) the second GET streams immediately and the test
// fails.
func TestWebDAVStreamSemaphoreIsGlobalAcrossRequests(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	body := bytes.Repeat([]byte("x"), 4096)
	if rr := davRequest(t, s, http.MethodPut, "docs/big.bin", bytes.NewReader(body), nil); rr.Code != http.StatusCreated {
		t.Fatalf("PUT setup: code=%d want 201 (%s)", rr.Code, rr.Body.String())
	}

	// Pin the GLOBAL stream budget to one slot. handleWebDAV must hand this one
	// semaphore to every per-request localdav.Server; if it mints a fresh
	// per-request semaphore instead (OA-1) the cap is not global.
	s.mu.Lock()
	s.streamSem = make(chan struct{}, 1)
	s.mu.Unlock()

	first := &blockingDavWriter{
		ResponseRecorder: httptest.NewRecorder(),
		started:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		s.ServeHTTP(first, davGetReq(t, s, "docs/big.bin"))
	}()

	select {
	case <-first.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first /dav GET never reached the streaming body")
	}
	// The first GET now holds the single global stream slot, parked in Write.

	second := &blockingDavWriter{
		ResponseRecorder: httptest.NewRecorder(),
		started:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		s.ServeHTTP(second, davGetReq(t, s, "docs/big.bin"))
	}()

	select {
	case <-second.started:
		close(first.release)
		close(second.release)
		<-firstDone
		<-secondDone
		t.Fatal("second concurrent /dav GET entered the streaming body while the single global stream slot was held: the MaxStreams cap is per-request, not global (OA-1)")
	case <-time.After(750 * time.Millisecond):
		// Correct: the second GET is blocked on the shared semaphore.
	}

	// Release the first; the freed slot must let the second proceed, proving the
	// cap gates rather than deadlocks.
	close(first.release)
	select {
	case <-second.started:
	case <-time.After(2 * time.Second):
		close(second.release)
		t.Fatal("second /dav GET never acquired the freed global stream slot")
	}
	close(second.release)
	<-firstDone
	<-secondDone
}
