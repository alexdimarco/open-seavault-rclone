// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCachedIndexReflectsMutationsWithinSession verifies that the in-memory
// index cache stays consistent across operations on one long-lived *Vault:
// puts become visible to subsequent reads, and removes disappear, without
// re-reading the manifests from disk each time.
func TestCachedIndexReflectsMutationsWithinSession(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("f%d.txt", i)
		body := fmt.Sprintf("body-%d", i)
		if _, err := v.PutReader(strings.NewReader(body), name, int64(len(body)), 0o600, time.Now()); err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
		// Immediately visible to a read on the same vault object.
		if _, ok, err := v.FileInfo(name); err != nil || !ok {
			t.Fatalf("FileInfo(%s) after put: ok=%v err=%v", name, ok, err)
		}
	}

	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatalf("expected 5 files, got %d: %#v", len(files), files)
	}

	if err := v.Remove("f2.txt"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.FileInfo("f2.txt"); ok {
		t.Fatal("f2.txt should be gone from the cached view after Remove")
	}

	// A fresh Open (cold cache) must agree with the cached view.
	v2, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	files2, err := v2.Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(files2) != 4 {
		t.Fatalf("fresh open expected 4 files, got %d: %#v", len(files2), files2)
	}
	for p := range files2 {
		if strings.HasSuffix(p, "f2.txt") {
			t.Fatalf("removed file resurfaced on cold open: %s", p)
		}
	}
}

// TestCachedIndexRoundTripStillCorrect ensures the cache does not corrupt
// content: bytes written through one vault object read back identically.
func TestCachedIndexRoundTripStillCorrect(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("seavault-cache-roundtrip-", 1000)
	if _, err := v.PutReader(strings.NewReader(want), "big.txt", int64(len(want)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := v.WriteFileTo("big.txt", &sb); err != nil {
		t.Fatal(err)
	}
	if sb.String() != want {
		t.Fatalf("round-trip mismatch: got %d bytes want %d", sb.Len(), len(want))
	}
}

// TestConcurrentPutsAreSafe exercises the cache mutex: many goroutines putting
// distinct paths on one vault must not race or lose records. Run with -race.
func TestConcurrentPutsAreSafe(t *testing.T) {
	root := t.TempDir() + "/vault"
	const pw = "password"
	createTestVault(t, root, pw)
	v, err := Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}

	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("c/file-%d.txt", i)
			body := fmt.Sprintf("payload-%d", i)
			if _, err := v.PutReader(strings.NewReader(body), name, int64(len(body)), 0o600, time.Now()); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent put failed: %v", err)
	}

	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for p := range files {
		if strings.HasPrefix(p, "content/c/file-") {
			got++
		}
	}
	if got != n {
		t.Fatalf("expected %d concurrent files, got %d", n, got)
	}
}
