// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// TestReloadRaces2WorldReadableKeyWarningOnRenewal (reload-races-2, I-T2): a
// renewal that lands a group/world-readable key must surface the chmod-600
// warning on the HOT RELOAD, not only at cold start. Before the fix, reload()
// discarded info.Warnings, so a renewed 0644 key was swapped in silently.
func TestReloadRaces2WorldReadableKeyWarningOnRenewal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX key-permission warning is not emitted on Windows")
	}
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.crt")
	keyPath := filepath.Join(dir, "leaf.key")

	mtime := time.Now()
	rewrite := func(certPEM, keyPEM []byte, keyPerm os.FileMode) {
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, keyPerm); err != nil {
			t.Fatal(err)
		}
		// WriteFile leaves an existing file's mode unchanged; force it.
		if err := os.Chmod(keyPath, keyPerm); err != nil {
			t.Fatal(err)
		}
		mtime = mtime.Add(time.Minute)
		if err := os.Chtimes(certPath, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(keyPath, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}

	// leaf1: valid, key mode 0600 → no warning at load.
	cert1, key1, leaf1 := ca.issue(t, leafSpec{cn: "renew.example"})
	rewrite(cert1, key1, 0o600)

	resolved, err := Resolve(Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: PurposeServe, Cfg: appconfig.Default()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	rec := &recorder{}
	servingDir := t.TempDir()
	rl := resolved.Reloader(ReloaderOptions{Interval: 15 * time.Millisecond, ServingDir: servingDir, Logf: rec.logf})
	if rl == nil {
		t.Fatal("Reloader must be non-nil for a TLS-on resolution")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rl.Run(ctx)

	// Wait until leaf1 is loaded (serving.json written) and confirm the 0600 key
	// produced no chmod warning.
	fp1 := fingerprintOf(leaf1)
	if !waitFor(2*time.Second, func() bool {
		s, e := ReadServing(servingDir)
		return e == nil && s.Fingerprint == fp1
	}) {
		t.Fatal("initial serving.json for leaf1 was not written")
	}
	if warnContains(rec.snapshot(), "chmod 600") {
		t.Fatalf("leaf1 with a 0600 key must not warn about permissions; got %v", rec.snapshot())
	}

	// Renew: a valid leaf2 whose key lands group/world-readable (0644).
	cert2, key2, leaf2 := ca.issue(t, leafSpec{cn: "renew.example"})
	rewrite(cert2, key2, 0o644)
	fp2 := fingerprintOf(leaf2)

	// The renewed pair validates and is swapped in ...
	if !waitFor(3*time.Second, func() bool {
		s, e := ReadServing(servingDir)
		return e == nil && s.Fingerprint == fp2
	}) {
		t.Fatal("renewed leaf2 was not swapped in")
	}
	// ... AND the chmod-600 warning is surfaced on the hot reload.
	if !waitFor(2*time.Second, func() bool { return warnContains(rec.snapshot(), "chmod 600") }) {
		t.Fatalf("a renewal landing a world-readable key must log the chmod-600 warning; got %v", rec.snapshot())
	}
	assertNoKeyMaterial(t, strings.Join(rec.snapshot(), "\n"), key2)
}

// TestReloadRaces3C6GateUsesLoadedBytes (reload-races-3, C6): the no-downgrade
// gate must be evaluated on the leaf actually LOADED and served, not on the
// separately-read validate bytes. A fault-injection hook swaps an expired pair
// onto disk between the validate read and the load read; the reloader must serve
// the LOADED bytes through the gate and therefore refuse the expired leaf,
// keeping the still-valid serving leaf. Before the fix (gate on the validate
// read) the reloader would store and serve the expired leaf.
func TestReloadRaces3C6GateUsesLoadedBytes(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.crt")
	keyPath := filepath.Join(dir, "leaf.key")

	// Serving: a valid leaf1.
	cert1, key1, leaf1 := ca.issue(t, leafSpec{cn: "toctou.example"})
	if err := os.WriteFile(certPath, cert1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key1, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: PurposeServe, Cfg: appconfig.Default()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	rec := &recorder{}
	rl := resolved.Reloader(ReloaderOptions{ServingDir: t.TempDir(), Logf: rec.logf})
	if rl == nil {
		t.Fatal("Reloader must be non-nil")
	}

	// The candidate visible to the validate read: an IN-WINDOW leaf2.
	cert2, key2, _ := ca.issue(t, leafSpec{cn: "toctou.example"})
	if err := os.WriteFile(certPath, cert2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key2, 0o600); err != nil {
		t.Fatal(err)
	}

	// Between the validate read and the load read, swap in an EXPIRED pair.
	certExp, keyExp, expLeaf := ca.issue(t, leafSpec{
		cn:        "toctou.example",
		notBefore: time.Now().AddDate(-1, 0, 0),
		notAfter:  time.Now().Add(-time.Hour),
	})
	var once sync.Once
	reloadTOCTOUHook = func() {
		once.Do(func() {
			_ = os.WriteFile(certPath, certExp, 0o600)
			_ = os.WriteFile(keyPath, keyExp, 0o600)
		})
	}
	t.Cleanup(func() { reloadTOCTOUHook = nil })

	rl.reload() // synchronous: validate reads leaf2 (valid); load reads leaf3 (expired)

	got := rl.holder.leaf()
	if got == nil {
		t.Fatal("no serving leaf after reload")
	}
	if got.SerialNumber.Cmp(expLeaf.SerialNumber) == 0 {
		t.Fatal("C6 (reload-races-3): the reloader served the EXPIRED leaf that load actually read; the downgrade gate was evaluated on the earlier validate bytes, not on the loaded/served bytes")
	}
	if got.SerialNumber.Cmp(leaf1.SerialNumber) != 0 {
		t.Fatalf("served leaf serial = %v, want the kept valid leaf1 %v", got.SerialNumber, leaf1.SerialNumber)
	}
}
