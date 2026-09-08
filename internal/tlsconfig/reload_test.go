// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// recorder is a thread-safe capture of the reloader's warning lines.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lines)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// dialLeaf performs a real TLS handshake against addr, verifying the server
// certificate against pool, and returns the served leaf.
func dialLeaf(addr, serverName string, pool *x509.CertPool) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	return state.PeerCertificates[0], nil
}

func serialOf(addr, serverName string, pool *x509.CertPool) *big.Int {
	leaf, err := dialLeaf(addr, serverName, pool)
	if err != nil || leaf == nil {
		return nil
	}
	return leaf.SerialNumber
}

// installPairFile atomically replaces path with data and stamps it with mtime
// (temp file + Chtimes + rename), so the poll-based Reloader never reads a torn
// (empty/partial) file and the path's mtime transitions exactly once. It mirrors
// production atomicWrite; a renewal driven through it is a single coherent
// change, not a race of separate write-then-chtime transitions.
func installPairFile(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-reload-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmpName, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		t.Fatal(err)
	}
}

// coherentRewriter returns a rewrite(cert, key) that installs a renewal as ONE
// change the poll-based Reloader can observe. It writes both files atomically
// (no torn read) and advances ONLY the key's mtime, holding the cert's mtime
// fixed: because the Reloader reads BOTH files' content whenever EITHER mtime
// changes, a single advancing mtime with both new contents already in place is a
// single, coherent pair-transition. Two separately-advancing mtimes (the old
// os.WriteFile+os.Chtimes pattern) let a poll land between them and count a
// rejected renewal twice — the pre-existing flake in "exactly one warning".
func coherentRewriter(t *testing.T, certPath, keyPath string) func(certPEM, keyPEM []byte) {
	certMtime := time.Now()
	keyMtime := certMtime
	return func(certPEM, keyPEM []byte) {
		installPairFile(t, certPath, certPEM, certMtime) // fixed mtime: no standalone transition
		keyMtime = keyMtime.Add(time.Minute)
		installPairFile(t, keyPath, keyPEM, keyMtime) // the one advancing mtime drives detection
	}
}

// TestR1HotReload is the §2 hot-reload / I-T3 / C6 proof against a real listener:
// a client with the test CA connects; rewriting the pair swaps the served leaf
// within the injected poll; a mismatched pair keeps the old leaf and logs one
// warning; and an EXPIRED (or not-yet-valid) renewed pair never downgrades a
// still-valid serving leaf (C6).
func TestR1HotReload(t *testing.T) {
	ca := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	const name = "reload.test.example"

	watchDir := t.TempDir()
	certPath := filepath.Join(watchDir, "leaf.crt")
	keyPath := filepath.Join(watchDir, "leaf.key")

	// Each renewal is installed as a single coherent change (atomic writes; only
	// the key's mtime advances) so the stat-poll detects it exactly once and never
	// reads a torn pair — see coherentRewriter.
	rewrite := coherentRewriter(t, certPath, keyPath)

	// leaf1: the initial serving pair.
	cert1, key1, leaf1 := ca.issue(t, leafSpec{cn: name})
	rewrite(cert1, key1)

	resolved, err := Resolve(Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: PurposeServe, Cfg: appconfig.Default()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	rec := &recorder{}
	rl := resolved.Reloader(ReloaderOptions{Interval: 15 * time.Millisecond, ServingDir: t.TempDir(), Logf: rec.logf})
	if rl == nil {
		t.Fatal("Reloader must be non-nil for a TLS-on resolution")
	}

	// Real TLS listener serving from the resolved (hot-swappable) config.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })}
	go srv.Serve(tls.NewListener(ln, resolved.TLS))
	defer srv.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rl.Run(ctx)

	// Initially, the client sees leaf1.
	if got := serialOf(addr, name, pool); got == nil || got.Cmp(leaf1.SerialNumber) != 0 {
		t.Fatalf("initial served leaf = %v, want leaf1 serial %v", got, leaf1.SerialNumber)
	}

	// Rewrite with leaf2 (same CA, same name, new serial) → served within the poll.
	cert2, key2, leaf2 := ca.issue(t, leafSpec{cn: name})
	rewrite(cert2, key2)
	if !waitFor(3*time.Second, func() bool {
		got := serialOf(addr, name, pool)
		return got != nil && got.Cmp(leaf2.SerialNumber) == 0
	}) {
		t.Fatalf("reloader did not serve leaf2 (serial %v) within the poll", leaf2.SerialNumber)
	}

	// A mismatched pair: the old leaf (leaf2) is kept and exactly one warning logged.
	before := rec.count()
	certBad, _, _ := ca.issue(t, leafSpec{cn: name}) // a leaf whose key we discard
	wrongKey := keyToPEM(t, genKey(t))
	rewrite(certBad, wrongKey)
	if !waitFor(2*time.Second, func() bool { return rec.count() == before+1 }) {
		t.Fatalf("mismatched reload must log exactly one warning; got %d new: %v", rec.count()-before, rec.snapshot())
	}
	// Give the poll a few more cycles to prove it does NOT keep re-warning or swap.
	time.Sleep(120 * time.Millisecond)
	if n := rec.count() - before; n != 1 {
		t.Fatalf("mismatched reload logged %d warnings, want exactly 1: %v", n, rec.snapshot())
	}
	if got := serialOf(addr, name, pool); got == nil || got.Cmp(leaf2.SerialNumber) != 0 {
		t.Fatalf("after a mismatched reload the served leaf = %v, want the kept leaf2 %v", got, leaf2.SerialNumber)
	}

	// An EXPIRED renewed pair while leaf2 is still valid → no downgrade (C6).
	before = rec.count()
	certExp, keyExp, _ := ca.issue(t, leafSpec{cn: name, notBefore: time.Now().AddDate(-1, 0, 0), notAfter: time.Now().Add(-time.Hour)})
	rewrite(certExp, keyExp)
	if !waitFor(2*time.Second, func() bool { return rec.count() == before+1 }) {
		t.Fatalf("expired-candidate reload must log one warning; got %d new: %v", rec.count()-before, rec.snapshot())
	}
	time.Sleep(120 * time.Millisecond)
	if got := serialOf(addr, name, pool); got == nil || got.Cmp(leaf2.SerialNumber) != 0 {
		t.Fatalf("C6 violated: after an expired-candidate reload the served leaf = %v, want the kept valid leaf2 %v", got, leaf2.SerialNumber)
	}

	// A NOT-YET-VALID renewed pair while leaf2 is still valid → no downgrade (C6).
	before = rec.count()
	certFut, keyFut, _ := ca.issue(t, leafSpec{cn: name, notBefore: time.Now().Add(48 * time.Hour), notAfter: time.Now().AddDate(1, 0, 0)})
	rewrite(certFut, keyFut)
	if !waitFor(2*time.Second, func() bool { return rec.count() == before+1 }) {
		t.Fatalf("not-yet-valid-candidate reload must log one warning; got %d new: %v", rec.count()-before, rec.snapshot())
	}
	time.Sleep(120 * time.Millisecond)
	if got := serialOf(addr, name, pool); got == nil || got.Cmp(leaf2.SerialNumber) != 0 {
		t.Fatalf("C6 violated: after a not-yet-valid reload the served leaf = %v, want leaf2 %v", got, leaf2.SerialNumber)
	}

	// A VALID renewed pair (leaf3) is still accepted after the refusals — the
	// reloader is not wedged by the earlier rejects.
	cert3, key3, leaf3 := ca.issue(t, leafSpec{cn: name})
	rewrite(cert3, key3)
	if !waitFor(3*time.Second, func() bool {
		got := serialOf(addr, name, pool)
		return got != nil && got.Cmp(leaf3.SerialNumber) == 0
	}) {
		t.Fatalf("a valid renewal after rejects was not served (leaf3 serial %v)", leaf3.SerialNumber)
	}
}

// TestR3ServingHeartbeatAndStatus is the C11 staleness proof: serving.json is
// written on load and on reload with the serving fingerprint and notAfter; a leaf
// with < 14 days left logs the daily warning; and the status helper reports
// days-left and staleness from the file.
func TestR3ServingHeartbeatAndStatus(t *testing.T) {
	ca := newTestCA(t)

	t.Run("serving.json on load and reload", func(t *testing.T) {
		watchDir := t.TempDir()
		certPath := filepath.Join(watchDir, "leaf.crt")
		keyPath := filepath.Join(watchDir, "leaf.key")
		rewrite := coherentRewriter(t, certPath, keyPath)

		cert1, key1, leaf1 := ca.issue(t, leafSpec{cn: "hb.example"})
		rewrite(cert1, key1)
		resolved, err := Resolve(Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: PurposeServe, Cfg: appconfig.Default()})
		if err != nil {
			t.Fatal(err)
		}
		servingDir := t.TempDir()
		rl := resolved.Reloader(ReloaderOptions{Interval: 15 * time.Millisecond, ServingDir: servingDir, Logf: func(string, ...any) {}})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go rl.Run(ctx)

		fp1 := fingerprintOf(leaf1)
		if !waitFor(2*time.Second, func() bool {
			s, err := ReadServing(servingDir)
			return err == nil && s.Fingerprint == fp1
		}) {
			s, _ := ReadServing(servingDir)
			t.Fatalf("serving.json not written on load: got %+v want fingerprint %s", s, fp1)
		}
		s, err := ReadServing(servingDir)
		if err != nil {
			t.Fatal(err)
		}
		if !s.NotAfter.Equal(leaf1.NotAfter) {
			t.Fatalf("serving.json notAfter = %v, want %v", s.NotAfter, leaf1.NotAfter)
		}
		if len(s.Names) == 0 || s.Names[0] != "hb.example" {
			t.Fatalf("serving.json names = %v, want [hb.example ...]", s.Names)
		}
		if s.UpdatedAt.IsZero() {
			t.Fatal("serving.json updatedAt must be set")
		}

		// Reload → serving.json carries the new leaf's fingerprint.
		cert2, key2, leaf2 := ca.issue(t, leafSpec{cn: "hb.example"})
		fp2 := fingerprintOf(leaf2)
		rewrite(cert2, key2)
		if !waitFor(3*time.Second, func() bool {
			s, err := ReadServing(servingDir)
			return err == nil && s.Fingerprint == fp2
		}) {
			s, _ := ReadServing(servingDir)
			t.Fatalf("serving.json not updated on reload: got fingerprint %s want %s", s.Fingerprint, fp2)
		}
	})

	t.Run("< 14-day warning on load", func(t *testing.T) {
		watchDir := t.TempDir()
		certPEM, keyPEM, _ := ca.issue(t, leafSpec{cn: "soon.example", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(10 * 24 * time.Hour)})
		certPath, keyPath := writePair(t, watchDir, certPEM, keyPEM)
		resolved, err := Resolve(Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: PurposeServe, Cfg: appconfig.Default()})
		if err != nil {
			t.Fatal(err)
		}
		rec := &recorder{}
		rl := resolved.Reloader(ReloaderOptions{Interval: 15 * time.Millisecond, ServingDir: t.TempDir(), Logf: rec.logf})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go rl.Run(ctx)

		if !waitFor(2*time.Second, func() bool { return warnContains(rec.snapshot(), "days left") }) {
			t.Fatalf("a leaf with < 14 days left must log a days-left warning; got %v", rec.snapshot())
		}
		assertNoKeyMaterial(t, strings.Join(rec.snapshot(), "\n"), keyPEM)
	})

	t.Run("status helper reports days-left and staleness", func(t *testing.T) {
		now := time.Now()
		type row struct {
			name        string
			updatedAt   time.Time
			notAfter    time.Time
			present     bool
			wantPresent bool
			wantStale   bool
			wantDays    int
		}
		rows := []row{
			{name: "fresh", updatedAt: now, notAfter: now.Add(30 * 24 * time.Hour), present: true, wantPresent: true, wantStale: false, wantDays: 30},
			{name: "one-day-old-not-stale", updatedAt: now.Add(-24 * time.Hour), notAfter: now.Add(20 * 24 * time.Hour), present: true, wantPresent: true, wantStale: false, wantDays: 20},
			{name: "three-days-stale", updatedAt: now.Add(-3 * 24 * time.Hour), notAfter: now.Add(10 * 24 * time.Hour), present: true, wantPresent: true, wantStale: true, wantDays: 10},
			{name: "absent", present: false, wantPresent: false},
		}
		if len(rows) == 0 {
			t.Fatal("status table is empty")
		}
		for _, r := range rows {
			t.Run(r.name, func(t *testing.T) {
				dir := t.TempDir()
				if r.present {
					s := Serving{Fingerprint: "abc123", Names: []string{"status.example"}, NotAfter: r.notAfter, UpdatedAt: r.updatedAt}
					data, _ := json.MarshalIndent(s, "", "  ")
					if err := os.WriteFile(filepath.Join(dir, servingFileName), data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				got := RunningListenerStatus(dir, now)
				if got.Present != r.wantPresent {
					t.Fatalf("Present = %v, want %v", got.Present, r.wantPresent)
				}
				if !r.wantPresent {
					return
				}
				if got.Stale != r.wantStale {
					t.Fatalf("Stale = %v, want %v", got.Stale, r.wantStale)
				}
				if got.DaysLeft != r.wantDays {
					t.Fatalf("DaysLeft = %d, want %d", got.DaysLeft, r.wantDays)
				}
			})
		}
	})
}

func fingerprintOf(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}
