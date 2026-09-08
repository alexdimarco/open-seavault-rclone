// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/tlsconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// waitUntil polls cond until it holds or the timeout elapses.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// parseLeafPEM decodes the first CERTIFICATE block of certPEM.
func parseLeafPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func leafSerialPEM(t *testing.T, certPEM []byte) *big.Int {
	return parseLeafPEM(t, certPEM).SerialNumber
}

func leafFingerprintPEM(t *testing.T, certPEM []byte) string {
	sum := sha256.Sum256(parseLeafPEM(t, certPEM).Raw)
	return hex.EncodeToString(sum[:])
}

// dialServedSerial performs a real TLS handshake against addr (verifying against
// pool) and returns the served leaf's serial, or nil on any failure.
func dialServedSerial(addr string, pool *x509.CertPool) *big.Int {
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	return st.PeerCertificates[0].SerialNumber
}

// startDaemonAndCapture runs cmd in a goroutine, capturing the live http.Server
// and bound address the hook publishes, and registers cleanup that shuts the
// server down so cmd returns (which cancels the reloader). It fails the test if
// cmd returns before serving.
func startDaemonAndCapture(t *testing.T, hook *func(*http.Server, string), run func() error) string {
	t.Helper()
	type ready struct {
		srv  *http.Server
		addr string
	}
	readyCh := make(chan ready, 1)
	prev := *hook
	*hook = func(srv *http.Server, addr string) { readyCh <- ready{srv, addr} }
	t.Cleanup(func() { *hook = prev })

	doneCh := make(chan error, 1)
	go func() { doneCh <- run() }()

	var r ready
	select {
	case r = <-readyCh:
	case err := <-doneCh:
		t.Fatalf("daemon returned before serving: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("daemon did not reach the serving hook")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = r.srv.Shutdown(ctx)
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
		}
	})
	return r.addr
}

// TestReloaderWiredThroughServeStartup (reload-not-wired-1, A2-c6/A3-c6): the
// END-TO-END proof the slice verifiers lacked. It boots a REAL TLS listener
// through the REAL `seavault serve` startup path (cmdServe), asserts
// <appdata>/config/tls/serving.json is written while the listener is up,
// rewrites the on-disk pair, and asserts the renewed leaf is served within the
// poll and serving.json reflects it. Before the wiring fix, cmdServe never
// constructed the Reloader: serving.json stayed absent and the renewed pair was
// never served.
func TestReloaderWiredThroughServeStartup(t *testing.T) {
	appHome := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", appHome)
	t.Setenv("SEAVAULT_PASSWORD", "correct horse battery staple")
	t.Setenv("SEAVAULT_SERVE_PASSWORD", "webdav-basic-pw")

	prev := tlsReloadInterval
	tlsReloadInterval = 20 * time.Millisecond
	t.Cleanup(func() { tlsReloadInterval = prev })

	ca := newU3CA(t)
	watchDir := t.TempDir()
	certPath := filepath.Join(watchDir, "leaf.crt")
	keyPath := filepath.Join(watchDir, "leaf.key")

	mtime := time.Now()
	rewrite := func(certPEM, keyPEM []byte) {
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		mtime = mtime.Add(time.Minute)
		_ = os.Chtimes(certPath, mtime, mtime)
		_ = os.Chtimes(keyPath, mtime, mtime)
	}

	cert1, key1 := ca.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	rewrite(cert1, key1)
	leaf1Serial := leafSerialPEM(t, cert1)

	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := vault.Create(vaultPath, "correct horse battery staple", vault.DefaultChunkParams()); err != nil {
		t.Fatalf("create vault: %v", err)
	}

	addr := startDaemonAndCapture(t, &serveTestHook, func() error {
		return cmdServe([]string{
			"--addr", "127.0.0.1:0",
			"--no-keychain",
			"--tls-cert", certPath,
			"--tls-key", keyPath,
			"--quiet-credentials",
			vaultPath,
		})
	})

	servingDir := filepath.Join(appHome, "config", "tls")
	if !waitUntil(5*time.Second, func() bool {
		s, err := tlsconfig.ReadServing(servingDir)
		return err == nil && s.Fingerprint == leafFingerprintPEM(t, cert1)
	}) {
		s, _ := tlsconfig.ReadServing(servingDir)
		t.Fatalf("serving.json was not written for leaf1 at %s while the listener is up (reloader not wired); got %+v", servingDir, s)
	}

	if got := dialServedSerial(addr, ca.pool); got == nil || got.Cmp(leaf1Serial) != 0 {
		t.Fatalf("initial served leaf serial = %v, want leaf1 %v", got, leaf1Serial)
	}

	// Renew on disk; the running daemon must serve the new leaf within the poll.
	cert2, key2 := ca.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	rewrite(cert2, key2)
	leaf2Serial := leafSerialPEM(t, cert2)
	if !waitUntil(6*time.Second, func() bool {
		got := dialServedSerial(addr, ca.pool)
		return got != nil && got.Cmp(leaf2Serial) == 0
	}) {
		t.Fatalf("renewed leaf (serial %v) was not served within the poll — hot-reload not wired into cmdServe", leaf2Serial)
	}
	if !waitUntil(4*time.Second, func() bool {
		s, err := tlsconfig.ReadServing(servingDir)
		return err == nil && s.Fingerprint == leafFingerprintPEM(t, cert2)
	}) {
		s, _ := tlsconfig.ReadServing(servingDir)
		t.Fatalf("serving.json did not update to the renewed leaf; got %+v", s)
	}
}

// TestReloaderWiredThroughGUIStartup (reload-not-wired-1, A2-c6): the same
// end-to-end proof through the REAL `seavault gui` startup path (cmdGUI), so both
// wirings the adversarial finding names are exercised: serving.json is written
// while the GUI serves TLS, and a renewed pair is served within the poll.
func TestReloaderWiredThroughGUIStartup(t *testing.T) {
	appHome := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", appHome)

	prev := tlsReloadInterval
	tlsReloadInterval = 20 * time.Millisecond
	t.Cleanup(func() { tlsReloadInterval = prev })

	ca := newU3CA(t)
	watchDir := t.TempDir()
	certPath := filepath.Join(watchDir, "leaf.crt")
	keyPath := filepath.Join(watchDir, "leaf.key")

	mtime := time.Now()
	rewrite := func(certPEM, keyPEM []byte) {
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		mtime = mtime.Add(time.Minute)
		_ = os.Chtimes(certPath, mtime, mtime)
		_ = os.Chtimes(keyPath, mtime, mtime)
	}

	cert1, key1 := ca.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	rewrite(cert1, key1)
	leaf1Serial := leafSerialPEM(t, cert1)

	addr := startDaemonAndCapture(t, &guiTestHook, func() error {
		return cmdGUI([]string{
			"--addr", "127.0.0.1:0",
			"--no-open",
			"--exit-on-browser-close=false",
			"--tls-cert", certPath,
			"--tls-key", keyPath,
		})
	})

	servingDir := filepath.Join(appHome, "config", "tls")
	if !waitUntil(5*time.Second, func() bool {
		s, err := tlsconfig.ReadServing(servingDir)
		return err == nil && s.Fingerprint == leafFingerprintPEM(t, cert1)
	}) {
		s, _ := tlsconfig.ReadServing(servingDir)
		t.Fatalf("serving.json was not written for the GUI listener at %s (reloader not wired into cmdGUI); got %+v", servingDir, s)
	}

	if got := dialServedSerial(addr, ca.pool); got == nil || got.Cmp(leaf1Serial) != 0 {
		t.Fatalf("initial GUI served leaf serial = %v, want leaf1 %v", got, leaf1Serial)
	}

	cert2, key2 := ca.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	rewrite(cert2, key2)
	leaf2Serial := leafSerialPEM(t, cert2)
	if !waitUntil(6*time.Second, func() bool {
		got := dialServedSerial(addr, ca.pool)
		return got != nil && got.Cmp(leaf2Serial) == 0
	}) {
		t.Fatalf("renewed leaf (serial %v) was not served within the poll — hot-reload not wired into cmdGUI", leaf2Serial)
	}
}
