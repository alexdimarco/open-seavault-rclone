// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/localdav"
	"github.com/alexdimarco/open-seavault-rclone/internal/loopback"
	"github.com/alexdimarco/open-seavault-rclone/internal/tlsconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
	"github.com/alexdimarco/open-seavault-rclone/internal/webui"
)

// --- real-certificate test helpers (standard library only) ---------------

type u3CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func u3GenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func u3Serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

func u3KeyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func u3CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newU3CA(t *testing.T) u3CA {
	t.Helper()
	key := u3GenKey(t)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          u3Serial(t),
		Subject:               pkix.Name{CommonName: "SeaVault U3 Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return u3CA{cert: cert, key: key, pool: pool}
}

// issue returns a CA-signed leaf PEM + matching key PEM covering the given DNS
// and IP SANs.
func (ca u3CA) issue(t *testing.T, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key := u3GenKey(t)
	now := time.Now()
	cn := "leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          u3Serial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return u3CertPEM(der), u3KeyPEM(t, key)
}

// selfSignedLeaf returns a self-signed leaf (issuer == subject) + matching key.
func selfSignedLeaf(t *testing.T, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key := u3GenKey(t)
	now := time.Now()
	cn := "self"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          u3Serial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}
	return u3CertPEM(der), u3KeyPEM(t, key)
}

func writePairFiles(t *testing.T, dir string, certPEM, keyPEM []byte) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "leaf.crt")
	keyPath = filepath.Join(dir, "leaf.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- P2: the bind guard table (design §3, I-T1) --------------------------

// TestEnsureLoopbackBindGuardTable is the rewritten guard table (row P2): host ×
// (tls off, self-signed, CA) × insecure-bind → allowed/refused and the exact
// warning. Plaintext on a non-loopback address without --insecure-bind is
// refused in every row. Every row is asserted.
func TestEnsureLoopbackBindGuardTable(t *testing.T) {
	type mode struct {
		name       string
		tlsOn      bool
		selfSigned bool
	}
	off := mode{"tls-off", false, false}
	selfSigned := mode{"self-signed", true, true}
	ca := mode{"ca", true, false}

	type row struct {
		name         string
		addr         string
		m            mode
		insecureBind bool
		wantAllowed  bool
		wantWarnings []string
	}
	rows := []row{
		// Loopback / localhost: always allowed, never warned, in every mode.
		{"loopback/off", "127.0.0.1:8787", off, false, true, nil},
		{"loopback/self-signed", "127.0.0.1:8787", selfSigned, false, true, nil},
		{"loopback/ca", "127.0.0.1:8787", ca, false, true, nil},
		{"localhost/off", "localhost:8787", off, false, true, nil},
		{"localhost/ca", "localhost:8787", ca, false, true, nil},
		{"ipv6-loopback/ca", "[::1]:8787", ca, false, true, nil},

		// LAN IP, TLS off: refused unless --insecure-bind.
		{"lan/off/no-override", "192.168.1.5:8787", off, false, false, nil},
		{"lan/off/override", "192.168.1.5:8787", off, true, true, nil},

		// LAN IP, TLS on: admitted; self-signed adds the trust warning; CA is clean.
		{"lan/self-signed", "192.168.1.5:8787", selfSigned, false, true, []string{selfSignedTrustWarning}},
		{"lan/ca", "192.168.1.5:8787", ca, false, true, nil},

		// Empty host (every interface), TLS off: refused unless --insecure-bind.
		{"empty/off/no-override", ":8787", off, false, false, nil},
		{"empty/off/override", ":8787", off, true, true, nil},

		// Empty host, TLS on: admitted with the every-interface warning; self-signed
		// stacks the trust warning first.
		{"empty/ca", ":8787", ca, false, true, []string{everyInterfaceWarning}},
		{"empty/self-signed", ":8787", selfSigned, false, true, []string{selfSignedTrustWarning, everyInterfaceWarning}},
	}
	if len(rows) == 0 {
		t.Fatal("guard table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			warnings, err := ensureLoopbackBind(r.addr, r.insecureBind, r.m.tlsOn, r.m.selfSigned)
			allowed := err == nil
			if allowed != r.wantAllowed {
				t.Fatalf("allowed=%v (err=%v), want allowed=%v", allowed, err, r.wantAllowed)
			}
			if !r.wantAllowed {
				// I-T1: plaintext non-loopback without the override is refused and
				// the error names the override.
				if !strings.Contains(err.Error(), "--insecure-bind") {
					t.Fatalf("refusal %q does not name the --insecure-bind override", err.Error())
				}
				return
			}
			if !equalStrings(warnings, r.wantWarnings) {
				t.Fatalf("warnings = %#v, want %#v", warnings, r.wantWarnings)
			}
		})
	}
}

// --- G1 (cmd half): gui TLS resolution, precedence, launch link (C1) -----

// TestGUITLSResolvePrecedenceAndLaunch proves the gui-side wiring of row G1:
// --tls-cert/--tls-key win over the shared tls section; the tls section is used
// when no flags are given; the legacy gui.certFile still works; and a
// non-loopback TLS bind advertises the confirmed --allow-host name in the launch
// link (C1) while a loopback bind keeps its own address.
func TestGUITLSResolvePrecedenceAndLaunch(t *testing.T) {
	ca := newU3CA(t)
	dir := t.TempDir()

	flagCertPEM, flagKeyPEM := ca.issue(t, []string{"flag.example"}, nil)
	flagCert, flagKey := writePairFiles(t, mkdir(t, dir, "flag"), flagCertPEM, flagKeyPEM)
	cfgCertPEM, cfgKeyPEM := ca.issue(t, []string{"cfg.example"}, nil)
	cfgCert, cfgKey := writePairFiles(t, mkdir(t, dir, "cfg"), cfgCertPEM, cfgKeyPEM)
	legacyCertPEM, legacyKeyPEM := ca.issue(t, []string{"legacy.example"}, nil)
	legacyCert, legacyKey := writePairFiles(t, mkdir(t, dir, "legacy"), legacyCertPEM, legacyKeyPEM)

	base := appconfig.Config{
		Version: appconfig.Version,
		GUI:     appconfig.GUIConfig{Protocol: "http"},
		TLS:     appconfig.TLSSection{CertFile: cfgCert, KeyFile: cfgKey},
	}

	t.Run("flags win over the tls section", func(t *testing.T) {
		r, err := tlsconfig.Resolve(tlsconfig.Options{CertFlag: flagCert, KeyFlag: flagKey, Cfg: base, Purpose: tlsconfig.PurposeGUI})
		if err != nil {
			t.Fatal(err)
		}
		if r.Source != tlsconfig.SourceFlags {
			t.Fatalf("source = %q, want flags", r.Source)
		}
		if r.CertPath != flagCert {
			t.Fatalf("certPath = %q, want the flag cert %q", r.CertPath, flagCert)
		}
		if r.Source == tlsconfig.SourceNone {
			t.Fatal("flags must turn TLS on")
		}
	})

	t.Run("the tls section is used when no flags are given", func(t *testing.T) {
		r, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: base, Purpose: tlsconfig.PurposeGUI})
		if err != nil {
			t.Fatal(err)
		}
		if r.Source != tlsconfig.SourceConfig {
			t.Fatalf("source = %q, want config", r.Source)
		}
		if r.CertPath != cfgCert {
			t.Fatalf("certPath = %q, want the config cert %q", r.CertPath, cfgCert)
		}
	})

	t.Run("legacy gui.certFile still works", func(t *testing.T) {
		legacyCfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "https", CertFile: legacyCert, KeyFile: legacyKey}}
		r, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: legacyCfg, Purpose: tlsconfig.PurposeGUI})
		if err != nil {
			t.Fatal(err)
		}
		if r.Source != tlsconfig.SourceLegacyGUI {
			t.Fatalf("source = %q, want legacy-gui", r.Source)
		}
		if r.CertPath != legacyCert {
			t.Fatalf("certPath = %q, want the legacy cert %q", r.CertPath, legacyCert)
		}
	})

	t.Run("non-loopback launch link uses the allow-host name (C1)", func(t *testing.T) {
		// Non-loopback bind + confirmed --allow-host: the launch host is the name,
		// not the bind IP.
		got := launchAddrForBind("192.168.1.5:8787", true, []string{"vault.example"}, []string{"vault.example"})
		if got != "vault.example:8787" {
			t.Fatalf("launchAddr = %q, want vault.example:8787", got)
		}
		// No --allow-host: falls back to the certificate's first DNS SAN.
		got = launchAddrForBind("192.168.1.5:8787", true, nil, []string{"192.168.1.5", "san.example"})
		if got != "san.example:8787" {
			t.Fatalf("launchAddr = %q, want san.example:8787 (first DNS SAN, skipping the IP SAN)", got)
		}
		// Loopback keeps 127.0.0.1 even with an allow-host present.
		got = launchAddrForBind("127.0.0.1:8787", true, []string{"vault.example"}, []string{"vault.example"})
		if got != "127.0.0.1:8787" {
			t.Fatalf("loopback launchAddr = %q, want 127.0.0.1:8787", got)
		}
	})
}

func mkdir(t *testing.T, base, name string) string {
	t.Helper()
	p := filepath.Join(base, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- S1: serve over a real TLS listener; PROPFIND over HTTPS -------------

// TestServeTLSListenerPropfind (row S1): a real localdav server is served over a
// real TLS listener via the production serveOn seam; a Go WebDAV client that
// trusts the test CA performs PROPFIND over HTTPS. The same non-loopback bind
// without TLS and without --insecure-bind is refused, and --tls with an empty
// section is a typed error.
func TestServeTLSListenerPropfind(t *testing.T) {
	ca := newU3CA(t)
	dir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	certPath, keyPath := writePairFiles(t, dir, certPEM, keyPEM)

	resolved, err := tlsconfig.Resolve(tlsconfig.Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: tlsconfig.PurposeServe})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.TLS == nil {
		t.Fatal("serve resolve produced no TLS config")
	}

	// A real vault behind a real localdav server.
	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := vault.Create(vaultPath, "passphrase", vault.DefaultChunkParams()); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v, err := vault.Open(vaultPath, "passphrase")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	dav := localdav.New(v)
	dav.Credentials = &localdav.BasicCredentials{User: "seavault", Password: "pw"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := buildLoopbackServer(ln.Addr().String(), dav)
	go func() { _ = serveOn(ln, srv, resolved) }()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	url := "https://127.0.0.1:" + port + "/"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool}}}

	req, err := http.NewRequest("PROPFIND", url, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Depth", "0")
	req.SetBasicAuth("seavault", "pw")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PROPFIND over HTTPS failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND status = %d, want 207; body=%s", resp.StatusCode, string(body))
	}
	if resp.TLS == nil {
		t.Fatal("response was not served over TLS")
	}
	if !strings.Contains(string(body), "<") {
		t.Fatalf("PROPFIND body is not a multistatus XML document: %q", string(body))
	}

	// The same non-loopback bind without TLS and without the override is refused.
	if _, err := ensureLoopbackBind("192.168.1.5:8765", false, false, false); err == nil {
		t.Fatal("plaintext non-loopback serve without --insecure-bind must be refused")
	}

	// --tls with an empty section is a typed remedy error, not silent plaintext.
	if _, err := resolveServeTLS("", "", true, appconfig.Config{Version: appconfig.Version}, "127.0.0.1"); err == nil {
		t.Fatal("--tls with an empty tls section must error, not serve plaintext")
	} else if !strings.Contains(err.Error(), "tls setup") {
		t.Fatalf("empty --tls error %q should name the tls setup remedy", err.Error())
	}
}

// --- E1: non-loopback interface; first bytes are a TLS handshake ---------

func firstNonLoopbackIPv4() (net.IP, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, true
		}
	}
	return nil, false
}

// TestNonLoopbackTLSHandshakeOnWire (row E1, I-T1 end-to-end, C10): bind both the
// gui webui server and the serve localdav handler to a real non-loopback
// interface address with a resolved TLS source; the first bytes on the wire are a
// TLS handshake (a client trusting the test CA completes the handshake) and a
// plaintext HTTP GET is rejected. Skipped only when the machine has no
// non-loopback interface.
func TestNonLoopbackTLSHandshakeOnWire(t *testing.T) {
	ip, ok := firstNonLoopbackIPv4()
	if !ok {
		t.Skip("no non-loopback IPv4 interface on this machine; E1 wire test skipped")
	}
	ca := newU3CA(t)
	dir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, []string{"e1.example"}, []net.IP{ip})
	certPath, keyPath := writePairFiles(t, dir, certPEM, keyPEM)

	guiServer, err := webui.NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}})
	if err != nil {
		t.Fatal(err)
	}

	vaultPath := filepath.Join(t.TempDir(), "vault")
	if err := vault.Create(vaultPath, "passphrase", vault.DefaultChunkParams()); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	v, err := vault.Open(vaultPath, "passphrase")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	davServer := localdav.New(v)

	cases := []struct {
		name    string
		handler http.Handler
	}{
		{"gui", guiServer},
		{"serve", davServer},
	}
	if len(cases) == 0 {
		t.Fatal("no server cases")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolved, err := tlsconfig.Resolve(tlsconfig.Options{CertFlag: certPath, KeyFlag: keyPath, Purpose: tlsconfig.PurposeServe})
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
			if err != nil {
				t.Fatalf("listen on %s: %v", ip, err)
			}
			srv := buildLoopbackServer(ln.Addr().String(), c.handler)
			go func() { _ = serveOn(ln, srv, resolved) }()
			defer srv.Close()

			addr := ln.Addr().String()

			// First bytes on the wire ARE a TLS handshake: a raw dial that speaks
			// TLS (verifying the leaf against the test CA) completes the handshake.
			raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial %s: %v", addr, err)
			}
			tconn := tls.Client(raw, &tls.Config{RootCAs: ca.pool, ServerName: ip.String()})
			if err := tconn.Handshake(); err != nil {
				t.Fatalf("TLS handshake against the listener failed: %v", err)
			}
			_ = tconn.Close()

			// A plaintext HTTP GET is rejected: decrypted content is never served
			// over cleartext. Either the client sees a protocol error, or Go's
			// http.Server answers plaintext-on-TLS with a 400 "HTTP request to an
			// HTTPS server" — never a 200 that carries app content (I-T1).
			plain := &http.Client{Timeout: 5 * time.Second}
			resp, err := plain.Get("http://" + addr + "/")
			if err == nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					t.Fatalf("plaintext GET to the TLS listener was SERVED (HTTP 200); decrypted content must never reach a cleartext request")
				}
				if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "HTTP request to an HTTPS server") {
					t.Fatalf("plaintext GET rejection was not the expected HTTPS-only refusal: status=%d body=%q", resp.StatusCode, string(body))
				}
			}
			// err != nil is also a valid rejection (protocol error): plaintext
			// never reaches app content either way.
		})
	}
}

// --- H1 (cmd half): SAN-not-in-allowlist warning; allowlist admits; self-signed

// TestStartupSANAllowlistAndSelfSigned (row H1, I-T6, C7): a certificate whose
// DNS SAN is absent from the Host allowlist fires the startup warning; adding the
// name to tls.allowHosts admits the Host at the rebinding guard; and a legacy
// self-signed pair resolves with SelfSigned=true and fires the trust-prompt
// warning in the startup log.
func TestStartupSANAllowlistAndSelfSigned(t *testing.T) {
	ca := newU3CA(t)
	dir := t.TempDir()

	t.Run("SAN absent from allowlist warns; adding it admits the Host", func(t *testing.T) {
		certPEM, keyPEM := ca.issue(t, []string{"vault.example"}, nil)
		certPath, keyPath := writePairFiles(t, dir, certPEM, keyPEM)
		cfg := appconfig.Config{Version: appconfig.Version, TLS: appconfig.TLSSection{CertFile: certPath, KeyFile: keyPath}}
		resolved, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: cfg, Purpose: tlsconfig.PurposeServe})
		if err != nil {
			t.Fatal(err)
		}

		// Not in the allowlist: startup warns naming the certificate name.
		allowedBefore := allowedHostsForBind("192.168.1.5:8765", nil, nil)
		var before strings.Builder
		logTLSStartup(&before, "serve", resolved, allowedBefore)
		if !strings.Contains(before.String(), "vault.example") || !strings.Contains(before.String(), "not in the Host allowlist") {
			t.Fatalf("startup log did not warn about the absent SAN; got:\n%s", before.String())
		}
		if loopback.HostAllowed("vault.example", allowedBefore) {
			t.Fatal("precondition: vault.example must NOT be admitted before it is allowlisted")
		}

		// Adding it to tls.allowHosts admits the Host and clears the warning.
		allowedAfter := allowedHostsForBind("192.168.1.5:8765", nil, []string{"vault.example"})
		if !loopback.HostAllowed("vault.example", allowedAfter) {
			t.Fatal("a name in tls.allowHosts must be admitted by the rebinding guard")
		}
		var after strings.Builder
		logTLSStartup(&after, "serve", resolved, allowedAfter)
		if strings.Contains(after.String(), "not in the Host allowlist") {
			t.Fatalf("startup log still warned after the name was allowlisted:\n%s", after.String())
		}
	})

	t.Run("legacy self-signed pair resolves SelfSigned and warns of the trust prompt", func(t *testing.T) {
		selfDir := mkdir(t, dir, "self")
		certPEM, keyPEM := selfSignedLeaf(t, []string{"self.example"}, nil)
		certPath, keyPath := writePairFiles(t, selfDir, certPEM, keyPEM)
		cfg := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "https", CertFile: certPath, KeyFile: keyPath}}
		resolved, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: cfg, Purpose: tlsconfig.PurposeGUI})
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Source != tlsconfig.SourceLegacyGUI {
			t.Fatalf("source = %q, want legacy-gui", resolved.Source)
		}
		if !resolved.SelfSigned {
			t.Fatal("a self-signed leaf in the legacy fields must resolve SelfSigned=true (C7)")
		}
		var log strings.Builder
		logTLSStartup(&log, "gui", resolved, allowedHostsForBind("192.168.1.5:8787", nil, []string{"self.example"}))
		if !strings.Contains(log.String(), selfSignedTrustWarning) {
			t.Fatalf("startup log did not fire the self-signed trust-prompt warning:\n%s", log.String())
		}
	})
}

// --- Z1: no pre-U3 test deleted or edited --------------------------------

// TestNoPreU3TestDeletedOrEdited (row Z1, I-T4): every _test.go file present on
// main is byte-identical in the worktree, except the maintainer-authorized files
// (cmd/seavault/main_test.go — the sanctioned guard-signature adaptation, predesign
// review integration-seams-3; and cmd/seavault/commands_test.go — the authorized H4
// rewrite deriving both the registry and dispatch sides from code, maintainer
// authorization 2026-09-08); even in those, no test function that existed on main
// may be removed. New test files are permitted (additions never fail Z1).
func TestNoPreU3TestDeletedOrEdited(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available; Z1 diff guard skipped")
	}
	repoRoot := gitTopLevel(t)

	// The pre-U3 test files whose bodies legitimately changed, each under an explicit
	// maintainer authorization. For every one of them Z1 still forbids REMOVING a
	// test function that existed on main; only edits/additions within the file are
	// allowed. main_test.go carries the U3 additions and the sanctioned guard-
	// signature adaptation; commands_test.go carries the authorized H4 rewrite.
	guardHostFiles := map[string]bool{
		"cmd/seavault/main_test.go":     true,
		"cmd/seavault/commands_test.go": true,
	}

	mainTestFiles := gitListTestFiles(t, repoRoot)
	if len(mainTestFiles) == 0 {
		t.Fatal("git listed no _test.go files on main; Z1 cannot verify anything")
	}
	checked := 0
	for _, f := range mainTestFiles {
		mainContent, ok := gitShow(t, repoRoot, "main:"+f)
		if !ok {
			t.Fatalf("could not read %s from main", f)
		}
		nowBytes, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatalf("pre-U3 test file %s is missing from the worktree (deleted?): %v", f, err)
		}
		if guardHostFiles[f] {
			// Forbid removals of any test function that existed on main. Anchor the
			// match to the declaration "func <name>(" so a name that is a prefix of
			// a sibling (TestX vs TestXExtra) is not falsely counted as present.
			for _, fn := range testFuncNames(mainContent) {
				if !strings.Contains(string(nowBytes), "func "+fn+"(") {
					t.Fatalf("pre-U3 test %q was removed from %s", fn, f)
				}
			}
			checked++
			continue
		}
		if string(nowBytes) != mainContent {
			t.Fatalf("pre-U3 test file %s was edited; Z1 forbids editing pre-U3 tests", f)
		}
		checked++
	}
	if checked != len(mainTestFiles) {
		t.Fatalf("checked %d of %d pre-U3 test files", checked, len(mainTestFiles))
	}
}

func gitTopLevel(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout; Z1 skipped: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func gitListTestFiles(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "ls-tree", "-r", "--name-only", "main")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("could not list main's tree (is main present?); Z1 skipped: %v", err)
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "_test.go") {
			files = append(files, line)
		}
	}
	return files
}

func gitShow(t *testing.T, root, ref string) (string, bool) {
	t.Helper()
	cmd := exec.Command("git", "show", ref)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func testFuncNames(content string) []string {
	var names []string
	for _, line := range strings.Split(content, "\n") {
		for _, pfx := range []string{"func Test", "func Benchmark", "func Example", "func Fuzz"} {
			if strings.HasPrefix(line, pfx) {
				rest := strings.TrimPrefix(line, "func ")
				name := rest
				for i, r := range rest {
					if r == '(' || r == ' ' {
						name = rest[:i]
						break
					}
				}
				if name != "" {
					names = append(names, name)
				}
			}
		}
	}
	return names
}
