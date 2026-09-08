// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA is a real in-test certificate authority. Leaves it issues are verified
// by clients against ca.cert, so the TLS tests exercise genuine handshakes and
// path validation, not mocks.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

func keyToPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func certToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key := genKey(t)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: "SeaVault Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
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
	return testCA{cert: cert, key: key}
}

// leafSpec parameterizes an issued leaf.
type leafSpec struct {
	cn        string
	dnsNames  []string
	notBefore time.Time
	notAfter  time.Time
	key       *ecdsa.PrivateKey // leaf key; a fresh one is generated when nil
}

// issue returns a leaf certificate PEM (leaf only; the client holds the CA) and
// the PEM of the key that MATCHES it.
func (ca testCA) issue(t *testing.T, s leafSpec) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key := s.key
	if key == nil {
		key = genKey(t)
	}
	if s.notBefore.IsZero() {
		s.notBefore = time.Now().Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = time.Now().AddDate(1, 0, 0)
	}
	dns := s.dnsNames
	if len(dns) == 0 && s.cn != "" {
		dns = []string{s.cn}
	}
	cn := s.cn
	if cn == "" && len(dns) > 0 {
		cn = dns[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dns,
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return certToPEM(der), keyToPEM(t, key), parsed
}

// selfSigned returns a self-signed leaf (issuer == subject) and its matching key.
func selfSigned(t *testing.T, s leafSpec) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key := s.key
	if key == nil {
		key = genKey(t)
	}
	if s.notBefore.IsZero() {
		s.notBefore = time.Now().Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = time.Now().AddDate(1, 0, 0)
	}
	dns := s.dnsNames
	if len(dns) == 0 && s.cn != "" {
		dns = []string{s.cn}
	}
	cn := s.cn
	if cn == "" && len(dns) > 0 {
		cn = dns[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dns,
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse self-signed: %v", err)
	}
	return certToPEM(der), keyToPEM(t, key), parsed
}

// writePair writes cert and key PEM into dir and returns their paths (key at 0600).
func writePair(t *testing.T, dir string, certPEM, keyPEM []byte) (certPath, keyPath string) {
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

// touchFuture bumps a file's mtime past now so the reloader's stat poll detects
// the change deterministically regardless of filesystem timestamp resolution.
func touchFuture(t *testing.T, paths ...string) {
	t.Helper()
	future := time.Now().Add(2 * time.Second)
	for _, p := range paths {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}
}
