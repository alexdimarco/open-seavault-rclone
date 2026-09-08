// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"time"
)

// renewWindow is how far ahead of NotAfter a leaf is considered "expiring soon".
// Below it, Validate emits a warning and the reloader logs the daily heartbeat
// warning; the value matches the design's < 14-day surface (C11).
const renewWindow = 14 * 24 * time.Hour

// Info is the non-secret summary of a certificate pair. It never carries key
// material — only names, times, the leaf fingerprint, and human warnings.
type Info struct {
	Names       []string // DNS SANs then textual IP SANs, in leaf order
	NotBefore   time.Time
	NotAfter    time.Time
	SubjectCN   string
	IssuerCN    string
	SelfSigned  bool   // leaf issuer == leaf subject (DER-exact)
	Fingerprint string // sha256 of the leaf DER, lowercase hex
	Warnings    []string
}

// Validate parses the PEM chain (leaf first), confirms the private key matches
// the leaf, and reports SANs, validity window, and fingerprint. It returns a
// typed error (ErrCertParse, ErrKeyParse, ErrKeyMismatch) on a hard failure, and
// otherwise returns Info with any soft warnings (expired, not yet valid, expiring
// soon, group/world-readable key on Unix). now is injected by the reloader; the
// exported Validate uses the wall clock.
func Validate(certPath, keyPath string) (Info, error) {
	return validateAt(certPath, keyPath, time.Now())
}

func validateAt(certPath, keyPath string, now time.Time) (Info, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return Info{}, fmt.Errorf("%w: cannot read %s", ErrCertParse, certPath)
	}
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return Info{}, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return Info{}, fmt.Errorf("%w: cannot read %s", ErrKeyParse, keyPath)
	}
	priv, err := parsePrivateKey(keyPEM)
	if err != nil {
		return Info{}, err
	}
	if !publicKeysEqual(leaf.PublicKey, priv) {
		// Name the cert file, never the key file's contents.
		return Info{}, fmt.Errorf("%w: %s", ErrKeyMismatch, certPath)
	}

	sum := sha256.Sum256(leaf.Raw)
	info := Info{
		Names:       leafNames(leaf),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		SubjectCN:   leaf.Subject.CommonName,
		IssuerCN:    leaf.Issuer.CommonName,
		SelfSigned:  string(leaf.RawIssuer) == string(leaf.RawSubject),
		Fingerprint: hex.EncodeToString(sum[:]),
	}

	switch {
	case now.After(leaf.NotAfter):
		info.Warnings = append(info.Warnings,
			fmt.Sprintf("certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339)))
	case now.Before(leaf.NotBefore):
		info.Warnings = append(info.Warnings,
			fmt.Sprintf("certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339)))
	case leaf.NotAfter.Sub(now) < renewWindow:
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		info.Warnings = append(info.Warnings,
			fmt.Sprintf("certificate expires in %d days (%s) — renew soon", days, leaf.NotAfter.UTC().Format(time.RFC3339)))
	}
	if w := keyPermWarning(keyPath); w != "" {
		info.Warnings = append(info.Warnings, w)
	}
	return info, nil
}

// parseLeaf decodes the first CERTIFICATE block and parses it as the leaf.
func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("%w: no CERTIFICATE block found", ErrCertParse)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertParse, err)
		}
		return leaf, nil
	}
}

// parsePrivateKey decodes the first PRIVATE KEY block and parses it as PKCS#8,
// PKCS#1, or SEC1 EC. The returned value is a crypto.Signer; the raw key bytes
// never leave this function.
func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	rest := keyPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("%w: no PRIVATE KEY block found", ErrKeyParse)
		}
		if len(block.Type) < len("PRIVATE KEY") ||
			block.Type[len(block.Type)-len("PRIVATE KEY"):] != "PRIVATE KEY" {
			continue
		}
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		return nil, fmt.Errorf("%w: unsupported private key encoding", ErrKeyParse)
	}
}

// publicKeysEqual reports whether the private key's public half matches the
// leaf's public key, without exposing key material.
func publicKeysEqual(leafPub crypto.PublicKey, priv crypto.PrivateKey) bool {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return false
	}
	pub := signer.Public()
	switch lp := leafPub.(type) {
	case *rsa.PublicKey:
		return lp.Equal(pub)
	case *ecdsa.PublicKey:
		return lp.Equal(pub)
	case ed25519.PublicKey:
		return lp.Equal(pub)
	default:
		return false
	}
}

// leafNames returns the leaf's DNS SANs followed by its IP SANs rendered as
// text, preserving the certificate's order.
func leafNames(leaf *x509.Certificate) []string {
	names := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// keyPermWarning returns a warning when the key file is group- or world-readable
// on a Unix host, naming chmod 600. On Windows (no POSIX mode bits) it is silent.
func keyPermWarning(keyPath string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		return ""
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("key file %s is group/world-readable — run chmod 600 %s", keyPath, keyPath)
	}
	return ""
}
