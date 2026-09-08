// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

// Package tlsconfig resolves, validates, and hot-reloads the TLS certificate
// pair the GUI and WebDAV servers serve. It is standard-library-only
// (crypto/tls, crypto/x509) and never logs, echoes, or returns private key
// material: warnings and errors name file paths and remedies, never key bytes.
//
// The precedence chain (Design §2) is: the --tls-cert/--tls-key flags → the
// shared tls.certFile/keyFile config section → the legacy gui.certFile/keyFile
// fields (gui purpose only) → for gui when gui.protocol is https the self-signed
// floor (appconfig.EnsureSelfSignedCertificate) → none. serve has no legacy or
// self-signed tier: with nothing configured it stays plaintext loopback.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// Source names which tier of the precedence chain supplied the serving pair.
type Source string

const (
	SourceFlags      Source = "flags"
	SourceConfig     Source = "config"
	SourceLegacyGUI  Source = "legacy-gui"
	SourceSelfSigned Source = "self-signed"
	SourceNone       Source = "none"
)

// Purpose distinguishes the two callers; only gui has the legacy and
// self-signed tiers.
const (
	PurposeGUI   = "gui"
	PurposeServe = "serve"
)

// Typed errors. Callers use errors.Is against these sentinels; the wrapped
// message adds the offending field or path (never key material).
var (
	// ErrHalfPair is returned when exactly one of a cert/key pair is configured
	// at the winning tier. The message names both fields of that tier.
	ErrHalfPair = errors.New("tls: a certificate and key must be configured together")
	// ErrKeyMismatch is returned when a configured full pair's private key does
	// not match the certificate's leaf public key (startup refusal, C13).
	ErrKeyMismatch = errors.New("tls: private key does not match the certificate")
	// ErrCertParse is returned when the certificate file cannot be read or its
	// PEM/DER chain cannot be parsed.
	ErrCertParse = errors.New("tls: certificate could not be parsed")
	// ErrKeyParse is returned when the key file cannot be read or its PEM/DER
	// private key cannot be parsed.
	ErrKeyParse = errors.New("tls: private key could not be parsed")
)

// Options are the inputs to Resolve.
type Options struct {
	CertFlag string // --tls-cert
	KeyFlag  string // --tls-key
	Cfg      appconfig.Config
	Purpose  string // PurposeGUI | PurposeServe
	BindHost string // used only to seed the self-signed floor's SANs
}

// Resolved is the outcome of Resolve. TLS is nil when Source is none.
type Resolved struct {
	TLS        *tls.Config
	Source     Source
	CertPath   string
	KeyPath    string
	SelfSigned bool
	Names      []string
	NotAfter   time.Time
	Warnings   []string

	holder *certHolder // shared with a Reloader; nil when Source==none
}

// certHolder stores the serving *tls.Certificate behind an atomic.Value so a
// Reloader goroutine can swap it under a live listener without a lock on the
// hot GetCertificate path.
type certHolder struct {
	v atomic.Value // stores *tls.Certificate
}

func (h *certHolder) store(c *tls.Certificate) { h.v.Store(c) }

func (h *certHolder) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, _ := h.v.Load().(*tls.Certificate)
	if c == nil {
		return nil, errors.New("tls: no certificate loaded")
	}
	return c, nil
}

// leaf returns the parsed leaf of the currently-stored certificate, or nil.
func (h *certHolder) leaf() *x509.Certificate {
	c, _ := h.v.Load().(*tls.Certificate)
	if c == nil {
		return nil
	}
	return c.Leaf
}

// Resolve walks the precedence chain and returns the serving state. A configured
// full pair whose key does not match its leaf returns ErrKeyMismatch (startup
// refusal, C13); half a pair returns ErrHalfPair; an unparsable file returns
// ErrCertParse/ErrKeyParse. When nothing is configured (and no self-signed floor
// applies) it returns Source=none with a nil TLS config and no error.
func Resolve(o Options) (*Resolved, error) {
	certPath, keyPath, src, err := pickPair(o)
	if err != nil {
		return nil, err
	}
	if src == SourceNone {
		return &Resolved{Source: SourceNone}, nil
	}

	info, verr := Validate(certPath, keyPath)
	if verr != nil {
		// ErrKeyMismatch, ErrCertParse, ErrKeyParse all propagate: a configured
		// pair that does not load is a startup refusal, not a silent fallback.
		return nil, verr
	}

	cert, lerr := loadCertificate(certPath, keyPath)
	if lerr != nil {
		return nil, lerr
	}
	h := &certHolder{}
	h.store(cert)

	r := &Resolved{
		TLS:      &tls.Config{GetCertificate: h.get, MinVersion: tls.VersionTLS12},
		Source:   src,
		CertPath: certPath,
		KeyPath:  keyPath,
		Names:    info.Names,
		NotAfter: info.NotAfter,
		Warnings: info.Warnings,
		holder:   h,
	}
	// Self-signed classification (C7): the floor is self-signed by construction;
	// a legacy-tier pair is self-signed when GUI.SelfSigned was persisted; and
	// any pair whose issuer == subject is self-signed regardless of tier, so a
	// migrated self-signed pair in the legacy fields still fires the trust-prompt
	// warning and is never reported as bring-your-own.
	r.SelfSigned = src == SourceSelfSigned ||
		(src == SourceLegacyGUI && o.Cfg.GUI.SelfSigned) ||
		info.SelfSigned
	return r, nil
}

// pickPair applies the precedence chain and returns the winning cert/key paths
// and their Source, or a typed error. It does not read the files (Resolve does).
func pickPair(o Options) (certPath, keyPath string, src Source, err error) {
	// 1. Flags.
	cf, kf := strings.TrimSpace(o.CertFlag), strings.TrimSpace(o.KeyFlag)
	if cf != "" || kf != "" {
		if cf == "" || kf == "" {
			return "", "", "", fmt.Errorf("%w: --tls-cert and --tls-key must be given together", ErrHalfPair)
		}
		return cf, kf, SourceFlags, nil
	}

	// 2. Shared tls config section.
	tc, tk := strings.TrimSpace(o.Cfg.TLS.CertFile), strings.TrimSpace(o.Cfg.TLS.KeyFile)
	if tc != "" || tk != "" {
		if tc == "" || tk == "" {
			return "", "", "", fmt.Errorf("%w: tls.certFile and tls.keyFile must be set together", ErrHalfPair)
		}
		return tc, tk, SourceConfig, nil
	}

	// The legacy and self-signed tiers exist for the GUI only. WebDAV (serve)
	// has no self-signed floor and does not inherit the GUI's legacy pair, so a
	// user who has done nothing keeps plaintext loopback (I-T4).
	if o.Purpose == PurposeGUI {
		// 3. Legacy gui.certFile/keyFile fields.
		lc, lk := strings.TrimSpace(o.Cfg.GUI.CertFile), strings.TrimSpace(o.Cfg.GUI.KeyFile)
		if lc != "" || lk != "" {
			if lc == "" || lk == "" {
				return "", "", "", fmt.Errorf("%w: gui.certFile and gui.keyFile must be set together", ErrHalfPair)
			}
			return lc, lk, SourceLegacyGUI, nil
		}
		// 4. Self-signed floor, only when the GUI protocol is https.
		if o.Cfg.GUI.Protocol == "https" {
			ncfg, e := appconfig.EnsureSelfSignedCertificate(o.Cfg, o.BindHost)
			if e != nil {
				return "", "", "", e
			}
			return strings.TrimSpace(ncfg.GUI.CertFile), strings.TrimSpace(ncfg.GUI.KeyFile), SourceSelfSigned, nil
		}
	}

	// 5. None.
	return "", "", SourceNone, nil
}

// loadCertificate builds a *tls.Certificate with its Leaf populated. It is used
// both by Resolve and by the Reloader; callers have already validated the pair,
// but X509KeyPair re-checks that the key matches the leaf.
func loadCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCertParse, certPath)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParse, keyPath)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyMismatch, certPath)
	}
	if pair.Leaf == nil && len(pair.Certificate) > 0 {
		leaf, perr := x509.ParseCertificate(pair.Certificate[0])
		if perr != nil {
			return nil, fmt.Errorf("%w: %s", ErrCertParse, certPath)
		}
		pair.Leaf = leaf
	}
	return &pair, nil
}
