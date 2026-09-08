// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"errors"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// TestP1PrecedenceAndClassification is the §2 precedence table: (flags, config,
// legacy, self-signed, none) × (gui, serve). Each row asserts the resolved
// Source, whether TLS is on, the paths, and — for the self-signed tiers — the
// SelfSigned classification (C7). Half a pair at the winning tier returns
// ErrHalfPair naming both fields. Every row asserts; there are no vacuous rows.
func TestP1PrecedenceAndClassification(t *testing.T) {
	ca := newTestCA(t)
	// A single app home for the self-signed floor row (writes under config/tls).
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

	// caPair returns a fresh valid CA-issued (bring-your-own) pair.
	caPair := func(cn string) (string, string) {
		certPEM, keyPEM, _ := ca.issue(t, leafSpec{cn: cn})
		return writePair(t, t.TempDir(), certPEM, keyPEM)
	}
	// ssPair returns a fresh valid self-signed pair (issuer == subject).
	ssPair := func(cn string) (string, string) {
		certPEM, keyPEM, _ := selfSigned(t, leafSpec{cn: cn})
		return writePair(t, t.TempDir(), certPEM, keyPEM)
	}

	type row struct {
		name           string
		build          func() Options
		wantErrIs      error    // non-nil ⇒ Resolve must return this sentinel
		wantMsgHas     []string // substrings the error message must contain
		wantSource     Source
		wantTLSOn      bool
		wantSelfSigned bool
		wantHavePaths  bool // resolved cert/key paths are non-empty
	}

	rows := []row{
		{
			name: "flags/gui",
			build: func() Options {
				c, k := caPair("gui.flags.example")
				return Options{CertFlag: c, KeyFlag: k, Purpose: PurposeGUI, Cfg: appconfig.Default()}
			},
			wantSource: SourceFlags, wantTLSOn: true, wantSelfSigned: false, wantHavePaths: true,
		},
		{
			name: "flags/serve",
			build: func() Options {
				c, k := caPair("serve.flags.example")
				return Options{CertFlag: c, KeyFlag: k, Purpose: PurposeServe, Cfg: appconfig.Default()}
			},
			wantSource: SourceFlags, wantTLSOn: true, wantHavePaths: true,
		},
		{
			name: "config/gui",
			build: func() Options {
				c, k := caPair("gui.config.example")
				cfg := appconfig.Default()
				cfg.TLS.CertFile, cfg.TLS.KeyFile = c, k
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantSource: SourceConfig, wantTLSOn: true, wantHavePaths: true,
		},
		{
			name: "config/serve",
			build: func() Options {
				c, k := caPair("serve.config.example")
				cfg := appconfig.Default()
				cfg.TLS.CertFile, cfg.TLS.KeyFile = c, k
				return Options{Purpose: PurposeServe, Cfg: cfg}
			},
			wantSource: SourceConfig, wantTLSOn: true, wantHavePaths: true,
		},
		{
			name: "legacy-byo/gui",
			build: func() Options {
				c, k := caPair("gui.legacy.example")
				cfg := appconfig.Default()
				cfg.GUI.CertFile, cfg.GUI.KeyFile = c, k
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantSource: SourceLegacyGUI, wantTLSOn: true, wantSelfSigned: false, wantHavePaths: true,
		},
		{
			name: "legacy-selfsigned-issuer/gui", // C7: issuer==subject ⇒ SelfSigned
			build: func() Options {
				c, k := ssPair("gui.legacy.ss.example")
				cfg := appconfig.Default()
				cfg.GUI.CertFile, cfg.GUI.KeyFile = c, k
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantSource: SourceLegacyGUI, wantTLSOn: true, wantSelfSigned: true, wantHavePaths: true,
		},
		{
			name: "legacy-selfsigned-flag/gui", // C7: GUI.SelfSigned=true ⇒ SelfSigned
			build: func() Options {
				c, k := caPair("gui.legacy.flag.example")
				cfg := appconfig.Default()
				cfg.GUI.CertFile, cfg.GUI.KeyFile = c, k
				cfg.GUI.SelfSigned = true
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantSource: SourceLegacyGUI, wantTLSOn: true, wantSelfSigned: true, wantHavePaths: true,
		},
		{
			name: "self-signed-floor/gui", // gui + protocol https, nothing configured
			build: func() Options {
				cfg := appconfig.Default()
				cfg.GUI.Protocol = "https"
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantSource: SourceSelfSigned, wantTLSOn: true, wantSelfSigned: true, wantHavePaths: true,
		},
		{
			name: "none/gui", // gui + protocol http, nothing configured
			build: func() Options {
				cfg := appconfig.Default()
				cfg.GUI.Protocol = "http"
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantSource: SourceNone, wantTLSOn: false, wantHavePaths: false,
		},
		{
			name: "legacy-not-inherited/serve", // serve must NOT read gui legacy fields (I-T4)
			build: func() Options {
				c, k := caPair("serve.legacy.example")
				cfg := appconfig.Default()
				cfg.GUI.CertFile, cfg.GUI.KeyFile = c, k
				return Options{Purpose: PurposeServe, Cfg: cfg}
			},
			wantSource: SourceNone, wantTLSOn: false, wantHavePaths: false,
		},
		{
			name: "self-signed-floor-not-for-serve", // serve has no self-signed floor
			build: func() Options {
				cfg := appconfig.Default()
				cfg.GUI.Protocol = "https"
				return Options{Purpose: PurposeServe, Cfg: cfg}
			},
			wantSource: SourceNone, wantTLSOn: false, wantHavePaths: false,
		},
		{
			name: "none/serve",
			build: func() Options {
				return Options{Purpose: PurposeServe, Cfg: appconfig.Default()}
			},
			wantSource: SourceNone, wantTLSOn: false, wantHavePaths: false,
		},
		{
			name: "half-pair-flags/gui", // cert flag without key flag
			build: func() Options {
				c, _ := caPair("gui.half.example")
				return Options{CertFlag: c, Purpose: PurposeGUI, Cfg: appconfig.Default()}
			},
			wantErrIs: ErrHalfPair, wantMsgHas: []string{"--tls-cert", "--tls-key"},
		},
		{
			name: "half-pair-flags/serve", // key flag without cert flag
			build: func() Options {
				_, k := caPair("serve.half.example")
				return Options{KeyFlag: k, Purpose: PurposeServe, Cfg: appconfig.Default()}
			},
			wantErrIs: ErrHalfPair, wantMsgHas: []string{"--tls-cert", "--tls-key"},
		},
		{
			name: "half-pair-config/gui", // config cert without config key
			build: func() Options {
				c, _ := caPair("gui.halfcfg.example")
				cfg := appconfig.Default()
				cfg.TLS.CertFile = c
				return Options{Purpose: PurposeGUI, Cfg: cfg}
			},
			wantErrIs: ErrHalfPair, wantMsgHas: []string{"tls.certFile", "tls.keyFile"},
		},
	}

	if len(rows) == 0 {
		t.Fatal("P1 table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, err := Resolve(r.build())
			if r.wantErrIs != nil {
				if !errors.Is(err, r.wantErrIs) {
					t.Fatalf("Resolve error = %v, want errors.Is %v", err, r.wantErrIs)
				}
				for _, sub := range r.wantMsgHas {
					if !strings.Contains(err.Error(), sub) {
						t.Fatalf("error %q must name %q", err.Error(), sub)
					}
				}
				if got != nil {
					t.Fatalf("Resolve must return nil Resolved on error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("Resolve returned nil Resolved without error")
			}
			if got.Source != r.wantSource {
				t.Fatalf("Source = %q, want %q", got.Source, r.wantSource)
			}
			if (got.TLS != nil) != r.wantTLSOn {
				t.Fatalf("TLS on = %v, want %v (Source %q)", got.TLS != nil, r.wantTLSOn, got.Source)
			}
			if got.SelfSigned != r.wantSelfSigned {
				t.Fatalf("SelfSigned = %v, want %v (Source %q)", got.SelfSigned, r.wantSelfSigned, got.Source)
			}
			havePaths := got.CertPath != "" && got.KeyPath != ""
			if havePaths != r.wantHavePaths {
				t.Fatalf("have paths = %v (cert %q key %q), want %v", havePaths, got.CertPath, got.KeyPath, r.wantHavePaths)
			}
			if r.wantTLSOn {
				// A TLS-on row must serve a real certificate through GetCertificate.
				if got.TLS.GetCertificate == nil {
					t.Fatal("TLS.GetCertificate must be set for a TLS-on resolution")
				}
				cert, cerr := got.TLS.GetCertificate(nil)
				if cerr != nil || cert == nil || cert.Leaf == nil {
					t.Fatalf("GetCertificate must return a loaded leaf: cert=%v err=%v", cert, cerr)
				}
				if got.NotAfter.IsZero() {
					t.Fatal("NotAfter must be set for a TLS-on resolution")
				}
			}
		})
	}
}

// TestP3StartupKeyMismatchRefusal (C13): a CONFIGURED full pair whose key does
// not match the leaf makes Resolve return ErrKeyMismatch and bind nothing — a
// path distinct from ErrHalfPair (P1) and from reload (R1). Proven for both a
// flags-tier and a config-tier configured pair, for gui and serve.
func TestP3StartupKeyMismatchRefusal(t *testing.T) {
	ca := newTestCA(t)

	// A full-but-mismatched pair: a CA-issued leaf plus the PEM of a DIFFERENT key.
	mismatched := func() (certPath, keyPath string) {
		leafKey := genKey(t)
		certPEM, _, _ := ca.issue(t, leafSpec{cn: "mismatch.example", key: leafKey})
		wrongKeyPEM := keyToPEM(t, genKey(t)) // a key that does not match the leaf
		return writePair(t, t.TempDir(), certPEM, wrongKeyPEM)
	}

	type row struct {
		name  string
		build func() Options
	}
	rows := []row{
		{"flags/gui", func() Options {
			c, k := mismatched()
			return Options{CertFlag: c, KeyFlag: k, Purpose: PurposeGUI, Cfg: appconfig.Default()}
		}},
		{"flags/serve", func() Options {
			c, k := mismatched()
			return Options{CertFlag: c, KeyFlag: k, Purpose: PurposeServe, Cfg: appconfig.Default()}
		}},
		{"config/gui", func() Options {
			c, k := mismatched()
			cfg := appconfig.Default()
			cfg.TLS.CertFile, cfg.TLS.KeyFile = c, k
			return Options{Purpose: PurposeGUI, Cfg: cfg}
		}},
	}
	if len(rows) == 0 {
		t.Fatal("P3 table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, err := Resolve(r.build())
			if !errors.Is(err, ErrKeyMismatch) {
				t.Fatalf("Resolve error = %v, want errors.Is ErrKeyMismatch", err)
			}
			if errors.Is(err, ErrHalfPair) {
				t.Fatal("a mismatched full pair must be ErrKeyMismatch, not ErrHalfPair")
			}
			if got != nil {
				t.Fatalf("Resolve must bind nothing on mismatch, got %+v", got)
			}
		})
	}
}
