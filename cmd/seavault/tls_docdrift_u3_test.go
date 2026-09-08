// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/setup"
)

// TestTLSDocsDriftD1 is the design §7 D1 row (drift guard; C4, C9). The
// documentation slice ships docs/tls-and-certificates.md, a SECURITY.md
// "Network-exposed mode" section, and README links. This test fails the build if
// any of them drifts from the authoritative sources:
//
//  1. Every TLS command and flag the guide names actually exists in the CLI
//     --help surface (built from the real usage writers), and the guide names
//     each one — so the guide can never reference a command/flag that does not
//     exist, nor silently omit one.
//  2. The provider table in the guide equals the wizard's authoritative
//     setup.DNSProviders() table (display name, lego code, certbot plugin, and
//     every environment variable), asserted on EVERY row (an empty table is
//     itself a failure — no vacuous pass).
//  3. Route B names the lego install step (C4).
//  4. SECURITY.md carries the "Network-exposed mode" heading and BOTH residual
//     sentences verbatim (C9 / I-T7).
//  5. README links the guide from the GUI and WebDAV sections.
func TestTLSDocsDriftD1(t *testing.T) {
	doc := mustReadRepoFile(t, filepath.Join("..", "..", "docs", "tls-and-certificates.md"))
	security := mustReadRepoFile(t, filepath.Join("..", "..", "SECURITY.md"))
	readme := mustReadRepoFile(t, filepath.Join("..", "..", "README.md"))
	help := tlsHelpCorpus(t)

	// 1a. The five `tls` subcommands. The `tls` command group's own --help line
	//     (tlsUsage) names each subcommand; the guide must name each as a full
	//     `seavault tls <sub>` command. This catches a subcommand that the guide
	//     documents but the CLI does not expose (or vice versa).
	tlsHelp := tlsUsage()
	for _, sub := range []string{"setup", "use", "status", "check", "reset"} {
		if !strings.Contains(tlsHelp, sub) {
			t.Errorf("D1: `tls %s` named in the guide is absent from the tls --help line (command drift): %q", sub, tlsHelp)
		}
		if full := "seavault tls " + sub; !strings.Contains(doc, full) {
			t.Errorf("D1: docs/tls-and-certificates.md does not name the command %q", full)
		}
	}

	// 1b. The TLS flags. Each must resolve in BOTH the real --help corpus (proving
	//     it exists on serve/gui/tls) and the guide (proving the guide names it).
	//     The bare `--tls` flag is matched with a not-followed-by-dash pattern so
	//     it is never satisfied vacuously by `--tls-cert` / `--tls-key`.
	bareTLS := regexp.MustCompile(`--tls(?:[^-]|$)`)
	flags := []struct {
		tok string
		re  *regexp.Regexp
	}{
		{"--tls-cert", nil},
		{"--tls-key", nil},
		{"--tls", bareTLS},
		{"--cert", nil},
		{"--key", nil},
		{"--allow-host", nil},
	}
	match := func(hay, tok string, re *regexp.Regexp) bool {
		if re != nil {
			return re.MatchString(hay)
		}
		return strings.Contains(hay, tok)
	}
	for _, f := range flags {
		if !match(help, f.tok, f.re) {
			t.Errorf("D1: flag %q named in the guide is absent from the CLI --help surface (flag drift)", f.tok)
		}
		if !match(doc, f.tok, f.re) {
			t.Errorf("D1: docs/tls-and-certificates.md does not name flag %q", f.tok)
		}
	}

	// 2. Provider table equals the wizard's authoritative table, every row.
	provs := setup.DNSProviders()
	if len(provs) == 0 {
		t.Fatal("D1: setup.DNSProviders() is empty; the provider table must list at least one provider")
	}
	for _, p := range provs {
		wants := []string{p.Display, p.LegoName, "dns-" + p.CertbotPlugin}
		wants = append(wants, p.EnvVars...)
		for _, w := range wants {
			if strings.TrimSpace(w) == "" {
				t.Errorf("D1: provider %q has an empty field; the wizard table must be fully populated", p.Key)
				continue
			}
			if !strings.Contains(doc, w) {
				t.Errorf("D1: provider %q — the guide's provider table is missing %q (drift from setup.DNSProviders())", p.Key, w)
			}
		}
	}

	// 3. Route B names the lego install step (C4). This must match the exact
	//    string the wizard prints in the binary-not-found branch.
	const legoInstall = "go install github.com/go-acme/lego/v4/cmd/lego@latest"
	if !strings.Contains(doc, legoInstall) {
		t.Errorf("D1: Route B must name the lego install step (C4): %q", legoInstall)
	}

	// 4. SECURITY.md: the section heading and both residual sentences (C9/I-T7).
	if !strings.Contains(security, "Network-exposed mode") {
		t.Error(`D1: SECURITY.md must contain the "Network-exposed mode" section heading (I-T7)`)
	}
	residuals := []string{
		"the GUI login and WebDAV Basic auth become network-facing (rate limiting and lockout are a later phase)",
		"clients that accept a self-signed prompt are MITM-able on first connect",
	}
	for _, s := range residuals {
		if !strings.Contains(security, s) {
			t.Errorf("D1: SECURITY.md is missing the residual sentence (I-T7): %q", s)
		}
	}

	// 5. README links the guide from the GUI and WebDAV sections (two links). Count
	//    the markdown link TARGET form so each real link counts once (a plain
	//    `docs/tls-and-certificates.md` string appears twice per markdown link).
	const guideTarget = "](docs/tls-and-certificates.md)"
	if n := strings.Count(readme, guideTarget); n < 2 {
		t.Errorf("D1: README must link docs/tls-and-certificates.md from the GUI and WebDAV sections (found %d links, want >= 2)", n)
	}
}

// tlsHelpCorpus assembles the real CLI --help surface from the authoritative
// usage writers: the top-level usage text, the `tls` command-group usage line,
// and the serve/gui subcommand usage strings (returned as errors for a wrong
// argument count, which is the only branch reached — neither loads config nor
// binds a listener). The corpus is the source of truth for "the flag exists".
func tlsHelpCorpus(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(usageText())
	b.WriteByte('\n')
	b.WriteString(tlsUsage())
	b.WriteByte('\n')
	// serve with no positional argument returns its usage string before any side
	// effect (NArg() != 1); it names --tls-cert/--tls-key/--tls/--allow-host.
	if err := cmdServe(nil); err != nil {
		b.WriteString(err.Error())
		b.WriteByte('\n')
	} else {
		t.Fatal("cmdServe(nil) was expected to return its usage error")
	}
	// gui with two positional arguments returns its usage string before any side
	// effect (NArg() > 1); it names --tls-cert/--tls-key/--allow-host.
	if err := cmdGUI([]string{"__x__", "__y__"}); err != nil {
		b.WriteString(err.Error())
		b.WriteByte('\n')
	} else {
		t.Fatal("cmdGUI two-arg call was expected to return its usage error")
	}
	return b.String()
}

func mustReadRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return string(b)
}

// TestTLSDocsDriftD1FixTranche extends the §7 D1 drift guard to the doc sections
// added by the U3 F-D fix tranche (friction A3-c1 / A3-c2 / A3-c5 / A1-c5 / A1-c6).
// Each new section carries a load-bearing anchor string; the build fails if any of
// them is removed or renamed, so the guide can never silently drop the how-to that
// closes a filed friction finding. Every row asserts (an empty table is a failure).
func TestTLSDocsDriftD1FixTranche(t *testing.T) {
	doc := mustReadRepoFile(t, filepath.Join("..", "..", "docs", "tls-and-certificates.md"))

	rows := []struct {
		finding string
		want    string
	}{
		// A3-c1 — decision aid mapping the reader's situation to a route.
		{"A3-c1 decision aid", "## Which route fits your situation?"},
		// A3-c1 (TLS-9) — make the SAN resolve on the LAN without internal DNS.
		{"A3-c1 name-resolve section", "## Making the certificate name resolve on the LAN"},
		{"A3-c1 bare-IP statement", "Connecting by bare IP cannot"},
		{"A3-c1 name-only certificate", "name-only certificate"},
		{"A3-c1 Windows hosts path", `C:\Windows\System32\drivers\etc\hosts`},
		{"A3-c1 macOS dns flush", "dscacheutil -flushcache"},
		{"A3-c1 router/local-DNS A record", "local-DNS A record"},
		// A3-c2 — the net use UNC form and the WebClient prerequisites.
		{"A3-c2 net use UNC @SSL@ form", "@SSL@"},
		{"A3-c2 WebClient auto-start", "sc config WebClient start= auto"},
		{"A3-c2 WebClient start", "net start WebClient"},
		// A3-c5 — concrete per-OS firewall commands.
		{"A3-c5 ufw", "ufw allow from"},
		{"A3-c5 firewalld", "firewall-cmd"},
		{"A3-c5 macOS pf", "pfctl"},
		{"A3-c5 Windows netsh", "netsh advfirewall firewall add rule"},
		// A1-c5 — reaching a headless host from a phone (text + QR).
		{"A1-c5 phone section", "## Reaching a headless host from a phone"},
		{"A1-c5 QR tool", "qrencode"},
		// A1-c6 — renewal cadence (daily lego/certbot vs monthly Tailscale) and the
		// tls check non-zero exit on an expired leaf (after F-A).
		{"A1-c6 tailscale not-idempotent", "not an idempotent renew"},
		{"A1-c6 monthly cadence", "OnCalendar=monthly"},
		{"A1-c6 tls check expiry exit", "including an expired or not-yet-valid certificate"},
	}
	if len(rows) == 0 {
		t.Fatal("D1 fix-tranche drift table is empty")
	}
	for _, r := range rows {
		if !strings.Contains(doc, r.want) {
			t.Errorf("D1 (fix tranche): docs/tls-and-certificates.md is missing the %s anchor %q", r.finding, r.want)
		}
	}
}
