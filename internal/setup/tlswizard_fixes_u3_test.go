// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// --- wizard-tools-1: domain validation + shell-quoting -------------------

// TestNormalizeDNSNameTable (wizard-tools-1/2): the domain/name normalizer accepts
// valid dotted DNS names (and one wildcard label) and REJECTS anything carrying
// whitespace, a shell metacharacter, a path separator, or a bad label — so nothing
// derived from it can be hostile. Every row is asserted.
func TestNormalizeDNSNameTable(t *testing.T) {
	rows := []struct {
		in     string
		wantOK bool
		want   string
	}{
		{"vault.example.com", true, "vault.example.com"},
		{"Vault.Example.COM", true, "vault.example.com"},
		{"*.example.com", true, "*.example.com"},
		{"host.tailnet-name.ts.net.", true, "host.tailnet-name.ts.net"},
		{"a.io;touch INJECTED;#", false, ""},
		{"has space.com", false, ""},
		{"../../../PWNED_TS", false, ""},
		{"/tmp/HIJACK", false, ""},
		{"-bad.example.com", false, ""},
		{"bad-.example.com", false, ""},
		{"single", false, ""},
		{"", false, ""},
		{"a..b.com", false, ""},
		{"*.*.example.com", false, ""},
	}
	if len(rows) == 0 {
		t.Fatal("normalizeDNSName table is empty")
	}
	for _, r := range rows {
		got, ok := normalizeDNSName(r.in)
		if ok != r.wantOK {
			t.Fatalf("normalizeDNSName(%q) ok=%v want %v (got %q)", r.in, ok, r.wantOK, got)
		}
		if ok && got != r.want {
			t.Fatalf("normalizeDNSName(%q)=%q want %q", r.in, got, r.want)
		}
	}
}

// TestLetsEncryptGuidanceShellQuotesHostileValues (wizard-tools-1): even a hostile
// domain reaching the guidance builder directly (defence in depth, past the flow's
// own validation) is single-quoted everywhere it is interpolated into the printed
// lego AND certbot commands — including the --email derived from the domain — so a
// pasted command cannot inject.
func TestLetsEncryptGuidanceShellQuotesHostileValues(t *testing.T) {
	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	const hostile = "a.io;touch INJECTED;#"
	prov := dnsProviders[0]
	for _, tool := range []string{"lego", "certbot"} {
		lines := letsEncryptGuidance(tool, prov, hostile, "/x/y z", "/c", "/k", deps)
		out := strings.Join(lines, "\n")
		if !strings.Contains(out, "'you@a.io;touch INJECTED;#'") {
			t.Fatalf("%s: the --email value is not shell-quoted (injectable):\n%s", tool, out)
		}
		if !strings.Contains(out, "'a.io;touch INJECTED;#'") {
			t.Fatalf("%s: the --domains value is not shell-quoted (injectable):\n%s", tool, out)
		}
		// The bare injection payload must never appear on a run-command line
		// outside single quotes.
		for _, l := range lines {
			if !strings.Contains(l, "touch INJECTED") {
				continue
			}
			if strings.Contains(l, "you@a.io;touch INJECTED;#") && !strings.Contains(l, "'you@a.io;touch INJECTED;#'") {
				t.Fatalf("%s: email interpolated UNQUOTED:\n%s", tool, l)
			}
		}
	}
}

// TestTLSWizardLetsEncryptRejectsHostileDomain (wizard-tools-1): a hostile domain
// entered at the prompt is rejected with a remedy and never flows into any printed
// command; the wizard returns to the route menu.
func TestTLSWizardLetsEncryptRejectsHostileDomain(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	calls := 0
	s := &tlsScript{t: t}
	s.selectBy = func(title string, opts []Option, def int) int {
		switch {
		case strings.Contains(title, "Who needs"):
			return 1
		case strings.Contains(title, "How do you want to obtain"):
			calls++
			if calls == 1 {
				return int(routeLetsEncrypt)
			}
			return int(routeSelfSigned)
		}
		return def
	}
	s.textBy = func(label, def string) string {
		if strings.Contains(label, "domain") {
			return "a.io;touch INJECTED;#"
		}
		return def
	}
	s.confirmBy = declineProbe
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	out := s.shownJoined()
	if !strings.Contains(strings.ToLower(out), "not a valid domain") {
		t.Fatalf("hostile domain was not rejected with a remedy:\n%s", out)
	}
	if strings.Contains(out, "touch INJECTED") {
		t.Fatalf("the hostile domain flowed into printed output:\n%s", out)
	}
}

// --- wizard-tools-2: tailscale MagicDNS name validation + argv hygiene ---

// TestTLSWizardTailscaleRejectsHostileMagicDNSName (wizard-tools-2): a tailscale
// status reporting a path-traversal MagicDNS name is refused BEFORE it is used as a
// filesystem path or an argv, and `tailscale cert` is never run.
func TestTLSWizardTailscaleRejectsHostileMagicDNSName(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	var runs []string
	deps := TLSDeps{
		LookPath: lookPathPresent("tailscale"),
		Run: func(name string, args ...string) ([]byte, error) {
			runs = append(runs, name+" "+strings.Join(args, " "))
			return nil, errors.New("must not run")
		},
		ReadTailscaleStatus: func() (TailscaleStatus, error) {
			return TailscaleStatus{MagicDNSName: "../../../PWNED_TS", TailnetName: "x"}, nil
		},
	}
	calls := 0
	s := &tlsScript{t: t}
	s.selectBy = func(title string, opts []Option, def int) int {
		switch {
		case strings.Contains(title, "Who needs"):
			return 1
		case strings.Contains(title, "How do you want to obtain"):
			calls++
			if calls == 1 {
				return int(routeTailscale)
			}
			return int(routeSelfSigned)
		}
		return def
	}
	s.confirmBy = declineProbe
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("a hostile MagicDNS name must be refused before `tailscale cert` runs; ran %v", runs)
	}
	if !strings.Contains(strings.ToLower(s.shownJoined()), "refusing to use it") {
		t.Fatalf("hostile MagicDNS name was not rejected with a remedy:\n%s", s.shownJoined())
	}
}

// TestTLSWizardTailscalePassesNameAfterDoubleDash (wizard-tools-2): the validated
// MagicDNS name is passed to `tailscale cert` after a `--` terminator, so a value
// beginning with `-` can never be read as a flag.
func TestTLSWizardTailscalePassesNameAfterDoubleDash(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newTestCA(t)
	var runs []string
	deps := TLSDeps{
		LookPath: lookPathPresent("tailscale"),
		Run:      tailscaleRunFake(t, ca, &runs),
		ReadTailscaleStatus: func() (TailscaleStatus, error) {
			return TailscaleStatus{MagicDNSName: "myhost.tailnet-name.ts.net", TailnetName: "tailnet-name.ts.net"}, nil
		},
	}
	s := &tlsScript{t: t, selectBy: routeSelector(routeTailscale), confirmBy: func(q string, def bool) bool {
		switch {
		case strings.Contains(q, "tailscale cert"):
			return true
		case strings.Contains(q, "trust check"):
			return false
		}
		return def
	}}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("want exactly one run, got %v", runs)
	}
	if !strings.Contains(runs[0], " -- myhost.tailnet-name.ts.net") {
		t.Fatalf("the MagicDNS name must be passed after a `--` terminator; argv: %q", runs[0])
	}
}

// --- A1-c4: listen-step default, address list, serve-port derivation -----

// TestClassifyChoicesFiltersAndFlags (A1-c4 address list): container/bridge/virtual
// and link-local and down/loopback interfaces are dropped; each survivor is
// annotated with its interface name; the Tailscale address is flagged and sorts
// first.
func TestClassifyChoicesFiltersAndFlags(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }
	ifaces := []ifaceInfo{
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []net.IP{ip("127.0.0.1")}},
		{name: "eno1", flags: net.FlagUp, addrs: []net.IP{ip("192.168.1.5")}},
		{name: "docker0", flags: net.FlagUp, addrs: []net.IP{ip("172.17.0.1")}},
		{name: "br-abc123", flags: net.FlagUp, addrs: []net.IP{ip("172.18.0.1")}},
		{name: "virbr0", flags: net.FlagUp, addrs: []net.IP{ip("192.168.122.1")}},
		{name: "tailscale0", flags: net.FlagUp, addrs: []net.IP{ip("100.101.102.103")}},
		{name: "wlan0", flags: net.FlagUp, addrs: []net.IP{ip("169.254.7.7")}}, // link-local
		{name: "eth-down", flags: 0, addrs: []net.IP{ip("10.0.0.9")}},          // down
	}
	got := classifyChoices(ifaces)
	byIP := map[string]interfaceChoice{}
	for _, c := range got {
		byIP[c.ip] = c
	}
	if _, ok := byIP["192.168.1.5"]; !ok {
		t.Fatalf("the real LAN address was filtered out: %+v", got)
	}
	ts, ok := byIP["100.101.102.103"]
	if !ok {
		t.Fatalf("the tailscale address was filtered out: %+v", got)
	}
	if !ts.isTailscale {
		t.Fatalf("the tailscale address was not flagged: %+v", ts)
	}
	if ts.iface != "tailscale0" {
		t.Fatalf("the interface name was not annotated: %+v", ts)
	}
	for _, bad := range []string{"127.0.0.1", "172.17.0.1", "172.18.0.1", "192.168.122.1", "169.254.7.7", "10.0.0.9"} {
		if _, ok := byIP[bad]; ok {
			t.Fatalf("address %s should have been filtered out: %+v", bad, got)
		}
	}
	if len(got) == 0 || !got[0].isTailscale {
		t.Fatalf("the tailscale address must sort first: %+v", got)
	}
}

// TestBuildListenOptionsNeverDefaultsEveryInterface (A1-c4 listen default): the
// listen menu defaults to the single most-specific address (the Tailscale one when
// present) and NEVER to every interface; with no addresses it defaults to the
// custom prompt, still not every interface.
func TestBuildListenOptionsNeverDefaultsEveryInterface(t *testing.T) {
	choices := []interfaceChoice{
		{ip: "100.101.102.103", iface: "tailscale0", isTailscale: true},
		{ip: "192.168.1.5", iface: "eno1"},
	}
	opts, def, every, custom := buildListenOptions(choices)
	if def == every {
		t.Fatal("must not default to every interface")
	}
	if def < 0 || def >= every {
		t.Fatalf("default index %d must be a concrete address index (< %d)", def, every)
	}
	if !strings.Contains(opts[def].Label, "100.101.102.103") || !strings.Contains(opts[def].Label, "Tailscale") {
		t.Fatalf("the default should be the Tailscale address, got %q", opts[def].Label)
	}
	if !strings.Contains(strings.ToLower(opts[every].Label), "every interface") {
		t.Fatalf("the every-interface option is missing: %q", opts[every].Label)
	}
	_, def0, every0, custom0 := buildListenOptions(nil)
	if def0 == every0 {
		t.Fatal("with no addresses, must not default to every interface")
	}
	if def0 != custom0 {
		t.Fatalf("with no addresses, default should be the custom prompt (%d), got %d", custom0, def0)
	}
	_ = custom
}

// TestServeBindForDistinctPort (A1-c4 serve port): the WebDAV bind keeps the host
// but always takes a DIFFERENT port from the GUI, no matter which port the GUI
// uses — never reusing the GUI's host:port.
func TestServeBindForDistinctPort(t *testing.T) {
	rows := []struct{ gui, want string }{
		{"192.168.1.5:8787", "192.168.1.5:8765"},
		{"192.168.1.5:9999", "192.168.1.5:8765"},
		{"192.168.1.5:8765", "192.168.1.5:8766"},
		{":8787", ":8765"},
	}
	if len(rows) == 0 {
		t.Fatal("serveBindFor table is empty")
	}
	for _, r := range rows {
		got := serveBindFor(r.gui)
		if got != r.want {
			t.Fatalf("serveBindFor(%q)=%q want %q", r.gui, got, r.want)
		}
		if got == r.gui {
			t.Fatalf("serve bind %q must differ from the gui bind %q", got, r.gui)
		}
	}
}

// --- A1-c6: renewal snippets carry concrete values -----------------------

// TestShowRenewalSubstitutesConcreteValues (A1-c6): the cron/systemd/schtasks
// snippets carry the concrete renew command and name, with no bare "<renew
// command>"/"<name>" placeholder left behind.
func TestShowRenewalSubstitutesConcreteValues(t *testing.T) {
	rows := []struct {
		name         string
		recipe       renewalRecipe
		wantContains []string
	}{
		{
			"tailscale",
			renewalRecipe{route: routeNameTailscale, name: "myhost.tailnet.ts.net", command: "tailscale cert myhost.tailnet.ts.net"},
			[]string{"tailscale cert myhost.tailnet.ts.net"},
		},
		{
			"lego",
			renewalRecipe{route: routeNameLego, name: "vault.example.com", command: "lego --path /x --dns cloudflare --domains vault.example.com renew"},
			[]string{"vault.example.com renew"},
		},
	}
	if len(rows) == 0 {
		t.Fatal("renewal table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := &tlsScript{t: t}
			showRenewal(s, r.recipe)
			out := s.shownJoined()
			if strings.Contains(out, "<renew command>") || strings.Contains(out, "<name>") {
				t.Fatalf("renewal snippets still carry a bare placeholder:\n%s", out)
			}
			for _, w := range r.wantContains {
				if !strings.Contains(out, w) {
					t.Fatalf("missing concrete value %q in:\n%s", w, out)
				}
			}
			if !strings.Contains(out, "cron: 17 3 * * *  "+r.recipe.command) {
				t.Fatalf("the cron snippet did not carry the concrete command:\n%s", out)
			}
			lo := strings.ToLower(out)
			if !strings.Contains(lo, "systemd timer") || !strings.Contains(lo, "schtasks") {
				t.Fatalf("a scheduler snippet is missing:\n%s", out)
			}
		})
	}
}

// --- A1-c2: tailscale failure message ------------------------------------

// TestTLSWizardTailscaleFailureLeadsWithStderr (A1-c2): a `tailscale cert` failure
// leads with the tool's own stderr (not the raw Go "exit status N") and its remedy
// points back to the menu the wizard already sits at, not "re-run seavault tls
// setup".
func TestTLSWizardTailscaleFailureLeadsWithStderr(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	deps := TLSDeps{
		LookPath: lookPathPresent("tailscale"),
		Run: func(name string, args ...string) ([]byte, error) {
			return []byte("HTTPS is not enabled on your tailnet; enable it in the admin console"), errors.New("exit status 1")
		},
		ReadTailscaleStatus: func() (TailscaleStatus, error) {
			return TailscaleStatus{MagicDNSName: "host.example.ts.net", TailnetName: "example.ts.net"}, nil
		},
	}
	calls := 0
	s := &tlsScript{t: t}
	s.selectBy = func(title string, opts []Option, def int) int {
		switch {
		case strings.Contains(title, "Who needs"):
			return 1
		case strings.Contains(title, "How do you want to obtain"):
			calls++
			if calls == 1 {
				return int(routeTailscale)
			}
			return int(routeSelfSigned)
		}
		return def
	}
	s.confirmBy = func(q string, def bool) bool {
		switch {
		case strings.Contains(q, "tailscale cert"):
			return true
		case strings.Contains(q, "trust check"):
			return false
		}
		return def
	}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	out := s.shownJoined()
	if !strings.Contains(out, "HTTPS is not enabled on your tailnet") {
		t.Fatalf("the wizard did not surface the tool's stderr:\n%s", out)
	}
	if strings.Contains(out, "failed: exit status 1") {
		t.Fatalf("the wizard printed the raw Go error string above the stderr:\n%s", out)
	}
	if !strings.Contains(out, "choose Tailscale again from this menu") {
		t.Fatalf("the failure remedy must point back to the menu, not re-running the wizard:\n%s", out)
	}
}

// --- A1-c3: allowlist prompt jargon + consequence ------------------------

// TestStepAllowlistStatesConsequenceDropsJargon (A1-c3): the allowlist prompt drops
// the "rebinding guard" jargon and states the 403 consequence at the decision
// point, while still proposing the concrete SAN.
func TestStepAllowlistStatesConsequenceDropsJargon(t *testing.T) {
	s := &tlsScript{t: t}
	hosts := stepAllowlist(s, []string{"vault.example.com", "*.example.com"})
	out := s.shownJoined()
	if strings.Contains(strings.ToLower(out), "rebinding guard") {
		t.Fatalf("the allowlist prompt must not use rebinding-guard jargon:\n%s", out)
	}
	if strings.Contains(strings.ToLower(strings.Join(s.texts, "\n")), "rebinding guard") {
		t.Fatalf("the allowlist Text label still uses jargon: %v", s.texts)
	}
	if !strings.Contains(out, "403") {
		t.Fatalf("the allowlist prompt must state the 403 consequence:\n%s", out)
	}
	if !containsString(hosts, "vault.example.com") {
		t.Fatalf("the concrete host was dropped: %v", hosts)
	}
}

// --- A2-c2: wait loop does not re-spam guidance; checks immediately ------

// TestLetsEncryptWaitLoopImmediateAndNoReprint (A2-c2): the install/command
// guidance is printed once, the wait loop does not re-print the whole block, and
// files written during the Enter are detected immediately (no spurious "still
// waiting").
func TestLetsEncryptWaitLoopImmediateAndNoReprint(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newTestCA(t)
	const domain = "vault.example.com"
	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	tlsDir, _ := appdir.EnsureConfigDir("tls")
	certPath, keyPath := acmeOutputPaths("lego", tlsDir, domain)

	s := &tlsScript{t: t}
	s.selectBy = func(title string, opts []Option, def int) int {
		switch {
		case strings.Contains(title, "Who needs"):
			return 1
		case strings.Contains(title, "How do you want to obtain"):
			return int(routeLetsEncrypt)
		case strings.Contains(title, "DNS provider"):
			return 0
		case strings.Contains(title, "ACME client"):
			return 0
		}
		return def
	}
	s.textBy = func(label, def string) string {
		if strings.Contains(label, "domain") {
			return domain
		}
		return def
	}
	s.confirmBy = func(q string, def bool) bool {
		if strings.Contains(q, "trust check") {
			return false
		}
		return def
	}
	s.onConfirm = func(q string) {
		if strings.Contains(q, "Press Enter when the certificate files exist") {
			// The user "runs lego" during the FIRST press: files exist right away.
			certPEM, keyPEM := ca.issue(t, []string{domain}, nil)
			if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	out := s.shownJoined()
	// The install line is unique to the guidance block; if the wait loop re-spammed
	// the block it would appear more than once (A2-c2).
	if n := strings.Count(out, "lego/v4/cmd/lego@latest"); n != 1 {
		t.Fatalf("the guidance block must be printed exactly once, appeared %d times:\n%s", n, out)
	}
	if strings.Contains(out, "Still waiting") {
		t.Fatalf("files were materialised on Enter, so no 'still waiting' line should appear:\n%s", out)
	}
}

// --- A2-c3: BYO route prints its own renewal recipe ----------------------

// TestTLSWizardBYORenewalIsNotSelfSigned (A2-c3): a bring-your-own certificate gets
// a renew-at-your-CA-and-replace recipe, never the self-signed re-run.
func TestTLSWizardBYORenewalIsNotSelfSigned(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newTestCA(t)
	srcDir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, []string{"vault.corp.example"}, nil)
	certPath, keyPath := writePair(t, srcDir, certPEM, keyPEM)

	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	s := &tlsScript{t: t, selectBy: routeSelector(routeBYO), textBy: byoPaths(certPath, keyPath), confirmBy: declineProbe}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	out := s.shownJoined()
	lo := strings.ToLower(out)
	if strings.Contains(lo, "regenerate the self-signed") {
		t.Fatalf("the BYO route printed the self-signed renewal recipe:\n%s", out)
	}
	if !strings.Contains(lo, "replace these files in place") && !strings.Contains(lo, "your own ca") {
		t.Fatalf("the BYO route did not print its own renewal recipe:\n%s", out)
	}
}

// --- A3-c3: self-signed names de-dup + https explanation -----------------

// TestTLSWizardKeepSelfSignedDedupNamesAndExplainsHTTPS (A3-c3): the self-signed
// names line lists 127.0.0.1 exactly once, and the wizard states plainly that
// gui.protocol=https was set and what enabling HTTPS means.
func TestTLSWizardKeepSelfSignedDedupNamesAndExplainsHTTPS(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	s := &tlsScript{t: t, selectBy: routeSelector(routeSelfSigned), confirmBy: declineProbe}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	var namesLine string
	for _, l := range s.shown {
		if strings.Contains(l, "covers:") {
			namesLine = l
		}
	}
	if namesLine == "" {
		t.Fatalf("the self-signed route did not print a names line:\n%s", s.shownJoined())
	}
	if n := strings.Count(namesLine, "127.0.0.1"); n != 1 {
		t.Fatalf("the self-signed names line lists 127.0.0.1 %d times, want 1: %q", n, namesLine)
	}
	lo := strings.ToLower(s.shownJoined())
	if !strings.Contains(lo, "gui.protocol is now https") {
		t.Fatalf("the wizard did not state gui.protocol=https was set:\n%s", s.shownJoined())
	}
	if !strings.Contains(lo, "trust prompt") || (!strings.Contains(lo, "serves https") && !strings.Contains(lo, "https (not plain http)")) {
		t.Fatalf("the wizard did not explain what enabling https means:\n%s", s.shownJoined())
	}
}
