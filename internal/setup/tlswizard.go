// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/tlsconfig"
)

// TLSDeps is the external-tool seam for the `tls setup` wizard (design §4). Tool
// PRESENCE is probed with LookPath and tailnet identity is read with
// ReadTailscaleStatus; the ONLY tool the wizard ever RUNS is `tailscale cert`
// (no secret is involved), through Run. Let's Encrypt via lego/certbot is always
// PRINTED, never executed, and the wizard never asks for or stores a provider
// token — I-T5, proven by W6. Everything here is injectable so the tests drive a
// scripted tool seam.
type TLSDeps struct {
	// LookPath reports whether a tool binary is on PATH (default exec.LookPath).
	LookPath func(name string) (string, error)
	// Run invokes a tool and returns its combined output. The wizard calls it
	// ONLY for `tailscale cert`; a faithful default runs the process.
	Run func(name string, args ...string) ([]byte, error)
	// ReadTailscaleStatus reads this machine's tailnet identity (default: run
	// `tailscale status --json` and parse it).
	ReadTailscaleStatus func() (TailscaleStatus, error)
}

// TailscaleStatus is the non-secret subset of `tailscale status --json` the
// wizard needs: the machine's MagicDNS name (the cert's DNS SAN) and the tailnet.
type TailscaleStatus struct {
	MagicDNSName string // e.g. "myhost.tailnet-name.ts.net" (Self.DNSName, trailing dot trimmed)
	TailnetName  string // e.g. "tailnet-name.ts.net"
}

// DefaultTLSDeps returns the real, process-invoking seam used by the CLI.
func DefaultTLSDeps() TLSDeps {
	return TLSDeps{
		LookPath: exec.LookPath,
		Run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		ReadTailscaleStatus: readTailscaleStatusFromCLI,
	}
}

func (d TLSDeps) withDefaults() TLSDeps {
	def := DefaultTLSDeps()
	if d.LookPath == nil {
		d.LookPath = def.LookPath
	}
	if d.Run == nil {
		d.Run = def.Run
	}
	if d.ReadTailscaleStatus == nil {
		d.ReadTailscaleStatus = def.ReadTailscaleStatus
	}
	return d
}

// has reports whether a tool binary is present, tolerating a nil-path success.
func (d TLSDeps) has(name string) (string, bool) {
	p, err := d.LookPath(name)
	if err != nil || strings.TrimSpace(p) == "" {
		return "", false
	}
	return p, true
}

func readTailscaleStatusFromCLI() (TailscaleStatus, error) {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return TailscaleStatus{}, err
	}
	return parseTailscaleStatus(out)
}

// parseTailscaleStatus extracts the machine's MagicDNS name and tailnet from the
// `tailscale status --json` document. It reads only non-secret identity fields.
func parseTailscaleStatus(data []byte) (TailscaleStatus, error) {
	var raw struct {
		Self struct {
			DNSName string `json:"DNSName"`
		} `json:"Self"`
		MagicDNSSuffix string `json:"MagicDNSSuffix"`
		CurrentTailnet struct {
			Name           string `json:"Name"`
			MagicDNSSuffix string `json:"MagicDNSSuffix"`
		} `json:"CurrentTailnet"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return TailscaleStatus{}, err
	}
	name := strings.TrimSuffix(strings.TrimSpace(raw.Self.DNSName), ".")
	tailnet := strings.TrimSpace(raw.CurrentTailnet.Name)
	if tailnet == "" {
		tailnet = strings.TrimSpace(raw.MagicDNSSuffix)
	}
	return TailscaleStatus{MagicDNSName: name, TailnetName: tailnet}, nil
}

// DNSProvider is one row of the curated DNS-01 table (design §4 step 2): the
// display name, the lego provider code, the certbot plugin, the environment
// variable(s) the token goes in, and the least-privilege scope to grant. The
// wizard prints these; it never reads a token.
type DNSProvider struct {
	Key           string
	Display       string
	LegoName      string
	CertbotPlugin string
	EnvVars       []string
	Scope         string
}

// dnsProviders is the single source of truth for the DNS-01 provider table. The
// documentation slice (D1) asserts docs/tls-and-certificates.md matches this via
// DNSProviders().
var dnsProviders = []DNSProvider{
	{
		Key: "cloudflare", Display: "Cloudflare", LegoName: "cloudflare", CertbotPlugin: "cloudflare",
		EnvVars: []string{"CF_DNS_API_TOKEN"},
		Scope:   "an API token scoped to Zone:DNS:Edit on the single zone (a scoped API token, NOT the Global API Key)",
	},
	{
		Key: "route53", Display: "AWS Route 53", LegoName: "route53", CertbotPlugin: "route53",
		EnvVars: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		Scope:   "IAM credentials limited to route53:ChangeResourceRecordSets on the one hosted zone plus route53:GetChange and route53:ListHostedZonesByName",
	},
	{
		Key: "digitalocean", Display: "DigitalOcean", LegoName: "digitalocean", CertbotPlugin: "digitalocean",
		EnvVars: []string{"DO_AUTH_TOKEN"},
		Scope:   "a personal access token with write scope for DNS only",
	},
	{
		Key: "gcloud", Display: "Google Cloud DNS", LegoName: "gcloud", CertbotPlugin: "google",
		EnvVars: []string{"GCE_PROJECT", "GCE_SERVICE_ACCOUNT_FILE"},
		Scope:   "a service account with the DNS Administrator role scoped to the project, exported to a JSON key file",
	},
}

// DNSProviders returns a copy of the curated provider table for the docs drift
// guard (D1) and any other read-only consumer.
func DNSProviders() []DNSProvider {
	out := make([]DNSProvider, len(dnsProviders))
	copy(out, dnsProviders)
	return out
}

// tlsRoute enumerates the step-2 certificate routes in a FIXED order so a scripted
// prompter selects a route by a stable index regardless of tool detection.
type tlsRoute int

const (
	routeTailscale tlsRoute = iota
	routeLetsEncrypt
	routeBYO
	routeSelfSigned
)

// route names drive the renewal recipe (step 7).
const (
	routeNameTailscale  = "tailscale"
	routeNameLego       = "lego"
	routeNameCertbot    = "certbot"
	routeNameSelfSigned = "self-signed"
)

// maxCertWaitLoops bounds the "press Enter when the files exist" loop so a
// scripted or inattentive caller cannot spin forever when the files never appear.
const maxCertWaitLoops = 240

// RunTLSWizard drives the interactive `tls setup` wizard over the shared
// setup.Prompter (design §4). It handles NO secret — the wizard never prompts for
// a provider token and runs only `tailscale cert` (I-T5). Side effects are a
// single appconfig.Save of the resolved tls.* section (legacy fields cleared) and
// the printed guidance; the bind address is never persisted.
func RunTLSWizard(pr Prompter, deps TLSDeps) error {
	deps = deps.withDefaults()

	who, err := pr.Select(
		"Who needs to reach this vault's GUI or WebDAV endpoint?",
		[]Option{
			{Label: "Only this computer (loopback) — nothing extra is required"},
			{Label: "Other devices on my network or VPN"},
		}, 0)
	if err != nil {
		return err
	}
	if who == 0 {
		pr.Show("On loopback the GUI already works over plain HTTP and WebDAV needs no certificate — nothing is required.")
		on, err := pr.Confirm("Turn on HTTPS with a self-signed certificate for the GUI anyway?", false)
		if err != nil {
			return err
		}
		if !on {
			pr.Show("No change made. The GUI stays on http://127.0.0.1 (loopback) and WebDAV stays plaintext loopback.")
			return nil
		}
		return finishSelfSigned(pr)
	}

	// Other devices: choose and run a route, looping back to the menu on any
	// recoverable dead end (a validation failure, a cancelled tool, a key mismatch).
	for {
		route, err := chooseRoute(pr, deps)
		if err != nil {
			return err
		}
		var cert, key, routeName string
		var back bool
		switch route {
		case routeTailscale:
			cert, key, routeName, back = routeTailscaleFlow(pr, deps)
		case routeLetsEncrypt:
			cert, key, routeName, back = routeLetsEncryptFlow(pr, deps)
		case routeBYO:
			cert, key, routeName, back = routeBYOFlow(pr)
		case routeSelfSigned:
			return finishSelfSigned(pr)
		}
		if back {
			continue
		}

		// Step 3: validate the pair. A key mismatch names the remedy and returns to
		// the route menu; nothing is persisted on any validation failure.
		info, verr := tlsconfig.Validate(cert, key)
		if verr != nil {
			if errors.Is(verr, tlsconfig.ErrKeyMismatch) {
				pr.Show("The private key does not match the certificate. Re-export the matching key (or re-run the issuing tool), then choose a route again.")
			} else {
				pr.Show("The certificate pair could not be validated: " + verr.Error())
			}
			continue
		}
		showValidateSummary(pr, cert, key, info)

		// Step 4: names and allowlist (concrete DNS SANs; wildcards dropped, C5).
		allowHosts := stepAllowlist(pr, info.Names)

		// Step 5: where to listen (advisory; NOT persisted).
		stepListen(pr, allowHosts, info.Names)

		// Step 6: persist tls.* + gui.protocol=https; clear the legacy fields.
		if err := persistToolCert(cert, key, allowHosts); err != nil {
			return err
		}
		pr.Show("Saved. gui.protocol is now https, the shared tls section points at this certificate, and the legacy gui.certFile/keyFile were cleared.")

		// Step 7: renewal recipe for the chosen route.
		showRenewal(pr, routeName)

		// Step 8: optional local trust probe (advisory).
		maybeProbe(pr, allowHosts, info.Names)
		return nil
	}
}

// chooseRoute presents the four routes in a FIXED order, annotating the tools it
// detected. Tailscale is the default when present; otherwise DNS-01.
func chooseRoute(pr Prompter, deps TLSDeps) (tlsRoute, error) {
	tsPath, tsOK := deps.has("tailscale")
	legoPath, legoOK := deps.has("lego")
	certbotPath, certbotOK := deps.has("certbot")

	opts := []Option{
		{Label: annotate("Tailscale — issues a trusted certificate for your tailnet name", tsOK, tsPath)},
		{Label: annotate("Let's Encrypt via DNS-01 (lego or certbot) — for a public domain you control", legoOK || certbotOK, firstNonEmpty(legoPath, certbotPath))},
		{Label: "I already have certificate files (corporate CA, or another ACME client)"},
		{Label: "Keep the self-signed certificate (trust prompts on every device; Windows WebDAV refuses it)"},
	}
	def := int(routeLetsEncrypt)
	if tsOK {
		def = int(routeTailscale)
	}
	idx, err := pr.Select("How do you want to obtain a certificate the other devices will trust?", opts, def)
	if err != nil {
		return 0, err
	}
	if idx < 0 || idx > int(routeSelfSigned) {
		idx = def
	}
	return tlsRoute(idx), nil
}

// routeTailscaleFlow reads the tailnet name, explains the admin-console
// requirement, and RUNS `tailscale cert` into the app tls/ directory — the only
// tool the wizard ever executes (I-T5). On any failure it prints the remedy and
// returns to the route menu.
func routeTailscaleFlow(pr Prompter, deps TLSDeps) (cert, key, routeName string, back bool) {
	if _, ok := deps.has("tailscale"); !ok {
		pr.Show("The tailscale binary was not found. Install Tailscale from https://tailscale.com/download, then re-run `seavault tls setup`.")
		return "", "", "", true
	}
	st, err := deps.ReadTailscaleStatus()
	if err != nil {
		pr.Show("Could not read `tailscale status --json`: " + err.Error())
		pr.Show("Make sure Tailscale is running and you are logged in, then re-run `seavault tls setup`.")
		return "", "", "", true
	}
	name := strings.TrimSuffix(strings.TrimSpace(st.MagicDNSName), ".")
	if name == "" {
		pr.Show("Tailscale reported no MagicDNS name for this machine; enable MagicDNS in the tailnet admin console (https://login.tailscale.com/admin/dns), then re-run `seavault tls setup`.")
		return "", "", "", true
	}
	pr.Show("This machine's tailnet name is " + name + ".")
	pr.Show("HTTPS certificates must be ENABLED in your tailnet admin console (https://login.tailscale.com/admin/dns) — this is a common dead end; `tailscale cert` fails until it is turned on.")
	run, err := pr.Confirm("Run `tailscale cert` now to obtain the certificate? (no secret is involved, so this is safe to run)", true)
	if err != nil || !run {
		return "", "", "", true
	}
	dir, err := appdir.EnsureConfigDir("tls")
	if err != nil {
		pr.Show("Could not create the tls directory: " + err.Error())
		return "", "", "", true
	}
	cert = filepath.Join(dir, name+".crt")
	key = filepath.Join(dir, name+".key")
	out, runErr := deps.Run("tailscale", "cert", "--cert-file", cert, "--key-file", key, name)
	if runErr != nil {
		pr.Show("`tailscale cert` failed: " + runErr.Error())
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			pr.Show(trimmed)
		}
		pr.Show("If it reports that HTTPS is not enabled, turn on HTTPS certificates in the tailnet admin console (https://login.tailscale.com/admin/dns) and re-run `seavault tls setup`.")
		return "", "", "", true
	}
	pr.Show("Obtained a Tailscale certificate for " + name + " in " + dir + ".")
	return cert, key, routeNameTailscale, false
}

// routeLetsEncryptFlow guides a DNS-01 issuance with lego or certbot. It NEVER
// runs the tool and NEVER prompts for a token: it prints the install guidance
// FIRST when the binary is missing (C4), then the exact command with the
// least-privilege scope and expected output paths, then waits — re-checking for
// the files and keeping the guidance visible above the wait prompt.
func routeLetsEncryptFlow(pr Prompter, deps TLSDeps) (cert, key, routeName string, back bool) {
	domain, err := pr.Text("Which domain will the certificate cover? (e.g. vault.example.com; a wildcard like *.example.com is allowed)", "")
	if err != nil {
		return "", "", "", true
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		pr.Show("No domain entered; returning to the route menu.")
		return "", "", "", true
	}
	prov := chooseDNSProvider(pr)
	tool := chooseACMETool(pr, deps)

	dir, err := appdir.EnsureConfigDir("tls")
	if err != nil {
		pr.Show("Could not create the tls directory: " + err.Error())
		return "", "", "", true
	}
	cert, key = acmeOutputPaths(tool, dir, domain)

	guidance := letsEncryptGuidance(tool, prov, domain, dir, cert, key, deps)
	showLines(pr, guidance)

	for i := 0; i < maxCertWaitLoops; i++ {
		if fileExists(cert) && fileExists(key) {
			pr.Show("Found the certificate files.")
			return cert, key, routeNameFor(tool), false
		}
		cont, err := pr.Confirm("Press Enter when the certificate files exist (or answer 'n' to cancel)", true)
		if err != nil || !cont {
			pr.Show("Cancelled; returning to the route menu.")
			return "", "", "", true
		}
		// Keep the install and command guidance visible above the wait prompt (C4).
		pr.Show("Still waiting for:")
		pr.Show("  certificate: " + cert)
		pr.Show("  private key: " + key)
		showLines(pr, guidance)
	}
	pr.Show("Gave up waiting for the certificate files. Re-run `seavault tls setup` once the tool has written them.")
	return "", "", "", true
}

// routeBYOFlow references an existing pair in place (never copied) with the
// chain-order note.
func routeBYOFlow(pr Prompter) (cert, key, routeName string, back bool) {
	c, err := pr.Text("Path to your certificate (PEM chain, leaf first)", "")
	if err != nil {
		return "", "", "", true
	}
	k, err := pr.Text("Path to the matching private key (PEM)", "")
	if err != nil {
		return "", "", "", true
	}
	c, k = strings.TrimSpace(c), strings.TrimSpace(k)
	if c == "" || k == "" {
		pr.Show("Both a certificate and a key path are required; returning to the route menu.")
		return "", "", "", true
	}
	pr.Show("Order the certificate PEM leaf-first, then any intermediates; do NOT include the root. The files are referenced in place — never copied — so keep them where they are.")
	return c, k, "byo", false
}

// finishSelfSigned states the consequences, ensures the self-signed floor pair
// exists, persists gui.protocol=https with the shared section cleared, prints the
// renewal note, and offers the probe.
func finishSelfSigned(pr Prompter) error {
	pr.Show("Keeping a self-signed certificate: every device shows a trust prompt on first connect, and Windows' built-in WebDAV client refuses a self-signed certificate outright.")
	if err := persistSelfSigned(); err != nil {
		return err
	}
	pr.Show("Saved. gui.protocol is now https and the self-signed certificate will be served on the GUI.")
	showRenewal(pr, routeNameSelfSigned)
	maybeProbe(pr, nil, nil)
	return nil
}

// chooseDNSProvider presents the curated table plus an "other" escape.
func chooseDNSProvider(pr Prompter) DNSProvider {
	opts := make([]Option, 0, len(dnsProviders)+1)
	for _, p := range dnsProviders {
		opts = append(opts, Option{Label: p.Display + " (lego code: " + p.LegoName + ")"})
	}
	opts = append(opts, Option{Label: "Other / not listed (see the lego and certbot provider docs)"})
	idx, err := pr.Select("Which DNS provider hosts this domain?", opts, 0)
	if err != nil || idx < 0 || idx >= len(dnsProviders) {
		return DNSProvider{
			Key: "other", Display: "your DNS provider", LegoName: "<provider>", CertbotPlugin: "<provider>",
			EnvVars: []string{"<PROVIDER_ENV_VARS>"},
			Scope:   "a least-privilege API token scoped to just this zone (see the provider's lego/certbot docs)",
		}
	}
	return dnsProviders[idx]
}

// chooseACMETool picks lego or certbot, defaulting to whichever is present (lego
// first, since it needs no root).
func chooseACMETool(pr Prompter, deps TLSDeps) string {
	_, legoOK := deps.has("lego")
	_, certbotOK := deps.has("certbot")
	opts := []Option{
		{Label: annotate("lego (a single binary; needs no root)", legoOK, "")},
		{Label: annotate("certbot (a system package; needs root)", certbotOK, "")},
	}
	def := 0
	if !legoOK && certbotOK {
		def = 1
	}
	idx, err := pr.Select("Which ACME client will you run?", opts, def)
	if err != nil {
		return "lego"
	}
	if idx == 1 {
		return "certbot"
	}
	return "lego"
}

// letsEncryptGuidance builds the printed block: install guidance FIRST when the
// binary is missing (C4), then the least-privilege token guidance (which env var,
// which scope — never a prompt for the value), then the exact command with the
// expected output paths, then the usual challenges.
func letsEncryptGuidance(tool string, prov DNSProvider, domain, dir, cert, key string, deps TLSDeps) []string {
	var lines []string
	_, found := deps.has(tool)
	if !found {
		if tool == "lego" {
			lines = append(lines,
				"lego was not found. Install it without root FIRST:",
				"  go install github.com/go-acme/lego/v4/cmd/lego@latest",
				"  (or download a release binary from https://github.com/go-acme/lego/releases)",
			)
		} else {
			lines = append(lines,
				"certbot was not found. Install it FIRST with your system package manager (certbot needs root to run):",
				"  Debian/Ubuntu: sudo apt install certbot python3-certbot-dns-"+prov.CertbotPlugin,
				"  Fedora:        sudo dnf install certbot certbot-dns-"+prov.CertbotPlugin,
				"  macOS:         brew install certbot",
			)
		}
		lines = append(lines, "")
	}
	lines = append(lines,
		"DNS provider: "+prov.Display+"  (lego code: "+prov.LegoName+", certbot plugin: dns-"+prov.CertbotPlugin+")",
		"Create a least-privilege token: "+prov.Scope+".",
		"Put the token in the environment variable(s): "+strings.Join(prov.EnvVars, ", ")+".",
		"The wizard never asks for and never stores the token — you run the command below yourself.",
		"",
	)
	email := "you@" + baseDomain(domain)
	if tool == "lego" {
		lines = append(lines,
			"Run this yourself (with the token exported in the environment above):",
			"  lego --path "+shellQuoteWizard(dir)+" --email "+email+" --dns "+prov.LegoName+" --domains "+shellQuoteWizard(domain)+" run",
			"Expected output files:",
			"  certificate: "+cert,
			"  private key: "+key,
		)
	} else {
		lines = append(lines,
			"Run this yourself as root (with the token exported in the environment above):",
			"  sudo -E certbot certonly --non-interactive --agree-tos --email "+email+" --dns-"+prov.CertbotPlugin+" --domains "+shellQuoteWizard(domain),
			"certbot writes the files under /etc/letsencrypt/live/"+baseDomain(domain)+"/; reference them here:",
			"  certificate: "+cert,
			"  private key: "+key,
		)
	}
	lines = append(lines,
		"",
		"Usual challenges: DNS propagation delay (wait a few minutes before pressing Enter), a CAA record that blocks the CA, and Let's Encrypt rate limits (test against the staging server with --server https://acme-staging-v02.api.letsencrypt.org/directory first).",
	)
	return lines
}

// acmeOutputPaths returns the cert/key paths the wait loop re-checks. For lego it
// is the deterministic <tls>/certificates/<sanitized-domain>.{crt,key}; for
// certbot it is the conventional /etc/letsencrypt/live/<base>/{fullchain,privkey}.pem.
func acmeOutputPaths(tool, dir, domain string) (cert, key string) {
	if tool == "certbot" {
		base := "/etc/letsencrypt/live/" + baseDomain(domain)
		return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
	}
	sanitized := strings.ReplaceAll(domain, "*", "_")
	certsDir := filepath.Join(dir, "certificates")
	return filepath.Join(certsDir, sanitized+".crt"), filepath.Join(certsDir, sanitized+".key")
}

func routeNameFor(tool string) string {
	if tool == "certbot" {
		return routeNameCertbot
	}
	return routeNameLego
}

// showValidateSummary prints the non-secret summary of a validated pair: paths,
// names, expiry, and any warnings (expiring soon, or a group/world-readable key —
// never key bytes).
func showValidateSummary(pr Prompter, cert, key string, info tlsconfig.Info) {
	pr.Show("Certificate looks good:")
	pr.Show("  certificate: " + cert)
	pr.Show("  private key: " + key)
	names := "(none)"
	if len(info.Names) > 0 {
		names = strings.Join(info.Names, ", ")
	}
	pr.Show("  names: " + names)
	pr.Show("  expires: " + info.NotAfter.UTC().Format(time.RFC3339))
	for _, w := range info.Warnings {
		pr.Show("  warning: " + w)
	}
}

// stepAllowlist proposes the concrete DNS SANs as the Host allowlist, DROPS
// wildcard SANs with the exact-match explanation (C5), and lets the user confirm
// or edit. A wildcard the user types back is dropped again — the exact-match
// rebinding guard is authoritative and gains no wildcard matching.
func stepAllowlist(pr Prompter, names []string) []string {
	concrete, wildcards := proposeAllowHosts(names)
	if len(wildcards) > 0 {
		pr.Show("Wildcard names (" + strings.Join(wildcards, ", ") + ") were dropped from the allowlist proposal: the Host allowlist matches EXACT names only, so add the concrete hostnames you will actually connect to.")
	}
	proposal := strings.Join(concrete, ", ")
	answer, err := pr.Text("Confirm or edit the comma-separated Host allowlist for the rebinding guard", proposal)
	if err != nil {
		answer = proposal
	}
	hosts, dropped := splitCleanHosts(answer)
	if len(dropped) > 0 {
		pr.Show("Dropped wildcard entr" + plural(len(dropped)) + " (" + strings.Join(dropped, ", ") + "): the allowlist stores exact names only.")
	}
	return hosts
}

// proposeAllowHosts splits certificate SANs into concrete names (kept) and
// wildcard names (dropped from the proposal, C5). IP SANs are concrete.
func proposeAllowHosts(names []string) (concrete, wildcards []string) {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if strings.Contains(n, "*") {
			wildcards = append(wildcards, n)
			continue
		}
		concrete = append(concrete, n)
	}
	return concrete, wildcards
}

// splitCleanHosts parses a comma-separated allowlist, trimming and de-duplicating
// and DROPPING any wildcard entry so a wildcard SAN is never stored in
// tls.allowHosts (C5). It returns the cleaned hosts and the dropped wildcards.
func splitCleanHosts(s string) (hosts, dropped []string) {
	seen := make(map[string]struct{})
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "*") {
			dropped = append(dropped, part)
			continue
		}
		if _, dup := seen[strings.ToLower(part)]; dup {
			continue
		}
		seen[strings.ToLower(part)] = struct{}{}
		hosts = append(hosts, part)
	}
	return hosts, dropped
}

// stepListen enumerates the machine's non-loopback addresses, states the exposure
// consequence and the VPN recommendation, and prints the exact gui/serve commands.
// The bind address is NOT persisted (design §4 step 5).
func stepListen(pr Prompter, allowHosts, names []string) {
	addrs := nonLoopbackInterfaceAddrs()
	if len(addrs) > 0 {
		pr.Show("This machine's non-loopback addresses: " + strings.Join(addrs, ", "))
	} else {
		pr.Show("No non-loopback interface addresses were detected; you can still bind an address explicitly.")
	}
	bind, err := pr.Text("Which address will the GUI/WebDAV bind for other devices? (host:port, or ':8787' for every interface)", ":8787")
	if err != nil {
		bind = ":8787"
	}
	bind = strings.TrimSpace(bind)
	pr.Show("Exposing a listener beyond loopback puts DECRYPTED content on the wire; a VPN such as Tailscale or WireGuard is safer than an open LAN. This bind address is NOT saved — it stays an explicit per-run choice.")

	guiCmd := "seavault gui --addr " + bind
	for _, h := range allowHosts {
		guiCmd += " --allow-host " + h
	}
	serveBind := bind
	if strings.HasSuffix(bind, ":8787") {
		serveBind = strings.TrimSuffix(bind, ":8787") + ":8765"
	}
	serveCmd := "seavault serve --addr " + serveBind + " --tls VAULT_DIR_OR_PROFILE"
	pr.Show("Start the GUI with:    " + guiCmd)
	pr.Show("Start WebDAV with:     " + serveCmd)
	if name := firstProbeName(allowHosts, names); name != "" {
		pr.Show("Other devices open:    https://" + name + portSuffix(bind))
	}
}

// showRenewal prints the renewal recipe for the route, with systemd-timer, cron,
// and Task Scheduler snippets and the 30-second hot-reload note (design §4 step 7).
func showRenewal(pr Prompter, route string) {
	pr.Show("Renewal:")
	switch route {
	case routeNameTailscale:
		pr.Show("  Re-run `tailscale cert <name>` before the ~90-day certificate expires (Tailscale certs are short-lived).")
	case routeNameLego:
		pr.Show("  Re-run lego with `renew` (same domain and environment variables) to renew.")
	case routeNameCertbot:
		pr.Show("  Run `certbot renew` (as root) to renew all certbot certificates.")
	default:
		pr.Show("  Regenerate the self-signed certificate by re-running `seavault tls setup`.")
	}
	pr.Show("  systemd timer: put the renew command in a .service unit and pair it with a daily .timer (OnCalendar=daily; Persistent=true).")
	pr.Show("  cron: 17 3 * * *  <renew command>   (renews daily at 03:17)")
	pr.Show("  Windows Task Scheduler: schtasks /Create /SC DAILY /TN SeaVaultCertRenew /TR \"<renew command>\" /ST 03:17")
	pr.Show("  open-seavault-rclone reloads a renewed certificate within 30 seconds — no restart is needed.")
}

// maybeProbe runs the optional step-8 trust probe against the just-persisted
// certificate using the system trust store, and reports the verdict. It is
// advisory: a bind failure is reported and setup still stands.
func maybeProbe(pr Prompter, allowHosts, certNames []string) {
	yes, err := pr.Confirm("Run a quick local trust check now? (optional)", true)
	if err != nil || !yes {
		return
	}
	cfg, err := appconfig.Load()
	if err != nil {
		pr.Show("Could not load the configuration for the check: " + err.Error())
		return
	}
	resolved, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: cfg, Purpose: tlsconfig.PurposeGUI})
	if err != nil || resolved == nil || resolved.TLS == nil {
		pr.Show("Could not resolve the certificate for the check.")
		return
	}
	name := firstProbeName(allowHosts, certNames)
	if name == "" {
		if len(resolved.Names) > 0 {
			name = resolved.Names[0]
		} else {
			name = "localhost"
		}
	}
	res := runProbe("127.0.0.1", resolved.TLS, name, resolved.SelfSigned, nil)
	switch res.verdict {
	case probeTrusted:
		pr.Show("Trust check: " + res.detail)
	case probeSelfSigned:
		pr.Show("Trust check: " + res.detail)
	case probeCannotBind:
		pr.Show("Trust check could not bind a probe listener (" + res.detail + "); the configuration was still saved.")
	default:
		pr.Show("Trust check reported a problem: " + res.detail)
	}
}

// persistToolCert writes the shared tls section for a tailscale/lego/BYO pair,
// sets gui.protocol=https, and clears the legacy gui fields so a wizard-cleared
// pair is never resurrected (design §3 C3, §4 step 6).
func persistToolCert(cert, key string, allowHosts []string) error {
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cfg.TLS.CertFile = cert
	cfg.TLS.KeyFile = key
	cfg.TLS.AllowHosts = allowHosts
	cfg.GUI.Protocol = "https"
	cfg.GUI.CertFile = ""
	cfg.GUI.KeyFile = ""
	cfg.GUI.SelfSigned = false
	return appconfig.Save(cfg)
}

// persistSelfSigned sets gui.protocol=https, clears the shared tls section so the
// self-signed floor governs, and materializes the self-signed pair.
func persistSelfSigned() error {
	cfg, err := appconfig.Load()
	if err != nil {
		return err
	}
	cfg.TLS = appconfig.TLSSection{}
	cfg.GUI.Protocol = "https"
	cfg.GUI.CertFile = ""
	cfg.GUI.KeyFile = ""
	cfg.GUI.SelfSigned = false
	cfg, err = appconfig.EnsureSelfSignedCertificate(cfg, "127.0.0.1")
	if err != nil {
		return err
	}
	return appconfig.Save(cfg)
}

// --- probe ---------------------------------------------------------------

type probeVerdict int

const (
	probeTrusted probeVerdict = iota
	probeSelfSigned
	probeFailed
	probeCannotBind
)

type probeResult struct {
	verdict probeVerdict
	detail  string
}

// runProbe serves a short-lived TLS listener with tlsCfg on bindHost and fetches
// it as connectName, verifying against roots (nil = the system trust store). It
// reports trusted / self-signed-prompt-expected / the exact failure (design §4
// step 8, proven by W5). No key material is read or logged.
func runProbe(bindHost string, tlsCfg *tls.Config, connectName string, selfSigned bool, roots *x509.CertPool) probeResult {
	host := strings.TrimSpace(bindHost)
	if host == "" {
		host = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return probeResult{verdict: probeCannotBind, detail: err.Error()}
		}
	}
	srv := &http.Server{
		Handler:  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		ErrorLog: log.New(io.Discard, "", 0), // a rejected client handshake is expected; do not log it
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	addr := ln.Addr().String()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: connectName, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	resp, err := client.Get("https://" + connectName + "/")
	if err == nil {
		_ = resp.Body.Close()
		return probeResult{verdict: probeTrusted, detail: "trusted by this machine's system trust store"}
	}

	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var unknownAuth x509.UnknownAuthorityError
	switch {
	case errors.As(err, &hostErr):
		return probeResult{verdict: probeFailed, detail: "name mismatch: the certificate does not cover " + connectName}
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return probeResult{verdict: probeFailed, detail: "the certificate is expired or not yet valid"}
	case errors.As(err, &unknownAuth):
		if selfSigned {
			return probeResult{verdict: probeSelfSigned, detail: "self-signed — a trust prompt is expected on other devices; Windows WebDAV will refuse it"}
		}
		return probeResult{verdict: probeFailed, detail: "unknown authority: there is no trusted chain to this certificate on this machine"}
	default:
		if selfSigned {
			return probeResult{verdict: probeSelfSigned, detail: "self-signed — a trust prompt is expected on other devices"}
		}
		return probeResult{verdict: probeFailed, detail: err.Error()}
	}
}

// --- small helpers -------------------------------------------------------

func annotate(label string, present bool, path string) string {
	if !present {
		return label + " (not detected)"
	}
	if strings.TrimSpace(path) != "" {
		return label + " (detected: " + path + ")"
	}
	return label + " (detected)"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// firstProbeName returns the launch/connect name: the first confirmed allow-host,
// else the certificate's first DNS SAN (an IP SAN is skipped).
func firstProbeName(allowHosts, certNames []string) string {
	for _, h := range allowHosts {
		if h = strings.TrimSpace(h); h != "" && !strings.Contains(h, "*") {
			if net.ParseIP(h) == nil {
				return h
			}
		}
	}
	for _, n := range certNames {
		n = strings.TrimSpace(n)
		if n == "" || strings.Contains(n, "*") || net.ParseIP(n) != nil {
			continue
		}
		return n
	}
	return ""
}

func nonLoopbackInterfaceAddrs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

func showLines(pr Prompter, lines []string) {
	for _, l := range lines {
		pr.Show(l)
	}
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// baseDomain strips a leading wildcard label so "*.example.com" → "example.com".
func baseDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "*.")
	return domain
}

// portSuffix returns ":port" from a host:port bind, or "" when there is no port.
func portSuffix(bind string) string {
	if _, port, err := net.SplitHostPort(bind); err == nil && port != "" {
		return ":" + port
	}
	return ""
}

// shellQuoteWizard single-quotes a value for a printed POSIX shell command when it
// contains whitespace or a shell metacharacter, so a copy-pasted command is safe.
func shellQuoteWizard(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, " \t\n*?[]{}()$`\"\\|&;<>#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
