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
	routeNameBYO        = "byo"
	routeNameSelfSigned = "self-signed"
)

// maxCertWaitLoops bounds the "press Enter when the files exist" loop so a
// scripted or inattentive caller cannot spin forever when the files never appear.
const maxCertWaitLoops = 240

// maxRouteMenuAttempts bounds the outer route-menu loop so a prompter that keeps
// returning a dead-end route (or a genuinely stuck caller) cannot livelock the
// wizard (A2-c1 defence-in-depth). The primary guard is that Select/Text/Confirm
// propagate a closed-stdin EOF, which aborts the loop at once.
const maxRouteMenuAttempts = 64

// errBackToMenu is the sentinel a route flow returns to send the wizard back to
// the route menu (a recoverable dead end: a declined confirmation, an empty or
// invalid entry, a cancelled or failed external tool). Any OTHER non-nil error
// from a flow aborts the wizard — in particular a closed-stdin EOF, so the wizard
// never livelocks waiting on input that will never come (A2-c1).
var errBackToMenu = errors.New("tls setup: back to the route menu")

// renewalRecipe carries the CONCRETE values step 7 substitutes into the renewal
// snippets (A1-c6): the primary DNS/tailnet name, the exact renew command for the
// chosen route, and (for a bring-your-own pair) the file paths to replace in
// place. No bare "<renew command>"/"<name>" placeholder reaches the printed
// cron/systemd/schtasks snippets.
type renewalRecipe struct {
	route   string // routeName* constant
	name    string // primary DNS name / tailnet name / domain
	command string // the concrete renew command to schedule
	cert    string // BYO: certificate path to replace in place
	key     string // BYO: key path to replace in place
}

// wizardInputErr turns a closed-stdin EOF (a piped or exhausted stdin, Ctrl-D)
// into a clear abort message instead of a bare "EOF" or a livelock (A2-c1).
func wizardInputErr(err error) error {
	if errors.Is(err, io.EOF) {
		return errors.New("tls setup aborted: standard input closed (EOF) before the wizard finished — run `seavault tls setup` in an interactive terminal")
	}
	return err
}

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
		return wizardInputErr(err)
	}
	if who == 0 {
		pr.Show("On loopback the GUI already works over plain HTTP and WebDAV needs no certificate — nothing is required.")
		on, err := pr.Confirm("Turn on HTTPS with a self-signed certificate for the GUI anyway?", false)
		if err != nil {
			return wizardInputErr(err)
		}
		if !on {
			pr.Show("No change made. The GUI stays on http://127.0.0.1 (loopback) and WebDAV stays plaintext loopback.")
			return nil
		}
		return finishSelfSigned(pr)
	}

	// Other devices: choose and run a route, looping back to the menu on any
	// recoverable dead end (a validation failure, a cancelled tool, a key
	// mismatch). A prompt error other than errBackToMenu (a closed-stdin EOF)
	// aborts at once with a clear message; the loop is bounded as a further guard
	// so it can never livelock (A2-c1).
	for attempt := 0; attempt < maxRouteMenuAttempts; attempt++ {
		route, err := chooseRoute(pr, deps)
		if err != nil {
			return wizardInputErr(err)
		}
		var cert, key string
		var recipe renewalRecipe
		var flowErr error
		switch route {
		case routeTailscale:
			cert, key, recipe, flowErr = routeTailscaleFlow(pr, deps)
		case routeLetsEncrypt:
			cert, key, recipe, flowErr = routeLetsEncryptFlow(pr, deps)
		case routeBYO:
			cert, key, recipe, flowErr = routeBYOFlow(pr)
		case routeSelfSigned:
			if ferr := finishSelfSigned(pr); ferr != nil {
				return ferr
			}
			// This is the "other devices" branch: keeping a self-signed certificate
			// here cannot map a Windows network drive (Windows' WebDAV client refuses
			// it), so name how to re-run for a mappable certificate (A3-c3).
			pr.Show("To map a Windows network drive later, re-run `seavault tls setup` and choose Tailscale or your own CA instead — a self-signed certificate cannot be used for a Windows drive mapping.")
			return nil
		}
		if errors.Is(flowErr, errBackToMenu) {
			continue
		}
		if flowErr != nil {
			return wizardInputErr(flowErr)
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
		if err := stepListen(pr, allowHosts, info.Names); err != nil {
			return wizardInputErr(err)
		}

		// Step 6: persist tls.* + gui.protocol=https; clear the legacy fields.
		if err := persistToolCert(cert, key, allowHosts); err != nil {
			return err
		}
		pr.Show("Saved. gui.protocol is now https, the shared tls section points at this certificate, and the legacy gui.certFile/keyFile were cleared.")

		// Step 7: renewal recipe for the chosen route.
		showRenewal(pr, recipe)

		// Step 8: optional local trust probe (advisory).
		maybeProbe(pr, allowHosts, info.Names)
		return nil
	}
	return errors.New("tls setup aborted: too many attempts without a usable certificate")
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
// tool the wizard ever executes (I-T5). The tailscale-supplied MagicDNS name is
// validated against a DNS-label grammar BEFORE it is used as a path or an argv
// (wizard-tools-2) and is passed after a `--` terminator so it can never be read
// as a flag. On a recoverable dead end it returns errBackToMenu; a closed-stdin
// EOF is propagated so the wizard aborts.
func routeTailscaleFlow(pr Prompter, deps TLSDeps) (cert, key string, recipe renewalRecipe, err error) {
	if _, ok := deps.has("tailscale"); !ok {
		pr.Show("The tailscale binary was not found. Install Tailscale from https://tailscale.com/download, then choose Tailscale again from this menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	st, rerr := deps.ReadTailscaleStatus()
	if rerr != nil {
		pr.Show("Could not read `tailscale status --json`: " + rerr.Error())
		pr.Show("Make sure Tailscale is running and you are logged in, then choose Tailscale again from this menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	raw := strings.TrimSuffix(strings.TrimSpace(st.MagicDNSName), ".")
	if raw == "" {
		pr.Show("Tailscale reported no MagicDNS name for this machine; enable MagicDNS in the tailnet admin console (https://login.tailscale.com/admin/dns), then choose Tailscale again from this menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	name, ok := normalizeDNSName(raw)
	if !ok || strings.Contains(name, "*") {
		// A MagicDNS name is always a plain dotted host; anything else (a path
		// traversal, a flag, whitespace, a wildcard) is refused before it reaches
		// a filesystem path or the tailscale argv (wizard-tools-2).
		pr.Show("Tailscale reported an unexpected machine name that is not a valid DNS name; refusing to use it. Check `tailscale status` and your tailnet admin console, then choose Tailscale again from this menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	pr.Show("This machine's tailnet name is " + name + ".")
	pr.Show("HTTPS certificates must be ENABLED in your tailnet admin console (https://login.tailscale.com/admin/dns) — this is a common dead end; `tailscale cert` fails until it is turned on.")
	run, cerr := pr.Confirm("Run `tailscale cert` now to obtain the certificate? (no secret is involved, so this is safe to run)", true)
	if cerr != nil {
		return "", "", renewalRecipe{}, cerr
	}
	if !run {
		return "", "", renewalRecipe{}, errBackToMenu
	}
	dir, derr := appdir.EnsureConfigDir("tls")
	if derr != nil {
		pr.Show("Could not create the tls directory: " + derr.Error())
		return "", "", renewalRecipe{}, errBackToMenu
	}
	cert = filepath.Join(dir, name+".crt")
	key = filepath.Join(dir, name+".key")
	// Defence in depth: the validated name has no separators, so the joined paths
	// must stay directly inside the tls dir (wizard-tools-2).
	if filepath.Dir(cert) != filepath.Clean(dir) || filepath.Dir(key) != filepath.Clean(dir) {
		pr.Show("Refusing to write the certificate outside the tls directory. Choose Tailscale again from this menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	// The name is passed after `--` so a value beginning with `-` can never be
	// read as a flag by `tailscale cert` (wizard-tools-2).
	out, runErr := deps.Run("tailscale", "cert", "--cert-file", cert, "--key-file", key, "--", name)
	if runErr != nil {
		// Lead with the tool's own stderr, not the raw Go "exit status N"
		// (A1-c2); only fall back to the Go error when there is no useful stderr.
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			pr.Show("`tailscale cert` failed:")
			pr.Show(trimmed)
		} else {
			pr.Show("`tailscale cert` failed: " + runErr.Error())
		}
		pr.Show("If it reports that HTTPS is not enabled, turn on HTTPS certificates in the tailnet admin console (https://login.tailscale.com/admin/dns), then choose Tailscale again from this menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	pr.Show("Obtained a Tailscale certificate for " + name + " in " + dir + ".")
	recipe = renewalRecipe{route: routeNameTailscale, name: name, command: "tailscale cert " + shellQuoteWizard(name)}
	return cert, key, recipe, nil
}

// routeLetsEncryptFlow guides a DNS-01 issuance with lego or certbot. It NEVER
// runs the tool and NEVER prompts for a token: it prints the install guidance
// FIRST when the binary is missing (C4), then the exact command with the
// least-privilege scope and expected output paths, then waits — re-checking for
// the files and keeping the guidance visible above the wait prompt.
func routeLetsEncryptFlow(pr Prompter, deps TLSDeps) (cert, key string, recipe renewalRecipe, err error) {
	entered, terr := pr.Text("Which domain will the certificate cover? (e.g. vault.example.com; a wildcard like *.example.com is allowed)", "")
	if terr != nil {
		return "", "", renewalRecipe{}, terr
	}
	entered = strings.TrimSpace(entered)
	if entered == "" {
		pr.Show("No domain entered; returning to the route menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	// Validate and normalize the domain to a syntactically valid DNS name BEFORE
	// deriving an email, output paths, or a printed command from it, so a hostile
	// value (whitespace, a shell metacharacter, a path traversal) cannot flow into
	// any of them (wizard-tools-1).
	domain, ok := normalizeDNSName(entered)
	if !ok {
		pr.Show("That is not a valid domain name. Enter a DNS name like vault.example.com (or *.example.com for a wildcard) using letters, digits, hyphens, and dots only. Returning to the route menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	prov := chooseDNSProvider(pr)
	tool := chooseACMETool(pr, deps)

	dir, derr := appdir.EnsureConfigDir("tls")
	if derr != nil {
		pr.Show("Could not create the tls directory: " + derr.Error())
		return "", "", renewalRecipe{}, errBackToMenu
	}
	cert, key = acmeOutputPaths(tool, dir, domain)

	// The install + command + expected-paths guidance is printed ONCE, above the
	// wait prompt (C4). The wait loop does not re-print the whole block on every
	// poll (A2-c2).
	guidance := letsEncryptGuidance(tool, prov, domain, dir, cert, key, deps)
	showLines(pr, guidance)

	for i := 0; i < maxCertWaitLoops; i++ {
		if fileExists(cert) && fileExists(key) {
			pr.Show("Found the certificate files.")
			return cert, key, letsEncryptRecipe(tool, prov, domain, dir), nil
		}
		cont, cerr := pr.Confirm("Press Enter when the certificate files exist (or answer 'n' to cancel)", true)
		if cerr != nil {
			return "", "", renewalRecipe{}, cerr
		}
		if !cont {
			pr.Show("Cancelled; returning to the route menu.")
			return "", "", renewalRecipe{}, errBackToMenu
		}
		// Re-check the files IMMEDIATELY after Enter, before any "still waiting"
		// line, so a user who has just written them is not told to keep waiting
		// (A2-c2).
		if fileExists(cert) && fileExists(key) {
			pr.Show("Found the certificate files.")
			return cert, key, letsEncryptRecipe(tool, prov, domain, dir), nil
		}
		// A compact reminder pointing at the guidance above — NOT the whole block
		// again (A2-c2).
		pr.Show("Still waiting for the files listed above:")
		pr.Show("  certificate: " + cert)
		pr.Show("  private key: " + key)
	}
	pr.Show("Gave up waiting for the certificate files. Re-run `seavault tls setup` once the tool has written them.")
	return "", "", renewalRecipe{}, errBackToMenu
}

// letsEncryptRecipe builds the CONCRETE renewal command for the chosen ACME tool
// so step 7 substitutes it into the scheduler snippets with no placeholders
// (A1-c6). Every interpolated value is shell-quoted (wizard-tools-1).
func letsEncryptRecipe(tool string, prov DNSProvider, domain, dir string) renewalRecipe {
	if tool == "certbot" {
		return renewalRecipe{route: routeNameCertbot, name: domain, command: "sudo -E certbot renew"}
	}
	cmd := "lego --path " + shellQuoteWizard(dir) +
		" --email " + shellQuoteWizard("you@"+baseDomain(domain)) +
		" --dns " + shellQuoteWizard(prov.LegoName) +
		" --domains " + shellQuoteWizard(domain) + " renew"
	return renewalRecipe{route: routeNameLego, name: domain, command: cmd}
}

// routeBYOFlow references an existing pair in place (never copied) with the
// chain-order note.
func routeBYOFlow(pr Prompter) (cert, key string, recipe renewalRecipe, err error) {
	c, cerr := pr.Text("Path to your certificate (PEM chain, leaf first)", "")
	if cerr != nil {
		return "", "", renewalRecipe{}, cerr
	}
	k, kerr := pr.Text("Path to the matching private key (PEM)", "")
	if kerr != nil {
		return "", "", renewalRecipe{}, kerr
	}
	c, k = strings.TrimSpace(c), strings.TrimSpace(k)
	if c == "" || k == "" {
		pr.Show("Both a certificate and a key path are required; returning to the route menu.")
		return "", "", renewalRecipe{}, errBackToMenu
	}
	pr.Show("Order the certificate PEM leaf-first, then any intermediates; do NOT include the root. The files are referenced in place — never copied — so keep them where they are.")
	return c, k, renewalRecipe{route: routeNameBYO, cert: c, key: k}, nil
}

// finishSelfSigned states the consequences, ensures the self-signed floor pair
// exists, persists gui.protocol=https with the shared section cleared, prints the
// renewal note, and offers the probe.
func finishSelfSigned(pr Prompter) error {
	pr.Show("Keeping a self-signed certificate: every device shows a trust prompt on first connect, and Windows' built-in WebDAV client refuses a self-signed certificate outright.")
	if err := persistSelfSigned(); err != nil {
		return err
	}
	// State plainly that gui.protocol=https was set and what that means (A3-c3).
	pr.Show("Saved. gui.protocol is now https: the GUI serves HTTPS (not plain HTTP) on every start and marks its login cookie Secure, and a browser will show a trust prompt for this self-signed certificate until you add it to that device's trust store. Return to plain HTTP on loopback any time with `seavault tls reset`.")
	// The self-signed names line is de-duplicated so 127.0.0.1 is not shown twice
	// (the self-signed floor lists it as both the requested host and the loopback
	// default) (A3-c3).
	if names := selfSignedNames(); len(names) > 0 {
		pr.Show("The self-signed certificate covers: " + strings.Join(names, ", "))
	}
	showRenewal(pr, renewalRecipe{route: routeNameSelfSigned, command: "seavault tls setup"})
	maybeProbe(pr, nil, nil)
	return nil
}

// selfSignedNames resolves the just-persisted self-signed pair and returns its
// SANs with duplicates removed (A3-c3). It never reads or returns key material.
func selfSignedNames() []string {
	cfg, err := appconfig.Load()
	if err != nil {
		return nil
	}
	resolved, err := tlsconfig.Resolve(tlsconfig.Options{Cfg: cfg, Purpose: tlsconfig.PurposeGUI})
	if err != nil || resolved == nil {
		return nil
	}
	return dedupeStrings(resolved.Names)
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
	// Every interpolated value is shell-quoted so a copy-pasted command is safe
	// even if a value carries whitespace or a shell metacharacter (wizard-tools-1);
	// the domain is already validated to a DNS name upstream, and the email is
	// derived from it, but both are quoted here as defence in depth.
	email := shellQuoteWizard("you@" + baseDomain(domain))
	if tool == "lego" {
		lines = append(lines,
			"Run this yourself (with the token exported in the environment above):",
			"  lego --path "+shellQuoteWizard(dir)+" --email "+email+" --dns "+shellQuoteWizard(prov.LegoName)+" --domains "+shellQuoteWizard(domain)+" run",
			"Expected output files:",
			"  certificate: "+cert,
			"  private key: "+key,
		)
	} else {
		lines = append(lines,
			"Run this yourself as root (with the token exported in the environment above):",
			"  sudo -E certbot certonly --non-interactive --agree-tos --email "+email+" "+shellQuoteWizard("--dns-"+prov.CertbotPlugin)+" --domains "+shellQuoteWizard(domain),
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
	// State the consequence at the decision point, in plain terms — no
	// "rebinding guard" jargon (A1-c3).
	pr.Show("Only the hostnames on this list may reach the vault: a request whose Host header is not on the list is refused with 403. Include EVERY name a device will actually type in its address bar or drive mapping.")
	if len(wildcards) > 0 {
		pr.Show("Wildcard names (" + strings.Join(wildcards, ", ") + ") were dropped from the proposal: the list matches exact names only, so add the concrete hostnames you will actually connect to.")
	}
	proposal := strings.Join(concrete, ", ")
	answer, err := pr.Text("Confirm or edit the comma-separated list of allowed hostnames", proposal)
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

// stepListen enumerates the machine's non-loopback interface addresses (filtering
// container/bridge/virtual and link-local interfaces, annotating each with its
// interface name and flagging the Tailscale one), offers them as a menu that
// DEFAULTS to the single most-specific address — the Tailscale address when a
// tailnet is detected — and never to every interface (A1-c4), states the exposure
// consequence, and prints the exact gui/serve commands with the serve port
// derived independently of the gui port (A1-c4). The bind address is NOT
// persisted (design §4 step 5). A closed-stdin EOF is returned so the wizard
// aborts (A2-c1).
func stepListen(pr Prompter, allowHosts, names []string) error {
	choices := classifyChoices(systemIfaceInfos())
	opts, defIdx, everyIdx, _ := buildListenOptions(choices)

	idx, err := pr.Select("Which address should the GUI and WebDAV listen on for other devices? (never every interface by default)", opts, defIdx)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(opts) {
		idx = defIdx
	}

	var guiBind string
	switch {
	case idx >= 0 && idx < len(choices):
		port, perr := askListenPort(pr)
		if perr != nil {
			return perr
		}
		guiBind = net.JoinHostPort(choices[idx].ip, port)
	case idx == everyIdx:
		pr.Show("Every interface means the listener is reachable on ALL of this machine's networks — an open LAN, guest Wi-Fi, and any container/VM bridge. Prefer a single address unless you specifically need this.")
		port, perr := askListenPort(pr)
		if perr != nil {
			return perr
		}
		guiBind = net.JoinHostPort("", port)
	default: // customIdx
		typed, terr := pr.Text("Enter the bind address (host:port, or :PORT for every interface)", defaultCustomBind(choices))
		if terr != nil {
			return terr
		}
		guiBind = strings.TrimSpace(typed)
		if guiBind == "" {
			guiBind = defaultCustomBind(choices)
		}
	}

	pr.Show("Exposing a listener beyond loopback puts DECRYPTED content on the wire; a VPN such as Tailscale or WireGuard is safer than an open LAN. This bind address is NOT saved — it stays an explicit per-run choice.")

	guiCmd := "seavault gui --addr " + guiBind
	for _, h := range allowHosts {
		guiCmd += " --allow-host " + shellQuoteWizard(h)
	}
	serveCmd := "seavault serve --addr " + serveBindFor(guiBind) + " --tls VAULT_DIR_OR_PROFILE"
	pr.Show("Start the GUI with:    " + guiCmd)
	pr.Show("Start WebDAV with:     " + serveCmd)
	if name := firstProbeName(allowHosts, names); name != "" {
		pr.Show("Other devices open:    https://" + name + portSuffix(guiBind))
	}
	return nil
}

// askListenPort reads the GUI port, defaulting to the app's 8787.
func askListenPort(pr Prompter) (string, error) {
	port, err := pr.Text("Which port should the GUI listen on?", "8787")
	if err != nil {
		return "", err
	}
	if port = strings.TrimSpace(port); port == "" {
		port = "8787"
	}
	return port, nil
}

// buildListenOptions turns the classified interface addresses into the listen
// menu: one entry per concrete address (Tailscale-first, so index 0 is the
// recommended default), then an explicit "every interface" entry (never the
// default), then a "type it yourself" entry. When there are no concrete
// addresses the default is the custom prompt, still not every interface (A1-c4).
func buildListenOptions(choices []interfaceChoice) (opts []Option, defIdx, everyIdx, customIdx int) {
	for _, c := range choices {
		label := c.ip + "  (interface " + c.iface + ")"
		if c.isTailscale {
			label += " — Tailscale, recommended"
		}
		opts = append(opts, Option{Label: label})
	}
	everyIdx = len(opts)
	opts = append(opts, Option{Label: "Every interface — exposes DECRYPTED content on every network (docker/VM bridges included); not recommended"})
	customIdx = len(opts)
	opts = append(opts, Option{Label: "A different address (type host:port yourself)"})
	if len(choices) == 0 {
		defIdx = customIdx
	} else {
		defIdx = 0
	}
	return opts, defIdx, everyIdx, customIdx
}

// defaultCustomBind proposes a sensible host:port for the custom prompt: the
// recommended (first) interface address on :8787, or ":8787" when none was found.
func defaultCustomBind(choices []interfaceChoice) string {
	if len(choices) > 0 {
		return net.JoinHostPort(choices[0].ip, "8787")
	}
	return ":8787"
}

// serveBindFor derives the WebDAV bind from the GUI bind, keeping the host but
// choosing a DIFFERENT port so serve never collides with the GUI regardless of
// which port the GUI uses (A1-c4). It does not assume the GUI port is 8787.
func serveBindFor(guiBind string) string {
	host, guiPort, err := net.SplitHostPort(guiBind)
	if err != nil {
		// No parseable port: keep the whole value as the host and append a port.
		host = strings.TrimSpace(guiBind)
		guiPort = ""
	}
	servePort := "8765"
	if guiPort == servePort {
		servePort = "8766"
	}
	return net.JoinHostPort(host, servePort)
}

// showRenewal prints the renewal recipe for the route with the CONCRETE renew
// command and name substituted into the systemd-timer, cron, and Task Scheduler
// snippets — no bare placeholders (A1-c6) — plus the 30-second hot-reload note
// (design §4 step 7). The Tailscale route schedules MONTHLY, not daily, because
// `tailscale cert` re-issues unconditionally on every run rather than renewing
// idempotently near expiry (A1-c6); lego/certbot/self-signed keep the daily
// cadence. A bring-your-own pair gets its own recipe (renew at your CA and
// replace the files in place), never the self-signed re-run (A2-c3).
func showRenewal(pr Prompter, r renewalRecipe) {
	pr.Show("Renewal:")
	switch r.route {
	case routeNameTailscale:
		pr.Show("  Re-run this before the ~90-day certificate expires (Tailscale certificates are short-lived):")
		pr.Show("    " + r.command)
		pr.Show("  `tailscale cert` re-issues the certificate unconditionally every time it runs — it is not an idempotent renew that only acts near expiry — so schedule it MONTHLY, not daily:")
		pr.Show("  systemd timer: put `" + r.command + "` in a .service unit and pair it with a monthly .timer (OnCalendar=monthly; Persistent=true).")
		pr.Show("  cron: 17 3 1 * *  " + r.command + "   (runs on the 1st of each month at 03:17)")
		pr.Show("  Windows Task Scheduler: schtasks /Create /SC MONTHLY /TN SeaVaultCertRenew /TR \"" + r.command + "\" /ST 03:17")
		pr.Show("  open-seavault-rclone reloads a renewed certificate within 30 seconds — no restart is needed.")
		return
	case routeNameLego:
		pr.Show("  Renew " + r.name + " with (the same DNS token exported in the environment):")
		pr.Show("    " + r.command)
	case routeNameCertbot:
		pr.Show("  Renew " + r.name + " with (as root):")
		pr.Show("    " + r.command)
	case routeNameBYO:
		pr.Show("  This certificate came from your own CA or ACME client. Renew it there and replace these files in place (they are referenced, never copied):")
		pr.Show("    certificate: " + r.cert)
		pr.Show("    private key: " + r.key)
		pr.Show("  Schedule your own renew-and-replace command with a systemd timer, cron, or Windows Task Scheduler.")
		pr.Show("  open-seavault-rclone reloads the replaced pair within 30 seconds — no restart is needed. Do NOT re-run `seavault tls setup` to renew.")
		return
	default: // self-signed
		pr.Show("  Regenerate the self-signed certificate by re-running:")
		pr.Show("    " + r.command)
	}
	pr.Show("  systemd timer: put `" + r.command + "` in a .service unit and pair it with a daily .timer (OnCalendar=daily; Persistent=true).")
	pr.Show("  cron: 17 3 * * *  " + r.command + "   (runs daily at 03:17)")
	pr.Show("  Windows Task Scheduler: schtasks /Create /SC DAILY /TN SeaVaultCertRenew /TR \"" + r.command + "\" /ST 03:17")
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

// interfaceChoice is one enumerated bind target: the address string, the owning
// interface name (so the operator can tell a Tailscale address from a LAN one),
// and whether it is a Tailscale address (flagged and preferred as the default).
type interfaceChoice struct {
	ip          string
	iface       string
	isTailscale bool
}

// ifaceInfo is the injectable, testable view of one network interface: its name,
// flags, and unicast IPs. systemIfaceInfos reads it from the OS; the tests feed
// synthetic values so classifyChoices can be exercised without real interfaces.
type ifaceInfo struct {
	name  string
	flags net.Flags
	addrs []net.IP
}

// systemIfaceInfos reads the machine's interfaces and their addresses. It is the
// only OS-touching part of the listen step; classifyChoices does the filtering.
func systemIfaceInfos() []ifaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifaceInfo, 0, len(ifaces))
	for _, ifc := range ifaces {
		info := ifaceInfo{name: ifc.Name, flags: ifc.Flags}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				info.addrs = append(info.addrs, ip)
			}
		}
		out = append(out, info)
	}
	return out
}

// classifyChoices turns raw interface info into bind choices, DROPPING loopback,
// down, link-local, unspecified, and container/bridge/virtual interfaces
// (docker0, br-*, virbr*, veth*, vmnet*, vboxnet*), annotating each survivor with
// its interface name and flagging Tailscale addresses (A1-c4). The result is
// sorted Tailscale-first (then by address) so the caller's default is the
// Tailscale/most-specific address, never every interface.
func classifyChoices(ifaces []ifaceInfo) []interfaceChoice {
	var out []interfaceChoice
	for _, ifc := range ifaces {
		if ifc.flags&net.FlagUp == 0 || ifc.flags&net.FlagLoopback != 0 {
			continue
		}
		if skipVirtualIface(ifc.name) {
			continue
		}
		for _, ip := range ifc.addrs {
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, interfaceChoice{
				ip:          ip.String(),
				iface:       ifc.name,
				isTailscale: isTailscaleIface(ifc.name, ip),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].isTailscale != out[j].isTailscale {
			return out[i].isTailscale // Tailscale addresses sort first
		}
		return out[i].ip < out[j].ip
	})
	return out
}

// skipVirtualIface reports whether an interface name is a container/VM/bridge
// device whose address is not a useful bind target for other real devices
// (A1-c4). It matches Docker's docker0/docker*, libvirt's virbr*, Docker's
// bridge networks br-*, veth pairs, and VMware/VirtualBox host-only nets.
func skipVirtualIface(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "docker0", strings.HasPrefix(n, "docker"):
		return true
	case strings.HasPrefix(n, "br-"):
		return true
	case strings.HasPrefix(n, "virbr"):
		return true
	case strings.HasPrefix(n, "veth"):
		return true
	case strings.HasPrefix(n, "vmnet"):
		return true
	case strings.HasPrefix(n, "vboxnet"):
		return true
	}
	return false
}

// isTailscaleIface reports whether an interface/address pair is Tailscale's: the
// interface is named tailscale*, or the address is in Tailscale's ranges
// (100.64.0.0/10 CGNAT for IPv4, fd7a:115c:a1e0::/48 for IPv6).
func isTailscaleIface(name string, ip net.IP) bool {
	if strings.HasPrefix(strings.ToLower(name), "tailscale") {
		return true
	}
	return isTailscaleIP(ip)
}

func isTailscaleIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 — CGNAT, which Tailscale uses for its IPv4 addresses.
		return v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
	}
	if v6 := ip.To16(); v6 != nil {
		// fd7a:115c:a1e0::/48 — Tailscale's ULA prefix.
		return v6[0] == 0xfd && v6[1] == 0x7a && v6[2] == 0x11 && v6[3] == 0x5c && v6[4] == 0xa1 && v6[5] == 0xe0
	}
	return false
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

// normalizeDNSName trims and lowercases a domain, allows a single leading "*."
// wildcard label, tolerates a trailing root dot, and reports whether the
// remainder is a syntactically valid dotted DNS name: at least two labels, each
// 1–63 chars of ASCII letters/digits/hyphen with no leading or trailing hyphen,
// total length ≤ 253. It therefore rejects any value with whitespace, a shell
// metacharacter, a path separator, or "..", so nothing derived from it (an email,
// an output path, a printed command) can be hostile (wizard-tools-1/2). The
// returned name is the normalized form (lowercased, trailing dot removed).
func normalizeDNSName(domain string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return "", false
	}
	wildcard := strings.HasPrefix(d, "*.")
	if wildcard {
		d = d[2:]
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	total := 0
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 {
			return "", false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
		total += len(l) + 1
	}
	if total-1 > 253 {
		return "", false
	}
	if wildcard {
		return "*." + d, true
	}
	return d, true
}

// dedupeStrings returns the non-empty inputs with later duplicates removed, order
// preserved. It de-duplicates a SAN list before it is printed (A3-c3).
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
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
