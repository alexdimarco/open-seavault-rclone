// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// --- scripted prompter for the tls wizard --------------------------------

// tlsScript is a scripted Prompter for the tls wizard. Each decision is answered
// by a function keyed on the prompt text, so the tests are robust to prompt order.
// onConfirm runs a side effect (e.g. materialising cert files) BEFORE a Confirm is
// answered, to drive the file-wait loop. Secret must never be called — the wizard
// handles no secret (I-T5).
type tlsScript struct {
	t         *testing.T
	selectBy  func(title string, opts []Option, def int) int
	confirmBy func(q string, def bool) bool
	textBy    func(label, def string) string
	onConfirm func(q string)

	shown    []string
	selects  []string
	confirms []string
	texts    []string
}

func (s *tlsScript) Select(title string, opts []Option, def int) (int, error) {
	s.selects = append(s.selects, title)
	if s.selectBy != nil {
		return s.selectBy(title, opts, def), nil
	}
	return def, nil
}

func (s *tlsScript) Confirm(q string, def bool) (bool, error) {
	s.confirms = append(s.confirms, q)
	if s.onConfirm != nil {
		s.onConfirm(q)
	}
	if s.confirmBy != nil {
		return s.confirmBy(q, def), nil
	}
	return def, nil
}

func (s *tlsScript) Text(label, def string) (string, error) {
	s.texts = append(s.texts, label)
	if s.textBy != nil {
		return s.textBy(label, def), nil
	}
	return def, nil
}

func (s *tlsScript) Secret(label string) (string, error) {
	s.t.Fatalf("tls wizard must never call Secret (label=%q): it handles no secret", label)
	return "", nil
}

func (s *tlsScript) Show(msg string) { s.shown = append(s.shown, msg) }

func (s *tlsScript) shownJoined() string { return strings.Join(s.shown, "\n") }

func (s *tlsScript) promptsJoined() string {
	all := append([]string{}, s.selects...)
	all = append(all, s.confirms...)
	all = append(all, s.texts...)
	return strings.Join(all, "\n")
}

// --- real-certificate helpers (standard library only) --------------------

func tlsGenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func tlsSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

func tlsKeyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func tlsCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key := tlsGenKey(t)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          tlsSerial(t),
		Subject:               pkix.Name{CommonName: "SeaVault U3 Wizard Test Root"},
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
	return testCA{cert: cert, key: key, pool: pool}
}

func (ca testCA) issue(t *testing.T, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key := tlsGenKey(t)
	now := time.Now()
	cn := "leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          tlsSerial(t),
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
	return tlsCertPEM(der), tlsKeyPEM(t, key)
}

func selfSignedLeaf(t *testing.T, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key := tlsGenKey(t)
	now := time.Now()
	cn := "self"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          tlsSerial(t),
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
	return tlsCertPEM(der), tlsKeyPEM(t, key)
}

func writePair(t *testing.T, dir string, certPEM, keyPEM []byte) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "leaf.crt")
	keyPath = filepath.Join(dir, "leaf.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func tlsCfgFromPEM(t *testing.T, certPEM, keyPEM []byte) *tls.Config {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
}

// assertNoKeyBytes fails when output contains any base64 body line of the private
// key file, or a PRIVATE KEY header (I-T2).
func assertNoKeyBytes(t *testing.T, output, keyPath string) {
	t.Helper()
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if strings.Contains(output, "PRIVATE KEY") {
		t.Fatalf("output contains a PRIVATE KEY header — key material leaked")
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 40 && !strings.Contains(line, "PRIVATE KEY") && strings.Contains(output, line) {
			t.Fatalf("output contains a private-key body line — key material leaked")
		}
	}
}

// tailscaleRunFake records each tool invocation and, for `tailscale cert`, writes
// a real CA-signed leaf to the requested --cert-file/--key-file so the wizard's
// subsequent Validate passes against real certificates (mock only the tool seam).
func tailscaleRunFake(t *testing.T, ca testCA, runs *[]string) func(string, ...string) ([]byte, error) {
	return func(name string, args ...string) ([]byte, error) {
		*runs = append(*runs, name+" "+strings.Join(args, " "))
		certPath, keyPath, dnsName := parseTailscaleCertArgs(args)
		if certPath == "" || keyPath == "" || dnsName == "" {
			return nil, errors.New("fake tailscale: missing --cert-file/--key-file/name")
		}
		certPEM, keyPEM := ca.issue(t, []string{dnsName}, nil)
		if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, err
		}
		return []byte("wrote cert"), nil
	}
}

func parseTailscaleCertArgs(args []string) (certPath, keyPath, name string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--cert-file":
			if i+1 < len(args) {
				certPath = args[i+1]
				i++
			}
		case "--key-file":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "--") && args[i] != "cert" {
				name = args[i]
			}
		}
	}
	return certPath, keyPath, name
}

func lookPathPresent(present ...string) func(string) (string, error) {
	set := make(map[string]struct{}, len(present))
	for _, p := range present {
		set[p] = struct{}{}
	}
	return func(name string) (string, error) {
		if _, ok := set[name]; ok {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

func mustNotRun(t *testing.T) func(string, ...string) ([]byte, error) {
	return func(name string, args ...string) ([]byte, error) {
		t.Fatalf("the wizard ran a tool it must never run: %s %v", name, args)
		return nil, nil
	}
}

func noTailscale() (TailscaleStatus, error) { return TailscaleStatus{}, errors.New("no tailscale") }

func routeSelector(route tlsRoute) func(string, []Option, int) int {
	return func(title string, opts []Option, def int) int {
		switch {
		case strings.Contains(title, "Who needs"):
			return 1
		case strings.Contains(title, "How do you want to obtain"):
			return int(route)
		}
		return def
	}
}

func declineProbe(q string, def bool) bool {
	if strings.Contains(q, "trust check") {
		return false
	}
	return def
}

func byoPaths(cert, key string) func(string, string) string {
	return func(label, def string) string {
		switch {
		case strings.Contains(label, "certificate"):
			return cert
		case strings.Contains(label, "private key"):
			return key
		}
		return def
	}
}

func slicesEqualStr(a, b []string) bool {
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

// --- W1: Tailscale route -------------------------------------------------

// TestTLSWizardTailscaleRoute (row W1): with tailscale present the wizard runs
// `tailscale cert` with the expected argv, the files land in the app tls/ dir, the
// config is persisted (tls.* set, gui.protocol=https, legacy fields cleared, the
// tailnet name in the allowlist), and no shown line contains key bytes.
func TestTLSWizardTailscaleRoute(t *testing.T) {
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
		t.Fatalf("expected exactly one tool run, got %v", runs)
	}
	if !strings.HasPrefix(runs[0], "tailscale cert --cert-file ") {
		t.Fatalf("run argv = %q, want a `tailscale cert --cert-file ...` invocation", runs[0])
	}

	cfg, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	const name = "myhost.tailnet-name.ts.net"
	tlsDir, _ := appdir.EnsureConfigDir("tls")
	if cfg.GUI.Protocol != "https" {
		t.Fatalf("gui.protocol = %q, want https", cfg.GUI.Protocol)
	}
	if cfg.GUI.CertFile != "" || cfg.GUI.KeyFile != "" {
		t.Fatalf("legacy fields not cleared: cert=%q key=%q", cfg.GUI.CertFile, cfg.GUI.KeyFile)
	}
	if filepath.Dir(cfg.TLS.CertFile) != tlsDir {
		t.Fatalf("cert not in the app tls dir: %q (tls dir %q)", cfg.TLS.CertFile, tlsDir)
	}
	if !fileExists(cfg.TLS.CertFile) || !fileExists(cfg.TLS.KeyFile) {
		t.Fatalf("cert/key did not land in tls/: cert=%q key=%q", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	if !containsString(cfg.TLS.AllowHosts, name) {
		t.Fatalf("allowHosts = %v, want it to include the tailnet name %q", cfg.TLS.AllowHosts, name)
	}
	assertNoKeyBytes(t, s.shownJoined(), cfg.TLS.KeyFile)
}

// --- W6: I-T5 with lego AND certbot present ------------------------------

// TestTLSWizardIT5OnlyRunsTailscaleCert (row W6, I-T5, C8): with tailscale, lego
// AND certbot all present, the tailscale route records a run ONLY for the
// `tailscale cert` argv (never lego/certbot) and no prompt asks for a token.
func TestTLSWizardIT5OnlyRunsTailscaleCert(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newTestCA(t)
	var runs []string
	deps := TLSDeps{
		LookPath: lookPathPresent("tailscale", "lego", "certbot"),
		Run:      tailscaleRunFake(t, ca, &runs),
		ReadTailscaleStatus: func() (TailscaleStatus, error) {
			return TailscaleStatus{MagicDNSName: "host.example.ts.net", TailnetName: "example.ts.net"}, nil
		},
	}
	s := &tlsScript{t: t, selectBy: routeSelector(routeTailscale), confirmBy: func(q string, def bool) bool {
		if strings.Contains(q, "tailscale cert") {
			return true
		}
		if strings.Contains(q, "trust check") {
			return false
		}
		return def
	}}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("with lego+certbot present the seam must record exactly ONE run (tailscale cert); got %v", runs)
	}
	if !strings.HasPrefix(runs[0], "tailscale cert ") {
		t.Fatalf("the single run must be `tailscale cert ...`; got %q", runs[0])
	}
	for _, r := range runs {
		if strings.Contains(r, "lego") || strings.Contains(r, "certbot") {
			t.Fatalf("lego/certbot must NEVER be run by the wizard; got %q", r)
		}
	}
	if strings.Contains(strings.ToLower(s.promptsJoined()), "token") {
		t.Fatalf("no prompt may ask for a provider token; prompts:\n%s", s.promptsJoined())
	}
}

// --- W2: Let's Encrypt via lego, binary absent ---------------------------

// TestTLSWizardLetsEncryptLegoAbsent (row W2, C4): with lego absent the wizard
// prints the install line BEFORE the run command, never runs a tool, and its
// "press Enter when the files exist" loop re-checks until the files appear; the
// resolved pair is then persisted and no shown line contains key bytes.
func TestTLSWizardLetsEncryptLegoAbsent(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newTestCA(t)
	var runs []string
	deps := TLSDeps{
		LookPath: lookPathPresent(), // nothing present
		Run: func(name string, args ...string) ([]byte, error) {
			runs = append(runs, name)
			return nil, errors.New("must not run")
		},
		ReadTailscaleStatus: noTailscale,
	}
	tlsDir, _ := appdir.EnsureConfigDir("tls")
	const domain = "vault.example.com"
	certPath, keyPath := acmeOutputPaths("lego", tlsDir, domain)

	waitCount := 0
	s := &tlsScript{t: t}
	s.selectBy = func(title string, opts []Option, def int) int {
		switch {
		case strings.Contains(title, "Who needs"):
			return 1
		case strings.Contains(title, "How do you want to obtain"):
			return int(routeLetsEncrypt)
		case strings.Contains(title, "DNS provider"):
			return 0 // Cloudflare
		case strings.Contains(title, "ACME client"):
			return 0 // lego
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
		return def // the wait-loop Confirm defaults to true (keep waiting)
	}
	s.onConfirm = func(q string) {
		if strings.Contains(q, "Press Enter when the certificate files exist") {
			waitCount++
			if waitCount == 2 {
				// The user "ran lego" between presses: the real files now exist.
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
	}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}

	if len(runs) != 0 {
		t.Fatalf("the wizard must NOT run any tool on the lego route; ran %v", runs)
	}
	out := s.shownJoined()
	installIdx := strings.Index(out, "go install github.com/go-acme/lego/v4/cmd/lego@latest")
	cmdIdx := strings.Index(out, "lego --path")
	if installIdx < 0 {
		t.Fatalf("the lego install line was not printed:\n%s", out)
	}
	if cmdIdx < 0 {
		t.Fatalf("the lego run command was not printed:\n%s", out)
	}
	if installIdx > cmdIdx {
		t.Fatalf("install guidance (index %d) must precede the run command (index %d) (C4)", installIdx, cmdIdx)
	}
	if waitCount < 2 {
		t.Fatalf("the file-wait loop did not re-check; it was asked %d time(s), want >= 2", waitCount)
	}
	cfg, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CertFile != certPath {
		t.Fatalf("tls.certFile = %q, want the lego output path %q", cfg.TLS.CertFile, certPath)
	}
	if cfg.GUI.Protocol != "https" {
		t.Fatalf("gui.protocol = %q, want https", cfg.GUI.Protocol)
	}
	if !containsString(cfg.TLS.AllowHosts, domain) {
		t.Fatalf("allowHosts = %v, want it to include %q", cfg.TLS.AllowHosts, domain)
	}
	assertNoKeyBytes(t, out, cfg.TLS.KeyFile)
}

// --- W3: bring-your-own files --------------------------------------------

// TestTLSWizardBYORoute (row W3): a bring-your-own pair is referenced IN PLACE
// (never copied into tls/), persisted, with its concrete SAN in the allowlist and
// no key bytes shown.
func TestTLSWizardBYORoute(t *testing.T) {
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

	cfg, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CertFile != certPath {
		t.Fatalf("BYO cert must be referenced in place: tls.certFile=%q, want %q", cfg.TLS.CertFile, certPath)
	}
	if cfg.TLS.KeyFile != keyPath {
		t.Fatalf("BYO key must be referenced in place: tls.keyFile=%q, want %q", cfg.TLS.KeyFile, keyPath)
	}
	tlsDir, _ := appdir.EnsureConfigDir("tls")
	if strings.HasPrefix(certPath, tlsDir) {
		t.Fatal("test precondition: the BYO source must live OUTSIDE the tls dir")
	}
	if !containsString(cfg.TLS.AllowHosts, "vault.corp.example") {
		t.Fatalf("allowHosts = %v, want the SAN", cfg.TLS.AllowHosts)
	}
	if cfg.GUI.Protocol != "https" {
		t.Fatalf("gui.protocol = %q, want https", cfg.GUI.Protocol)
	}
	assertNoKeyBytes(t, s.shownJoined(), keyPath)
}

// --- W4: keep the self-signed certificate --------------------------------

// TestTLSWizardKeepSelfSigned (row W4): the keep-self-signed route states the
// consequences (trust prompts; Windows WebDAV refuses it), persists
// gui.protocol=https with the shared tls section cleared and the self-signed floor
// materialised, and shows no key bytes.
func TestTLSWizardKeepSelfSigned(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	s := &tlsScript{t: t, selectBy: routeSelector(routeSelfSigned), confirmBy: declineProbe}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	out := s.shownJoined()
	if !strings.Contains(out, "trust prompt") || !strings.Contains(strings.ToLower(out), "windows") {
		t.Fatalf("self-signed consequences were not stated:\n%s", out)
	}
	cfg, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GUI.Protocol != "https" {
		t.Fatalf("gui.protocol = %q, want https", cfg.GUI.Protocol)
	}
	if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		t.Fatalf("keep-self-signed must not set the shared tls section: cert=%q key=%q", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	if cfg.GUI.CertFile == "" || !cfg.GUI.SelfSigned {
		t.Fatalf("the self-signed floor pair was not materialised: cert=%q selfSigned=%v", cfg.GUI.CertFile, cfg.GUI.SelfSigned)
	}
	assertNoKeyBytes(t, out, cfg.GUI.KeyFile)
}

// --- W5: the step-8 trust probe ------------------------------------------

// TestTLSWizardProbe (row W5): the probe reports "self-signed — trust prompt
// expected" for a self-signed pair verified against the system store, and
// "trusted" for a CA-signed leaf verified against a pool the test injects. Both
// rows are asserted.
func TestTLSWizardProbe(t *testing.T) {
	ca := newTestCA(t)
	loopbackIP := []net.IP{net.ParseIP("127.0.0.1")}
	ssCertPEM, ssKeyPEM := selfSignedLeaf(t, []string{"localhost"}, loopbackIP)
	caCertPEM, caKeyPEM := ca.issue(t, []string{"localhost"}, loopbackIP)

	rows := []struct {
		name       string
		cfg        *tls.Config
		selfSigned bool
		roots      *x509.CertPool
		want       probeVerdict
		wantDetail string
	}{
		{"self-signed floor via system store", tlsCfgFromPEM(t, ssCertPEM, ssKeyPEM), true, nil, probeSelfSigned, "self-signed"},
		{"CA leaf via injected pool", tlsCfgFromPEM(t, caCertPEM, caKeyPEM), false, ca.pool, probeTrusted, "trusted"},
	}
	if len(rows) == 0 {
		t.Fatal("probe table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			res := runProbe("127.0.0.1", r.cfg, "localhost", r.selfSigned, r.roots)
			if res.verdict != r.want {
				t.Fatalf("verdict = %d (detail %q), want %d", res.verdict, res.detail, r.want)
			}
			if !strings.Contains(res.detail, r.wantDetail) {
				t.Fatalf("detail = %q, want substring %q", res.detail, r.wantDetail)
			}
		})
	}
}

// --- H1 wildcard row + proposeAllowHosts table ---------------------------

// TestTLSWizardWildcardSANDropped (row H1, C5): a certificate whose SANs include a
// wildcard is persisted with the wildcard EXCLUDED from tls.allowHosts, the
// concrete SAN kept, and the wizard states why (exact-match only).
func TestTLSWizardWildcardSANDropped(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	ca := newTestCA(t)
	srcDir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, []string{"*.corp.example", "vault.corp.example"}, nil)
	certPath, keyPath := writePair(t, srcDir, certPEM, keyPEM)

	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	s := &tlsScript{t: t, selectBy: routeSelector(routeBYO), textBy: byoPaths(certPath, keyPath), confirmBy: declineProbe}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}

	cfg, err := appconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range cfg.TLS.AllowHosts {
		if strings.Contains(h, "*") {
			t.Fatalf("a wildcard SAN was stored in tls.allowHosts: %q", h)
		}
	}
	if containsString(cfg.TLS.AllowHosts, "*.corp.example") {
		t.Fatalf("wildcard stored in allowHosts: %v", cfg.TLS.AllowHosts)
	}
	if !containsString(cfg.TLS.AllowHosts, "vault.corp.example") {
		t.Fatalf("the concrete SAN must be kept: %v", cfg.TLS.AllowHosts)
	}
	out := s.shownJoined()
	if !strings.Contains(out, "*.corp.example") || !strings.Contains(strings.ToLower(out), "exact") {
		t.Fatalf("the wizard did not explain the dropped wildcard (exact-match only):\n%s", out)
	}
}

// TestProposeAllowHostsTable asserts the concrete/wildcard split on every row.
func TestProposeAllowHostsTable(t *testing.T) {
	rows := []struct {
		name         string
		in           []string
		wantConcrete []string
		wantWild     []string
	}{
		{"concrete only", []string{"a.example", "b.example"}, []string{"a.example", "b.example"}, nil},
		{"wildcard dropped", []string{"*.corp.example", "vault.corp.example"}, []string{"vault.corp.example"}, []string{"*.corp.example"}},
		{"ip san is concrete", []string{"192.168.1.5", "host.example"}, []string{"192.168.1.5", "host.example"}, nil},
		{"blank entries skipped", []string{"", "  ", "x.example"}, []string{"x.example"}, nil},
		{"all wildcards", []string{"*.a.example", "*.b.example"}, nil, []string{"*.a.example", "*.b.example"}},
	}
	if len(rows) == 0 {
		t.Fatal("proposeAllowHosts table is empty")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c, w := proposeAllowHosts(r.in)
			if !slicesEqualStr(c, r.wantConcrete) {
				t.Fatalf("concrete = %v, want %v", c, r.wantConcrete)
			}
			if !slicesEqualStr(w, r.wantWild) {
				t.Fatalf("wildcards = %v, want %v", w, r.wantWild)
			}
		})
	}
}

// TestParseTailscaleStatus asserts the non-secret identity fields are extracted
// and the trailing dot on the MagicDNS name is trimmed.
func TestParseTailscaleStatus(t *testing.T) {
	data := []byte(`{"Self":{"DNSName":"myhost.tailnet-name.ts.net."},"MagicDNSSuffix":"tailnet-name.ts.net","CurrentTailnet":{"Name":"tailnet-name.ts.net"}}`)
	st, err := parseTailscaleStatus(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.MagicDNSName != "myhost.tailnet-name.ts.net" {
		t.Fatalf("MagicDNSName = %q, want the dot trimmed", st.MagicDNSName)
	}
	if st.TailnetName != "tailnet-name.ts.net" {
		t.Fatalf("TailnetName = %q", st.TailnetName)
	}
}
