// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package appconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

const Version = 1

type Config struct {
	Version        int            `json:"version"`
	GUI            GUIConfig      `json:"gui"`
	TLS            TLSSection     `json:"tls"`
	Auth           AuthSection    `json:"auth"`
	Log            LogConfig      `json:"log"`
	RuntimeSources RuntimeSources `json:"runtimeSources"`
}

// AuthSection groups the authentication-surface policy. Today it carries only the
// U4 rate-limit / lockout knobs (auth.limits); it is a section so future auth
// policy has a home without another top-level field.
type AuthSection struct {
	Limits AuthLimits `json:"limits"`
}

// AuthLimits is the persisted configuration for the U4 authentication rate
// limiter and lockout (design-u4 §2.1/§2.2). It never holds a credential — only
// thresholds, durations (as human strings like "15m"/"250ms"), and the
// emergency off switch. Enabled is a pointer so an absent field defaults to ON
// (I-R4): a missing auth.limits section, or one without "enabled", is enabled,
// and only an explicit `"enabled": false` disables. DisabledSince records when a
// persisted (config-file) disable took effect, so `tls status`/the settings page
// can say "OFF since <date>" and the running server can re-warn (C7); it is
// meaningless — and cleared by Normalize — whenever the limiter is enabled.
type AuthLimits struct {
	Enabled                   *bool  `json:"enabled,omitempty"`
	FailuresBeforeLock        int    `json:"failuresBeforeLock,omitempty"`
	AccountFailuresBeforeLock int    `json:"accountFailuresBeforeLock,omitempty"`
	Window                    string `json:"window,omitempty"`
	LockStart                 string `json:"lockStart,omitempty"`
	LockMax                   string `json:"lockMax,omitempty"`
	FailureDelay              string `json:"failureDelay,omitempty"`
	MaxKeys                   int    `json:"maxKeys,omitempty"`
	DisabledSince             string `json:"disabledSince,omitempty"`
}

// DefaultAuthLimits returns the design's normalized auth-limit defaults (§2.1):
// enabled, 5 failures before a peer lock, 20 for the per-account ceiling, a 15m
// streak window, a 30s→15m doubling lock, a 250ms throttle, and a 10 000-key map
// bound. Durations are the human strings a person edits.
func DefaultAuthLimits() AuthLimits {
	enabled := true
	return AuthLimits{
		Enabled:                   &enabled,
		FailuresBeforeLock:        5,
		AccountFailuresBeforeLock: 20,
		Window:                    "15m",
		LockStart:                 "30s",
		LockMax:                   "15m",
		FailureDelay:              "250ms",
		MaxKeys:                   10000,
	}
}

// IsEnabled reports whether the limiter is on. An absent Enabled pointer means
// on (the default), so a config that never mentions auth.limits is protected.
func (a AuthLimits) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// StatusLine renders the one-line operator-facing auth-limit status used by `tls
// status`, the GUI settings surface, and the non-loopback startup exposure line
// (C7 / §2.3). Enabled: the threshold, the streak Window, and the lock band —
// the Window is surfaced so a hostile-but-normalized value is visible in the
// readout, never hidden. Disabled: the "OFF" state, dated when a persisted
// disable recorded DisabledSince, always with the re-enable remedy. Call it on a
// normalized AuthLimits (Load/Normalize fill the values); it never emits a
// credential.
func (a AuthLimits) StatusLine() string {
	if a.IsEnabled() {
		return fmt.Sprintf("auth limits: on (%d failures in %s → %s…%s)", a.FailuresBeforeLock, a.Window, a.LockStart, a.LockMax)
	}
	if strings.TrimSpace(a.DisabledSince) != "" {
		return fmt.Sprintf("auth limits: OFF since %s — re-enable with --auth-limit on or auth.limits.enabled=true", a.DisabledSince)
	}
	return "auth limits: OFF — re-enable with --auth-limit on or auth.limits.enabled=true"
}

// TLSSection is the shared, purpose-neutral certificate configuration introduced
// in U3. It supersedes the legacy gui.certFile/keyFile fields (which stay
// readable for compatibility and are cleared by the wizard when it writes this
// section). CertFile/KeyFile point at a PEM chain (leaf first) and its matching
// private key; AllowHosts lists the exact DNS names the Host-header rebinding
// guard should additionally admit when binding beyond loopback. It never holds
// private key material — only paths and names.
type TLSSection struct {
	CertFile   string   `json:"certFile"`
	KeyFile    string   `json:"keyFile"`
	AllowHosts []string `json:"allowHosts,omitempty"`
}

type GUIConfig struct {
	Protocol           string `json:"protocol"`
	CertFile           string `json:"certFile"`
	KeyFile            string `json:"keyFile"`
	SelfSigned         bool   `json:"selfSigned"`
	Username           string `json:"username"`
	PasswordConfigured bool   `json:"passwordConfigured"`
	PasswordHash       string `json:"passwordHash,omitempty"`
}

type LogConfig struct {
	MaxEntries int    `json:"maxEntries"`
	FilePath   string `json:"filePath"`
	Persist    bool   `json:"persist"`
}

type RuntimeSources struct {
	RcloneChannel       string `json:"rcloneChannel"`
	RsyncSourceBaseURL  string `json:"rsyncSourceBaseUrl"`
	RsyncRuntimeBaseURL string `json:"rsyncRuntimeBaseUrl"`
	WSLInstallSource    string `json:"wslInstallSource"`
}

func Default() Config {
	return Config{Version: Version, GUI: GUIConfig{Protocol: "http"}, Auth: AuthSection{Limits: DefaultAuthLimits()}, Log: LogConfig{MaxEntries: 200}, RuntimeSources: RuntimeSources{RcloneChannel: "stable", RsyncSourceBaseURL: "https://download.samba.org/pub/rsync", RsyncRuntimeBaseURL: "", WSLInstallSource: "wsl.exe --install"}}
}

func Path() (string, error) {
	dir, err := appdir.EnsureConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "appconfig.json"), nil
}

func Load() (Config, error) {
	cfg := Default()
	p, err := Path()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), err
	}
	return Normalize(cfg), nil
}

func Save(cfg Config) error {
	cfg = Normalize(cfg)
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(p, append(data, '\n'), 0o600)
}

func Normalize(cfg Config) Config {
	def := Default()
	cfg.Version = Version
	cfg.GUI.Protocol = strings.ToLower(strings.TrimSpace(cfg.GUI.Protocol))
	if cfg.GUI.Protocol != "https" {
		cfg.GUI.Protocol = "http"
	}
	cfg.GUI.CertFile = strings.TrimSpace(cfg.GUI.CertFile)
	cfg.GUI.KeyFile = strings.TrimSpace(cfg.GUI.KeyFile)
	cfg.TLS = normalizeTLS(cfg.TLS)
	cfg.Auth.Limits = normalizeAuthLimits(cfg.Auth.Limits)
	cfg.GUI.Username = strings.TrimSpace(cfg.GUI.Username)
	cfg.GUI.PasswordHash = strings.TrimSpace(cfg.GUI.PasswordHash)
	if cfg.GUI.PasswordHash != "" {
		cfg.GUI.PasswordConfigured = true
	}
	if cfg.GUI.Username == "" {
		cfg.GUI.PasswordConfigured = false
		cfg.GUI.PasswordHash = ""
	}
	if cfg.Log.MaxEntries <= 0 {
		cfg.Log.MaxEntries = def.Log.MaxEntries
	}
	if cfg.Log.MaxEntries > 5000 {
		cfg.Log.MaxEntries = 5000
	}
	cfg.Log.FilePath = strings.TrimSpace(cfg.Log.FilePath)
	cfg.RuntimeSources.RcloneChannel = strings.TrimSpace(cfg.RuntimeSources.RcloneChannel)
	if cfg.RuntimeSources.RcloneChannel == "" {
		cfg.RuntimeSources.RcloneChannel = def.RuntimeSources.RcloneChannel
	}
	cfg.RuntimeSources.RsyncSourceBaseURL = strings.TrimSpace(cfg.RuntimeSources.RsyncSourceBaseURL)
	if cfg.RuntimeSources.RsyncSourceBaseURL == "" {
		cfg.RuntimeSources.RsyncSourceBaseURL = def.RuntimeSources.RsyncSourceBaseURL
	}
	cfg.RuntimeSources.RsyncRuntimeBaseURL = strings.TrimSpace(cfg.RuntimeSources.RsyncRuntimeBaseURL)
	if cfg.RuntimeSources.RsyncRuntimeBaseURL == "" {
		cfg.RuntimeSources.RsyncRuntimeBaseURL = def.RuntimeSources.RsyncRuntimeBaseURL
	}
	cfg.RuntimeSources.WSLInstallSource = strings.TrimSpace(cfg.RuntimeSources.WSLInstallSource)
	if cfg.RuntimeSources.WSLInstallSource == "" {
		cfg.RuntimeSources.WSLInstallSource = def.RuntimeSources.WSLInstallSource
	}
	return cfg
}

// normalizeTLS trims the shared TLS paths and cleans the allow-host list: each
// entry is trimmed, empty entries are dropped, and duplicates are removed while
// preserving first-seen order. The Host allowlist matches exact names only, so
// no case folding or wildcard expansion happens here.
func normalizeTLS(t TLSSection) TLSSection {
	t.CertFile = strings.TrimSpace(t.CertFile)
	t.KeyFile = strings.TrimSpace(t.KeyFile)
	if len(t.AllowHosts) == 0 {
		t.AllowHosts = nil
		return t
	}
	seen := make(map[string]struct{}, len(t.AllowHosts))
	cleaned := make([]string, 0, len(t.AllowHosts))
	for _, h := range t.AllowHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		cleaned = append(cleaned, h)
	}
	if len(cleaned) == 0 {
		cleaned = nil
	}
	t.AllowHosts = cleaned
	return t
}

// Normalization bounds for the auth-limit knobs. Values outside these ranges are
// not clamped-to-edge but replaced by the default, because a degenerate-but-valid
// config value is as dangerous as a blank one: a threshold of two billion, or a
// one-nanosecond window (which resets the streak between any two real attempts,
// so nothing ever locks), would silently NEUTRALIZE the limiter while a naive
// readout still said "on". The floors keep a lock meaningful; the ceilings keep a
// threshold and the map bound from wandering off to "effectively unlimited".
const (
	minAuthWindow                = time.Minute
	minAuthLockStart             = time.Second
	maxFailuresBeforeLock        = 1000
	maxAccountFailuresBeforeLock = 100000
	maxAuthMaxKeys               = 10000000
)

// normalizeAuthLimits fills zero/blank/invalid auth-limit fields from the
// defaults, floors the durations, and caps the thresholds and the map bound, so
// a misconfigured OR degenerate-but-valid file can never silently produce a
// lock-on-first-attempt threshold, an effectively-unlimited threshold, an
// unbounded map, an unparsable duration, or a window/lock so small the limiter
// never locks. A blank, invalid, sub-floor, or over-cap value falls back to its
// default; the human form of an in-range duration is preserved. LockMax is
// raised to at least the (already-floored) LockStart. When the limiter is
// enabled, DisabledSince is cleared (it is meaningless), so re-enabling by
// flipping "enabled" back to true drops the stale timestamp on the next save.
func normalizeAuthLimits(a AuthLimits) AuthLimits {
	d := DefaultAuthLimits()
	if a.Enabled == nil {
		enabled := true
		a.Enabled = &enabled
	}
	if a.FailuresBeforeLock <= 0 || a.FailuresBeforeLock > maxFailuresBeforeLock {
		a.FailuresBeforeLock = d.FailuresBeforeLock
	}
	if a.AccountFailuresBeforeLock <= 0 || a.AccountFailuresBeforeLock > maxAccountFailuresBeforeLock {
		a.AccountFailuresBeforeLock = d.AccountFailuresBeforeLock
	}
	if a.MaxKeys <= 0 || a.MaxKeys > maxAuthMaxKeys {
		a.MaxKeys = d.MaxKeys
	}
	a.Window = normalizeDurationFloor(a.Window, d.Window, minAuthWindow)
	a.LockStart = normalizeDurationFloor(a.LockStart, d.LockStart, minAuthLockStart)
	a.LockMax = normalizeLockMax(a.LockStart, a.LockMax, d.LockMax)
	a.FailureDelay = normalizeDurationString(a.FailureDelay, d.FailureDelay, true)
	a.DisabledSince = strings.TrimSpace(a.DisabledSince)
	if a.IsEnabled() {
		a.DisabledSince = ""
	}
	return a
}

// normalizeDurationString trims s and returns it unchanged when it parses to a
// valid duration; otherwise it returns def. When allowZero is false a
// non-positive duration is treated as invalid (a zero window/lock would defeat
// the limiter); FailureDelay passes allowZero=true because a zero throttle is a
// legitimate choice (§2.1).
func normalizeDurationString(s, def string, allowZero bool) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	if dur < 0 || (dur == 0 && !allowZero) {
		return def
	}
	return s
}

// normalizeDurationFloor trims s and keeps it only when it parses to a duration
// of at least min; a blank, unparsable, or sub-floor value falls back to def
// (which is itself at least min). The floor is what stops a degenerate value
// like "1ns" from silently disabling the limiter.
func normalizeDurationFloor(s, def string, min time.Duration) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	dur, err := time.ParseDuration(s)
	if err != nil || dur < min {
		return def
	}
	return s
}

// normalizeLockMax keeps lockMax only when it parses and is at least the
// already-normalized lockStart; a blank or unparsable value falls back to def,
// and any value below lockStart is raised to lockStart (LockMax < LockStart would
// make the doubling band incoherent). lockStartStr is trusted to be a valid,
// floored duration string (normalizeDurationFloor produced it).
func normalizeLockMax(lockStartStr, lockMaxStr, def string) string {
	start, _ := time.ParseDuration(lockStartStr)
	s := strings.TrimSpace(lockMaxStr)
	dur, err := time.ParseDuration(s)
	if s == "" || err != nil {
		s = def
		dur, _ = time.ParseDuration(def)
	}
	if dur < start {
		return lockStartStr
	}
	return s
}

func EnsureSelfSignedCertificate(cfg Config, host string) (Config, error) {
	cfg = Normalize(cfg)
	if strings.TrimSpace(cfg.GUI.CertFile) != "" && strings.TrimSpace(cfg.GUI.KeyFile) != "" {
		return cfg, nil
	}
	dir, err := appdir.EnsureConfigDir("tls")
	if err != nil {
		return cfg, err
	}
	certPath := filepath.Join(dir, "seavault-local.crt")
	keyPath := filepath.Join(dir, "seavault-local.key")
	if _, certErr := os.Stat(certPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			cfg.GUI.CertFile = certPath
			cfg.GUI.KeyFile = keyPath
			cfg.GUI.SelfSigned = true
			return cfg, nil
		}
	}
	if err := writeSelfSigned(certPath, keyPath, host); err != nil {
		return cfg, err
	}
	cfg.GUI.CertFile = certPath
	cfg.GUI.KeyFile = keyPath
	cfg.GUI.SelfSigned = true
	return cfg, nil
}

func writeSelfSigned(certPath, keyPath, host string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "open-seavault-rclone local GUI"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if host == "" {
		host = "127.0.0.1"
	}
	for _, h := range []string{host, "localhost", "127.0.0.1", "::1"} {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certOut.Close()
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		_ = keyOut.Close()
		return err
	}
	return keyOut.Close()
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}
