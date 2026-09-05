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
	Log            LogConfig      `json:"log"`
	RuntimeSources RuntimeSources `json:"runtimeSources"`
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
	return Config{Version: Version, GUI: GUIConfig{Protocol: "http"}, Log: LogConfig{MaxEntries: 200}, RuntimeSources: RuntimeSources{RcloneChannel: "stable", RsyncSourceBaseURL: "https://download.samba.org/pub/rsync", RsyncRuntimeBaseURL: "", WSLInstallSource: "wsl.exe --install"}}
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
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "SeaVault local GUI"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
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
