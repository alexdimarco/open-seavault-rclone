// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

const (
	ManifestVersion    = 1
	DefaultBaseURL     = "https://downloads.rclone.org"
	DefaultBetaURL     = "https://beta.rclone.org"
	KeysURL            = "https://rclone.org/KEYS"
	SigningFingerprint = "FBF737ECE9F8AB18604BD2AC93935E02FF3B54FA"
)

var versionRE = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)

type Manifest struct {
	Version            int    `json:"version"`
	InstalledVersion   string `json:"installedVersion"`
	InstalledAt        string `json:"installedAt"`
	GOOS               string `json:"goos"`
	GOARCH             string `json:"goarch"`
	BinaryPath         string `json:"binaryPath"`
	SHA256             string `json:"sha256"`
	SourceURL          string `json:"sourceUrl"`
	ReleaseChannel     string `json:"releaseChannel"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	PreviousBinaryPath string `json:"previousBinaryPath,omitempty"`
	PreviousSHA256     string `json:"previousSha256,omitempty"`
	UpdateCheckedAt    string `json:"updateCheckedAt,omitempty"`
	SignatureVerified  bool   `json:"signatureVerified"`
	SignatureMethod    string `json:"signatureMethod,omitempty"`
	SignatureWarning   string `json:"signatureWarning,omitempty"`
	ChecksumVerified   bool   `json:"checksumVerified"`
}

type Status struct {
	Installed         bool   `json:"installed"`
	Version           string `json:"version,omitempty"`
	BinaryPath        string `json:"binaryPath,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	ReleaseChannel    string `json:"releaseChannel,omitempty"`
	InstalledAt       string `json:"installedAt,omitempty"`
	UpdateCheckedAt   string `json:"updateCheckedAt,omitempty"`
	PreviousVersion   string `json:"previousVersion,omitempty"`
	SignatureVerified bool   `json:"signatureVerified"`
	SignatureMethod   string `json:"signatureMethod,omitempty"`
	SignatureWarning  string `json:"signatureWarning,omitempty"`
	ChecksumVerified  bool   `json:"checksumVerified"`
	RuntimeOK         bool   `json:"runtimeOk"`
	RuntimeMessage    string `json:"runtimeMessage,omitempty"`
	LatestVersion     string `json:"latestVersion,omitempty"`
	LatestCheckError  string `json:"latestCheckError,omitempty"`
	RuntimeDir        string `json:"runtimeDir,omitempty"`
	ManifestPath      string `json:"manifestPath,omitempty"`
}

type LatestInfo struct {
	Version string `json:"version"`
	Channel string `json:"channel"`
	URL     string `json:"url"`
}

type InstallOptions struct {
	Version         string
	Channel         string
	FromBinary      string
	OfflineArchive  string
	OfflineSHA256   string
	SignatureMode   string // required, optional, skip
	AllowPrerelease bool
}

type Policy struct {
	AllowUpdates             bool     `json:"allowUpdates"`
	AllowedChannels          []string `json:"allowedChannels"`
	PinnedVersion            string   `json:"pinnedVersion"`
	AllowedDownloadHosts     []string `json:"allowedDownloadHosts"`
	UpdateCheckIntervalHours int      `json:"updateCheckIntervalHours"`
	RequireManualApproval    bool     `json:"requireManualApproval"`
	SignatureMode            string   `json:"signatureMode"`
}

type Installer struct {
	Client  *http.Client
	Now     func() time.Time
	BaseURL string
	BetaURL string
	KeysURL string
	GOOS    string
	GOARCH  string
}

func NewInstaller() *Installer {
	return &Installer{Client: http.DefaultClient, Now: func() time.Time { return time.Now().UTC() }, BaseURL: DefaultBaseURL, BetaURL: DefaultBetaURL, KeysURL: KeysURL, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

func RuntimeRoot() (string, error) { return appdir.RuntimeDir() }

func ManifestPath() (string, error) {
	root, err := RuntimeRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "runtime.json"), nil
}

func PolicyPath() (string, error) {
	dir, err := appdir.EnsureConfigDir("rclone")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "policy.json"), nil
}

func DefaultPolicy() Policy {
	return Policy{AllowUpdates: true, AllowedChannels: []string{"stable"}, UpdateCheckIntervalHours: 24, RequireManualApproval: true, SignatureMode: "optional"}
}

func LoadPolicy() Policy {
	p, err := PolicyPath()
	if err != nil {
		return DefaultPolicy()
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return DefaultPolicy()
	}
	var pol Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return DefaultPolicy()
	}
	if pol.SignatureMode == "" {
		pol.SignatureMode = "optional"
	}
	if len(pol.AllowedChannels) == 0 {
		pol.AllowedChannels = []string{"stable"}
	}
	if pol.UpdateCheckIntervalHours == 0 {
		pol.UpdateCheckIntervalHours = 24
	}
	return pol
}

func SavePolicy(pol Policy) error {
	p, err := PolicyPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func LoadManifest() (Manifest, error) {
	p, err := ManifestPath()
	if err != nil {
		return Manifest{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Manifest{}, os.ErrNotExist
	}
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func SaveManifest(m Manifest) error {
	p, err := ManifestPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	m.Version = ManifestVersion
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(p, data, 0o600)
}

func BinaryPath() (string, error) {
	m, err := LoadManifest()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(m.BinaryPath) == "" {
		return "", errors.New("managed rclone is not installed")
	}
	return m.BinaryPath, nil
}

func ActivePath() (string, error) { return BinaryPath() }

func StatusNow(ctx context.Context) Status { return NewInstaller().Status(ctx, false) }

func (i *Installer) Status(ctx context.Context, checkLatest bool) Status {
	root, _ := RuntimeRoot()
	mp, _ := ManifestPath()
	m, err := LoadManifest()
	if errors.Is(err, os.ErrNotExist) {
		st := Status{Installed: false, RuntimeOK: false, RuntimeMessage: "managed rclone is not installed", RuntimeDir: root, ManifestPath: mp}
		if checkLatest {
			li, e := i.Latest(ctx, "stable")
			if e == nil {
				st.LatestVersion = li.Version
			} else {
				st.LatestCheckError = e.Error()
			}
		}
		return st
	}
	if err != nil {
		return Status{Installed: false, RuntimeOK: false, RuntimeMessage: err.Error(), RuntimeDir: root, ManifestPath: mp}
	}
	st := Status{Installed: true, Version: m.InstalledVersion, BinaryPath: m.BinaryPath, SHA256: m.SHA256, ReleaseChannel: m.ReleaseChannel, InstalledAt: m.InstalledAt, UpdateCheckedAt: m.UpdateCheckedAt, PreviousVersion: m.PreviousVersion, SignatureVerified: m.SignatureVerified, SignatureMethod: m.SignatureMethod, SignatureWarning: m.SignatureWarning, ChecksumVerified: m.ChecksumVerified, RuntimeDir: root, ManifestPath: mp}
	if err := VerifyRuntime(m); err != nil {
		st.RuntimeOK = false
		st.RuntimeMessage = err.Error()
	} else {
		st.RuntimeOK = true
		st.RuntimeMessage = "managed rclone verified"
	}
	if checkLatest {
		li, e := i.Latest(ctx, m.ReleaseChannel)
		if e == nil {
			st.LatestVersion = li.Version
		} else {
			st.LatestCheckError = e.Error()
		}
	}
	return st
}

func (i *Installer) Latest(ctx context.Context, channel string) (LatestInfo, error) {
	base := strings.TrimRight(i.BaseURL, "/")
	if strings.EqualFold(channel, "beta") {
		base = strings.TrimRight(i.BetaURL, "/")
	}
	url := base + "/version.txt"
	data, err := i.fetch(ctx, url, 1<<20)
	if err != nil {
		return LatestInfo{}, err
	}
	version := parseVersion(string(data))
	if version == "" {
		return LatestInfo{}, fmt.Errorf("could not parse rclone version from %s", url)
	}
	if m, err := LoadManifest(); err == nil && strings.TrimSpace(m.BinaryPath) != "" {
		m.UpdateCheckedAt = i.Now().Format(time.RFC3339Nano)
		_ = SaveManifest(m)
	}
	return LatestInfo{Version: version, Channel: channel, URL: url}, nil
}

func (i *Installer) Install(ctx context.Context, opts InstallOptions) (Manifest, error) {
	channel := strings.ToLower(strings.TrimSpace(opts.Channel))
	if channel == "" {
		channel = "stable"
	}
	version := normalizeVersion(opts.Version)
	if version == "" && opts.FromBinary == "" && opts.OfflineArchive == "" {
		li, err := i.Latest(ctx, channel)
		if err != nil {
			return Manifest{}, err
		}
		version = li.Version
	}
	if version == "" {
		version = "current"
	}
	root, err := RuntimeRoot()
	if err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Manifest{}, err
	}
	old, _ := LoadManifest()

	var binPath, sourceURL, archiveHash string
	checksumVerified := false
	signatureVerified := false
	signatureMethod := ""
	signatureWarning := ""

	if opts.FromBinary != "" {
		src, err := userpath.Abs(opts.FromBinary)
		if err != nil {
			return Manifest{}, err
		}
		found, err := Version(ctx, src)
		if err != nil {
			return Manifest{}, err
		}
		version = found
		dir := filepath.Join(root, version)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Manifest{}, err
		}
		binName := "rclone"
		if i.GOOS == "windows" {
			binName = "rclone.exe"
		}
		binPath = filepath.Join(dir, binName)
		if err := copyFile(src, binPath, 0o700); err != nil {
			return Manifest{}, err
		}
		sourceURL = "registered-binary:" + src
	} else {
		work, err := os.MkdirTemp("", "seavault-rclone-install-*")
		if err != nil {
			return Manifest{}, err
		}
		defer os.RemoveAll(work)
		platform, err := artifactPlatform(i.GOOS, i.GOARCH)
		if err != nil {
			return Manifest{}, err
		}
		artifact, err := ArtifactName(version, i.GOOS, i.GOARCH)
		if err != nil {
			return Manifest{}, err
		}
		archivePath := opts.OfflineArchive
		checksumText := []byte(nil)
		if archivePath == "" {
			base := strings.TrimRight(i.BaseURL, "/")
			if strings.EqualFold(channel, "beta") {
				base = strings.TrimRight(i.BetaURL, "/")
			}
			if version == "current" {
				sourceURL = base + "/" + artifact
			} else {
				sourceURL = base + "/" + version + "/" + artifact
			}
			archivePath = filepath.Join(work, artifact)
			data, err := i.fetch(ctx, sourceURL, 512<<20)
			if err != nil {
				return Manifest{}, err
			}
			if err := os.WriteFile(archivePath, data, 0o600); err != nil {
				return Manifest{}, err
			}
			checksumURL := strings.TrimSuffix(sourceURL, artifact) + "SHA256SUMS"
			checksumText, err = i.fetch(ctx, checksumURL, 8<<20)
			if err != nil {
				return Manifest{}, fmt.Errorf("download SHA256SUMS: %w", err)
			}
			sig, warn := i.verifySignature(ctx, checksumText, opts.SignatureMode)
			if signatureMode(opts.SignatureMode) == "required" && !sig {
				return Manifest{}, fmt.Errorf("rclone SHA256SUMS signature verification is required: %s", warn)
			}
			signatureVerified = sig
			signatureWarning = warn
			if sig {
				signatureMethod = "gpg-rclone-KEYS"
			}
		} else {
			sourceURL = "offline-archive:" + archivePath
			if opts.OfflineSHA256 != "" {
				checksumText, err = os.ReadFile(opts.OfflineSHA256)
				if err != nil {
					return Manifest{}, err
				}
			}
		}
		archiveHash, err = fileSHA256(archivePath)
		if err != nil {
			return Manifest{}, err
		}
		if len(checksumText) != 0 {
			want, err := checksumForArtifact(checksumText, artifact)
			if err != nil {
				return Manifest{}, err
			}
			if !strings.EqualFold(want, archiveHash) {
				return Manifest{}, fmt.Errorf("downloaded rclone archive hash mismatch for %s", artifact)
			}
			checksumVerified = true
		}
		stage := filepath.Join(work, "stage")
		if err := os.MkdirAll(stage, 0o700); err != nil {
			return Manifest{}, err
		}
		binName := "rclone"
		if i.GOOS == "windows" {
			binName = "rclone.exe"
		}
		stageBin := filepath.Join(stage, binName)
		if err := extractExecutable(archivePath, stageBin, binName); err != nil {
			return Manifest{}, err
		}
		foundVersion, err := Version(ctx, stageBin)
		if err != nil {
			return Manifest{}, err
		}
		if normalizeVersion(opts.Version) != "" && foundVersion != normalizeVersion(opts.Version) {
			return Manifest{}, fmt.Errorf("downloaded rclone version mismatch: expected %s, got %s", normalizeVersion(opts.Version), foundVersion)
		}
		version = foundVersion
		dir := filepath.Join(root, version)
		_ = os.RemoveAll(dir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Manifest{}, err
		}
		binPath = filepath.Join(dir, platform.exeName)
		if err := copyFile(stageBin, binPath, 0o700); err != nil {
			return Manifest{}, err
		}
	}
	binHash, err := fileSHA256(binPath)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Version: ManifestVersion, InstalledVersion: version, InstalledAt: i.Now().Format(time.RFC3339Nano), GOOS: i.GOOS, GOARCH: i.GOARCH, BinaryPath: binPath, SHA256: binHash, SourceURL: sourceURL, ReleaseChannel: channel, PreviousVersion: old.InstalledVersion, PreviousBinaryPath: old.BinaryPath, PreviousSHA256: old.SHA256, SignatureVerified: signatureVerified, SignatureMethod: signatureMethod, SignatureWarning: signatureWarning, ChecksumVerified: checksumVerified}
	if archiveHash == "" && opts.FromBinary != "" {
		m.ChecksumVerified = true
	}
	if err := SaveManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (i *Installer) Update(ctx context.Context, opts InstallOptions) (Manifest, error) {
	if opts.Channel == "" {
		if m, err := LoadManifest(); err == nil && m.ReleaseChannel != "" {
			opts.Channel = m.ReleaseChannel
		} else {
			opts.Channel = "stable"
		}
	}
	return i.Install(ctx, opts)
}

func Rollback() (Manifest, error) {
	m, err := LoadManifest()
	if err != nil {
		return Manifest{}, err
	}
	if m.PreviousBinaryPath == "" || m.PreviousVersion == "" {
		return Manifest{}, errors.New("no previous rclone runtime is recorded for rollback")
	}
	if _, err := os.Stat(m.PreviousBinaryPath); err != nil {
		return Manifest{}, fmt.Errorf("previous rclone binary is unavailable: %w", err)
	}
	m.InstalledVersion, m.PreviousVersion = m.PreviousVersion, m.InstalledVersion
	m.BinaryPath, m.PreviousBinaryPath = m.PreviousBinaryPath, m.BinaryPath
	m.SHA256, m.PreviousSHA256 = m.PreviousSHA256, m.SHA256
	m.InstalledAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := SaveManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func VerifyRuntime(m Manifest) error {
	if m.BinaryPath == "" {
		return errors.New("managed rclone binary path is empty")
	}
	info, err := os.Stat(m.BinaryPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not an rclone executable", m.BinaryPath)
	}
	if m.SHA256 != "" {
		h, err := fileSHA256(m.BinaryPath)
		if err != nil {
			return err
		}
		if !strings.EqualFold(h, m.SHA256) {
			return fmt.Errorf("managed rclone hash mismatch: expected %s, got %s", m.SHA256, h)
		}
	}
	return nil
}

func Version(ctx context.Context, bin string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run rclone version: %w: %s", err, strings.TrimSpace(string(out)))
	}
	v := parseVersion(string(out))
	if v == "" {
		return "", fmt.Errorf("could not parse rclone version output: %s", strings.TrimSpace(string(out)))
	}
	return v, nil
}

func ArtifactName(version, goos, goarch string) (string, error) {
	p, err := artifactPlatform(goos, goarch)
	if err != nil {
		return "", err
	}
	v := normalizeVersion(version)
	if v == "" || v == "current" {
		return fmt.Sprintf("rclone-current-%s-%s.zip", p.osName, p.archName), nil
	}
	return fmt.Sprintf("rclone-%s-%s-%s.zip", v, p.osName, p.archName), nil
}

type platform struct{ osName, archName, exeName string }

func artifactPlatform(goos, goarch string) (platform, error) {
	p := platform{osName: goos, archName: goarch, exeName: "rclone"}
	switch goos {
	case "linux", "windows", "freebsd", "openbsd", "netbsd", "solaris":
	case "darwin":
		p.osName = "osx"
	default:
		return platform{}, fmt.Errorf("unsupported rclone OS %q", goos)
	}
	switch goarch {
	case "amd64", "386", "arm64":
		p.archName = goarch
	case "arm":
		p.archName = "arm-v7"
	default:
		return platform{}, fmt.Errorf("unsupported rclone architecture %q", goarch)
	}
	if goos == "windows" {
		p.exeName = "rclone.exe"
	}
	return p, nil
}

func parseVersion(s string) string {
	match := versionRE.FindStringSubmatch(s)
	if len(match) < 2 {
		return ""
	}
	return "v" + match[1]
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "latest") || strings.EqualFold(v, "stable") {
		return ""
	}
	if strings.EqualFold(v, "current") {
		return "current"
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func checksumForArtifact(sums []byte, artifact string) (string, error) {
	body := clearSignedBody(sums)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "Hash:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := strings.TrimPrefix(fields[len(fields)-1], "*")
			if filepath.Base(name) == artifact || strings.HasSuffix(filepath.Base(name), strings.TrimPrefix(artifact, "rclone-current")) {
				return strings.ToLower(fields[0]), nil
			}
		}
	}
	return "", fmt.Errorf("%s not found in SHA256SUMS", artifact)
}

func clearSignedBody(data []byte) []byte {
	s := string(data)
	start := strings.Index(s, "\n\n")
	if strings.HasPrefix(s, "-----BEGIN PGP SIGNED MESSAGE-----") && start >= 0 {
		s = s[start+2:]
	}
	if end := strings.Index(s, "-----BEGIN PGP SIGNATURE-----"); end >= 0 {
		s = s[:end]
	}
	s = strings.ReplaceAll(s, "\n- ", "\n")
	return []byte(s)
}

func signatureMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = LoadPolicy().SignatureMode
	}
	if mode == "" {
		mode = "optional"
	}
	return mode
}

func (i *Installer) verifySignature(ctx context.Context, sums []byte, mode string) (bool, string) {
	mode = signatureMode(mode)
	if mode == "skip" {
		return false, "signature verification skipped by policy"
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		if mode == "required" {
			return false, "gpg is required for signature verification but was not found"
		}
		return false, "gpg not available; SHA256 verification still enforced"
	}
	keys, err := i.fetch(ctx, i.KeysURL, 2<<20)
	if err != nil {
		if mode == "required" {
			return false, "could not download rclone KEYS: " + err.Error()
		}
		return false, "could not download rclone KEYS: " + err.Error()
	}
	tmp, err := os.MkdirTemp("", "seavault-rclone-gpg-*")
	if err != nil {
		return false, err.Error()
	}
	defer os.RemoveAll(tmp)
	keyPath := filepath.Join(tmp, "KEYS")
	sumsPath := filepath.Join(tmp, "SHA256SUMS")
	if err := os.WriteFile(keyPath, keys, 0o600); err != nil {
		return false, err.Error()
	}
	if err := os.WriteFile(sumsPath, sums, 0o600); err != nil {
		return false, err.Error()
	}
	if out, err := exec.CommandContext(ctx, gpg, "--batch", "--homedir", tmp, "--import", keyPath).CombinedOutput(); err != nil {
		return false, "could not import rclone KEYS: " + strings.TrimSpace(string(out))
	}
	out, err := exec.CommandContext(ctx, gpg, "--batch", "--homedir", tmp, "--status-fd", "1", "--verify", sumsPath).CombinedOutput()
	if err != nil {
		return false, "gpg signature verification failed: " + strings.TrimSpace(string(out))
	}
	text := strings.ToUpper(string(out))
	if !strings.Contains(text, SigningFingerprint) && !strings.Contains(text, "GOODSIG") && !strings.Contains(text, "VALIDSIG") {
		return false, "rclone signing key fingerprint could not be pinned"
	}
	return true, ""
}

func (i *Installer) fetch(ctx context.Context, raw string, max int64) ([]byte, error) {
	if err := allowedDownloadURL(raw); err != nil {
		return nil, err
	}
	client := i.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %s", raw, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, max))
}

func allowedDownloadURL(raw string) error {
	if strings.HasPrefix(raw, "http://127.0.0.1") || strings.HasPrefix(raw, "http://localhost") {
		return nil
	}
	if !strings.HasPrefix(raw, "https://downloads.rclone.org/") && !strings.HasPrefix(raw, "https://beta.rclone.org/") && !strings.HasPrefix(raw, "https://rclone.org/") {
		return fmt.Errorf("refusing non-official rclone download URL %s", raw)
	}
	return nil
}

func extractExecutable(zipPath, destPath, binName string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.FileInfo().IsDir() || filepath.Base(f.Name) != binName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
			return err
		}
		tmp := destPath + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, rc)
		closeErr := out.Close()
		if copyErr != nil {
			_ = os.Remove(tmp)
			return copyErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		if runtime.GOOS != "windows" {
			_ = os.Chmod(tmp, 0o700)
		}
		return os.Rename(tmp, destPath)
	}
	return fmt.Errorf("%s not found in rclone archive", binName)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func RedactText(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, key := range []string{"token", "refresh_token", "access_token", "client_secret", "password", "pass", "secret", "key_file_pass", "authorization"} {
			if strings.Contains(lower, key) && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				lines[i] = parts[0] + "= [REDACTED]"
			}
		}
	}
	return strings.Join(lines, "\n")
}

func MakeTestZip(path, exeName, body string) error {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("rclone-test/" + exeName)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(body)); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}
