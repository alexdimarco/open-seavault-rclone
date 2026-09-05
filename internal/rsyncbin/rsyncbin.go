// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncbin

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

const (
	ManifestVersion      = 1
	DefaultSourceBaseURL = "https://download.samba.org/pub/rsync"
	// DefaultRuntimeBaseURL is intentionally empty: there is no default managed
	// rsync runtime host. A network install must be given an explicit, trusted
	// runtime base URL (operator-configured). Shipping a real or placeholder
	// default would let anyone who controls that host (e.g. by registering an
	// example/squattable org) serve a runtime that gets executed as the user.
	DefaultRuntimeBaseURL = ""
)

var versionRE = regexp.MustCompile(`(?i)rsync\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)|rsync-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz`)

type Manifest struct {
	Version            int    `json:"version"`
	Tool               string `json:"tool"`
	InstalledVersion   string `json:"installedVersion"`
	InstalledAt        string `json:"installedAt"`
	GOOS               string `json:"goos"`
	GOARCH             string `json:"goarch"`
	BinaryPath         string `json:"binaryPath"`
	RuntimeDir         string `json:"runtimeDir"`
	SHA256             string `json:"sha256"`
	SourceVersion      string `json:"sourceVersion"`
	SourceURL          string `json:"sourceUrl"`
	RuntimeURL         string `json:"runtimeUrl,omitempty"`
	BuildID            string `json:"buildId,omitempty"`
	ReleaseChannel     string `json:"releaseChannel"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	PreviousBinaryPath string `json:"previousBinaryPath,omitempty"`
	PreviousSHA256     string `json:"previousSha256,omitempty"`
	UpdateCheckedAt    string `json:"updateCheckedAt,omitempty"`
	ChecksumVerified   bool   `json:"checksumVerified"`
	SignatureVerified  bool   `json:"signatureVerified"`
	SignatureMethod    string `json:"signatureMethod,omitempty"`
	SignatureWarning   string `json:"signatureWarning,omitempty"`
}

type Status struct {
	Installed        bool     `json:"installed"`
	Version          string   `json:"version,omitempty"`
	BinaryPath       string   `json:"binaryPath,omitempty"`
	RuntimeDir       string   `json:"runtimeDir,omitempty"`
	ManifestPath     string   `json:"manifestPath,omitempty"`
	SHA256           string   `json:"sha256,omitempty"`
	SourceVersion    string   `json:"sourceVersion,omitempty"`
	SourceURL        string   `json:"sourceUrl,omitempty"`
	RuntimeURL       string   `json:"runtimeUrl,omitempty"`
	InstalledAt      string   `json:"installedAt,omitempty"`
	UpdateCheckedAt  string   `json:"updateCheckedAt,omitempty"`
	PreviousVersion  string   `json:"previousVersion,omitempty"`
	RuntimeOK        bool     `json:"runtimeOk"`
	RuntimeMessage   string   `json:"runtimeMessage,omitempty"`
	LatestVersion    string   `json:"latestVersion,omitempty"`
	LatestSourceURL  string   `json:"latestSourceUrl,omitempty"`
	LatestCheckError string   `json:"latestCheckError,omitempty"`
	Candidates       []string `json:"candidates,omitempty"`
	DefaultHint      string   `json:"defaultHint,omitempty"`
}

type LatestInfo struct {
	Version   string `json:"version"`
	SourceURL string `json:"sourceUrl"`
	IndexURL  string `json:"indexUrl"`
}

type InstallOptions struct {
	Version        string
	FromBinary     string
	OfflineArchive string
	OfflineSHA256  string
	RuntimeBaseURL string
	BuildID        string
	SignatureMode  string
}

type Installer struct {
	Client         *http.Client
	Now            func() time.Time
	GOOS           string
	GOARCH         string
	SourceBaseURL  string
	RuntimeBaseURL string
	// AllowedDownloadHosts, when non-empty, restricts runtime/source downloads
	// to this set of hosts (in addition to the always-on HTTPS requirement).
	AllowedDownloadHosts []string
}

func NewInstaller() *Installer {
	return &Installer{Client: http.DefaultClient, Now: func() time.Time { return time.Now().UTC() }, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, SourceBaseURL: DefaultSourceBaseURL, RuntimeBaseURL: DefaultRuntimeBaseURL}
}

func RuntimeRoot() (string, error) { return appdir.EnsureDataDir("rsync") }

func ManifestPath() (string, error) {
	root, err := RuntimeRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "runtime.json"), nil
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
	m.Tool = "rsync"
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
		return "", errors.New("managed rsync is not installed")
	}
	if err := VerifyRuntime(m); err != nil {
		return "", err
	}
	return m.BinaryPath, nil
}

func ActivePath() (string, error) { return BinaryPath() }

func StatusNow(ctx context.Context, checkLatest bool) Status {
	return NewInstaller().Status(ctx, checkLatest)
}

func (i *Installer) Status(ctx context.Context, checkLatest bool) Status {
	root, _ := RuntimeRoot()
	mp, _ := ManifestPath()
	st := Status{RuntimeDir: root, ManifestPath: mp, Candidates: CandidateBinaryPaths(), DefaultHint: DefaultBinaryHint()}
	m, err := LoadManifest()
	if errors.Is(err, os.ErrNotExist) {
		st.RuntimeMessage = "managed rsync is not installed; SeaVault will use native import unless system rsync is selected"
	} else if err != nil {
		st.RuntimeMessage = err.Error()
	} else {
		st.Installed = true
		st.Version = m.InstalledVersion
		st.BinaryPath = m.BinaryPath
		st.SHA256 = m.SHA256
		st.SourceVersion = m.SourceVersion
		st.SourceURL = m.SourceURL
		st.RuntimeURL = m.RuntimeURL
		st.InstalledAt = m.InstalledAt
		st.UpdateCheckedAt = m.UpdateCheckedAt
		st.PreviousVersion = m.PreviousVersion
		if err := VerifyRuntime(m); err != nil {
			st.RuntimeOK = false
			st.RuntimeMessage = err.Error()
		} else {
			st.RuntimeOK = true
			st.RuntimeMessage = "managed rsync verified"
		}
	}
	if checkLatest {
		li, e := i.Latest(ctx)
		if e == nil {
			st.LatestVersion = li.Version
			st.LatestSourceURL = li.SourceURL
			if m, err := LoadManifest(); err == nil {
				m.UpdateCheckedAt = i.Now().Format(time.RFC3339Nano)
				_ = SaveManifest(m)
			}
		} else {
			st.LatestCheckError = e.Error()
		}
	}
	return st
}

func (i *Installer) Latest(ctx context.Context) (LatestInfo, error) {
	indexURL := strings.TrimRight(i.SourceBaseURL, "/") + "/"
	data, err := i.fetch(ctx, indexURL, 4<<20)
	if err != nil {
		return LatestInfo{}, err
	}
	versions := map[string]bool{}
	for _, m := range versionRE.FindAllStringSubmatch(string(data), -1) {
		v := m[1]
		if v == "" {
			v = m[2]
		}
		if v != "" {
			versions[v] = true
		}
	}
	if len(versions) == 0 {
		return LatestInfo{}, fmt.Errorf("could not find rsync source releases at %s", indexURL)
	}
	list := make([]string, 0, len(versions))
	for v := range versions {
		list = append(list, v)
	}
	sort.Slice(list, func(a, b int) bool { return compareVersions(list[a], list[b]) > 0 })
	v := list[0]
	return LatestInfo{Version: v, SourceURL: sourceTarballURL(i.SourceBaseURL, v), IndexURL: indexURL}, nil
}

func (i *Installer) Install(ctx context.Context, opts InstallOptions) (Manifest, error) {
	root, err := RuntimeRoot()
	if err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Manifest{}, err
	}
	old, _ := LoadManifest()
	version := normalizeVersion(opts.Version)
	if version == "" && opts.FromBinary == "" && opts.OfflineArchive == "" {
		li, err := i.Latest(ctx)
		if err != nil {
			return Manifest{}, err
		}
		version = li.Version
	}
	if version == "" {
		version = "current"
	}

	work, err := os.MkdirTemp("", "seavault-rsync-install-*")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(work)

	var binPath, sourceURL, runtimeURL, sourceVersion string
	checksumVerified := false
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
		sourceVersion = found
		sourceURL = "registered-binary:" + src
		dir := filepath.Join(root, version)
		if err := os.RemoveAll(dir); err != nil {
			return Manifest{}, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Manifest{}, err
		}
		binPath = filepath.Join(dir, exeName(i.GOOS))
		if err := copyFile(src, binPath, 0o700); err != nil {
			return Manifest{}, err
		}
		// A manually-registered binary is NOT verified against any trusted
		// checksum or signature; recording it as verified would misrepresent its
		// provenance in status output. Leave checksumVerified false and note it.
		checksumVerified = false
		signatureWarning = "manually-registered binary; not verified against a trusted checksum or signature"
	} else {
		archive := opts.OfflineArchive
		artifact := ArtifactName(version, i.GOOS, i.GOARCH)
		if archive == "" {
			base := strings.TrimRight(opts.RuntimeBaseURL, "/")
			if base == "" {
				base = strings.TrimRight(i.RuntimeBaseURL, "/")
			}
			if base == "" {
				return Manifest{}, errors.New("managed rsync runtime install requires --from-binary, --offline-archive, or a configured runtime base URL")
			}
			runtimeURL = base + "/" + version + "/" + artifact
			archive = filepath.Join(work, artifact)
			data, err := i.fetch(ctx, runtimeURL, 512<<20)
			if err != nil {
				return Manifest{}, fmt.Errorf("download managed rsync runtime: %w", err)
			}
			if err := os.WriteFile(archive, data, 0o600); err != nil {
				return Manifest{}, err
			}
			// Checksum verification is MANDATORY for network installs. A failure
			// to fetch SHA256SUMS (404, network error, or a MITM stripping it)
			// must abort the install rather than silently proceed with an
			// unverified runtime that then gets executed as the user.
			shaURL := strings.TrimSuffix(runtimeURL, artifact) + "SHA256SUMS"
			shaText, err := i.fetch(ctx, shaURL, 4<<20)
			if err != nil {
				return Manifest{}, fmt.Errorf("download managed rsync runtime checksums from %s: %w (refusing to install an unverified runtime)", shaURL, err)
			}
			h, err := fileSHA256(archive)
			if err != nil {
				return Manifest{}, err
			}
			want, err := checksumForArtifact(shaText, artifact)
			if err != nil {
				return Manifest{}, err
			}
			if !strings.EqualFold(h, want) {
				return Manifest{}, fmt.Errorf("managed rsync runtime hash mismatch for %s", artifact)
			}
			checksumVerified = true
		} else {
			abs, err := userpath.Abs(archive)
			if err != nil {
				return Manifest{}, err
			}
			archive = abs
			runtimeURL = "offline-archive:" + archive
			if opts.OfflineSHA256 != "" {
				shaText, err := os.ReadFile(opts.OfflineSHA256)
				if err != nil {
					return Manifest{}, err
				}
				h, err := fileSHA256(archive)
				if err != nil {
					return Manifest{}, err
				}
				want, err := checksumForArtifact(shaText, filepath.Base(archive))
				if err != nil {
					return Manifest{}, err
				}
				if !strings.EqualFold(h, want) {
					return Manifest{}, fmt.Errorf("offline rsync archive hash mismatch")
				}
				checksumVerified = true
			}
		}
		stage := filepath.Join(work, "stage")
		if err := unzipRuntime(archive, stage); err != nil {
			return Manifest{}, err
		}
		stageBin, err := findExecutable(stage, i.GOOS)
		if err != nil {
			return Manifest{}, err
		}
		found, err := Version(ctx, stageBin)
		if err != nil {
			return Manifest{}, err
		}
		if normalizeVersion(opts.Version) != "" && normalizeVersion(opts.Version) != found {
			return Manifest{}, fmt.Errorf("managed rsync runtime version mismatch: expected %s, got %s", normalizeVersion(opts.Version), found)
		}
		version = found
		sourceVersion = found
		sourceURL = sourceTarballURL(i.SourceBaseURL, found)
		dir := filepath.Join(root, version)
		if err := os.RemoveAll(dir); err != nil {
			return Manifest{}, err
		}
		if err := copyDir(stage, dir); err != nil {
			return Manifest{}, err
		}
		binPath = filepath.Join(dir, relPath(stage, stageBin))
		if i.GOOS != "windows" {
			_ = os.Chmod(binPath, 0o700)
		}
	}
	binHash, err := fileSHA256(binPath)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Version: ManifestVersion, Tool: "rsync", InstalledVersion: version, InstalledAt: i.Now().Format(time.RFC3339Nano), GOOS: i.GOOS, GOARCH: i.GOARCH, BinaryPath: binPath, RuntimeDir: filepath.Dir(binPath), SHA256: binHash, SourceVersion: sourceVersion, SourceURL: sourceURL, RuntimeURL: runtimeURL, BuildID: opts.BuildID, ReleaseChannel: "stable", PreviousVersion: old.InstalledVersion, PreviousBinaryPath: old.BinaryPath, PreviousSHA256: old.SHA256, ChecksumVerified: checksumVerified, SignatureWarning: signatureWarning}
	if err := SaveManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (i *Installer) Update(ctx context.Context, opts InstallOptions) (Manifest, error) {
	if opts.Version == "" {
		li, err := i.Latest(ctx)
		if err != nil {
			return Manifest{}, err
		}
		opts.Version = li.Version
	}
	return i.Install(ctx, opts)
}

func Rollback() (Manifest, error) {
	m, err := LoadManifest()
	if err != nil {
		return Manifest{}, err
	}
	if m.PreviousBinaryPath == "" || m.PreviousVersion == "" {
		return Manifest{}, errors.New("no previous rsync runtime is recorded for rollback")
	}
	if _, err := os.Stat(m.PreviousBinaryPath); err != nil {
		return Manifest{}, fmt.Errorf("previous rsync binary is unavailable: %w", err)
	}
	m.InstalledVersion, m.PreviousVersion = m.PreviousVersion, m.InstalledVersion
	m.BinaryPath, m.PreviousBinaryPath = m.PreviousBinaryPath, m.BinaryPath
	m.SHA256, m.PreviousSHA256 = m.PreviousSHA256, m.SHA256
	m.RuntimeDir = filepath.Dir(m.BinaryPath)
	m.InstalledAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := SaveManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func VerifyRuntime(m Manifest) error {
	if m.BinaryPath == "" {
		return errors.New("managed rsync binary path is empty")
	}
	info, err := os.Stat(m.BinaryPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not an rsync executable", m.BinaryPath)
	}
	if m.SHA256 != "" {
		h, err := fileSHA256(m.BinaryPath)
		if err != nil {
			return err
		}
		if !strings.EqualFold(h, m.SHA256) {
			return fmt.Errorf("managed rsync hash mismatch: expected %s, got %s", m.SHA256, h)
		}
	}
	return nil
}

func Version(ctx context.Context, bin string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run rsync --version: %w: %s", err, strings.TrimSpace(string(out)))
	}
	v := parseVersion(string(out))
	if v == "" {
		return "", fmt.Errorf("could not parse rsync version output: %s", strings.TrimSpace(string(out)))
	}
	return v, nil
}

func ArtifactName(version, goos, goarch string) string {
	v := normalizeVersion(version)
	if v == "" {
		v = "current"
	}
	name := fmt.Sprintf("seavault-rsync-%s-%s-%s.zip", v, goos, goarch)
	return name
}

func DefaultBinaryHint() string {
	if p, err := BinaryPath(); err == nil && strings.TrimSpace(p) != "" {
		return p
	}
	if p, err := exec.LookPath("rsync"); err == nil && strings.TrimSpace(p) != "" {
		return p
	}
	for _, p := range CandidateBinaryPaths() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	c := CandidateBinaryPaths()
	if len(c) > 0 {
		return c[0]
	}
	return "rsync"
}

func CandidateBinaryPaths() []string {
	managed := []string{}
	if p, err := BinaryPath(); err == nil {
		managed = append(managed, p)
	}
	switch runtime.GOOS {
	case "darwin":
		return append(managed, "/opt/homebrew/bin/rsync", "/usr/local/bin/rsync", "/usr/bin/rsync")
	case "windows":
		return append(managed, `C:\msys64\usr\bin\rsync.exe`, `C:\Program Files\cwRsync\bin\rsync.exe`, `C:\cygwin64\bin\rsync.exe`)
	default:
		return append(managed, "/usr/bin/rsync", "/usr/local/bin/rsync", "/bin/rsync")
	}
}

func parseVersion(s string) string {
	for _, m := range versionRE.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			return m[1]
		}
		if m[2] != "" {
			return m[2]
		}
	}
	return ""
}

func normalizeVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

func sourceTarballURL(base, version string) string {
	return strings.TrimRight(base, "/") + "/rsync-" + normalizeVersion(version) + ".tar.gz"
}

func exeName(goos string) string {
	if goos == "windows" {
		return "rsync.exe"
	}
	return "rsync"
}

// allowedDownloadURL enforces a safe transport for runtime/source downloads:
// HTTPS only (loopback HTTP is permitted for tests), the known placeholder
// host is always rejected, and when an operator configures an allowlist the
// URL host must be a member. This prevents a tampered or attacker-supplied
// runtime base URL from causing code execution via an unverified download.
func (i *Installer) allowedDownloadURL(raw string) error {
	if strings.HasPrefix(raw, "http://127.0.0.1") || strings.HasPrefix(raw, "http://localhost") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid download URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS managed-runtime download URL %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "example.com" || strings.HasSuffix(host, ".example.com") || strings.HasPrefix(strings.ToLower(u.Path), "/example/") {
		return fmt.Errorf("refusing placeholder/example managed-runtime download URL %q; configure a real runtime base URL", raw)
	}
	if len(i.AllowedDownloadHosts) > 0 {
		ok := false
		for _, h := range i.AllowedDownloadHosts {
			if strings.EqualFold(strings.TrimSpace(h), host) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("managed-runtime download host %q is not in the configured allowlist", host)
		}
	}
	return nil
}

func (i *Installer) fetch(ctx context.Context, url string, max int64) ([]byte, error) {
	if err := i.allowedDownloadURL(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := i.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: %s", url, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, max))
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
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

func checksumForArtifact(text []byte, artifact string) (string, error) {
	base := filepath.Base(artifact)
	for _, line := range strings.Split(string(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(filepath.Base(fields[len(fields)-1]), "*")
		if name == base {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS does not contain %s", base)
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o700)
		}
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(to, info.Mode().Perm()|0o700)
		}
		return copyFile(p, to, info.Mode().Perm()|0o600)
	})
}

func unzipRuntime(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := filepath.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe path in rsync runtime archive: %s", f.Name)
		}
		to := filepath.Join(dest, filepath.FromSlash(name))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(to, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, f.Mode()|0o600)
		if err != nil {
			_ = rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		closeErr := out.Close()
		_ = rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func findExecutable(root, goos string) (string, error) {
	want := exeName(goos)
	var found string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(p), want) {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("rsync runtime archive did not contain %s", want)
	}
	return found, nil
}

func relPath(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return filepath.Base(target)
	}
	return rel
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func compareVersions(a, b string) int {
	ap := versionParts(a)
	bp := versionParts(b)
	for i := 0; i < 3; i++ {
		if ap[i] > bp[i] {
			return 1
		}
		if ap[i] < bp[i] {
			return -1
		}
	}
	return 0
}

func versionParts(v string) [3]int {
	var out [3]int
	parts := strings.Split(normalizeVersion(v), ".")
	for i := 0; i < len(parts) && i < 3; i++ {
		fmt.Sscanf(parts[i], "%d", &out[i])
	}
	return out
}
