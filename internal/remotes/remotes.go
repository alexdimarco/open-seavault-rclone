// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package remotes

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

type Store struct {
	Version  int       `json:"version"`
	Profiles []Profile `json:"profiles"`
}

type Profile struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Vault     string        `json:"vault"`
	Remote    RemoteConfig  `json:"remote"`
	Runtime   RuntimeConfig `json:"runtime"`
	Safety    SafetyConfig  `json:"safety"`
	CreatedAt string        `json:"createdAt,omitempty"`
	UpdatedAt string        `json:"updatedAt,omitempty"`
}

type RemoteConfig struct {
	RemoteName       string `json:"remoteName"`
	RemotePath       string `json:"remotePath"`
	Backend          string `json:"backend"`
	ConfigMode       string `json:"configMode"`
	RcloneConfigPath string `json:"rcloneConfigPath"`
	Transfers        int    `json:"transfers"`
	Checkers         int    `json:"checkers"`
	FastList         bool   `json:"fastList"`
	Checksum         string `json:"checksum"`
	BandwidthLimit   string `json:"bandwidthLimit"`
	DryRunDefault    bool   `json:"dryRunDefault"`
	Host             string `json:"host,omitempty"`
	User             string `json:"user,omitempty"`
	Port             int    `json:"port,omitempty"`
	SSHKey           string `json:"sshKey,omitempty"`
	HostFingerprint  string `json:"hostFingerprint,omitempty"`
}

type RuntimeConfig struct {
	Channel                    string `json:"channel"`
	PinnedVersion              string `json:"pinnedVersion"`
	AutoCheckUpdates           bool   `json:"autoCheckUpdates"`
	AutoInstallSecurityUpdates bool   `json:"autoInstallSecurityUpdates"`
}

type SafetyConfig struct {
	DefaultOperation         string `json:"defaultOperation"`
	AllowDestructiveSync     bool   `json:"allowDestructiveSync"`
	RequireDryRunBeforeSync  bool   `json:"requireDryRunBeforeSync"`
	RetainDeletedObjectsDays int    `json:"retainDeletedObjectsDays"`
	VerifyAfterTransfer      bool   `json:"verifyAfterTransfer"`
}

func ConfigPath() (string, error) {
	dir, err := appdir.EnsureConfigDir("remotes")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "remote-profiles.json"), nil
}

func DefaultRcloneConfigPath() string {
	dir, err := appdir.EnsureConfigDir("rclone")
	if err != nil {
		return "rclone.conf"
	}
	return filepath.Join(dir, "rclone.conf")
}

func ResolveConfigPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "managed" {
		return DefaultRcloneConfigPath(), nil
	}
	return userpath.Abs(p)
}

func DefaultProfile(name, vaultPath, remotePath, backend string) Profile {
	backend = strings.ToLower(strings.TrimSpace(backend))
	if backend == "" {
		backend = "local"
	}
	return Normalize(Profile{
		Name:  name,
		Type:  "rclone",
		Vault: vaultPath,
		Remote: RemoteConfig{
			RemotePath:       remotePath,
			Backend:          backend,
			ConfigMode:       "managed",
			RcloneConfigPath: DefaultRcloneConfigPath(),
			Transfers:        8,
			Checkers:         16,
			FastList:         true,
			Checksum:         "auto",
			DryRunDefault:    true,
		},
		Runtime: RuntimeConfig{Channel: "stable", AutoCheckUpdates: true},
		Safety:  SafetyConfig{DefaultOperation: "copy", RequireDryRunBeforeSync: true, RetainDeletedObjectsDays: 30, VerifyAfterTransfer: true},
	})
}

func Load() (Store, error) {
	p, err := ConfigPath()
	if err != nil {
		return Store{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Store{Version: 1}, nil
	}
	if err != nil {
		return Store{}, err
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return Store{}, err
	}
	if s.Version == 0 {
		s.Version = 1
	}
	return s, nil
}

func SaveStore(s Store) error {
	p, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	s.Version = 1
	for i := range s.Profiles {
		s.Profiles[i] = Normalize(s.Profiles[i])
	}
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].Name < s.Profiles[j].Name })
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(p, data, 0o600)
}

func Add(p Profile) (Profile, error) {
	p = Normalize(p)
	if err := Validate(p); err != nil {
		return Profile{}, err
	}
	abs, err := userpath.Abs(p.Vault)
	if err != nil {
		return Profile{}, err
	}
	p.Vault = abs
	if strings.TrimSpace(p.Remote.RcloneConfigPath) != "" {
		cfg, err := ResolveConfigPath(p.Remote.RcloneConfigPath)
		if err != nil {
			return Profile{}, err
		}
		p.Remote.RcloneConfigPath = cfg
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	s, err := Load()
	if err != nil {
		return Profile{}, err
	}
	updated := false
	for i := range s.Profiles {
		if s.Profiles[i].Name == p.Name {
			if s.Profiles[i].CreatedAt != "" {
				p.CreatedAt = s.Profiles[i].CreatedAt
			}
			s.Profiles[i] = p
			updated = true
			break
		}
	}
	if !updated {
		s.Profiles = append(s.Profiles, p)
	}
	return p, SaveStore(s)
}

func Remove(name string) error {
	s, err := Load()
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	out := s.Profiles[:0]
	removed := false
	for _, p := range s.Profiles {
		if p.Name == name {
			removed = true
			continue
		}
		out = append(out, p)
	}
	if !removed {
		return fmt.Errorf("remote profile %q not found", name)
	}
	s.Profiles = out
	return SaveStore(s)
}

func Entries() ([]Profile, error) { return List() }

func List() ([]Profile, error) {
	s, err := Load()
	if err != nil {
		return nil, err
	}
	out := append([]Profile(nil), s.Profiles...)
	for i := range out {
		out[i] = Normalize(out[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func Get(name string) (Profile, bool, error) {
	s, err := Load()
	if err != nil {
		return Profile{}, false, err
	}
	for _, p := range s.Profiles {
		if p.Name == name {
			return Normalize(p), true, nil
		}
	}
	return Profile{}, false, nil
}

func Normalize(p Profile) Profile {
	p.Name = strings.TrimSpace(p.Name)
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if p.Type == "" {
		p.Type = "rclone"
	}
	p.Vault = strings.TrimSpace(p.Vault)
	p.Remote.RemoteName = strings.TrimSpace(p.Remote.RemoteName)
	p.Remote.RemotePath = strings.TrimSpace(p.Remote.RemotePath)
	p.Remote.Backend = strings.ToLower(strings.TrimSpace(p.Remote.Backend))
	if p.Remote.Backend == "" {
		p.Remote.Backend = "local"
	}
	if p.Remote.ConfigMode == "" {
		p.Remote.ConfigMode = "managed"
	}
	if p.Remote.RcloneConfigPath == "" {
		p.Remote.RcloneConfigPath = DefaultRcloneConfigPath()
	}
	if p.Remote.Transfers <= 0 {
		p.Remote.Transfers = 8
	}
	if p.Remote.Checkers <= 0 {
		p.Remote.Checkers = 16
	}
	if p.Remote.Checksum == "" {
		p.Remote.Checksum = "auto"
	}
	p.Runtime.Channel = strings.ToLower(strings.TrimSpace(p.Runtime.Channel))
	if p.Runtime.Channel == "" {
		p.Runtime.Channel = "stable"
	}
	if p.Safety.DefaultOperation == "" {
		p.Safety.DefaultOperation = "copy"
	}
	if p.Safety.RetainDeletedObjectsDays == 0 {
		p.Safety.RetainDeletedObjectsDays = 30
	}
	return p
}

func Validate(p Profile) error {
	if p.Name == "" {
		return errors.New("remote profile name is required")
	}
	if strings.ContainsAny(p.Name, `/\\`) || strings.Contains(p.Name, "..") {
		return errors.New("remote profile name must not contain path separators or ..")
	}
	if p.Type != "rclone" && p.Type != "local" {
		return fmt.Errorf("unsupported remote profile type %q", p.Type)
	}
	if p.Vault == "" {
		return errors.New("vault path is required")
	}
	if p.Remote.RemotePath == "" {
		return errors.New("remote path is required")
	}
	if strings.Contains(p.Remote.RemotePath, "\x00") {
		return errors.New("remote path contains an invalid NUL byte")
	}
	return nil
}

func EnsureManagedConfig() (string, error) {
	p := DefaultRcloneConfigPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(p, []byte("# open-seavault-rclone managed rclone configuration\n"), 0o600); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return p, nil
}

func RedactConfig(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "[") || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if looksSecret(key) {
			lines[i] = parts[0] + "= [REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}

func looksSecret(key string) bool {
	for _, s := range []string{"token", "secret", "password", "pass", "key", "client_id", "client_secret", "access", "refresh", "private"} {
		if strings.Contains(key, s) {
			return true
		}
	}
	return false
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
