// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

type Entry struct {
	Name      string `json:"name"`
	VaultPath string `json:"vaultPath"`
}

type Store struct {
	Version  int     `json:"version"`
	Profiles []Entry `json:"profiles"`
}

func ConfigPath() (string, error) {
	base, err := appdir.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "profiles.json"), nil
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

func Save(s Store) error {
	p, err := ConfigPath()
	if err != nil {
		return err
	}
	s.Version = 1
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Force 0600 on the file and 0700 on the config dir even when either already
	// exists (review wordlist-labels-2); shared with the recovery-label writer.
	return writeDeviceLocalFile(p, data)
}

func Add(name, vaultPath string) (Entry, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Entry{}, errors.New("profile name must not be empty")
	}
	if strings.ContainsAny(name, `/\\`) {
		return Entry{}, errors.New("profile name must not contain path separators")
	}
	abs, err := userpath.Abs(vaultPath)
	if err != nil {
		return Entry{}, err
	}
	s, err := Load()
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{Name: name, VaultPath: abs}
	updated := false
	for i := range s.Profiles {
		if s.Profiles[i].Name == name {
			s.Profiles[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		s.Profiles = append(s.Profiles, entry)
	}
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].Name < s.Profiles[j].Name })
	return entry, Save(s)
}

func Remove(name string) error {
	s, err := Load()
	if err != nil {
		return err
	}
	out := s.Profiles[:0]
	removed := false
	for _, e := range s.Profiles {
		if e.Name == name {
			removed = true
			continue
		}
		out = append(out, e)
	}
	if !removed {
		return fmt.Errorf("profile %q not found", name)
	}
	s.Profiles = out
	return Save(s)
}

func Resolve(name string) (Entry, bool, error) {
	s, err := Load()
	if err != nil {
		return Entry{}, false, err
	}
	for _, e := range s.Profiles {
		if e.Name == name {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

func Entries() ([]Entry, error) {
	s, err := Load()
	if err != nil {
		return nil, err
	}
	out := append([]Entry(nil), s.Profiles...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
