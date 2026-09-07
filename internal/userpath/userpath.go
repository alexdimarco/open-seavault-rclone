// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package userpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Abs expands shell-style user paths and returns an absolute, cleaned path.
// It supports ~, ~/..., environment variables like $HOME, ${HOME}, and the
// Windows-friendly %USERPROFILE% form even when running on non-Windows systems.
func Abs(input string) (string, error) {
	expanded, err := Expand(input)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// Expand expands the common forms users paste into the GUI or CLI. It does not
// require the target path to exist.
func Expand(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("vault path is required")
	}
	s = expandPercentEnv(os.ExpandEnv(s))
	if s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return "", errors.New("cannot expand ~ because the user home directory is unknown")
		}
		if s == "~" {
			s = home
		} else {
			s = filepath.Join(home, s[2:])
		}
	} else if strings.HasPrefix(s, "~") {
		return "", fmt.Errorf("cannot expand %q; use ~/path instead of another user's home shortcut", input)
	}
	return filepath.Clean(s), nil
}

func expandPercentEnv(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '%' {
			out.WriteByte(s[i])
			i++
			continue
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			out.WriteByte(s[i])
			i++
			continue
		}
		name := s[i+1 : i+1+j]
		if name == "" {
			out.WriteString("%%")
			i += 2
			continue
		}
		if val, ok := os.LookupEnv(name); ok {
			out.WriteString(val)
		} else {
			out.WriteString(s[i : i+j+2])
		}
		i += j + 2
	}
	return out.String()
}

// ValidateCreatableVaultPath returns a clear, early error for common GUI path
// mistakes before vault.Create attempts to make directories.
func ValidateCreatableVaultPath(absPath string) error {
	if strings.TrimSpace(absPath) == "" {
		return errors.New("vault path is required")
	}
	abs, err := filepath.Abs(absPath)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	if info, err := os.Stat(abs); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("vault path %s exists and is not a directory", abs)
		}
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if runtime.GOOS != "windows" && (abs == "/user" || strings.HasPrefix(abs, "/user/")) {
		return fmt.Errorf("%s is under /user, which is normally not a writable home directory. Use ~/Nextcloud/seavault, /Users/<name>/Nextcloud/seavault on macOS, or /home/<name>/Nextcloud/seavault on Linux", abs)
	}

	parent, err := nearestExistingParent(abs)
	if err != nil {
		return err
	}
	if isVolumeRoot(parent) {
		return fmt.Errorf("parent directory %s does not exist. Create or choose an existing local cloud-sync folder first; examples: ~/Nextcloud/seavault, ~/Dropbox/seavault, or ~/OneDrive/seavault", firstMissingComponent(abs))
	}
	if info, err := os.Stat(parent); err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("nearest existing parent %s is not a directory", parent)
	}
	return nil
}

func nearestExistingParent(path string) (string, error) {
	p := filepath.Clean(path)
	for {
		parent := filepath.Dir(p)
		if parent == p {
			if _, err := os.Stat(parent); err == nil {
				return parent, nil
			} else {
				return "", err
			}
		}
		if info, err := os.Stat(parent); err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("nearest existing parent %s is not a directory", parent)
			}
			return parent, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		p = parent
	}
}

func isVolumeRoot(p string) bool {
	p = filepath.Clean(p)
	return filepath.Dir(p) == p
}

func firstMissingComponent(abs string) string {
	p := filepath.Clean(abs)
	if !filepath.IsAbs(p) {
		return p
	}
	volume := filepath.VolumeName(p)
	rest := strings.TrimPrefix(p, volume)
	rest = strings.TrimLeft(rest, `/\`)
	first := rest
	if idx := strings.IndexAny(rest, `/\`); idx >= 0 {
		first = rest[:idx]
	}
	if volume != "" {
		return filepath.Join(volume+string(os.PathSeparator), first)
	}
	return string(os.PathSeparator) + first
}

func SuggestedVaultPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return []string{"~/Nextcloud/seavault", "~/Dropbox/seavault", "~/OneDrive/seavault"}
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "." || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, name := range []string{"Nextcloud", "Dropbox", "OneDrive", "Syncthing", "Google Drive", "iCloud Drive"} {
		base := filepath.Join(home, name)
		if info, err := os.Stat(base); err == nil && info.IsDir() {
			add(filepath.Join(base, "seavault"))
		}
	}
	if runtime.GOOS == "darwin" {
		cloudStorage := filepath.Join(home, "Library", "CloudStorage")
		if entries, err := os.ReadDir(cloudStorage); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					name := entry.Name()
					if strings.Contains(strings.ToLower(name), "onedrive") || strings.Contains(strings.ToLower(name), "google") || strings.Contains(strings.ToLower(name), "dropbox") {
						add(filepath.Join(cloudStorage, name, "seavault"))
					}
				}
			}
		}
	}
	add(filepath.Join(home, "Nextcloud", "seavault"))
	add(filepath.Join(home, "open-seavault-rclone"))
	sort.Strings(out)
	return out
}
