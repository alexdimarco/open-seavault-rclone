// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package appdir

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const appName = "SeaVault"

func ConfigDir() (string, error) {
	if root := strings.TrimSpace(os.Getenv("SEAVAULT_APP_HOME")); root != "" {
		return filepath.Join(root, "config"), nil
	}
	if root := strings.TrimSpace(os.Getenv("SEAVAULT_CONFIG_DIR")); root != "" {
		return filepath.Abs(root)
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("APPDATA"); base != "" {
			return filepath.Join(base, appName), nil
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", appName), nil
	default:
		if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
			return filepath.Join(base, "seavault"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", appName), nil
	}
	return filepath.Join(home, ".config", "seavault"), nil
}

func DataDir() (string, error) {
	if root := strings.TrimSpace(os.Getenv("SEAVAULT_APP_HOME")); root != "" {
		return filepath.Join(root, "data"), nil
	}
	if root := strings.TrimSpace(os.Getenv("SEAVAULT_DATA_DIR")); root != "" {
		return filepath.Abs(root)
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, appName), nil
		}
		if base := os.Getenv("APPDATA"); base != "" {
			return filepath.Join(base, appName), nil
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", appName), nil
	default:
		if base := os.Getenv("XDG_DATA_HOME"); base != "" {
			return filepath.Join(base, "seavault"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local", appName), nil
	}
	return filepath.Join(home, ".local", "share", "seavault"), nil
}

func RuntimeDir() (string, error) { return EnsureDataDir("rclone") }

func EnsureConfigDir(parts ...string) (string, error) {
	base, err := ConfigDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(append([]string{base}, parts...)...)
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

func EnsureDataDir(parts ...string) (string, error) {
	base, err := DataDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(append([]string{base}, parts...)...)
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}
