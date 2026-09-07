// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vaultmove

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
	"github.com/alexdimarco/open-seavault-rclone/internal/remotes"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

type Options struct {
	ProfileName            string
	Replace                bool
	UpdateMatchingProfiles bool
	UpdateRemoteProfiles   bool
}

type Result struct {
	SourcePath      string   `json:"sourcePath"`
	DestinationPath string   `json:"destinationPath"`
	Moved           bool     `json:"moved"`
	UsedRename      bool     `json:"usedRename"`
	UpdatedProfiles int      `json:"updatedProfiles"`
	UpdatedRemotes  int      `json:"updatedRemotes"`
	Warnings        []string `json:"warnings,omitempty"`
}

func MoveProfile(name, destination string, opts Options) (Result, error) {
	entry, ok, err := profile.Resolve(name)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, fmt.Errorf("saved vault %q was not found", name)
	}
	opts.ProfileName = name
	opts.UpdateMatchingProfiles = true
	return Move(entry.VaultPath, destination, opts)
}

func Move(source, destination string, opts Options) (Result, error) {
	sourceAbs, err := userpath.Abs(source)
	if err != nil {
		return Result{}, err
	}
	destAbs, err := userpath.Abs(destination)
	if err != nil {
		return Result{}, err
	}
	sourceAbs = filepath.Clean(sourceAbs)
	destAbs = filepath.Clean(destAbs)
	res := Result{SourcePath: sourceAbs, DestinationPath: destAbs}
	if sourceAbs == destAbs {
		return res, errors.New("source and destination vault paths are the same")
	}
	if err := validateSource(sourceAbs); err != nil {
		return res, err
	}
	if err := validateRelationship(sourceAbs, destAbs); err != nil {
		return res, err
	}
	if err := prepareDestination(destAbs, opts.Replace); err != nil {
		return res, err
	}
	usedRename, err := moveDir(sourceAbs, destAbs)
	if err != nil {
		return res, err
	}
	res.Moved = true
	res.UsedRename = usedRename

	if opts.ProfileName != "" {
		if _, err := profile.UpdatePath(opts.ProfileName, destAbs); err != nil {
			res.Warnings = append(res.Warnings, "vault moved, but saved vault location "+opts.ProfileName+" was not updated: "+err.Error())
		} else {
			res.UpdatedProfiles++
		}
	}
	if opts.UpdateMatchingProfiles {
		count, err := profile.UpdatePathsMatching(sourceAbs, destAbs)
		if err != nil {
			res.Warnings = append(res.Warnings, "vault moved, but matching saved vault locations were not updated: "+err.Error())
		} else {
			res.UpdatedProfiles += count
		}
	}
	if opts.UpdateRemoteProfiles {
		count, err := remotes.UpdateVaultPathMatching(sourceAbs, destAbs)
		if err != nil {
			res.Warnings = append(res.Warnings, "vault moved, but matching remote profiles were not updated: "+err.Error())
		} else {
			res.UpdatedRemotes = count
		}
	}
	return res, nil
}

func validateSource(source string) error {
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("source vault path is not accessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source vault path %s is not a directory", source)
	}
	if _, err := vault.ReadConfig(source); err != nil {
		return fmt.Errorf("source does not look like a open-seavault-rclone vault: %w", err)
	}
	return nil
}

func validateRelationship(source, dest string) error {
	rel, err := filepath.Rel(source, dest)
	if err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
		return errors.New("destination cannot be inside the source vault directory")
	}
	rel, err = filepath.Rel(dest, source)
	if err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
		return errors.New("destination cannot be a parent of the source vault directory")
	}
	return nil
}

func prepareDestination(dest string, replace bool) error {
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(dest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if !replace {
			return fmt.Errorf("destination %s exists and is not a directory", dest)
		}
		return os.Remove(dest)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return err
	}
	if len(entries) > 0 && !replace {
		return fmt.Errorf("destination %s already exists and is not empty; choose an empty path or enable replace", dest)
	}
	return os.RemoveAll(dest)
}

func moveDir(source, dest string) (bool, error) {
	if err := os.Rename(source, dest); err == nil {
		return true, nil
	}
	parent := filepath.Dir(dest)
	tmp := filepath.Join(parent, ".seavault-moving-"+filepath.Base(dest)+"-"+fmt.Sprint(time.Now().UnixNano()))
	if err := os.RemoveAll(tmp); err != nil {
		return false, err
	}
	if err := copyDir(source, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return false, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.RemoveAll(tmp)
		return false, err
	}
	if err := os.RemoveAll(source); err != nil {
		return false, fmt.Errorf("copied vault to %s but could not remove original %s: %w", dest, source, err)
	}
	return false, nil
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		s := filepath.Join(src, entry.Name())
		d := filepath.Join(dst, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.IsDir() {
			if err := copyDir(s, d); err != nil {
				return err
			}
			continue
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(s)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, d); err != nil {
				return err
			}
			continue
		}
		if !entryInfo.Mode().IsRegular() {
			continue
		}
		if err := copyFile(s, d, entryInfo.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
