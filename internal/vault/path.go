// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

func CleanVirtualPath(input string) (string, error) {
	s := strings.TrimSpace(strings.ReplaceAll(input, "\\", "/"))
	s = strings.TrimPrefix(s, "/")
	if s == "" || s == "." {
		return "", nil
	}
	cleaned := path.Clean(s)
	if cleaned == "." {
		return "", nil
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." || path.IsAbs(cleaned) {
		return "", fmt.Errorf("invalid virtual path %q", input)
	}
	return cleaned, nil
}

func virtualJoin(base, rel string) (string, error) {
	base, err := CleanVirtualPath(base)
	if err != nil {
		return "", err
	}
	rel = strings.ReplaceAll(rel, string(filepath.Separator), "/")
	rel, err = CleanVirtualPath(rel)
	if err != nil {
		return "", err
	}
	if base == "" {
		return rel, nil
	}
	if rel == "" {
		return base, nil
	}
	return path.Join(base, rel), nil
}
