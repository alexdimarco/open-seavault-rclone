// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocsMirrorCaveatCatalog is the DOC-3 drift guard: the provider caveat
// catalog in providers.go is the single source of truth, but the friction review
// (DOC-3) requires docs/cloud-provider-notes.md to carry the caveat TEXT (a
// verbatim mirror), and the README provider list to match the catalog EXACTLY.
// This test fails the build if the doc text and the code catalog ever diverge, so
// the copy in the doc can never silently drift from the authoritative strings.
// Every provider row is asserted (no vacuous pass): an empty AllProviders or an
// empty caveat is itself a failure.
func TestDocsMirrorCaveatCatalog(t *testing.T) {
	if len(AllProviders) == 0 {
		t.Fatal("AllProviders is empty; the catalog must list at least one provider")
	}

	repoRoot := filepath.Join("..", "..")
	providerNotes := mustReadDoc(t, filepath.Join(repoRoot, "docs", "cloud-provider-notes.md"))
	readme := mustReadDoc(t, filepath.Join(repoRoot, "README.md"))

	// 1. cloud-provider-notes.md carries every caveat verbatim, and every provider
	//    has a non-empty caveat and a display name (asserted per row).
	for _, p := range AllProviders {
		cav := Caveat(p)
		if strings.TrimSpace(cav) == "" {
			t.Errorf("provider %q has an empty caveat; every catalog entry must carry one", p)
			continue
		}
		if name := DisplayName(p); strings.TrimSpace(name) == "" || name == string(p) {
			t.Errorf("provider %q has no human display name", p)
		}
		if !strings.Contains(providerNotes, cav) {
			t.Errorf("docs/cloud-provider-notes.md is missing the verbatim caveat for %q (DOC-3 mirror drift).\nExpected the doc to contain:\n%s", p, cav)
		}
	}

	// 2. The README Quick-start provider list matches the catalog EXACTLY: every
	//    provider's display name is listed, and NOTHING else is (a provider added
	//    to or removed from the catalog without updating the README fails here).
	const startAnchor = "on your machine — "
	const endAnchor = " — it offers to put the vault"
	seg, ok := between(readme, startAnchor, endAnchor)
	if !ok {
		t.Fatalf("could not find the README provider-list sentence (anchors %q ... %q); if the wording changed, update this test's anchors", startAnchor, endAnchor)
	}
	remaining := seg
	for _, p := range AllProviders {
		name := DisplayName(p)
		if !strings.Contains(remaining, name) {
			t.Errorf("README provider list does not mention %q (%s); it must list every detected provider", p, name)
		}
		remaining = strings.ReplaceAll(remaining, name, "")
	}
	remaining = strings.ReplaceAll(remaining, ",", "")
	var extras []string
	for _, f := range strings.Fields(remaining) {
		if f == "or" || f == "and" {
			continue
		}
		extras = append(extras, f)
	}
	if len(extras) != 0 {
		t.Errorf("README provider list names entries not in the catalog: %v (the list must match the catalog exactly)", extras)
	}
}

func mustReadDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return string(b)
}

// between returns the substring of s strictly between the first occurrence of
// start and the first occurrence of end that follows it, and true; it returns
// ("", false) when either anchor is absent.
func between(s, start, end string) (string, bool) {
	i := strings.Index(s, start)
	if i < 0 {
		return "", false
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return "", false
	}
	return s[i : i+j], true
}
