// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// injectRawFile stores content at an arbitrary virtual path through the internal
// putReader, bypassing the ValidatePortableName gate that PutReader/putFile
// apply. It simulates a file a 0.15 peer or a non-Windows client created under a
// name that is illegal on Windows (e.g. content/a:b.txt), so the tests can prove
// such a file still reads and exports.
func injectRawFile(t *testing.T, v *Vault, vp string, data []byte) {
	t.Helper()
	idx, err := v.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.putReader(bytes.NewReader(data), vp, int64(len(data)), 0o600, time.Now().UTC(), &idx); err != nil {
		t.Fatal(err)
	}
	if v.usesManifestStore() {
		if err := v.commitFileManifest(vp, idx.Files[vp]); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := v.SaveIndex(idx); err != nil {
		t.Fatal(err)
	}
}

// TestPutReaderRefusesIllegalPortableName covers the create-time half of: a
// new upload target whose leaf is not portable is refused, and the offending
// character is named.
func TestPutReaderRefusesIllegalPortableName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "pw")
	v, err := Open(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("x"), "content/CON.txt", 1, 0o600, time.Now()); err == nil {
		t.Fatal("PutReader(content/CON.txt) succeeded; want refusal")
	} else if !strings.Contains(err.Error(), "reserved device name") {
		t.Fatalf("PutReader error %q does not name the reserved rule", err.Error())
	}
	if err := v.EnsureDirectory("a:b"); err == nil {
		t.Fatal("EnsureDirectory(a:b) succeeded; want refusal")
	}
	// A portable name is still accepted, and overwriting it keeps working.
	if _, err := v.PutReader(strings.NewReader("y"), "content/ok.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatalf("PutReader(ok.txt): %v", err)
	}
}

// TestExportSanitisesIllegalName is the export half of: an existing
// content/a:b.txt still reads, and export writes it as a_b.txt — no colon
// reaches the OS path — reporting the (original, written) pair.
func TestExportSanitisesIllegalName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "pw")
	v, err := Open(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("colon name content")
	injectRawFile(t, v, "content/a:b.txt", content)

	// Reading the existing illegal name must keep working.
	readBack := filepath.Join(t.TempDir(), "read.out")
	if err := v.GetPath("a:b.txt", readBack); err != nil {
		t.Fatalf("GetPath(a:b.txt): %v", err)
	}
	if got, _ := os.ReadFile(readBack); !bytes.Equal(got, content) {
		t.Fatalf("read of a:b.txt = %q, want %q", got, content)
	}

	dest := t.TempDir()
	res, err := v.ExportPath(context.Background(), "a:b.txt", dest, ExportOptions{})
	if err != nil {
		t.Fatalf("ExportPath: %v", err)
	}
	written := filepath.Join(dest, "a_b.txt")
	if got, err := os.ReadFile(written); err != nil {
		t.Fatalf("expected sanitised export at %s: %v", written, err)
	} else if !bytes.Equal(got, content) {
		t.Fatalf("exported content = %q, want %q", got, content)
	}
	// No colon-bearing path may be written (an ADS write on Windows).
	if _, err := os.Stat(filepath.Join(dest, "a:b.txt")); err == nil {
		t.Fatal("a colon-bearing path reached the OS filesystem")
	}
	// The result reports the (original, written) pair.
	var found bool
	for _, e := range res.Entries {
		if e.Path == "content/a:b.txt" {
			found = true
			if filepath.Base(e.DestPath) != "a_b.txt" {
				t.Fatalf("entry DestPath = %q, want leaf a_b.txt", e.DestPath)
			}
		}
	}
	if !found {
		t.Fatalf("no entry for content/a:b.txt in %#v", res.Entries)
	}
}

// TestExportCaseFoldCollision is: two portable names that differ only in case
// (Foo.txt, foo.txt) both export, the second disambiguated by the conflict
// suffix, even under the replace overwrite policy, so neither clobbers the other
// on a case-insensitive filesystem.
func TestExportCaseFoldCollision(t *testing.T) {
	for _, policy := range []string{OverwriteFail, OverwriteReplace} {
		t.Run(policy, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			createTestVault(t, root, "pw")
			v, err := Open(root, "pw")
			if err != nil {
				t.Fatal(err)
			}
			// Both names are portable, so ordinary PutReader accepts them.
			if _, err := v.PutReader(strings.NewReader("upper"), "content/dir/Foo.txt", 5, 0o600, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := v.PutReader(strings.NewReader("lower"), "content/dir/foo.txt", 5, 0o600, time.Now()); err != nil {
				t.Fatal(err)
			}
			dest := t.TempDir()
			res, err := v.ExportPath(context.Background(), "dir", dest, ExportOptions{Overwrite: policy})
			if err != nil {
				t.Fatalf("ExportPath: %v", err)
			}
			if res.Exported != 2 {
				t.Fatalf("exported %d files, want 2 (%#v)", res.Exported, res.Entries)
			}
			// Exactly one written leaf keeps the bare name; the other carries the
			// conflict suffix. Collect the leaves case-sensitively from the result.
			var leaves []string
			for _, e := range res.Entries {
				leaves = append(leaves, filepath.Base(e.DestPath))
			}
			var suffixed int
			for _, l := range leaves {
				if strings.Contains(l, ".conflict-") {
					suffixed++
				}
			}
			if suffixed != 1 {
				t.Fatalf("expected exactly one suffixed leaf, got leaves=%v", leaves)
			}
			// Both target files exist on disk with their distinct content.
			entriesByFolded := map[string]bool{}
			for _, e := range res.Entries {
				entriesByFolded[strings.ToLower(filepath.Base(e.DestPath))] = true
				if _, err := os.Stat(e.DestPath); err != nil {
					t.Fatalf("written file missing: %s: %v", e.DestPath, err)
				}
			}
			if len(entriesByFolded) != 2 {
				t.Fatalf("written leaves collided case-insensitively: %v", leaves)
			}
		})
	}
}
