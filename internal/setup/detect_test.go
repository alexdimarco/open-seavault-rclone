// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

// detectRow is one (goos × provider × present/absent) case of the §4 detection
// table, shared by T1 and T10. relPath is the directory to create under the
// injected home (path segments, joined with the OS separator); an empty relPath
// means "create nothing" so the provider must MISS.
type detectRow struct {
	name     string
	goos     string
	provider Provider
	relPath  []string
	wantHit  bool
}

func detectionTable() []detectRow {
	return []detectRow{
		// linux / generic home-relative
		{"linux dropbox present", "linux", ProviderDropbox, []string{"Dropbox"}, true},
		{"linux nextcloud present", "linux", ProviderNextcloud, []string{"Nextcloud"}, true},
		{"linux syncthing present", "linux", ProviderSyncthing, []string{"Sync"}, true},
		{"linux onedrive present", "linux", ProviderOneDrive, []string{"OneDrive"}, true},
		{"linux dropbox absent", "linux", ProviderDropbox, nil, false},
		{"linux icloud not detected on linux", "linux", ProviderICloud, []string{"iCloudDrive"}, false},
		// darwin
		{"darwin dropbox present", "darwin", ProviderDropbox, []string{"Dropbox"}, true},
		{"darwin onedrive cloudstorage glob", "darwin", ProviderOneDrive, []string{"Library", "CloudStorage", "OneDrive-Personal"}, true},
		{"darwin icloud present", "darwin", ProviderICloud, []string{"Library", "Mobile Documents", "com~apple~CloudDocs"}, true},
		{"darwin googledrive cloudstorage glob", "darwin", ProviderGoogleDrive, []string{"Library", "CloudStorage", "GoogleDrive-me@example.com", "My Drive"}, true},
		{"darwin googledrive absent", "darwin", ProviderGoogleDrive, nil, false},
		// windows
		{"windows icloud present", "windows", ProviderICloud, []string{"iCloudDrive"}, true},
		{"windows googledrive present", "windows", ProviderGoogleDrive, []string{"Google Drive"}, true},
		{"windows onedrive present", "windows", ProviderOneDrive, []string{"OneDrive"}, true},
		{"windows nextcloud absent", "windows", ProviderNextcloud, nil, false},
	}
}

// T1 (§4): the detector reports a provider exactly when its well-known folder
// exists as a directory, per OS, and attaches a non-empty caveat to every hit.
func TestDetectSyncFolders(t *testing.T) {
	rows := detectionTable()
	if len(rows) == 0 {
		t.Fatal("detection table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			home := t.TempDir()
			var wantPath string
			if len(row.relPath) > 0 {
				wantPath = filepath.Join(append([]string{home}, row.relPath...)...)
				if err := os.MkdirAll(wantPath, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			got := DetectSyncFolders(home, row.goos)

			var found *SyncFolder
			for i := range got {
				if got[i].Provider == row.provider {
					found = &got[i]
					break
				}
			}
			if row.wantHit {
				if found == nil {
					t.Fatalf("provider %s must be detected at %s; got %+v", row.provider, wantPath, got)
				}
				if found.Path != wantPath {
					t.Fatalf("provider %s detected at %q; want %q", row.provider, found.Path, wantPath)
				}
				if found.Note == "" {
					t.Fatalf("a hit for %s must carry a non-empty caveat Note", row.provider)
				}
				if found.Note != Caveat(row.provider) {
					t.Fatalf("hit Note for %s must be the catalog caveat; got %q", row.provider, found.Note)
				}
			} else if found != nil {
				t.Fatalf("provider %s must NOT be detected for goos=%s; got %+v", row.provider, row.goos, *found)
			}
		})
	}
}

// T7 (I-S6): the caveat catalog is the single source of truth and a detected
// provider surfaces its specific caveat. Every provider in the enum has a
// non-empty caveat, and OneDrive carries its Files On-Demand guidance.
func TestCaveatCatalog(t *testing.T) {
	if len(AllProviders) == 0 {
		t.Fatal("AllProviders is empty; the test would exercise nothing")
	}
	for _, p := range AllProviders {
		c := Caveat(p)
		if strings.TrimSpace(c) == "" {
			t.Fatalf("provider %s has no caveat in the catalog", p)
		}
	}
	// The specific OneDrive caveat must reach a detected hit and name its
	// concrete pitfall (Files On-Demand), so Show()/detect JSON carries it (T7).
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "OneDrive"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := DetectSyncFolders(home, "windows")
	var note string
	for _, f := range got {
		if f.Provider == ProviderOneDrive {
			note = f.Note
		}
	}
	if note == "" {
		t.Fatal("a detected OneDrive folder must surface a caveat Note")
	}
	if !strings.Contains(note, "Files On-Demand") || !strings.Contains(note, "Always keep on this device") {
		t.Fatalf("the OneDrive caveat must name its Files On-Demand pitfall and remedy; got %q", note)
	}
}

// T10 (C10): DetectSyncFolders and the single OS-path detector
// userpath.DetectSyncRoots agree on every row of the detection table, and
// SuggestedVaultPaths is built from the same detector, so the two never diverge.
func TestOneDetector(t *testing.T) {
	rows := detectionTable()
	if len(rows) == 0 {
		t.Fatal("detection table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			home := t.TempDir()
			if len(row.relPath) > 0 {
				if err := os.MkdirAll(filepath.Join(append([]string{home}, row.relPath...)...), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			folders := DetectSyncFolders(home, row.goos)
			roots := userpath.DetectSyncRoots(home, row.goos)
			if len(folders) != len(roots) {
				t.Fatalf("detectors disagree on count: setup=%d userpath=%d (goos=%s)", len(folders), len(roots), row.goos)
			}
			for i := range folders {
				if string(folders[i].Provider) != roots[i].Provider || folders[i].Path != roots[i].Path {
					t.Fatalf("detectors diverge at %d: setup=(%s,%s) userpath=(%s,%s)",
						i, folders[i].Provider, folders[i].Path, roots[i].Provider, roots[i].Path)
				}
			}
		})
	}

	// The []string entry point (SuggestedVaultPaths, real home + current GOOS)
	// is wired to the same detector: for each detected root under a temp HOME it
	// suggests "<root>/seavault".
	home := t.TempDir()
	setHomeEnv(t, home)
	for _, name := range []string{"Dropbox", "Nextcloud"} {
		if err := os.MkdirAll(filepath.Join(home, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	roots := userpath.DetectSyncRoots(home, runtime.GOOS)
	if len(roots) == 0 {
		t.Fatal("expected Dropbox/Nextcloud roots under the temp home")
	}
	suggested := userpath.SuggestedVaultPaths()
	for _, r := range roots {
		want := filepath.Join(r.Path, "seavault")
		if !containsString(suggested, want) {
			t.Fatalf("SuggestedVaultPaths must include %q (from detector root %q); got %v", want, r.Path, suggested)
		}
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// setHomeEnv points os.UserHomeDir at home for the duration of the test, across
// platforms.
func setHomeEnv(t *testing.T, home string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
		t.Setenv("HOMEDRIVE", "")
		t.Setenv("HOMEPATH", "")
	} else {
		t.Setenv("HOME", home)
	}
}
