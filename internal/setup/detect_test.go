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
	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// detectRow is one (goos × provider × present/absent) case of the §4 detection
// table, shared by T1, T10 and the preflight-note T-row. relPath is the
// directory to create under the injected home (path segments, joined with the
// OS separator); an empty relPath means "create nothing" so the provider must
// MISS. syncMarker creates a Syncthing folder marker inside relPath, which is
// what promotes a bare ~/Sync directory to a detected Syncthing root
// (detection-preflight-2).
type detectRow struct {
	name       string
	goos       string
	provider   Provider
	relPath    []string
	syncMarker bool
	wantHit    bool
}

func detectionTable() []detectRow {
	return []detectRow{
		// linux / generic home-relative
		{"linux dropbox present", "linux", ProviderDropbox, []string{"Dropbox"}, false, true},
		{"linux nextcloud present", "linux", ProviderNextcloud, []string{"Nextcloud"}, false, true},
		{"linux syncthing with marker present", "linux", ProviderSyncthing, []string{"Sync"}, true, true},
		{"linux bare Sync without marker misses", "linux", ProviderSyncthing, []string{"Sync"}, false, false},
		{"linux onedrive present", "linux", ProviderOneDrive, []string{"OneDrive"}, false, true},
		{"linux dropbox absent", "linux", ProviderDropbox, nil, false, false},
		{"linux icloud not detected on linux", "linux", ProviderICloud, []string{"iCloudDrive"}, false, false},
		// darwin
		{"darwin dropbox present", "darwin", ProviderDropbox, []string{"Dropbox"}, false, true},
		{"darwin onedrive cloudstorage glob", "darwin", ProviderOneDrive, []string{"Library", "CloudStorage", "OneDrive-Personal"}, false, true},
		{"darwin icloud present", "darwin", ProviderICloud, []string{"Library", "Mobile Documents", "com~apple~CloudDocs"}, false, true},
		{"darwin googledrive cloudstorage glob", "darwin", ProviderGoogleDrive, []string{"Library", "CloudStorage", "GoogleDrive-me@example.com", "My Drive"}, false, true},
		{"darwin syncthing with marker present", "darwin", ProviderSyncthing, []string{"Sync"}, true, true},
		{"darwin googledrive absent", "darwin", ProviderGoogleDrive, nil, false, false},
		// windows
		{"windows icloud present", "windows", ProviderICloud, []string{"iCloudDrive"}, false, true},
		{"windows googledrive present", "windows", ProviderGoogleDrive, []string{"Google Drive"}, false, true},
		{"windows onedrive present", "windows", ProviderOneDrive, []string{"OneDrive"}, false, true},
		{"windows nextcloud absent", "windows", ProviderNextcloud, nil, false, false},
	}
}

// materializeRow creates the row's provider directory (and, for a Syncthing
// marker row, the marker inside it) under home, returning the created directory
// path (or "" when the row creates nothing). Shared so T1, T10 and the
// preflight T-row set up the filesystem identically.
func materializeRow(t *testing.T, home string, row detectRow) string {
	t.Helper()
	if len(row.relPath) == 0 {
		return ""
	}
	dir := filepath.Join(append([]string{home}, row.relPath...)...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if row.syncMarker {
		// Syncthing creates a .stfolder marker directory inside every managed
		// folder; the detector keys off exactly this.
		if err := os.Mkdir(filepath.Join(dir, ".stfolder"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
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
			wantPath := materializeRow(t, home, row)
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
			materializeRow(t, home, row)
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

// detection-preflight-1: the create-time compatibility note fires for EVERY
// path the single detector returns, across the whole goos table. Before the
// single-source fix, iCloud (com~apple~CloudDocs / iCloudDrive), Syncthing
// (~/Sync) and G:\My Drive hits got a silently-empty note because the matcher's
// folder-name list had drifted from the detector's segments. This walks the
// detection table, materialises each hit, and asserts a non-empty
// SyncClientPreflightNote for every DetectSyncFolders path — so the two can
// never diverge again.
func TestDetectedRootsAllProducePreflightNote(t *testing.T) {
	rows := detectionTable()
	if len(rows) == 0 {
		t.Fatal("detection table is empty; the test would exercise nothing")
	}
	asserted := 0
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			home := t.TempDir()
			materializeRow(t, home, row)
			folders := DetectSyncFolders(home, row.goos)
			if row.wantHit && len(folders) == 0 {
				t.Fatalf("row %q expects a hit but the detector returned nothing", row.name)
			}
			for _, f := range folders {
				vaultPath := filepath.Join(f.Path, defaultVaultName)
				note := vault.SyncClientPreflightNote(vaultPath)
				if strings.TrimSpace(note) == "" {
					t.Fatalf("a detected %s root at %q must produce a non-empty preflight note for a vault at %q, but got \"\"", f.Provider, f.Path, vaultPath)
				}
				asserted++
			}
		})
	}
	// reached(): the table must have exercised at least one detected root, or the
	// assertion above never ran (a vacuous pass).
	if asserted == 0 {
		t.Fatal("no detected root was asserted; the preflight T-row exercised nothing")
	}
}

// detection-preflight-4: the iCloud caveat must not be macOS-only, because the
// detector attaches it to the Windows iCloud folder (~/iCloudDrive) too. It must
// carry guidance that applies on Windows, not only the macOS "Optimize Mac
// Storage" control.
func TestICloudCaveatIsPlatformNeutral(t *testing.T) {
	c := Caveat(ProviderICloud)
	if strings.TrimSpace(c) == "" {
		t.Fatal("the iCloud caveat must not be empty")
	}
	if !strings.Contains(c, "Windows") {
		t.Fatalf("the iCloud caveat is attached to Windows iCloud detection too, so it must give Windows-applicable guidance; got %q", c)
	}
	// It must remain useful on macOS as well.
	if !strings.Contains(c, "macOS") && !strings.Contains(c, "Mac") {
		t.Fatalf("the iCloud caveat must still cover macOS; got %q", c)
	}
}

// detection-preflight-2: a bare ~/Sync with no Syncthing marker is NOT a
// detected root (so the wizard never auto-answers "already synced" for a generic
// Sync directory), while a ~/Sync that carries a Syncthing marker IS. The
// detector and the preflight matcher agree on this: the marked folder gets a
// note, the bare one is simply not detected.
func TestSyncthingRequiresMarker(t *testing.T) {
	t.Run("bare Sync is not detected", func(t *testing.T) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, "Sync"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range DetectSyncFolders(home, "linux") {
			if f.Provider == ProviderSyncthing {
				t.Fatalf("a bare ~/Sync (no Syncthing marker) must NOT be detected as Syncthing; got %+v", f)
			}
		}
		if prov, ok := ProviderRootFor(filepath.Join(home, "Sync", "MyVault"), home, "linux"); ok {
			t.Fatalf("a vault under a bare ~/Sync must not pre-answer a provider; got %q", prov)
		}
	})
	t.Run("marked Sync is detected", func(t *testing.T) {
		home := t.TempDir()
		syncDir := filepath.Join(home, "Sync")
		if err := os.MkdirAll(filepath.Join(syncDir, ".stfolder"), 0o755); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range DetectSyncFolders(home, "linux") {
			if f.Provider == ProviderSyncthing {
				found = true
			}
		}
		if !found {
			t.Fatal("a ~/Sync with a .stfolder marker must be detected as Syncthing")
		}
	})
}

// detection-preflight-5: on case-insensitive filesystems (windows/darwin) a
// custom vault path under a detected root must be recognised even when its case
// differs from the root's, while a case-sensitive OS (linux) must NOT fold. The
// host FS here is case-sensitive, so this exercises the fold DECISION in
// ProviderRootFor/pathWithin via the injected goos, not the FS itself.
func TestProviderRootForCaseFolding(t *testing.T) {
	rows := []struct {
		name    string
		goos    string
		target  []string // path segments under home for the vault
		wantHit bool
	}{
		{"windows folds case", "windows", []string{"DROPBOX", "vault"}, true},
		{"darwin folds case", "darwin", []string{"dropbox", "vault"}, true},
		{"windows exact still matches", "windows", []string{"Dropbox", "vault"}, true},
		{"linux is case-sensitive (miss)", "linux", []string{"DROPBOX", "vault"}, false},
		{"linux exact matches", "linux", []string{"Dropbox", "vault"}, true},
	}
	if len(rows) == 0 {
		t.Fatal("case-folding table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			home := t.TempDir()
			// The real detected folder is created with canonical casing.
			if err := os.MkdirAll(filepath.Join(home, "Dropbox"), 0o755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(append([]string{home}, row.target...)...)
			prov, ok := ProviderRootFor(target, home, row.goos)
			if ok != row.wantHit {
				t.Fatalf("ProviderRootFor(%q, goos=%s) = (%q, %v); want hit=%v", target, row.goos, prov, ok, row.wantHit)
			}
			if row.wantHit && prov != ProviderDropbox {
				t.Fatalf("a path under the Dropbox root must resolve to dropbox; got %q", prov)
			}
		})
	}
}
