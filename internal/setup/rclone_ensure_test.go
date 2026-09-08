// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
)

// T14 (C11): RcloneEnsure asks consent BEFORE any network access. A present,
// verified runtime returns nil with no fetch and no consent prompt. Refused
// consent returns the typed ErrDownloadRefused naming the offline options, with
// no fetch. Granted consent installs exactly once.
func TestRcloneEnsure(t *testing.T) {
	rows := []struct {
		name          string
		status        rclonebin.Status
		consent       *bool // nil => a nil consent func
		wantErr       error
		wantConsented bool
		wantInstalled bool
		wantOffline   bool
	}{
		{
			name:          "present verified runtime",
			status:        rclonebin.Status{Installed: true, RuntimeOK: true},
			consent:       boolp(true),
			wantErr:       nil,
			wantConsented: false, // consent must NOT be asked when already present
			wantInstalled: false, // no fetch
		},
		{
			name:          "missing, consent refused",
			status:        rclonebin.Status{Installed: false, RuntimeOK: false},
			consent:       boolp(false),
			wantErr:       ErrDownloadRefused,
			wantConsented: true,
			wantInstalled: false, // refusal is BEFORE any fetch
			wantOffline:   true,
		},
		{
			name:          "missing, consent nil is a refusal",
			status:        rclonebin.Status{Installed: false, RuntimeOK: false},
			consent:       nil,
			wantErr:       ErrDownloadRefused,
			wantConsented: false,
			wantInstalled: false,
			wantOffline:   true,
		},
		{
			name:          "missing, consent granted installs once",
			status:        rclonebin.Status{Installed: false, RuntimeOK: false},
			consent:       boolp(true),
			wantErr:       nil,
			wantConsented: true,
			wantInstalled: true,
		},
	}
	if len(rows) == 0 {
		t.Fatal("RcloneEnsure table is empty; the test would exercise nothing")
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			restore := swapRcloneSeams(row.status)
			defer restore()

			var installCalls int
			rcloneInstall = func(context.Context) error { installCalls++; return nil }

			consented := false
			var consent func() bool
			if row.consent != nil {
				want := *row.consent
				consent = func() bool { consented = true; return want }
			}

			err := RcloneEnsure(consent)

			if row.wantErr == nil && err != nil {
				t.Fatalf("want nil error; got %v", err)
			}
			if row.wantErr != nil && !errors.Is(err, row.wantErr) {
				t.Fatalf("want error %v; got %v", row.wantErr, err)
			}
			if consented != row.wantConsented {
				t.Fatalf("consent asked=%v; want %v", consented, row.wantConsented)
			}
			if (installCalls > 0) != row.wantInstalled {
				t.Fatalf("install calls=%d; wantInstalled=%v", installCalls, row.wantInstalled)
			}
			if row.wantInstalled && installCalls != 1 {
				t.Fatalf("install must run exactly once; calls=%d", installCalls)
			}
			if row.wantOffline {
				if !strings.Contains(err.Error(), "--offline-archive") || !strings.Contains(err.Error(), "--from-binary") {
					t.Fatalf("the refusal must name the offline options; got %q", err.Error())
				}
			}
		})
	}
}

// A present runtime is detected through the REAL rclonebin Status/VerifyRuntime
// path (a seeded manifest + binary in a temp app home), and RcloneEnsure returns
// nil without asking consent or fetching.
func TestRcloneEnsurePresentViaRealRuntime(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	runtimeDir, err := rclonebin.RuntimeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binName := "rclone"
	if runtime.GOOS == "windows" {
		binName = "rclone.exe"
	}
	binPath := filepath.Join(runtimeDir, binName)
	if err := os.WriteFile(binPath, []byte("fake rclone binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// SHA256 left empty so VerifyRuntime checks presence only (no hash gate),
	// which is a real, supported manifest shape.
	if err := rclonebin.SaveManifest(rclonebin.Manifest{
		InstalledVersion: "v1.0.0-test",
		BinaryPath:       binPath,
		GOOS:             runtime.GOOS,
		GOARCH:           runtime.GOARCH,
	}); err != nil {
		t.Fatal(err)
	}
	if st := rclonebin.StatusNow(context.Background()); !st.Installed || !st.RuntimeOK {
		t.Fatalf("seeded runtime must verify; got %+v", st)
	}

	// rcloneInstall must never be reached; make it fail loudly if it is.
	restoreInstall := rcloneInstall
	rcloneInstall = func(context.Context) error {
		t.Fatal("RcloneEnsure must not fetch when a verified runtime is present")
		return nil
	}
	defer func() { rcloneInstall = restoreInstall }()

	consented := false
	if err := RcloneEnsure(func() bool { consented = true; return true }); err != nil {
		t.Fatalf("a present verified runtime must return nil; got %v", err)
	}
	if consented {
		t.Fatal("consent must not be asked when a runtime is already present")
	}
}

func boolp(b bool) *bool { return &b }

// swapRcloneSeams replaces rcloneStatus with a stub returning st and returns a
// function that restores both seams.
func swapRcloneSeams(st rclonebin.Status) func() {
	origStatus := rcloneStatus
	origInstall := rcloneInstall
	rcloneStatus = func() rclonebin.Status { return st }
	return func() {
		rcloneStatus = origStatus
		rcloneInstall = origInstall
	}
}
