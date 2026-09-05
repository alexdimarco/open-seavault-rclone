// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestArtifactName(t *testing.T) {
	tests := []struct {
		version string
		goos    string
		goarch  string
		want    string
	}{
		{"v1.74.0", "linux", "amd64", "rclone-v1.74.0-linux-amd64.zip"},
		{"1.74.0", "windows", "amd64", "rclone-v1.74.0-windows-amd64.zip"},
		{"current", "darwin", "arm64", "rclone-current-osx-arm64.zip"},
		{"", "linux", "arm", "rclone-current-linux-arm-v7.zip"},
	}
	for _, tc := range tests {
		got, err := ArtifactName(tc.version, tc.goos, tc.goarch)
		if err != nil {
			t.Fatalf("ArtifactName returned error: %v", err)
		}
		if got != tc.want {
			t.Fatalf("ArtifactName(%q,%q,%q)=%q want %q", tc.version, tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestInstallFromBinaryAndVerifyRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("script-based fake rclone is Unix-specific")
	}
	home := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", home)
	fake := filepath.Join(t.TempDir(), "rclone")
	body := "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo 'rclone v1.74.0'; exit 0; fi\necho ok\n"
	if err := os.WriteFile(fake, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	installer := NewInstaller()
	m, err := installer.Install(context.Background(), InstallOptions{FromBinary: fake, SignatureMode: "skip"})
	if err != nil {
		t.Fatalf("Install from binary failed: %v", err)
	}
	if m.InstalledVersion != "v1.74.0" {
		t.Fatalf("installed version=%q", m.InstalledVersion)
	}
	if !strings.HasPrefix(m.BinaryPath, home) {
		t.Fatalf("managed binary not under app home: %s", m.BinaryPath)
	}
	if err := VerifyRuntime(m); err != nil {
		t.Fatalf("VerifyRuntime failed: %v", err)
	}
	st := installer.Status(context.Background(), false)
	if !st.Installed || !st.RuntimeOK {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestRedactText(t *testing.T) {
	input := "token = abc\nclient_secret = xyz\nnormal = ok\n"
	out := RedactText(input)
	if strings.Contains(out, "abc") || strings.Contains(out, "xyz") {
		t.Fatalf("secret was not redacted: %s", out)
	}
	if !strings.Contains(out, "normal = ok") {
		t.Fatalf("non-secret value was unexpectedly changed: %s", out)
	}
}
