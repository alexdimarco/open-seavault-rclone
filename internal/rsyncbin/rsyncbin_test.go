// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rsyncbin

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestArtifactName(t *testing.T) {
	got := ArtifactName("3.4.2", "linux", "amd64")
	if got != "seavault-rsync-3.4.2-linux-amd64.zip" {
		t.Fatalf("unexpected artifact name: %s", got)
	}
}

func TestLatestParsesSourceIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<a href="rsync-3.3.0.tar.gz">old</a><a href="rsync-3.4.2.tar.gz">new</a>`))
	}))
	defer srv.Close()
	i := NewInstaller()
	i.SourceBaseURL = srv.URL
	li, err := i.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if li.Version != "3.4.2" || !strings.Contains(li.SourceURL, "rsync-3.4.2.tar.gz") {
		t.Fatalf("unexpected latest info: %#v", li)
	}
}

func TestInstallFromBinary(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	bin := filepath.Join(t.TempDir(), exeName(runtime.GOOS))
	if err := writeFakeRsync(bin, "3.4.2"); err != nil {
		t.Fatal(err)
	}
	i := NewInstaller()
	m, err := i.Install(context.Background(), InstallOptions{FromBinary: bin})
	if err != nil {
		t.Fatal(err)
	}
	if m.InstalledVersion != "3.4.2" || m.BinaryPath == bin {
		t.Fatalf("unexpected manifest: %#v", m)
	}
	if err := VerifyRuntime(m); err != nil {
		t.Fatal(err)
	}
}

func TestInstallOfflineArchive(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	work := t.TempDir()
	fake := filepath.Join(work, exeName(runtime.GOOS))
	if err := writeFakeRsync(fake, "3.4.2"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(work, "seavault-rsync-3.4.2.zip")
	if err := zipOne(archive, exeName(runtime.GOOS), fake); err != nil {
		t.Fatal(err)
	}
	i := NewInstaller()
	m, err := i.Install(context.Background(), InstallOptions{OfflineArchive: archive, Version: "3.4.2"})
	if err != nil {
		t.Fatal(err)
	}
	if m.InstalledVersion != "3.4.2" {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func TestInstallNetworkRequiresChecksum(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS") {
			http.NotFound(w, r) // checksums unavailable (404 / stripped by MITM)
			return
		}
		_, _ = w.Write([]byte("fake-runtime-archive-bytes"))
	}))
	defer srv.Close()
	i := NewInstaller()
	_, err := i.Install(context.Background(), InstallOptions{Version: "3.4.2", RuntimeBaseURL: srv.URL})
	if err == nil {
		t.Fatal("expected network install to fail when SHA256SUMS is unavailable")
	}
	if !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("expected an unverified-runtime error, got: %v", err)
	}
}

func TestAllowedDownloadURLRejectsUnsafeHosts(t *testing.T) {
	i := NewInstaller()
	bad := []string{
		"http://evil.attacker.net/runtime/SHA256SUMS",                                     // non-HTTPS, non-loopback
		"https://github.com/example/seavault-rsync-runtime/releases/download/3.4.2/x.zip", // placeholder /example/ path
		"https://example.com/runtime/x.zip",                                               // example host
	}
	for _, u := range bad {
		if err := i.allowedDownloadURL(u); err == nil {
			t.Fatalf("expected %q to be rejected", u)
		}
	}
	good := []string{"http://127.0.0.1:9/x", "https://download.samba.org/pub/rsync/"}
	for _, u := range good {
		if err := i.allowedDownloadURL(u); err != nil {
			t.Fatalf("expected %q to be allowed, got %v", u, err)
		}
	}
	i.AllowedDownloadHosts = []string{"runtime.internal"}
	if err := i.allowedDownloadURL("https://runtime.internal/a/b.zip"); err != nil {
		t.Fatalf("allowlisted host rejected: %v", err)
	}
	if err := i.allowedDownloadURL("https://other.internal/a/b.zip"); err == nil {
		t.Fatal("non-allowlisted host should be rejected")
	}
}

func TestInstallFromBinaryNotMarkedVerified(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	bin := filepath.Join(t.TempDir(), exeName(runtime.GOOS))
	if err := writeFakeRsync(bin, "3.4.2"); err != nil {
		t.Fatal(err)
	}
	i := NewInstaller()
	m, err := i.Install(context.Background(), InstallOptions{FromBinary: bin})
	if err != nil {
		t.Fatal(err)
	}
	if m.ChecksumVerified {
		t.Fatal("manually-registered binary must not be reported as checksum-verified")
	}
	if m.SignatureWarning == "" {
		t.Fatal("expected a provenance warning for a manually-registered binary")
	}
}

func writeFakeRsync(path, version string) error {
	body := "#!/usr/bin/bash\nif [ \"$1\" = \"--version\" ]; then echo 'rsync  version " + version + "  protocol version 31'; exit 0; fi\nexit 0\n"
	return os.WriteFile(path, []byte(body), 0o700)
}

func zipOne(zipPath, name, src string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o700)
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
