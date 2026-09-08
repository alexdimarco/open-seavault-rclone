// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"testing"

	"github.com/alexdimarco/open-seavault-rclone/internal/appconfig"
)

// TestSettingsSaveReconcilesAgainstDiskNotStaleMemory (config-precedence-1, C3):
// a long-lived GUI reconciles a Settings save against the ON-DISK config, so an
// out-of-band `seavault tls use` / `tls reset` made after the GUI started is
// honoured. Before the fix the handler reconciled against the stale in-memory
// snapshot: a save WIPED a CLI-added tls.* (its baseline showed tls.* empty) and
// RESURRECTED a CLI-removed cert (its baseline still showed tls.* configured).
func TestSettingsSaveReconcilesAgainstDiskNotStaleMemory(t *testing.T) {
	t.Run("CLI `tls use` after GUI open: save must NOT wipe tls.*", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

		// The GUI opened when nothing was configured: its in-memory snapshot has an
		// empty tls section.
		stale := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
		s, err := NewWithConfig("", stale)
		if err != nil {
			t.Fatal(err)
		}

		// Meanwhile `seavault tls use` wrote a full tls section to disk (and left the
		// legacy gui.certFile cleared).
		onDisk := appconfig.Config{
			Version: appconfig.Version,
			GUI:     appconfig.GUIConfig{Protocol: "https"},
			TLS:     appconfig.TLSSection{CertFile: "/etc/seavault/leaf.crt", KeyFile: "/etc/seavault/leaf.key", AllowHosts: []string{"vault.example"}},
		}
		if err := appconfig.Save(onDisk); err != nil {
			t.Fatal(err)
		}

		// The stale GUI saves an unrelated change (its form still shows http, no tls).
		attempt := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
		rr := postJSON(t, s, "/api/app-config", map[string]any{"config": attempt})
		if rr.Code != http.StatusOK {
			t.Fatalf("POST /api/app-config = %d body=%s", rr.Code, rr.Body.String())
		}

		loaded, err := appconfig.Load()
		if err != nil {
			t.Fatal(err)
		}
		if loaded.TLS.CertFile != "/etc/seavault/leaf.crt" || loaded.TLS.KeyFile != "/etc/seavault/leaf.key" {
			t.Fatalf("GUI save wiped the CLI-added tls section: got certFile=%q keyFile=%q", loaded.TLS.CertFile, loaded.TLS.KeyFile)
		}
		if loaded.GUI.Protocol != "https" {
			t.Fatalf("GUI save reverted the CLI-set protocol: got %q, want https", loaded.GUI.Protocol)
		}
	})

	t.Run("CLI `tls reset` after GUI open: save must NOT resurrect the cert", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

		// The GUI opened while tls.* was managed: its in-memory snapshot still holds
		// the configured cert and the (historically) populated legacy field.
		stale := appconfig.Config{
			Version: appconfig.Version,
			GUI:     appconfig.GUIConfig{Protocol: "https", CertFile: "/etc/seavault/leaf.crt", KeyFile: "/etc/seavault/leaf.key"},
			TLS:     appconfig.TLSSection{CertFile: "/etc/seavault/leaf.crt", KeyFile: "/etc/seavault/leaf.key", AllowHosts: []string{"vault.example"}},
		}
		s, err := NewWithConfig("", stale)
		if err != nil {
			t.Fatal(err)
		}

		// Meanwhile `seavault tls reset` cleared the tls section and the legacy field
		// on disk, returning to plain http.
		onDisk := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
		if err := appconfig.Save(onDisk); err != nil {
			t.Fatal(err)
		}

		// The stale GUI saves; its form carries no tls and http (the reset state).
		attempt := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
		rr := postJSON(t, s, "/api/app-config", map[string]any{"config": attempt})
		if rr.Code != http.StatusOK {
			t.Fatalf("POST /api/app-config = %d body=%s", rr.Code, rr.Body.String())
		}

		loaded, err := appconfig.Load()
		if err != nil {
			t.Fatal(err)
		}
		if loaded.TLS.CertFile != "" || loaded.TLS.KeyFile != "" {
			t.Fatalf("GUI save resurrected the CLI-reset tls section: got certFile=%q keyFile=%q", loaded.TLS.CertFile, loaded.TLS.KeyFile)
		}
		if loaded.GUI.CertFile != "" {
			t.Fatalf("GUI save resurrected the legacy gui.certFile after reset: %q", loaded.GUI.CertFile)
		}
	})

	t.Run("GET tlsManaged reflects the on-disk state, not the stale snapshot", func(t *testing.T) {
		t.Setenv("SEAVAULT_APP_HOME", t.TempDir())

		// GUI opened unconfigured; disk now has a managed tls section (CLI `tls use`).
		stale := appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http"}}
		s, err := NewWithConfig("", stale)
		if err != nil {
			t.Fatal(err)
		}
		onDisk := appconfig.Config{
			Version: appconfig.Version,
			GUI:     appconfig.GUIConfig{Protocol: "https"},
			TLS:     appconfig.TLSSection{CertFile: "/etc/seavault/leaf.crt", KeyFile: "/etc/seavault/leaf.key"},
		}
		if err := appconfig.Save(onDisk); err != nil {
			t.Fatal(err)
		}

		var got struct {
			TLSManaged bool `json:"tlsManaged"`
		}
		if code := getJSON(t, s, "/api/app-config", &got); code != http.StatusOK {
			t.Fatalf("GET /api/app-config = %d", code)
		}
		if !got.TLSManaged {
			t.Fatal("GET tlsManaged did not reflect the out-of-band CLI `tls use`; the toggle would still show as live")
		}
	})
}
