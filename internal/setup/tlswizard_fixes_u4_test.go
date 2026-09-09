// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"strings"
	"testing"
)

// TestTLSWizardKeepSelfSignedRedirectsToMappableRoute (U4 A3-c3): when the
// "other devices" branch keeps the self-signed certificate, the wizard names how
// to re-run for a certificate a Windows drive mapping can use — a self-signed
// certificate cannot map a Windows network drive, so the redirect points back to
// `seavault tls setup` and the Tailscale / own-CA routes. This complements the
// already-shipped consequence line (Windows WebDAV refuses self-signed) with the
// missing "how to re-run" half. The dedup / https-explanation assertions live in
// TestTLSWizardKeepSelfSignedDedupNamesAndExplainsHTTPS (F-C) and stay green.
func TestTLSWizardKeepSelfSignedRedirectsToMappableRoute(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	deps := TLSDeps{LookPath: lookPathPresent(), Run: mustNotRun(t), ReadTailscaleStatus: noTailscale}
	s := &tlsScript{t: t, selectBy: routeSelector(routeSelfSigned), confirmBy: declineProbe}
	if err := RunTLSWizard(s, deps); err != nil {
		t.Fatalf("wizard: %v", err)
	}
	out := s.shownJoined()
	lo := strings.ToLower(out)
	// The redirect must name re-running tls setup AND a mappable route, and tie it to
	// the Windows drive-mapping limitation.
	if !strings.Contains(out, "seavault tls setup") ||
		!strings.Contains(lo, "windows") ||
		!(strings.Contains(lo, "tailscale") || strings.Contains(lo, "own ca")) {
		t.Fatalf("keep-self-signed on the other-devices branch must say how to re-run for a Windows-mappable certificate; got:\n%s", out)
	}
}
