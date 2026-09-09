// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// U4 slice P3 — the P-DOCS drift guard (design §3 P-DOCS, §5 rows P1–P3, and the
// "extend the D1 drift guard for the new sections" finish-the-phase item). This
// file EXTENDS the §7 D1 drift guard (TestTLSDocsDriftD1 / …FixTranche in
// tls_docdrift_u3_test.go) to the documentation Track R ships in U4: the
// SECURITY.md rate-limit guarantees (I-R1…I-R10) and their residuals, the TLS
// guide's auth-limit behaviour (per-surface 429/Retry-After, the off switch,
// disabledSince), and the README v0.21 changelog (including the CLI 6 migration
// note and the DOCS 2 single-use-redeem note).
//
// It is a NEW test file (additions never fail the Z1 pre-phase guards); no
// pre-U4 test is edited. Every table asserts on every row and fails a vacuous
// (empty) table — the reached() discipline in Go idiom.

func p3ReadDoc(t *testing.T, rel ...string) string {
	t.Helper()
	parts := append([]string{"..", ".."}, rel...)
	return mustReadRepoFile(t, filepath.Join(parts...))
}

// TestU4DocsP3SecurityGuarantees is the P-DOCS SECURITY.md row: the network-
// exposed-mode rate-limit residual BECOMES a set of guarantees (I-R1…I-R10) with
// the §6 residuals stated plainly. The build fails if any guarantee label or any
// residual anchor is dropped, so SECURITY.md can never silently lose the U4
// authentication-hardening guarantees. It also co-asserts that the two verbatim
// residual sentences the pre-U4 D1 guard (TestTLSDocsDriftD1) still pins remain
// present — the first now quoted as the prior-phase residual that U4 closes — so
// this file documents, in one place, why the D1 substring survives unedited.
func TestU4DocsP3SecurityGuarantees(t *testing.T) {
	sec := p3ReadDoc(t, "SECURITY.md")

	// The new section heading and each guarantee label I-R1…I-R10.
	structural := []string{
		"## Authentication rate limiting and lockout",
		"I-R1", "I-R2", "I-R3", "I-R4", "I-R5",
		"I-R6", "I-R7", "I-R8", "I-R9", "I-R10",
	}
	if len(structural) == 0 {
		t.Fatal("P3 SECURITY structural table is empty")
	}
	for _, s := range structural {
		if !strings.Contains(sec, s) {
			t.Errorf("P3: SECURITY.md is missing the auth-limit anchor %q", s)
		}
	}

	// The §6 residuals, each named plainly (per-process reset, shared NAT / /64
	// sharing, the account-ceiling lever, source rotation beyond the /64 and the
	// ceiling as out of scope, and the banner-coverage limit).
	residuals := []struct {
		name string
		want string
	}{
		{"per-process reset", "reset on restart"},
		{"per-process/in-memory", "per process and in memory"},
		{"shared NAT sharing", "shared NAT"},
		{"/64 sharing", "a whole /64"},
		{"account-ceiling lever", "the per-account ceiling is itself a lever"},
		{"source rotation out of scope", "out of scope"},
		{"distributed attack labelled", "distributed attack"},
		{"banner covers post-login only", "only the post-login"},
		{"basic/login/launch have no banner", "cannot show a banner"},
	}
	if len(residuals) == 0 {
		t.Fatal("P3 SECURITY residual table is empty")
	}
	for _, r := range residuals {
		if !strings.Contains(sec, r.want) {
			t.Errorf("P3: SECURITY.md is missing the §6 residual anchor for %s: %q", r.name, r.want)
		}
	}

	// The two pre-U4 D1-pinned residual sentences must still be present verbatim
	// (TestTLSDocsDriftD1 requires them and is frozen by the Z1 guards). The first
	// is now the quoted prior-phase residual that U4 closes; the second stands.
	pinned := []string{
		"the GUI login and WebDAV Basic auth become network-facing (rate limiting and lockout are a later phase)",
		"clients that accept a self-signed prompt are MITM-able on first connect",
	}
	for _, p := range pinned {
		if !strings.Contains(sec, p) {
			t.Errorf("P3: SECURITY.md dropped the D1-pinned residual sentence %q (this would also break TestTLSDocsDriftD1)", p)
		}
	}
	// The closed-residual note: the U3 residual is marked closed by U4, not left
	// standing as a contradiction to the new guarantees.
	if !strings.Contains(sec, "Phase U4) closes it") {
		t.Error(`P3: SECURITY.md must mark the U3 rate-limit residual as closed by U4 ("Phase U4) closes it")`)
	}
}

// TestU4DocsP3TLSGuideAuthLimits is the P-DOCS TLS-guide row: the guide documents
// the auth limits — the per-surface 429/Retry-After behaviour, the emergency off
// switch (`--auth-limit off` and `auth.limits.enabled=false`), and the persisted-
// disable dating (`disabledSince` / "OFF since") with its hourly re-warning. The
// build fails if any anchor is dropped.
func TestU4DocsP3TLSGuideAuthLimits(t *testing.T) {
	doc := p3ReadDoc(t, "docs", "tls-and-certificates.md")

	rows := []struct {
		name string
		want string
	}{
		{"on-by-default status line", "auth limits: on"},
		{"429 status", "429"},
		{"Retry-After header", "Retry-After"},
		{"off switch flag", "--auth-limit off"},
		{"off switch config key", "auth.limits.enabled=false"},
		{"persisted-disable dating", "OFF since"},
		{"disabledSince field", "disabledSince"},
		{"hourly re-warn", "re-warns"},
		{"throttle-only launch/redeem", "throttled but never locked"},
		{"tls status surface", "seavault tls status"},
	}
	if len(rows) == 0 {
		t.Fatal("P3 TLS-guide auth-limit table is empty")
	}
	for _, r := range rows {
		if !strings.Contains(doc, r.want) {
			t.Errorf("P3: docs/tls-and-certificates.md is missing the %s anchor %q", r.name, r.want)
		}
	}
	// The stale "a later phase" wording must be GONE from the guide's network-
	// exposed-mode section: U4 delivers the limiting the U3 guide deferred, so the
	// guide must no longer tell the reader there is none.
	for _, stale := range []string{
		"Rate limiting and account\n  lockout are a later phase",
		"no rate limiting and no account lockout (a later phase)",
	} {
		if strings.Contains(doc, stale) {
			t.Errorf("P3: docs/tls-and-certificates.md still says rate limiting is %q; U4 delivers it", stale)
		}
	}
}

// TestU4DocsP3ReadmeChangelogAndMigration is the P-DOCS README row: a "What
// changed in v0.21" changelog section that covers rate limiting + lockout, the
// CLI 6 migration note for scripts (an unknown subcommand now exits 2; a bare
// group verb still exits 0), and the DOCS 2 single-use-redeem note (re-mint after
// redeeming). The build fails if any anchor is dropped.
func TestU4DocsP3ReadmeChangelogAndMigration(t *testing.T) {
	readme := p3ReadDoc(t, "README.md")

	rows := []struct {
		name string
		want string
	}{
		{"v0.21 changelog heading", "## What changed in v0.21"},
		{"auth-limit off switch named", "--auth-limit off"},
		{"per-account ceiling summary", "per-account"},
		{"CLI 6 exit-2 migration", "an unknown subcommand now exits `2`"},
		{"CLI 6 bare-group still 0", "a bare group verb still exits `0`"},
		{"DOCS 2 single-use redeem", "Redeem is single-use"},
		{"DOCS 2 re-mint remedy", "seavault recovery generate"},
	}
	if len(rows) == 0 {
		t.Fatal("P3 README table is empty")
	}
	for _, r := range rows {
		if !strings.Contains(readme, r.want) {
			t.Errorf("P3: README.md is missing the %s anchor %q", r.name, r.want)
		}
	}
}

// TestU4DocsP3DeliveredTLSDocRows re-anchors the P-DOCS rows the U3 F-D tranche
// already shipped to the TLS guide (A3-c1 decision aid + LAN-name-resolve, A3-c2
// net-use UNC form, A3-c5 per-OS firewall commands, A1-c5 phone reach). The U4
// design re-lists them under P-DOCS as part of the polish backlog; they are
// delivered and separately guarded by TestTLSDocsDriftD1FixTranche, and this row
// makes the U4 P-DOCS completeness explicit so a later edit that drops one fails
// the U4 slice too.
func TestU4DocsP3DeliveredTLSDocRows(t *testing.T) {
	doc := p3ReadDoc(t, "docs", "tls-and-certificates.md")
	rows := []struct {
		finding string
		want    string
	}{
		{"A3-c1 decision aid (route for no-domain/no-VPN LAN)", "## Which route fits your situation?"},
		{"A3-c1 bring-your-own + client root install", "Route D"},
		{"A3-c2 net use UNC @SSL@ form", "@SSL@"},
		{"A3-c5 per-OS firewall — ufw", "ufw allow from"},
		{"A3-c5 per-OS firewall — Windows netsh scoped to subnet", "netsh advfirewall firewall add rule"},
		{"A1-c5 reaching a headless host from a phone", "## Reaching a headless host from a phone"},
	}
	if len(rows) == 0 {
		t.Fatal("P3 delivered-doc-rows table is empty")
	}
	for _, r := range rows {
		if !strings.Contains(doc, r.want) {
			t.Errorf("P3: docs/tls-and-certificates.md is missing the delivered %s anchor %q", r.finding, r.want)
		}
	}
}
