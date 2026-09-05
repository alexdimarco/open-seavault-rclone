// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package sshkeys

import (
	"context"
	"strings"
	"testing"
)

func TestGenerateListAndPublic(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	entry, err := Generate(context.Background(), "research")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if entry.Fingerprint == "" || !strings.HasPrefix(entry.Fingerprint, "SHA256:") {
		t.Fatalf("missing fingerprint: %+v", entry)
	}
	pub, err := Public("research_ed25519")
	if err != nil {
		t.Fatalf("Public failed: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("unexpected public key: %s", pub)
	}
	list, err := List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List len=%d err=%v", len(list), err)
	}
}
