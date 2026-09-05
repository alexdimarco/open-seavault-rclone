// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package remotes

import (
	"strings"
	"testing"
)

func TestAddGetListRemoteProfile(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	p := DefaultProfile("research", t.TempDir(), "b2ca:bucket/research", "b2")
	p.Remote.Transfers = 4
	stored, err := Add(p)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if stored.Name != "research" || stored.Remote.Backend != "b2" {
		t.Fatalf("unexpected stored profile: %+v", stored)
	}
	got, ok, err := Get("research")
	if err != nil || !ok {
		t.Fatalf("Get failed: ok=%v err=%v", ok, err)
	}
	if got.Remote.Transfers != 4 {
		t.Fatalf("transfers=%d", got.Remote.Transfers)
	}
	all, err := List()
	if err != nil || len(all) != 1 {
		t.Fatalf("List len=%d err=%v", len(all), err)
	}
}

func TestRedactConfig(t *testing.T) {
	cfg := "[remote]\ntype = b2\naccount = visible\nkey = secret\nclient_secret = secret2\n"
	out := RedactConfig(cfg)
	if strings.Contains(out, "key = secret") || strings.Contains(out, "secret2") {
		t.Fatalf("secret value remained in output: %s", out)
	}
	if !strings.Contains(out, "account = visible") {
		t.Fatalf("expected visible field preserved: %s", out)
	}
}
