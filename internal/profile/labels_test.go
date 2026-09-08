// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package profile

import (
	"strings"
	"testing"
)

// isolateLabelHome redirects the app-data root to a throwaway dir so the label
// store (a sibling of profiles.json under ConfigDir) never touches the developer's
// or CI's real home.
func isolateLabelHome(t *testing.T) {
	t.Helper()
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
}

// W5 (I-U3), profile side: the device-local recovery-label store round-trips keyed
// by the full entry ID, a missing record is not an error, and the stable 4-hex
// handle and the display string behave per §2.6.
func TestW5_RecoveryLabelStore(t *testing.T) {
	isolateLabelHome(t)

	const idA = "aabbccddeeff0011"
	const idB = "12ab34cd56ef7890"

	// A missing record is not an error and never a stored value.
	if _, ok, err := GetRecoveryLabel(idA); err != nil || ok {
		t.Fatalf("unknown entry must be (false,nil), got ok=%v err=%v", ok, err)
	}

	labelA := RecoveryKeyLabel{Label: "laptop key", Created: "2026-09-07", Device: "alex-laptop"}
	if err := SetRecoveryLabel(idA, labelA); err != nil {
		t.Fatalf("SetRecoveryLabel: %v", err)
	}
	got, ok, err := GetRecoveryLabel(idA)
	if err != nil || !ok {
		t.Fatalf("stored entry must be (true,nil), got ok=%v err=%v", ok, err)
	}
	if got != labelA {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, labelA)
	}

	// Empty entry ID is refused.
	if err := SetRecoveryLabel("   ", labelA); err == nil {
		t.Fatal("labeling an empty entry ID must be refused")
	}

	// Handle table: first four hex chars, lower-cased; short IDs pass through.
	handleRows := []struct {
		in   string
		want string
	}{
		{"aabbccddeeff0011", "aabb"},
		{"AABBccddeeff0011", "aabb"},
		{"deadbeefdeadbeef", "dead"},
		{"ab", "ab"},
		{"", ""},
	}
	if len(handleRows) == 0 {
		t.Fatal("no handle rows")
	}
	for _, r := range handleRows {
		if got := Handle(r.in); got != r.want {
			t.Fatalf("Handle(%q) = %q, want %q", r.in, got, r.want)
		}
	}

	// Listing: idA is labeled (ordinal 1), idB has no record (ordinal 2). Both show
	// their stable handle on this device regardless of a local record (C4).
	views, err := LabelledRecoveryKeys([]string{idA, idB})
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("expected 2 listing rows, got %d", len(views))
	}
	if views[0].Ordinal != 1 || views[1].Ordinal != 2 {
		t.Fatalf("ordinals must follow input order, got %d,%d", views[0].Ordinal, views[1].Ordinal)
	}
	if views[0].Handle != "aabb" || views[1].Handle != "12ab" {
		t.Fatalf("handles wrong: %q, %q", views[0].Handle, views[1].Handle)
	}
	if !views[0].HasRecord || views[0].Label != "laptop key" {
		t.Fatalf("labeled row must carry the record: %+v", views[0])
	}
	dispA := views[0].Display()
	for _, want := range []string{"#aabb", "laptop key", "created 2026-09-07", "alex-laptop"} {
		if !strings.Contains(dispA, want) {
			t.Fatalf("labeled display %q must contain %q", dispA, want)
		}
	}
	if views[1].HasRecord {
		t.Fatalf("unlabeled row must have no record: %+v", views[1])
	}
	if dispB := views[1].Display(); dispB != "Recovery key #12ab" {
		t.Fatalf("unlabeled display must degrade to the bare handle, got %q", dispB)
	}
}
