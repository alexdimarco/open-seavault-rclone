// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package profile

import (
	"os"
	"path/filepath"
	"runtime"
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

// TestWordlistLabels2_StorePermsForcedOnPreexistingFile (review wordlist-labels-2):
// os.WriteFile only applies a mode on CREATION, so a pre-existing 0644 store would
// stay world-readable. SaveLabels must force 0600 on the file and 0700 on the config
// dir regardless. os.Chmod on Windows only toggles the read-only bit, so the exact-
// mode assertion is Unix-only.
func TestWordlistLabels2_StorePermsForcedOnPreexistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits are not represented on Windows")
	}
	isolateLabelHome(t)
	p, err := LabelsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"version":1,"labels":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o644 {
		t.Fatalf("precondition: the store must start 0644, got %o", fi.Mode().Perm())
	}

	if err := SetRecoveryLabel("aabbccddeeff0011", RecoveryKeyLabel{Label: "k", Created: "2026-09-08", Device: "host"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("recovery-labels.json must be forced to 0600 after a save over a pre-existing file, got %o", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("the config dir must be forced to 0700, got %o", di.Mode().Perm())
	}
}

// TestWordlistLabels3_DeleteAndPruneOrphans (review wordlist-labels-3): a revoked
// key's label must not linger. DeleteRecoveryLabel removes exactly one record
// (missing/empty are no-ops), and LabelledRecoveryKeys prunes records whose entry ID
// is not in the current on-disk set — but NEVER when that set is empty (an ambiguous
// closed / not-yet-loaded vault).
func TestWordlistLabels3_DeleteAndPruneOrphans(t *testing.T) {
	isolateLabelHome(t)
	const idA = "aaaa1111bbbb2222"
	const idB = "cccc3333dddd4444"
	const idC = "eeee5555ffff6666"
	for _, id := range []string{idA, idB, idC} {
		if err := SetRecoveryLabel(id, RecoveryKeyLabel{Label: "L", Created: "2026-09-08", Device: "host"}); err != nil {
			t.Fatal(err)
		}
	}

	// DeleteRecoveryLabel removes exactly idB and nothing else.
	if err := DeleteRecoveryLabel(idB); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := GetRecoveryLabel(idB); err != nil || ok {
		t.Fatalf("the deleted record must be gone, got ok=%v err=%v", ok, err)
	}
	if _, ok, _ := GetRecoveryLabel(idA); !ok {
		t.Fatal("delete removed the wrong record (idA)")
	}
	if _, ok, _ := GetRecoveryLabel(idC); !ok {
		t.Fatal("delete removed the wrong record (idC)")
	}

	// Missing and empty deletes are no-ops.
	if err := DeleteRecoveryLabel(idB); err != nil {
		t.Fatalf("deleting an absent record must be a no-op, got %v", err)
	}
	if err := DeleteRecoveryLabel("   "); err != nil {
		t.Fatalf("deleting an empty ID must be a no-op, got %v", err)
	}

	// An EMPTY current set must not prune (ambiguous closed/not-loaded vault).
	if _, err := LabelledRecoveryKeys(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := GetRecoveryLabel(idA); !ok {
		t.Fatal("an empty entry set must not prune labels (idA vanished)")
	}
	if _, ok, _ := GetRecoveryLabel(idC); !ok {
		t.Fatal("an empty entry set must not prune labels (idC vanished)")
	}

	// A NON-EMPTY current set of {idA} prunes the orphan idC (its key was revoked)
	// and keeps idA.
	views, err := LabelledRecoveryKeys([]string{idA})
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].ID != idA || !views[0].HasRecord {
		t.Fatalf("current set {idA} must list idA with its record, got %+v", views)
	}
	if _, ok, _ := GetRecoveryLabel(idC); ok {
		t.Fatal("LabelledRecoveryKeys must prune the orphaned idC record (its key was revoked)")
	}
	if _, ok, _ := GetRecoveryLabel(idA); !ok {
		t.Fatal("the still-current idA record must survive pruning")
	}
}
