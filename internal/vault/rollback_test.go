// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readConfigBytes(t *testing.T, root string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(metaRootOf(t, root), ConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeConfigBytes(t *testing.T, root string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(metaRootOf(t, root), ConfigFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeConfigStruct(t *testing.T, root string, cfg VaultConfig) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeConfigBytes(t, root, data)
}

// R8 (design §5, D5.3, P1-6, Cond 7/8/9): freshness-anchor rollback handling.
// After a password change, replaying the pre-change vault.json is a rollback:
//   - ANY unlock hard-refuses with ErrConfigRolledBack (strict gate, Cond 9),
//     and the refusal message names --accept-rollback so a human can proceed;
//   - --accept-rollback opens AND clears the anchor so the restored config
//     re-TOFUs (Cond 8);
//   - the rotator's OWN anchor was advanced by rewriteConfig, so the replay is
//     caught on the very device that made the change (Cond 7);
//   - a FRESH device (no anchor) opens the same config without a warning and
//     anchors it (TOFU).
func TestFreshnessRollback(t *testing.T) {
	rotatorHome := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", rotatorHome)

	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "pw0")

	// Rotate once (epoch 1), snapshot that config, then rotate again (epoch 2). The
	// rotator's anchor high-water is now 2 (advanced by rewriteConfig, Condition 7).
	v, err := Open(root, "pw0")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ChangePassword("pw1"); err != nil {
		t.Fatal(err)
	}
	preChange := readConfigBytes(t, root) // epoch 1, opens with pw1
	v2, err := Open(root, "pw1")
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.ChangePassword("pw2"); err != nil {
		t.Fatal(err)
	}
	if mustReadConfig(t, root).FormatEpoch != 2 {
		t.Fatalf("precondition: after two changes FormatEpoch must be 2, got %d", mustReadConfig(t, root).FormatEpoch)
	}

	if anc, existed := readTestAnchor(t, v2); !existed || anc.FormatEpoch != 2 {
		t.Fatalf("precondition: the rotator's anchor high-water must be 2 (existed=%v, anchor=%+v)", existed, anc)
	}

	// Replay the pre-change (epoch 1) config over vault.json.
	writeConfigBytes(t, root, preChange)
	if mustReadConfig(t, root).FormatEpoch != 1 {
		t.Fatal("precondition: the replayed config must be at epoch 1")
	}

	// (Cond 9 / Cond 7) A non-interactive unlock on the rotator hard-refuses.
	if _, err := OpenWithOptions(root, "pw1", OpenOptions{}); !errors.Is(err, ErrConfigRolledBack) {
		t.Fatalf("a non-interactive open of a rolled-back config must be ErrConfigRolledBack, got %v", err)
	}

	// (strict gate) The refusal message names --accept-rollback so a present human
	// can make an informed choice; and the refusal does not lower the anchor.
	_, rerr := OpenWithOptions(root, "pw1", OpenOptions{})
	if !errors.Is(rerr, ErrConfigRolledBack) {
		t.Fatalf("a rolled-back open must refuse with ErrConfigRolledBack, got %v", rerr)
	}
	if !strings.Contains(rerr.Error(), "--accept-rollback") {
		t.Fatalf("the rollback refusal must tell the operator how to proceed (--accept-rollback), got %q", rerr.Error())
	}
	if anc, _ := readTestAnchor(t, v2); anc.FormatEpoch != 2 {
		t.Fatalf("a rollback refusal must NOT lower the anchor high-water: got %d", anc.FormatEpoch)
	}

	// (Cond 8) --accept-rollback opens AND clears the anchor (re-TOFU at epoch 1).
	_, err = OpenWithOptions(root, "pw1", OpenOptions{AcceptRollback: true})
	if err != nil {
		t.Fatalf("--accept-rollback must open the rolled-back config: %v", err)
	}
	if anc, existed := readTestAnchor(t, v2); !existed || anc.FormatEpoch != 1 {
		t.Fatalf("--accept-rollback must re-TOFU the anchor to the restored epoch 1 (existed=%v, anchor=%+v)", existed, anc)
	}
	// After acceptance the restored config opens cleanly, even non-interactively.
	if _, err := OpenWithOptions(root, "pw1", OpenOptions{}); err != nil {
		t.Fatalf("after --accept-rollback the restored config must open cleanly non-interactively: %v", err)
	}

	// (D5.4) A FRESH device (no anchor) TOFUs the same config: opens without a
	// warning and anchors it, even under a strict non-interactive unlock.
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	_, err = OpenWithOptions(root, "pw1", OpenOptions{})
	if err != nil {
		t.Fatalf("a fresh device must open a valid config via TOFU without a rollback refusal: %v", err)
	}
	if anc, existed := readTestAnchor(t, v2); !existed || anc.FormatEpoch != 1 {
		t.Fatalf("a fresh device must anchor the epoch it saw (existed=%v, anchor=%+v)", existed, anc)
	}
}

// R12 (design §3.6, D3.6, Cond 13): a concurrent divergent config — two devices
// mutating at once produce the SAME FormatEpoch with DIFFERENT ConfigTags. Open
// on a device that recorded one tag at that epoch, then served the other, refuses
// with ErrConfigDiverged rather than silently accepting whichever copy synced.
func TestConfigDivergence(t *testing.T) {
	isolateAppHome(t) // one app home == "device A"
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "base-pw")

	v, err := Open(root, "base-pw")
	if err != nil {
		t.Fatal(err)
	}
	keys := copyKeys(v.keys)

	// Device A rotates to epoch 1, tag T_A; A's anchor records (1, T_A).
	if err := v.ChangePassword("passA"); err != nil {
		t.Fatal(err)
	}
	cfgA := mustReadConfig(t, root)
	if cfgA.FormatEpoch != 1 {
		t.Fatalf("precondition: A's rotation must be epoch 1, got %d", cfgA.FormatEpoch)
	}
	if anc, existed := readTestAnchor(t, v); !existed || anc.FormatEpoch != 1 || anc.ConfigTag != cfgA.ConfigTag {
		t.Fatalf("precondition: A's anchor must record (1, T_A): existed=%v anchor=%+v tagA=%q", existed, anc, cfgA.ConfigTag)
	}

	// Craft device B's DIVERGENT config: a different password rewrap (fresh salts
	// => different tag) at the SAME epoch 1, with a VALID tag over the master key.
	cfgB := cfgA
	cfgB.WrapEntries = append([]WrapEntry(nil), cfgA.WrapEntries...)
	if err := applyPasswordRewrap(&cfgB, "passB", keys); err != nil {
		t.Fatal(err)
	}
	cfgB.FormatEpoch = 1 // tie with A
	cfgB.ConfigTag = ""
	tagB, err := computeConfigTag(keys.MasterKey, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	cfgB.ConfigTag = tagB
	if constantTimeStringEqual(tagB, cfgA.ConfigTag) {
		t.Fatal("precondition: B's config tag must differ from A's (a genuine divergence)")
	}
	writeConfigStruct(t, root, cfgB)

	// Device A opens the divergent copy: epoch tie (1 == 1), differing tag -> hard
	// ErrConfigDiverged (Condition 13), not silent acceptance.
	if _, err := Open(root, "passB"); !errors.Is(err, ErrConfigDiverged) {
		t.Fatalf("a concurrent divergent config at an equal FormatEpoch must be ErrConfigDiverged, got %v", err)
	}

	// Control: A's OWN config (the tag A anchored) still opens — no false positive.
	writeConfigStruct(t, root, cfgA)
	if _, err := Open(root, "passA"); err != nil {
		t.Fatalf("device A's own anchored config must still open (no false divergence): %v", err)
	}
}
