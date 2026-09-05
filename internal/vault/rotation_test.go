// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	rotOldPassword = "correct horse battery staple"
	rotNewPassword = "trombone marmalade seventeen dusk"
)

// chunkFileSet returns the set of chunk object paths under a vault's metadata
// dir, so a test can prove a config-only mutation rewrote NO chunk (design D3.4:
// "no chunk or manifest is rewritten").
func chunkFileSet(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	meta := metaRootOf(t, root)
	out := map[string]struct{}{}
	_ = filepath.WalkDir(filepath.Join(meta, "objects", "chunks"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".chunk") {
			out[p] = struct{}{}
		}
		return nil
	})
	return out
}

func hasRecoveryEntry(cfg VaultConfig) bool {
	for _, e := range cfg.WrapEntries {
		if e.Type == WrapTypeRecovery {
			return true
		}
	}
	return false
}

// R6 (design §3/§5, D3.4, P1-7, Cond 5): password change rewraps the same
// master||index under a new password — the OLD password stops opening on the A2
// client AND on the legacy top-level wrap, the NEW password opens (including a
// non-interactive/keychain-style unlock), a file put before the change still
// decrypts with no chunk rewritten, and FormatEpoch is incremented. The legacy
// wrap is kept current with the new password (Condition 4) so a 0.16 peer keeps
// unlocking.
func TestPasswordChange(t *testing.T) {
	isolateAppHome(t)
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, rotOldPassword)

	// Put a file BEFORE the change; capture the on-disk chunk set and epoch.
	v, err := Open(root, rotOldPassword)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "payload that must survive a password rotation unchanged"
	if _, err := v.PutReader(strings.NewReader(payload), "content/keep.txt", int64(len(payload)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	chunksBefore := chunkFileSet(t, root)
	if len(chunksBefore) == 0 {
		t.Fatal("precondition: the put must have written at least one chunk")
	}
	epochBefore := mustReadConfig(t, root).FormatEpoch

	if err := v.ChangePassword(rotNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	cfg := mustReadConfig(t, root)
	if cfg.FormatEpoch <= epochBefore {
		t.Fatalf("password change must bump FormatEpoch: %d -> %d", epochBefore, cfg.FormatEpoch)
	}

	// The NEW password opens, including a NON-interactive (keychain-style) unlock —
	// the path a keychain-backed re-open takes once the CLI refreshed the stored
	// secret (Condition 5). A rolled-back or stale config would be refused here.
	vNew, err := OpenWithOptions(root, rotNewPassword, OpenOptions{})
	if err != nil {
		t.Fatalf("the new password must open the vault (keychain-style non-interactive unlock): %v", err)
	}
	var buf bytes.Buffer
	if err := vNew.WriteFileTo("content/keep.txt", &buf); err != nil {
		t.Fatalf("a file put before the change must still decrypt after it: %v", err)
	}
	if buf.String() != payload {
		t.Fatalf("decrypted payload mismatch after rotation: %q", buf.String())
	}

	// No chunk was rewritten (only vault.json changed).
	chunksAfter := chunkFileSet(t, root)
	if len(chunksAfter) != len(chunksBefore) {
		t.Fatalf("password change must not rewrite chunks: %d before, %d after", len(chunksBefore), len(chunksAfter))
	}
	for p := range chunksBefore {
		if _, ok := chunksAfter[p]; !ok {
			t.Fatalf("chunk %s disappeared across a password change (unexpected rewrite)", p)
		}
	}

	// The OLD password stops opening on the A2 client.
	if _, err := Open(root, rotOldPassword); !errors.Is(err, errWrongSecret) {
		t.Fatalf("the old password must no longer open the vault, got %v", err)
	}
	// The OLD password stops opening the legacy top-level wrap directly (Condition
	// 4: the legacy fields are rewrapped to the new secret, not left stale).
	if _, err := unwrapKeys(rotOldPassword, cfg.KDF, cfg.WrapNonce, cfg.WrappedKeys); !errors.Is(err, errWrongSecret) {
		t.Fatalf("the old password must not unwrap the legacy top-level wrap after a change, got %v", err)
	}
	// The NEW password DOES open the legacy top-level wrap (a 0.16 peer keeps
	// unlocking through the grace release).
	if _, err := unwrapKeys(rotNewPassword, cfg.KDF, cfg.WrapNonce, cfg.WrappedKeys); err != nil {
		t.Fatalf("the legacy top-level wrap must open with the new password (0.16 interop, Condition 4): %v", err)
	}
}

// R7 (design §3, D3.3, P1-7, Cond 1/12): recovery generate/redeem/revoke.
// Generate requires a matching read-back before it writes anything; redeem sets a
// new password AND removes the redeemed entry (so the phrase alone no longer
// opens); revoke removes one entry; and a crash mid-transaction leaves a
// consistent tagged config (the rewriteConfig transaction is atomic).
func TestRecoveryGenerateRedeemRevoke(t *testing.T) {
	isolateAppHome(t)

	t.Run("generate requires the read-back", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, rotOldPassword)
		v, err := Open(root, rotOldPassword)
		if err != nil {
			t.Fatal(err)
		}
		phrase, commit, err := v.PrepareRecovery()
		if err != nil {
			t.Fatalf("PrepareRecovery: %v", err)
		}
		if phrase == "" {
			t.Fatal("PrepareRecovery must return a non-empty phrase")
		}
		// A WRONG read-back must not match and the caller must NOT commit.
		if RecoveryPhraseMatches(phrase, "not the phrase at all") {
			t.Fatal("a wrong read-back must not match the minted phrase")
		}
		if hasRecoveryEntry(mustReadConfig(t, root)) {
			t.Fatal("no recovery entry may be written before commit (a wrong read-back aborts)")
		}
		// A correct read-back (re-typed with different grouping/case) matches, then
		// commit writes exactly one recovery entry.
		readback := strings.ToLower(strings.ReplaceAll(phrase, "-", " "))
		if !RecoveryPhraseMatches(phrase, readback) {
			t.Fatal("a correct read-back (regrouped/lower-cased) must match")
		}
		if err := commit(); err != nil {
			t.Fatalf("commit after a matching read-back: %v", err)
		}
		cfg := mustReadConfig(t, root)
		if !hasRecoveryEntry(cfg) {
			t.Fatal("commit must write a recovery entry")
		}
		if cfg.ConfigTag == "" {
			t.Fatal("commit must leave the config tagged")
		}
		// The phrase opens via its recovery entry; the password still opens.
		if _, _, err := OpenWithRecovery(root, phrase, OpenOptions{}); err != nil {
			t.Fatalf("the minted phrase must open its recovery entry: %v", err)
		}
		if _, err := Open(root, rotOldPassword); err != nil {
			t.Fatalf("the password must still open after generating a recovery key: %v", err)
		}
	})

	t.Run("redeem sets a new password and removes the redeemed entry", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, rotOldPassword)
		v, err := Open(root, rotOldPassword)
		if err != nil {
			t.Fatal(err)
		}
		phrase, commit, err := v.PrepareRecovery()
		if err != nil {
			t.Fatal(err)
		}
		if err := commit(); err != nil {
			t.Fatal(err)
		}
		// Open with the recovery phrase; capture the redeemed entry ID.
		vr, entryID, err := OpenWithRecovery(root, phrase, OpenOptions{})
		if err != nil {
			t.Fatalf("OpenWithRecovery: %v", err)
		}
		if entryID == "" {
			t.Fatal("OpenWithRecovery must return the ID of the recovery entry that opened")
		}
		if err := vr.RedeemRecovery(entryID, rotNewPassword); err != nil {
			t.Fatalf("RedeemRecovery: %v", err)
		}
		cfg := mustReadConfig(t, root)
		for _, e := range cfg.WrapEntries {
			if e.ID == entryID {
				t.Fatal("the redeemed recovery entry must be ABSENT from WrapEntries after redeem")
			}
		}
		if hasRecoveryEntry(cfg) {
			t.Fatal("the sole recovery entry must be gone after redeem")
		}
		// The new password opens; the old password does not.
		if _, err := Open(root, rotNewPassword); err != nil {
			t.Fatalf("the redeem's new password must open the vault: %v", err)
		}
		if _, err := Open(root, rotOldPassword); !errors.Is(err, errWrongSecret) {
			t.Fatalf("the old password must not open after a redeem, got %v", err)
		}
		// The redeemed phrase alone no longer opens (the entry was removed) — a
		// leaked phrase cannot keep opening the vault (Condition 1).
		if _, _, err := OpenWithRecovery(root, phrase, OpenOptions{}); !errors.Is(err, errWrongSecret) {
			t.Fatalf("the redeemed phrase must no longer open the vault, got %v", err)
		}
	})

	t.Run("revoke removes one entry, leaving the others", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, rotOldPassword)
		v, err := Open(root, rotOldPassword)
		if err != nil {
			t.Fatal(err)
		}
		p1, c1, err := v.PrepareRecovery()
		if err != nil {
			t.Fatal(err)
		}
		if err := c1(); err != nil {
			t.Fatal(err)
		}
		p2, c2, err := v.PrepareRecovery()
		if err != nil {
			t.Fatal(err)
		}
		if err := c2(); err != nil {
			t.Fatal(err)
		}
		refs := v.WrapEntryRefs()
		var recIDs []string
		for _, r := range refs {
			if r.Type == WrapTypeRecovery {
				recIDs = append(recIDs, r.ID)
			}
		}
		if len(recIDs) != 2 {
			t.Fatalf("expected two recovery entries before revoke, got %d", len(recIDs))
		}
		// Revoke the FIRST recovery entry (insertion order: p1's).
		if err := v.RevokeRecovery(recIDs[0]); err != nil {
			t.Fatalf("RevokeRecovery: %v", err)
		}
		cfg := mustReadConfig(t, root)
		for _, e := range cfg.WrapEntries {
			if e.ID == recIDs[0] {
				t.Fatal("the revoked entry must be gone")
			}
		}
		// The revoked phrase no longer opens; the surviving one still does.
		if _, _, err := OpenWithRecovery(root, p1, OpenOptions{}); !errors.Is(err, errWrongSecret) {
			t.Fatalf("the revoked recovery phrase must no longer open, got %v", err)
		}
		if _, _, err := OpenWithRecovery(root, p2, OpenOptions{}); err != nil {
			t.Fatalf("a recovery phrase that was NOT revoked must still open: %v", err)
		}
		// Revoking an unknown ID is an error, and does not mutate the config.
		epoch := cfg.FormatEpoch
		if err := v.RevokeRecovery("deadbeefdeadbeef"); err == nil {
			t.Fatal("revoking an unknown entry ID must error")
		}
		if got := mustReadConfig(t, root).FormatEpoch; got != epoch {
			t.Fatalf("a failed revoke must not bump FormatEpoch: %d -> %d", epoch, got)
		}
	})

	t.Run("a crash mid-transaction leaves a consistent tagged config", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		createTestVault(t, root, rotOldPassword)
		v, err := Open(root, rotOldPassword)
		if err != nil {
			t.Fatal(err)
		}
		phrase, commit, err := v.PrepareRecovery()
		if err != nil {
			t.Fatal(err)
		}
		if err := commit(); err != nil {
			t.Fatal(err)
		}
		before := mustReadConfig(t, root)
		if before.ConfigTag == "" {
			t.Fatal("precondition: the committed config must be tagged")
		}
		// Inject a crash MID-transaction: the mutate makes a partial change (removes
		// the recovery entry) then fails. Because rewriteConfig only publishes
		// vault.json AFTER mutate returns nil (a single atomic rename), the on-disk
		// config must be byte-identical to before — recovery intact, same epoch/tag.
		injected := errors.New("injected crash mid-redeem")
		err = v.rewriteConfig(func(c *VaultConfig) error {
			c.WrapEntries = nil // partial, would-be-catastrophic mutation
			return injected
		})
		if !errors.Is(err, injected) {
			t.Fatalf("the injected error must propagate, got %v", err)
		}
		after := mustReadConfig(t, root)
		if after.FormatEpoch != before.FormatEpoch {
			t.Fatalf("an aborted transaction must not bump FormatEpoch: %d -> %d", before.FormatEpoch, after.FormatEpoch)
		}
		if after.ConfigTag != before.ConfigTag {
			t.Fatal("an aborted transaction must not change the ConfigTag (no torn write)")
		}
		// The config still opens by password AND by the still-present recovery phrase.
		if _, err := Open(root, rotOldPassword); err != nil {
			t.Fatalf("the vault must still open by password after an aborted transaction: %v", err)
		}
		if _, _, err := OpenWithRecovery(root, phrase, OpenOptions{}); err != nil {
			t.Fatalf("the recovery phrase must still open after an aborted transaction (nothing was removed): %v", err)
		}
	})
}

func mustReadConfig(t *testing.T, root string) VaultConfig {
	t.Helper()
	cfg, err := ReadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
