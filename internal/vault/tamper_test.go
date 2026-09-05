// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// putContentFile puts body at virtualPath and returns the on-disk path of its
// (single) chunk object.
func putContentFile(t *testing.T, v *Vault, virtualPath string, body []byte) string {
	t.Helper()
	if _, err := v.PutReader(bytes.NewReader(body), virtualPath, int64(len(body)), 0o600, time.Now()); err != nil {
		t.Fatalf("put %q: %v", virtualPath, err)
	}
	idx, err := v.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := idx.Files[virtualPath]
	if !ok {
		t.Fatalf("record for %q missing after put", virtualPath)
	}
	if len(rec.Chunks) == 0 {
		t.Fatalf("record for %q has no chunks", virtualPath)
	}
	return v.chunkPath(rec.Chunks[0].ID)
}

func readAll(t *testing.T, v *Vault, virtualPath string) ([]byte, error) {
	t.Helper()
	var buf bytes.Buffer
	err := v.WriteFileTo(virtualPath, &buf)
	return buf.Bytes(), err
}

func flipLastByte(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatalf("file %q is empty; nothing to flip", path)
	}
	data[len(data)-1] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// manifestPathFor returns the on-disk path of the manifest that stores
// virtualPath's record (a put also writes directory-record manifests, so the
// file's own manifest is addressed by its keyed id rather than by "the only one").
func manifestPathFor(t *testing.T, v *Vault, virtualPath string) string {
	t.Helper()
	cleaned, err := CleanVirtualPath(virtualPath)
	if err != nil {
		t.Fatalf("clean %q: %v", virtualPath, err)
	}
	p := v.manifestPath(v.manifestID(cleaned))
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("manifest for %q not on disk at %q: %v", virtualPath, p, err)
	}
	return p
}

// TestTamperChunkFlippedByteFailsRead (R2, closes P1-22).
// Defence under test: AES-256-GCM AEAD Open (GCM tag verification) in
// (*Vault).decodeChunk — flipping a ciphertext/tag byte makes authentication
// fail, so the read surfaces an error rather than returning corrupted bytes.
func TestTamperChunkFlippedByteFailsRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "pw")
	v, err := Open(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("chunk-A-content-"), 64)
	chunk := putContentFile(t, v, "content/a.txt", body)

	// Untampered control: the read succeeds and round-trips.
	if got, err := readAll(t, v, "content/a.txt"); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("control read failed: err=%v equal=%v", err, bytes.Equal(got, body))
	}

	flipLastByte(t, chunk)

	if _, err := readAll(t, v, "content/a.txt"); err == nil {
		t.Fatal("reading a chunk with a flipped byte must error, but it did not")
	}
}

// TestTamperChunkSubstitutionFailsRead (R2, closes P1-22).
// Defence under test: the per-chunk associated data (chunkAADPrefix+ref.ID)
// bound into the AEAD in (*Vault).decodeChunk — B's ciphertext cannot
// authenticate under A's chunk-id AAD, and the object-ID HMAC re-check backs it
// up — so substituting A's object with B's bytes is detected on read of A.
func TestTamperChunkSubstitutionFailsRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "pw")
	v, err := Open(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	bodyA := bytes.Repeat([]byte("AAAA-content-"), 64)
	bodyB := bytes.Repeat([]byte("BBBB-different-"), 64)
	chunkA := putContentFile(t, v, "content/a.txt", bodyA)
	chunkB := putContentFile(t, v, "content/b.txt", bodyB)
	if chunkA == chunkB {
		t.Fatal("A and B unexpectedly share a chunk object; pick distinct content")
	}

	// Untampered control: both read back correctly.
	if got, err := readAll(t, v, "content/a.txt"); err != nil || !bytes.Equal(got, bodyA) {
		t.Fatalf("control read of A failed: err=%v equal=%v", err, bytes.Equal(got, bodyA))
	}

	// Overwrite A's object with B's bytes.
	bBytes, err := os.ReadFile(chunkB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chunkA, bBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readAll(t, v, "content/a.txt"); err == nil {
		t.Fatal("reading A after its object was replaced with B's bytes must error, but it did not")
	}
	// B is untouched and still reads.
	if got, err := readAll(t, v, "content/b.txt"); err != nil || !bytes.Equal(got, bodyB) {
		t.Fatalf("control read of B after substitution failed: err=%v equal=%v", err, bytes.Equal(got, bodyB))
	}
}

// TestTamperManifestFlippedByteFailsLoad (R2, closes P1-22).
// Defence under test: AES-256-GCM AEAD Open over the manifest
// (manifestAADPrefix+id) in (*Vault).decryptManifest — a flipped byte fails
// authentication and loadManifestIndex surfaces the error, so an index reload
// from a tampered manifest fails instead of silently accepting it.
func TestTamperManifestFlippedByteFailsLoad(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "pw")
	v, err := Open(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("manifest-guard-"), 64)
	putContentFile(t, v, "content/a.txt", body)

	// Untampered control: a fresh load from disk succeeds.
	if err := v.ReloadIndex(); err != nil {
		t.Fatalf("control reload failed: %v", err)
	}

	manifest := manifestPathFor(t, v, "content/a.txt")
	flipLastByte(t, manifest)

	if err := v.ReloadIndex(); err == nil {
		t.Fatal("reloading the index from a manifest with a flipped byte must error, but it did not")
	}
}
