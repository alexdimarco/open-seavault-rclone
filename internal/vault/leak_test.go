// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNoPlaintextInVault (, closes) is the plaintext-leak walk: it puts
// a file whose body carries a unique high-entropy marker and whose virtual path
// carries a distinctive token, then walks EVERY file under the metadata dir and
// fails if the marker appears in any file body or the token in any file name.
// Chunk bodies are AES-256-GCM sealed and chunk/manifest file names are keyed
// HMACs, so neither the content nor the path may surface as cleartext on disk.
// Defence under test: encryption-at-rest of chunk bodies ((*Vault).storeChunk)
// and keyed-hash object/manifest naming.
func TestNoPlaintextInVault(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "correct horse battery staple"
	createTestVault(t, root, password)

	// Distinct, high-entropy needles that cannot appear by chance in ciphertext.
	rawMarker := make([]byte, 16)
	rawToken := make([]byte, 16)
	if _, err := rand.Read(rawMarker); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(rawToken); err != nil {
		t.Fatal(err)
	}
	marker := []byte("LEAKMARKER-" + hex.EncodeToString(rawMarker))
	pathToken := "PLAINTEXTPATHTOKEN-" + hex.EncodeToString(rawToken)
	virtualPath := "content/" + pathToken + ".txt"

	// A body large enough to span at least one full chunk, with the marker in it.
	body := bytes.Join([][]byte{
		bytes.Repeat([]byte("filler-"), 500),
		marker,
		bytes.Repeat([]byte("-trailer"), 500),
	}, nil)

	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(bytes.NewReader(body), virtualPath, int64(len(body)), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Sanity: the marker really is present in the plaintext we handed in, so a
	// green result means "encrypted", not "never stored".
	if !bytes.Contains(body, marker) {
		t.Fatal("test bug: marker not present in the plaintext body")
	}

	walked := 0
	sawChunk := false
	sawManifest := false
	err = filepath.WalkDir(v.MetaRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		walked++
		name := d.Name()
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".chunk") {
			sawChunk = true
		}
		if strings.Contains(lower, ".manifest") {
			sawManifest = true
		}
		// The distinctive path token must not surface in any file name or in the
		// on-disk directory path.
		rel, _ := filepath.Rel(v.MetaRoot, p)
		if strings.Contains(name, pathToken) || strings.Contains(rel, pathToken) {
			t.Fatalf("virtual-path token leaked into an on-disk name: %q", rel)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(data, marker) {
			t.Fatalf("plaintext marker leaked into metadata file %q", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if walked == 0 {
		t.Fatal("walk inspected zero files under the metadata dir")
	}
	if !sawChunk {
		t.Fatal("walk never saw a chunk object; the body was not stored where expected")
	}
	if !sawManifest {
		t.Fatal("walk never saw a manifest; the path was not stored where expected")
	}
}
