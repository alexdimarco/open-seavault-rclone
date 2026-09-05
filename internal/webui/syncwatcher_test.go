// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/vault"
)

// TestSyncWatcherPicksUpExternalChange verifies the GUI server's background
// watcher refreshes the open vault when another process (simulating the
// Nextcloud sync client) writes into .seavault underneath it.
func TestSyncWatcherPicksUpExternalChange(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir() + "/vault"
	const pw = "password"
	if err := vault.Create(root, pw, vault.DefaultChunkParams()); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("a"), "a.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.vault = v
	s.vaultPath = root
	s.mu.Unlock()

	stop := s.StartSyncWatcher(15 * time.Millisecond)
	defer stop()
	time.Sleep(60 * time.Millisecond) // let the watcher establish its baseline

	// Another process delivers a new file's manifest into the same vault.
	v2, err := vault.Open(root, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.PutReader(strings.NewReader("b"), "ext.txt", 1, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := v.FileInfo("ext.txt"); ok {
			return // watcher reloaded; the server's vault now sees the external write
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("sync watcher did not pick up the external change within the deadline")
}
