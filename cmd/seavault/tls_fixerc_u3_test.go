// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/setup"
)

// --- A2-c1: the stdin prompter distinguishes a closed stdin --------------

// TestStdinPrompterPropagatesEOF (A2-c1): on a closed/exhausted stdin every prompt
// method surfaces io.EOF instead of silently accepting the default, so a caller can
// abort rather than loop forever. A final line WITHOUT a trailing newline is still
// delivered.
func TestStdinPrompterPropagatesEOF(t *testing.T) {
	if _, err := newStdinPrompterFrom(strings.NewReader("")).Select("t", []setup.Option{{Label: "a"}, {Label: "b"}}, 0); !errors.Is(err, io.EOF) {
		t.Fatalf("Select on closed stdin must return io.EOF, got %v", err)
	}
	if _, err := newStdinPrompterFrom(strings.NewReader("")).Confirm("q", true); !errors.Is(err, io.EOF) {
		t.Fatalf("Confirm on closed stdin must return io.EOF, got %v", err)
	}
	if _, err := newStdinPrompterFrom(strings.NewReader("")).Text("l", "d"); !errors.Is(err, io.EOF) {
		t.Fatalf("Text on closed stdin must return io.EOF, got %v", err)
	}
	got, err := newStdinPrompterFrom(strings.NewReader("keepme")).Text("l", "d")
	if err != nil || got != "keepme" {
		t.Fatalf("Text must deliver a final unterminated line: got %q err %v", got, err)
	}
}

// TestTLSWizardAbortsOnClosedStdinNoLivelock (A2-c1 / TLS-4): after "Other devices"
// is chosen, an exhausted stdin makes the route menu ABORT with a clear message
// rather than livelock reprinting. The 5s guard fails the test if it ever spins.
func TestTLSWizardAbortsOnClosedStdinNoLivelock(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	pr := newStdinPrompterFrom(strings.NewReader("2\n")) // pick "Other devices", then EOF
	deps := setup.TLSDeps{
		LookPath:            func(string) (string, error) { return "", errors.New("not found") },
		Run:                 func(string, ...string) ([]byte, error) { return nil, errors.New("must not run") },
		ReadTailscaleStatus: func() (setup.TailscaleStatus, error) { return setup.TailscaleStatus{}, errors.New("no tailscale") },
	}
	done := make(chan error, 1)
	go func() { done <- setup.RunTLSWizard(pr, deps) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the wizard must abort on a closed stdin, got nil")
		}
		if !errors.Is(err, io.EOF) && !strings.Contains(strings.ToLower(err.Error()), "input") && !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("the abort error must name the closed-stdin cause, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wizard livelocked on a closed stdin (no abort within 5s)")
	}
}

// --- A3-c4: plaintext bind refusal leads with the TLS route --------------

// TestBindRefusalLeadsWithTLSRoute (A3-c4): the refusal for a plaintext non-loopback
// bind leads with the TLS route (`seavault tls setup` / --tls-cert/--tls-key) and
// mentions --insecure-bind only afterwards, as a last resort.
func TestBindRefusalLeadsWithTLSRoute(t *testing.T) {
	rows := []string{"192.168.1.5:8787", "0.0.0.0:8787", ":8787"}
	if len(rows) == 0 {
		t.Fatal("bind-refusal table is empty")
	}
	for _, addr := range rows {
		t.Run(addr, func(t *testing.T) {
			_, err := ensureLoopbackBind(addr, false, false, false)
			if err == nil {
				t.Fatalf("a plaintext non-loopback bind %q must be refused", addr)
			}
			msg := err.Error()
			tlsIdx := strings.Index(msg, "tls setup")
			insIdx := strings.Index(msg, "--insecure-bind")
			if tlsIdx < 0 {
				t.Fatalf("the refusal must name the TLS route (`seavault tls setup`): %q", msg)
			}
			if insIdx < 0 {
				t.Fatalf("the refusal must still name --insecure-bind: %q", msg)
			}
			if tlsIdx > insIdx {
				t.Fatalf("the refusal must LEAD with the TLS route, not --insecure-bind: %q", msg)
			}
		})
	}
}
