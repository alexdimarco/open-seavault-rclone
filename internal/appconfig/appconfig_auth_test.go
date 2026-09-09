// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package appconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAuthLimitsNormalizeDefaults (U4 §2.1, slice R2 part a): the auth.limits
// section defaults ON, only an explicit `enabled:false` disables, invalid or
// missing durations fall back to the defaults, DisabledSince is cleared while
// enabled, and the section survives a JSON round-trip. Every row asserts.
func TestAuthLimitsNormalizeDefaults(t *testing.T) {
	t.Run("absent_section_is_enabled_with_defaults", func(t *testing.T) {
		// A config JSON with no auth section at all must normalize to an enabled
		// limiter carrying the design defaults (a missing section is protected).
		var cfg Config
		if err := json.Unmarshal([]byte(`{"version":1,"gui":{"protocol":"http"}}`), &cfg); err != nil {
			t.Fatal(err)
		}
		got := Normalize(cfg).Auth.Limits
		if !got.IsEnabled() {
			t.Fatal("an absent auth.limits section must be ENABLED by default (I-R4)")
		}
		def := DefaultAuthLimits()
		if got.FailuresBeforeLock != def.FailuresBeforeLock || got.AccountFailuresBeforeLock != def.AccountFailuresBeforeLock {
			t.Fatalf("thresholds not defaulted: %+v", got)
		}
		if got.Window != def.Window || got.LockStart != def.LockStart || got.LockMax != def.LockMax || got.FailureDelay != def.FailureDelay {
			t.Fatalf("durations not defaulted: %+v", got)
		}
		if got.MaxKeys != def.MaxKeys {
			t.Fatalf("maxKeys not defaulted: %d", got.MaxKeys)
		}
	})

	t.Run("explicit_false_disables", func(t *testing.T) {
		var cfg Config
		if err := json.Unmarshal([]byte(`{"auth":{"limits":{"enabled":false,"disabledSince":"2026-01-02T03:04:05Z"}}}`), &cfg); err != nil {
			t.Fatal(err)
		}
		got := Normalize(cfg).Auth.Limits
		if got.IsEnabled() {
			t.Fatal("an explicit enabled:false must disable the limiter")
		}
		if strings.TrimSpace(got.DisabledSince) == "" {
			t.Fatal("DisabledSince must be preserved while disabled")
		}
	})

	t.Run("invalid_and_zero_durations_fall_back", func(t *testing.T) {
		cfg := Default()
		cfg.Auth.Limits.Window = "not-a-duration"
		cfg.Auth.Limits.LockStart = "0s" // a zero lock would defeat the limiter
		cfg.Auth.Limits.FailuresBeforeLock = -3
		cfg.Auth.Limits.MaxKeys = 0
		got := Normalize(cfg).Auth.Limits
		def := DefaultAuthLimits()
		if got.Window != def.Window {
			t.Fatalf("invalid window not defaulted: %q", got.Window)
		}
		if got.LockStart != def.LockStart {
			t.Fatalf("zero lockStart not defaulted: %q", got.LockStart)
		}
		if got.FailuresBeforeLock != def.FailuresBeforeLock {
			t.Fatalf("negative threshold not defaulted: %d", got.FailuresBeforeLock)
		}
		if got.MaxKeys != def.MaxKeys {
			t.Fatalf("zero maxKeys not defaulted: %d", got.MaxKeys)
		}
	})

	t.Run("zero_failure_delay_is_kept", func(t *testing.T) {
		cfg := Default()
		cfg.Auth.Limits.FailureDelay = "0s" // a zero throttle is a legitimate choice
		if got := Normalize(cfg).Auth.Limits.FailureDelay; got != "0s" {
			t.Fatalf("a zero FailureDelay must be kept, got %q", got)
		}
	})

	t.Run("disabledSince_cleared_while_enabled", func(t *testing.T) {
		cfg := Default() // enabled
		cfg.Auth.Limits.DisabledSince = "2026-01-02T03:04:05Z"
		if got := Normalize(cfg).Auth.Limits.DisabledSince; got != "" {
			t.Fatalf("DisabledSince must be cleared while enabled, got %q", got)
		}
	})

	t.Run("status_line", func(t *testing.T) {
		on := DefaultAuthLimits().StatusLine()
		if !strings.Contains(on, "on (") || !strings.Contains(on, "failures") {
			t.Fatalf("enabled StatusLine is wrong: %q", on)
		}
		// The Window must be surfaced so a hostile-but-normalized value is visible
		// in the readout (off-switch-config-2), never hidden behind "on". Use a
		// config whose Window is DISTINCT from LockStart/LockMax so the check is not
		// satisfied vacuously by another field that happens to share the value.
		cfg := Default()
		cfg.Auth.Limits.Window = "7m"
		cfg.Auth.Limits.LockStart = "30s"
		cfg.Auth.Limits.LockMax = "9m"
		distinct := Normalize(cfg).Auth.Limits
		if distinct.Window != "7m" {
			t.Fatalf("test premise wrong: normalized window %q want 7m", distinct.Window)
		}
		line7 := distinct.StatusLine()
		if !strings.Contains(line7, "7m") {
			t.Fatalf("enabled StatusLine must surface the Window (7m), distinct from the lock band: %q", line7)
		}
		disabled := AuthLimits{DisabledSince: "2026-01-02T03:04:05Z"}
		enabledFalse := false
		disabled.Enabled = &enabledFalse
		line := disabled.StatusLine()
		if !strings.Contains(line, "OFF since 2026-01-02T03:04:05Z") {
			t.Fatalf("disabled StatusLine must date the OFF state: %q", line)
		}
		if !strings.Contains(line, "--auth-limit on") && !strings.Contains(line, "auth.limits.enabled=true") {
			t.Fatalf("disabled StatusLine must name the re-enable remedy: %q", line)
		}
	})

	// off-switch-config-2: a degenerate-but-valid config value must not silently
	// neutralize the limiter. A one-nanosecond window (which would reset the streak
	// between any two real attempts, so nothing ever locks), a sub-second lock, and
	// a two-billion threshold or map bound are out of range and fall back to the
	// defaults; a LockMax below LockStart is raised to LockStart; and the normalized
	// Window is visible in the status line.
	t.Run("degenerate_but_valid_values_are_clamped", func(t *testing.T) {
		cfg := Default()
		cfg.Auth.Limits.Window = "1ns"                         // resets the streak instantly
		cfg.Auth.Limits.LockStart = "1ms"                      // sub-second lock
		cfg.Auth.Limits.LockMax = "500us"                      // below LockStart, and tiny
		cfg.Auth.Limits.FailuresBeforeLock = 2000000000        // effectively unlimited
		cfg.Auth.Limits.AccountFailuresBeforeLock = 2000000000 // effectively unlimited
		cfg.Auth.Limits.MaxKeys = 2000000000                   // effectively unbounded
		got := Normalize(cfg).Auth.Limits
		def := DefaultAuthLimits()
		if got.Window != def.Window {
			t.Fatalf("a 1ns window must be floored to the default, got %q", got.Window)
		}
		if got.LockStart != def.LockStart {
			t.Fatalf("a sub-second lockStart must be floored to the default, got %q", got.LockStart)
		}
		if got.FailuresBeforeLock != def.FailuresBeforeLock {
			t.Fatalf("a huge failuresBeforeLock must fall back to the default, got %d", got.FailuresBeforeLock)
		}
		if got.AccountFailuresBeforeLock != def.AccountFailuresBeforeLock {
			t.Fatalf("a huge accountFailuresBeforeLock must fall back to the default, got %d", got.AccountFailuresBeforeLock)
		}
		if got.MaxKeys != def.MaxKeys {
			t.Fatalf("a huge maxKeys must fall back to the default, got %d", got.MaxKeys)
		}
		// The floored window is now visible in the readout — no silent neutralization.
		if !strings.Contains(got.StatusLine(), got.Window) {
			t.Fatalf("StatusLine must surface the normalized Window: %q", got.StatusLine())
		}
	})

	t.Run("lockMax_below_lockStart_is_raised", func(t *testing.T) {
		cfg := Default()
		cfg.Auth.Limits.LockStart = "2m"
		cfg.Auth.Limits.LockMax = "30s" // below LockStart
		got := Normalize(cfg).Auth.Limits
		if got.LockStart != "2m" {
			t.Fatalf("a valid in-range lockStart must be preserved, got %q", got.LockStart)
		}
		if got.LockMax != "2m" {
			t.Fatalf("a lockMax below lockStart must be raised to lockStart, got %q", got.LockMax)
		}
	})
}
