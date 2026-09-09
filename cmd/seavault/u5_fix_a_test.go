// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/bundlelaunch"
)

// TestSecondBundleLaunchRefusesSquatter (relaunch-lock-log-1, HIGH): a squatting
// listener that occupies the victim's bind port and answers /api/relaunch with an
// attacker URL — no MAC, off the machine — must be refused. The second launch
// verifies the responder MAC and the loopback/port constraints BEFORE opening
// anything, so it opens nothing, records the refusal to the 0600 sink, drops the
// stale/attacker lock, and returns the ordinary bind error.
func TestSecondBundleLaunchRefusesSquatter(t *testing.T) {
	appHome := setupBundleEnv(t)

	// The attacker: a loopback HTTP server that ignores the presented token and
	// returns an off-machine launch URL with NO responder MAC.
	atk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"launchURL":"http://attacker.example/phish?launch=EVIL"}`))
	}))
	defer atk.Close()
	_, portStr, err := net.SplitHostPort(atk.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	atkPort, _ := strconv.Atoi(portStr)
	victimAddr := atk.Listener.Addr().String() // the attacker holds this port

	// A stale lock names the attacker's port and some token.
	if err := os.MkdirAll(bundleDataDir(appHome), 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := bundleLockPath(appHome)
	if err := bundlelaunch.WriteLock(lockPath, bundlelaunch.Lock{Token: "attacker-controlled-token", Port: atkPort}); err != nil {
		t.Fatal(err)
	}

	// Capture whatever the launch would open (no --no-open, so a followed relaunch
	// WOULD open the attacker URL).
	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	var openedURL string
	openBrowserFn = func(u string) error { openedURL = u; return nil }

	err = cmdGUI([]string{"--addr", victimAddr, "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	if err == nil {
		t.Fatal("a bind conflict with a squatting responder must surface the bind error, not follow the attacker (relaunch-lock-log-1)")
	}
	if openedURL != "" {
		t.Fatalf("the launch must open NOTHING when the responder is not authenticated; opened=%q", openedURL)
	}
	// The refusal is logged to the 0600 sink (relaunch-silent-1 / I-M8).
	data, rerr := os.ReadFile(bundleLogPath(appHome))
	if rerr != nil {
		t.Fatalf("the bundle launch must record its exit reason to the file sink: %v", rerr)
	}
	if !strings.Contains(string(data), "relaunch refused") {
		t.Fatal("the file log must carry the relaunch-refused exit reason")
	}
	if strings.Contains(string(data), "attacker.example") || strings.Contains(string(data), "EVIL") {
		t.Fatal("the attacker URL must never be written anywhere")
	}
	// The stale/attacker lock is removed after the failed relaunch.
	if _, serr := os.Stat(lockPath); !os.IsNotExist(serr) {
		t.Fatalf("the stale lock must be removed after a failed relaunch; stat err = %v", serr)
	}
}

// TestBundleBindFailNoInstanceLogsReason (relaunch-silent-1, MEDIUM / I-M8): a
// bundle launch that cannot bind AND finds no lock (no running instance) must not
// die silently — the exit reason is written to the 0600 gui.log before the bind
// error is returned. Before the fix the file was never created on this path.
func TestBundleBindFailNoInstanceLogsReason(t *testing.T) {
	appHome := setupBundleEnv(t)

	// Occupy the target addr with a plain listener that is not our instance, and
	// leave NO lock file behind.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.Addr().String()

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	opened := 0
	openBrowserFn = func(string) error { opened++; return nil }

	err = cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	if err == nil {
		t.Fatal("a bundle launch on a busy port with no instance must return the bind error")
	}
	if opened != 0 {
		t.Fatalf("nothing must be opened; browser opened %d times", opened)
	}
	data, rerr := os.ReadFile(bundleLogPath(appHome))
	if rerr != nil {
		t.Fatalf("the bundle launch must write its exit reason to the file sink before returning (I-M8): %v", rerr)
	}
	if !strings.Contains(string(data), "relaunch refused") {
		t.Fatalf("the file log must carry the bind-failed exit reason; got:\n%s", string(data))
	}
}

// TestBundleSignalRemovesLock (relaunch-lock-log-1): a SIGINT/SIGTERM on a bundle
// launch removes the single-instance lock and requests shutdown, so a kill does
// not leave a stale lock behind. Driven through the injectable signal seam so the
// handler is exercised without a real process-wide signal.
func TestBundleSignalRemovesLock(t *testing.T) {
	appHome := setupBundleEnv(t)
	addr := "127.0.0.1:" + freeLoopbackPort(t)

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	openBrowserFn = func(string) error { return nil }

	// Drive the signal seam manually.
	sigCh := make(chan os.Signal, 1)
	origSig := bundleSignalSource
	t.Cleanup(func() { bundleSignalSource = origSig })
	bundleSignalSource = func() (<-chan os.Signal, func()) { return sigCh, func() {} }

	s := startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	})
	lockPath := bundleLockPath(appHome)
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("a bundle launch must claim the single-instance lock: %v", err)
	}

	// Deliver the signal: the handler removes the lock and requests shutdown.
	sigCh <- os.Interrupt
	select {
	case <-s.ShutdownNotify():
	case <-time.After(5 * time.Second):
		t.Fatal("the signal handler did not request shutdown")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(lockPath); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the signal handler must remove the single-instance lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestBundleLaunchAndGraceNotifications (friction A/C3): a darwin bundle launch
// posts a desktop notification at launch and, on a grace-exit with no page, a
// second one pointing at the log file — through an injectable seam so this Linux
// test asserts the calls and their text. Neither notification may EVER carry the
// launch URL or its secret.
func TestBundleLaunchAndGraceNotifications(t *testing.T) {
	setupBundleEnv(t)
	addr := "127.0.0.1:" + freeLoopbackPort(t)

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	openBrowserFn = func(string) error { return nil }

	var mu sync.Mutex
	var notes []string
	origNotify := notifyUser
	t.Cleanup(func() { notifyUser = origNotify })
	notifyUser = func(text string) {
		mu.Lock()
		notes = append(notes, text)
		mu.Unlock()
	}

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "300ms"})
	}()
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("bundle grace exit must return cleanly: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("bundle launch did not exit within the grace period")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(notes) == 0 {
		t.Fatal("a darwin bundle launch must post at least one notification (friction A/C3)")
	}
	var sawLaunch, sawGrace bool
	for _, n := range notes {
		if strings.Contains(n, "running in your browser") {
			sawLaunch = true
		}
		if strings.Contains(n, "could not open the browser") && strings.Contains(n, "log file") {
			sawGrace = true
		}
		// The notification must never carry the launch URL or its secret.
		if strings.Contains(n, "launch=") || strings.Contains(n, "://") {
			t.Fatalf("a notification must never carry the launch URL/secret; got %q", n)
		}
	}
	if !sawLaunch {
		t.Fatal("missing the launch notification (open-seavault-rclone is running in your browser)")
	}
	if !sawGrace {
		t.Fatal("missing the grace-exit notification pointing at the log file")
	}
}

// TestVersionIsLinkerOverridableVar (C/C4, C/C6): the build version is a
// package-level var (not a const), so the release/CI workflows set it at link
// time with -X main.version=<tag>. The dev default reports the v0.22 line so a
// binary built from this tree is never mistaken for the two-major-old 0.21, and
// both the `version` subcommand and the usage banner read the same var — proven
// by overriding it and seeing both surfaces change.
func TestVersionIsLinkerOverridableVar(t *testing.T) {
	// The dev default is in step with the phase (was 0.21.0, the friction gap).
	stdout, _, code := captureRun(t, "version")
	if code != 0 {
		t.Fatalf("version exit = %d, want 0", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "0.22") {
		t.Fatalf("dev version %q must report the current (0.22) line, not a stale major.minor", strings.TrimSpace(stdout))
	}

	// Simulate the linker override (-X main.version=...) and confirm BOTH the
	// subcommand and the usage banner read the var. This only compiles because
	// version is a var.
	orig := version
	t.Cleanup(func() { version = orig })
	version = "9.9.9-linker"

	stdout, _, code = captureRun(t, "version")
	if code != 0 || strings.TrimSpace(stdout) != "9.9.9-linker" {
		t.Fatalf("version subcommand = %q (code %d), want 9.9.9-linker", strings.TrimSpace(stdout), code)
	}
	if banner := usageText(); !strings.Contains(banner, "seavault 9.9.9-linker") {
		t.Fatalf("usage banner must read the injected version; got:\n%s", banner)
	}
}
