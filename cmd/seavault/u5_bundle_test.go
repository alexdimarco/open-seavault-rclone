// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package main

import (
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/bundlelaunch"
)

// setupBundleEnv makes THIS Linux (or macOS) test host present as a macOS .app
// bundle launch: the injected OS is darwin and SEAVAULT_BUNDLE_LAUNCH=1, with a
// throwaway app-data home. It restores the OS seam after the test (LIFO cleanup
// runs it AFTER the captured server has been shut down, so no goroutine reads it
// concurrently). It returns the app-data home root.
func setupBundleEnv(t *testing.T) string {
	t.Helper()
	appHome := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", appHome)
	t.Setenv("SEAVAULT_BUNDLE_LAUNCH", "1")
	orig := bundleOSName
	bundleOSName = "darwin"
	t.Cleanup(func() { bundleOSName = orig })
	return appHome
}

func bundleDataDir(appHome string) string { return filepath.Join(appHome, "data") }
func bundleLogPath(appHome string) string {
	return filepath.Join(bundleDataDir(appHome), "logs", "gui.log")
}
func bundleLockPath(appHome string) string {
	return filepath.Join(bundleDataDir(appHome), "gui.lock")
}

// TestFinderLaunchRoutesToGUI (M1, §2.1): run() defaults to the gui command on a
// darwin bundle launch with no real arguments (or only the legacy -psn_ arg), and
// does NOT when a real argument is present. The gui dispatch is a seam so the
// routing is asserted without starting a server.
func TestFinderLaunchRoutesToGUI(t *testing.T) {
	origGOOS := bundleOSName
	origDispatch := runFinderLaunchGUI
	t.Cleanup(func() { bundleOSName = origGOOS; runFinderLaunchGUI = origDispatch })

	called := 0
	runFinderLaunchGUI = func() int { called++; return 77 }

	bundleOSName = "darwin"
	t.Setenv("SEAVAULT_BUNDLE_LAUNCH", "1")

	if code := run(nil); code != 77 || called != 1 {
		t.Fatalf("bundle no-args: code=%d called=%d, want code=77 called=1 (routed to gui)", code, called)
	}

	called = 0
	if code := run([]string{"-psn_0_123456"}); code != 77 || called != 1 {
		t.Fatalf("bundle only -psn_ arg: code=%d called=%d, want code=77 called=1", code, called)
	}

	called = 0
	if code := run([]string{"version"}); called != 0 || code != 0 {
		t.Fatalf("a real arg must run the command, not route to gui: code=%d called=%d, want code=0 called=0", code, called)
	}
}

// TestTerminalNoArgsPrintsUsage (I-M3, §2.1): a Terminal `seavault` with no
// arguments prints usage and exits 2, unchanged by the Finder-launch default —
// even on darwin, because without the bundle env or a /Contents/MacOS/ executable
// path it is not a bundle launch.
func TestTerminalNoArgsPrintsUsage(t *testing.T) {
	origGOOS := bundleOSName
	origDispatch := runFinderLaunchGUI
	t.Cleanup(func() { bundleOSName = origGOOS; runFinderLaunchGUI = origDispatch })
	called := 0
	runFinderLaunchGUI = func() int { called++; return 77 }

	// darwin, but a Terminal invocation (no bundle env, plain executable path).
	bundleOSName = "darwin"
	t.Setenv("SEAVAULT_BUNDLE_LAUNCH", "")
	if code := run(nil); code != 2 || called != 0 {
		t.Fatalf("darwin Terminal no-args: code=%d called=%d, want code=2 called=0 (usage, I-M3)", code, called)
	}

	// The non-darwin default host: no-args prints usage too.
	bundleOSName = origGOOS
	if code := run(nil); code != 2 || called != 0 {
		t.Fatalf("Terminal no-args: code=%d called=%d, want code=2 called=0", code, called)
	}
}

// TestBundleGraceExitWritesFileLog (M2, §2.2, I-M6, I-M8): a bundle launch whose
// browser page never connects exits within the grace period, and the 0600 FILE
// logs/gui.log carries the launch URL and the grace-exit line (stdout is not the
// proof, C7).
func TestBundleGraceExitWritesFileLog(t *testing.T) {
	appHome := setupBundleEnv(t)
	addr := "127.0.0.1:" + freeLoopbackPort(t)

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	openBrowserFn = func(string) error { return nil }

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
		t.Fatal("bundle launch did not exit within the grace period (I-M6)")
	}

	logPath := bundleLogPath(appHome)
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("a bundle launch must write the file log sink: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("gui.log perm = %o, want 600 (I-M8)", perm)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// Assert on markers only — never echo the file content or the launch secret.
	if !strings.Contains(content, "launch: ") {
		t.Fatal("the file log must carry the launch line")
	}
	if !strings.Contains(content, "/?launch=") {
		t.Fatal("the launch line must carry the launch URL (the sanctioned 0600 sink)")
	}
	if !strings.Contains(content, "grace-exit:") {
		t.Fatal("the file log must carry the grace-exit line (I-M6)")
	}
}

// TestBundleConnectedPageKeepsAlive (M2, §2.2): a bundle launch whose page DOES
// connect is not killed by the grace timer.
func TestBundleConnectedPageKeepsAlive(t *testing.T) {
	appHome := setupBundleEnv(t)
	addr := "127.0.0.1:" + freeLoopbackPort(t)

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	openBrowserFn = func(string) error { return nil }

	s := startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "2s"})
	})

	// A real page connects: redeem the launch link, then send a heartbeat so the
	// server records BrowserSeen.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	if resp, err := client.Get(s.LaunchURL("http://" + addr)); err == nil {
		resp.Body.Close()
	} else {
		t.Fatalf("redeem launch: %v", err)
	}
	if resp, err := client.Get("http://" + addr + "/api/browser-heartbeat"); err == nil {
		resp.Body.Close()
	} else {
		t.Fatalf("heartbeat: %v", err)
	}
	if !s.BrowserSeen() {
		t.Fatal("the server did not record the connected page")
	}

	// Wait well past the grace period; the server must still be serving.
	time.Sleep(2500 * time.Millisecond)
	resp, err := client.Get("http://" + addr + "/api/browser-heartbeat")
	if err != nil {
		t.Fatalf("a connected-page bundle launch must stay alive past the grace period: %v", err)
	}
	resp.Body.Close()

	// The grace-exit line must NOT have been written.
	if data, err := os.ReadFile(bundleLogPath(appHome)); err == nil {
		if strings.Contains(string(data), "grace-exit:") {
			t.Fatal("a connected page must not trigger the grace exit")
		}
	}
}

// TestTerminalGUIWritesNoFileLog (M2, I-M8): a Terminal gui writes no file log
// sink and claims no single-instance lock.
func TestTerminalGUIWritesNoFileLog(t *testing.T) {
	appHome := t.TempDir()
	t.Setenv("SEAVAULT_APP_HOME", appHome)
	t.Setenv("SEAVAULT_BUNDLE_LAUNCH", "")
	// bundleOSName stays the real host OS; on macOS CI this test binary is not
	// under /Contents/MacOS/, so it is still a Terminal (non-bundle) launch.
	addr := "127.0.0.1:" + freeLoopbackPort(t)
	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	openBrowserFn = func(string) error { return nil }

	_ = startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false"})
	})

	if _, err := os.Stat(bundleLogPath(appHome)); !os.IsNotExist(err) {
		t.Fatalf("a Terminal gui must write no file log sink; stat err = %v", err)
	}
	if _, err := os.Stat(bundleLockPath(appHome)); !os.IsNotExist(err) {
		t.Fatalf("a Terminal gui must claim no single-instance lock; stat err = %v", err)
	}
}

// TestBundleBindsBeforeBrowserOpen (M10, §2.2(c)): the port is bound before the
// browser-open seam fires.
func TestBundleBindsBeforeBrowserOpen(t *testing.T) {
	setupBundleEnv(t)
	addr := "127.0.0.1:" + freeLoopbackPort(t)

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	boundAtOpen := make(chan bool, 1)
	openBrowserFn = func(string) error {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		ok := err == nil
		if c != nil {
			c.Close()
		}
		select {
		case boundAtOpen <- ok:
		default:
		}
		return nil
	}

	// No --no-open, so the browser-open seam fires during startup.
	_ = startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{"--addr", addr, "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	})

	select {
	case ok := <-boundAtOpen:
		if !ok {
			t.Fatal("the browser-open seam fired before the port was bound; bind must precede open (C10)")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the browser-open seam never fired")
	}
}

// TestSecondBundleLaunchReopensRunningInstance (M10, §2.2(d), I-M7): with an
// instance serving, a second bundle launch re-opens the running instance's
// current link (captured via the browser seam) and exits without binding a
// second server.
func TestSecondBundleLaunchReopensRunningInstance(t *testing.T) {
	setupBundleEnv(t)
	addr := "127.0.0.1:" + freeLoopbackPort(t)

	// Instance 1 serves (its own browser open suppressed with --no-open).
	s1 := startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	})
	want := s1.LaunchURL("http://" + addr)

	// Instance 2 captures what it opens.
	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	opened := make(chan string, 1)
	openBrowserFn = func(u string) error {
		select {
		case opened <- u:
		default:
		}
		return nil
	}

	// Instance 2 binds the SAME addr: bind fails, so it asks instance 1 for its
	// link and opens THAT, returning nil without starting a second server.
	if err := cmdGUI([]string{"--addr", addr, "--exit-on-browser-close=false", "--bundle-grace", "30s"}); err != nil {
		t.Fatalf("second bundle launch must exit cleanly after relaunch: %v", err)
	}
	select {
	case got := <-opened:
		if got != want {
			t.Fatalf("second launch opened the wrong link (match=%v)", got == want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second launch never opened the running instance's link")
	}
}

// TestStaleLockIgnoredOnFreshBind (M10, §2.2(d)): a fresh bundle launch ignores a
// pre-existing stale lock (no live listener) and claims its own.
func TestStaleLockIgnoredOnFreshBind(t *testing.T) {
	appHome := setupBundleEnv(t)

	// A stale lock pointing at a dead port.
	deadPort, _ := strconv.Atoi(freeLoopbackPort(t))
	if err := os.MkdirAll(bundleDataDir(appHome), 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := bundleLockPath(appHome)
	if err := bundlelaunch.WriteLock(lockPath, bundlelaunch.Lock{Token: "stale-token", Port: deadPort}); err != nil {
		t.Fatal(err)
	}

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	openBrowserFn = func(string) error { return nil }

	// A fresh bundle launch on a DIFFERENT free addr binds normally and serves.
	addr := "127.0.0.1:" + freeLoopbackPort(t)
	s := startGUIAndCaptureServer(t, func() error {
		return cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	})
	if s == nil {
		t.Fatal("a bundle launch must serve despite a stale lock")
	}
	lk, err := bundlelaunch.ReadLock(lockPath)
	if err != nil {
		t.Fatalf("the new instance must have written its own lock: %v", err)
	}
	if lk.Token == "stale-token" {
		t.Fatal("the stale lock was not replaced by the live instance's lock")
	}
}

// TestBindConflictWithStaleLockErrors (M10, §2.2(d), I-M7): when the bind fails
// and the lock is stale (its port answers no relaunch), the ordinary bind error
// surfaces and no browser link is opened — a stale lock is never followed.
func TestBindConflictWithStaleLockErrors(t *testing.T) {
	appHome := setupBundleEnv(t)

	// Occupy the target addr with a plain listener that is NOT our instance.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.Addr().String()

	// A stale lock pointing at a dead port (answers no /api/relaunch).
	deadPort, _ := strconv.Atoi(freeLoopbackPort(t))
	if err := os.MkdirAll(bundleDataDir(appHome), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := bundlelaunch.WriteLock(bundleLockPath(appHome), bundlelaunch.Lock{Token: "stale-token", Port: deadPort}); err != nil {
		t.Fatal(err)
	}

	origOpen := openBrowserFn
	t.Cleanup(func() { openBrowserFn = origOpen })
	opened := 0
	openBrowserFn = func(string) error { opened++; return nil }

	err = cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false", "--bundle-grace", "30s"})
	if err == nil {
		t.Fatal("a bind conflict with a stale lock must surface the bind error, not exit nil (I-M7)")
	}
	if opened != 0 {
		t.Fatalf("a stale lock must not trigger a relaunch; browser opened %d times", opened)
	}
}

// TestTerminalGUIBusyPortStillErrors (M10, I-M7): a Terminal gui on a busy port
// still errors as before.
func TestTerminalGUIBusyPortStillErrors(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	t.Setenv("SEAVAULT_BUNDLE_LAUNCH", "")
	// bundleOSName stays the real host OS (not forced to darwin): a Terminal launch.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.Addr().String()

	if err := cmdGUI([]string{"--addr", addr, "--no-open", "--exit-on-browser-close=false"}); err == nil {
		t.Fatal("Terminal gui on a busy port must error")
	}
}
