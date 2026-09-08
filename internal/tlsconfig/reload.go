// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package tlsconfig

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
)

// reloadTOCTOUHook, when non-nil, is invoked inside reload() AFTER the validate
// read and BEFORE the load read. It is a fault-injection seam for the
// reload-races-3 regression only: a test swaps the on-disk pair here to prove
// the C6 downgrade gate is evaluated on the bytes actually LOADED and served,
// not on the earlier validate read. Production leaves it nil (no behaviour).
var reloadTOCTOUHook func()

// DefaultPollInterval is how often the reloader stats the pair. It is portable
// (Windows has no SIGHUP) and injectable for tests via ReloaderOptions.Interval.
const DefaultPollInterval = 30 * time.Second

// heartbeatInterval is how often serving.json is rewritten and the expiry
// warning re-emitted even when the pair has not changed, so a silently disabled
// renewal timer becomes visible at runtime (C11).
const heartbeatInterval = 24 * time.Hour

// staleAfter is how long serving.json may go un-updated before `tls status`
// reports "no running listener seen".
const staleAfter = 2 * 24 * time.Hour

// servingFileName is the runtime heartbeat file under <appdata>/tls/.
const servingFileName = "serving.json"

// Serving is the on-disk shape of serving.json: what the RUNNING listener is
// serving right now. It holds only non-secret metadata.
type Serving struct {
	Fingerprint string    `json:"fingerprint"`
	Names       []string  `json:"names"`
	NotAfter    time.Time `json:"notAfter"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ReloaderOptions configure a Reloader. Zero values fall back to production
// defaults; tests inject a short Interval, a fixed Now, a temp ServingDir, and a
// capturing Logf.
type ReloaderOptions struct {
	Interval   time.Duration        // default DefaultPollInterval
	ServingDir string               // default <ConfigDir>/tls
	Now        func() time.Time     // default time.Now
	Logf       func(string, ...any) // default: discard (caller wires logging)
}

// Reloader hot-reloads the serving pair behind a live listener and maintains
// serving.json. It stats both files every Interval; on an mtime change it runs
// Validate and swaps the pair in only if it validates AND does not downgrade a
// still-valid serving leaf to an expired/not-yet-valid candidate (C6). A failed
// reload keeps the current pair and logs exactly one warning (the new mtime is
// recorded regardless, so a bad file is not re-reported every tick).
type Reloader struct {
	holder      *certHolder
	certPath    string
	keyPath     string
	interval    time.Duration
	servingPath string
	now         func() time.Time
	logf        func(string, ...any)

	mu               sync.Mutex
	lastCertMod      time.Time
	lastKeyMod       time.Time
	lastServingWrite time.Time
}

// Reloader builds a Reloader bound to the same certHolder the Resolved.TLS
// config serves from, so a swap is visible to the live listener. It returns nil
// when the resolved source is none (nothing to reload).
func (r *Resolved) Reloader(opts ReloaderOptions) *Reloader {
	if r == nil || r.holder == nil {
		return nil
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	dir := opts.ServingDir
	if dir == "" {
		if d, err := appdir.EnsureConfigDir("tls"); err == nil {
			dir = d
		}
	}
	return &Reloader{
		holder:      r.holder,
		certPath:    r.CertPath,
		keyPath:     r.KeyPath,
		interval:    interval,
		servingPath: filepath.Join(dir, servingFileName),
		now:         now,
		logf:        logf,
	}
}

// Run blocks until ctx is cancelled, polling every interval. It records the
// current mtimes and writes the initial serving.json before the first tick, so
// serving.json exists as soon as the listener is up.
func (rl *Reloader) Run(ctx context.Context) {
	rl.recordMods()
	rl.onServing(rl.holder.leaf())

	t := time.NewTicker(rl.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rl.tick()
		}
	}
}

// tick performs one poll cycle: detect an mtime change and, on change, attempt a
// validated, non-downgrading swap; otherwise emit the daily heartbeat.
func (rl *Reloader) tick() {
	cm, km, ok := statMods(rl.certPath, rl.keyPath)
	rl.mu.Lock()
	changed := ok && (!cm.Equal(rl.lastCertMod) || !km.Equal(rl.lastKeyMod))
	if ok {
		// Record the new mtimes up front so a rejected pair is not re-evaluated
		// (and re-warned) on every subsequent tick — exactly one warning.
		rl.lastCertMod, rl.lastKeyMod = cm, km
	}
	lastServing := rl.lastServingWrite
	rl.mu.Unlock()

	if changed {
		rl.reload()
		return
	}
	if rl.now().Sub(lastServing) >= heartbeatInterval {
		rl.onServing(rl.holder.leaf())
	}
}

// reload validates the changed pair and swaps it in unless it is invalid or a
// downgrade. On any refusal it keeps the current pair and logs one warning. On a
// successful swap it surfaces the validated non-temporal warnings (reload-races-2).
func (rl *Reloader) reload() {
	now := rl.now()
	info, err := validateAt(rl.certPath, rl.keyPath, now)
	if err != nil {
		rl.logf("tls reload: keeping the current certificate; the new pair was rejected: %v", err)
		return
	}
	if reloadTOCTOUHook != nil {
		reloadTOCTOUHook()
	}
	cert, lerr := loadCertificate(rl.certPath, rl.keyPath)
	if lerr != nil {
		rl.logf("tls reload: keeping the current certificate; the new pair failed to load: %v", lerr)
		return
	}
	// No live downgrade (C6), evaluated on the leaf we are ABOUT TO SERVE
	// (cert.Leaf) rather than on the separately-read validateAt bytes: a file
	// swapped between the validate read and the load read cannot smuggle an
	// out-of-window leaf past the gate (reload-races-3). loadCertificate's
	// X509KeyPair also re-confirms the key matches these exact bytes, so the
	// served pair is always internally consistent.
	serving := rl.holder.leaf()
	if candidateOutOfWindow(cert.Leaf, now) && serving != nil && withinWindow(serving, now) {
		rl.logf("tls reload: keeping the current certificate; the new leaf is expired or not yet valid while the serving leaf is still valid")
		return
	}
	rl.holder.store(cert)
	rl.onServing(cert.Leaf)
	// Surface the validated warnings on a successful swap (reload-races-2):
	// onServing already logs the serving leaf's expiry/days-left line, so drop
	// the temporal warnings here (de-duplicated against that line) and emit the
	// rest — notably a chmod-600 notice when a renewal landed a group/world-
	// readable key (I-T2), which would otherwise be dropped on a hot reload.
	for _, w := range info.Warnings {
		if isExpiryWarning(w) {
			continue
		}
		rl.logf("tls reload: %s", w)
	}
}

// candidateOutOfWindow reports whether leaf is expired or not yet valid at now.
// A nil leaf is treated as out of window (there is nothing valid to serve).
func candidateOutOfWindow(leaf *x509.Certificate, now time.Time) bool {
	return leaf == nil || now.After(leaf.NotAfter) || now.Before(leaf.NotBefore)
}

// isExpiryWarning reports whether w is one of Validate's temporal warnings
// (expired / not yet valid / expiring soon) — they all begin "certificate ".
// onServing logs the serving leaf's days-left line, so reload() skips these to
// avoid a duplicate while still surfacing non-temporal warnings (e.g. the
// chmod-600 key-permission notice, which begins "key file ").
func isExpiryWarning(w string) bool {
	return strings.HasPrefix(w, "certificate ")
}

// onServing writes serving.json for the given leaf and logs the expiry warning
// when the leaf has fewer than the renew window left. Called on initial load,
// on each successful reload, and on the daily heartbeat.
func (rl *Reloader) onServing(leaf *x509.Certificate) {
	if leaf == nil {
		return
	}
	now := rl.now()
	if err := rl.writeServing(leaf, now); err != nil {
		rl.logf("tls: could not update %s: %v", rl.servingPath, err)
	}
	rl.mu.Lock()
	rl.lastServingWrite = now
	rl.mu.Unlock()

	if leaf.NotAfter.Sub(now) < renewWindow {
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		rl.logf("tls: the serving certificate has %d days left (renew soon; the app reloads a renewed pair within %s)", days, rl.interval)
	}
}

// writeServing atomically writes serving.json with the leaf fingerprint, names,
// notAfter, and updatedAt. No key material is involved.
func (rl *Reloader) writeServing(leaf *x509.Certificate, now time.Time) error {
	sum := sha256.Sum256(leaf.Raw)
	s := Serving{
		Fingerprint: hex.EncodeToString(sum[:]),
		Names:       leafNames(leaf),
		NotAfter:    leaf.NotAfter,
		UpdatedAt:   now,
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rl.servingPath), 0o700); err != nil {
		return err
	}
	return atomicWrite(rl.servingPath, append(data, '\n'), 0o600)
}

// recordMods seeds the last-seen mtimes without triggering a reload.
func (rl *Reloader) recordMods() {
	cm, km, ok := statMods(rl.certPath, rl.keyPath)
	if !ok {
		return
	}
	rl.mu.Lock()
	rl.lastCertMod, rl.lastKeyMod = cm, km
	rl.mu.Unlock()
}

// withinWindow reports whether now is inside the leaf's validity window.
func withinWindow(leaf *x509.Certificate, now time.Time) bool {
	return !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter)
}

// statMods stats both files and returns their mtimes; ok is false if either
// cannot be stat'd (a mid-renewal partial write), so the tick makes no decision.
func statMods(certPath, keyPath string) (certMod, keyMod time.Time, ok bool) {
	cs, err := os.Stat(certPath)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	ks, err := os.Stat(keyPath)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	return cs.ModTime(), ks.ModTime(), true
}

// RunningStatus is what `tls status` reports about the RUNNING listener, read
// from serving.json. Present is false when no serving.json exists; Stale is true
// when it has not been updated within staleAfter (a listener that stopped).
type RunningStatus struct {
	Present     bool
	Stale       bool
	DaysLeft    int
	Names       []string
	Fingerprint string
	NotAfter    time.Time
	UpdatedAt   time.Time
}

// ReadServing reads serving.json from dir. A missing file returns os.ErrNotExist.
func ReadServing(dir string) (Serving, error) {
	data, err := os.ReadFile(filepath.Join(dir, servingFileName))
	if err != nil {
		return Serving{}, err
	}
	var s Serving
	if err := json.Unmarshal(data, &s); err != nil {
		return Serving{}, err
	}
	return s, nil
}

// RunningListenerStatus reads serving.json from dir and reports what the running
// listener serves relative to now: days left on the serving leaf and whether the
// heartbeat is stale (no running listener seen recently).
func RunningListenerStatus(dir string, now time.Time) RunningStatus {
	s, err := ReadServing(dir)
	if err != nil {
		return RunningStatus{Present: false}
	}
	return RunningStatus{
		Present:     true,
		Stale:       now.Sub(s.UpdatedAt) > staleAfter,
		DaysLeft:    int(s.NotAfter.Sub(now).Hours() / 24),
		Names:       s.Names,
		Fingerprint: s.Fingerprint,
		NotAfter:    s.NotAfter,
		UpdatedAt:   s.UpdatedAt,
	}
}

// ServingDir returns the default directory holding serving.json (<ConfigDir>/tls),
// creating it if needed. `tls status` uses it to locate the heartbeat file.
func ServingDir() (string, error) {
	return appdir.EnsureConfigDir("tls")
}

// atomicWrite writes data to path through a temp file + rename at the given perm.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-serving-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace serving.json: %w", err)
	}
	return nil
}
