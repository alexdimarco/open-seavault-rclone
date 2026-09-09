// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

// Package authlimit is a dependency-free, per-process, in-memory rate limiter
// and lockout for the credential-checking surfaces that Phase U3 made
// network-facing (WebDAV Basic auth, the GUI login, launch-secret redemption,
// the vault-password open, and recovery-phrase redeem). It is the Track R core
// of design-u4-ratelimit-and-polish.md §2.1.
//
// The limiter never weakens authentication (I-R1): a locked key is denied
// BEFORE any credential is examined, unlock happens only by the passage of the
// injected clock, and the peer is always the TCP remote address, never a
// header. No credential, hash, launch secret, or recovery phrase is ever passed
// to, stored by, or emitted from this package (I-R2) — the only identifiers it
// holds are the surface enum, the peer IP (or IPv6 /64), the account username,
// and counters.
//
// Concurrency model: every exported method takes the single mutex. Check
// RESERVES an in-flight attempt (a pending count) so that N concurrent requests
// for one key cannot all pass the pre-check and all reach credential
// verification (C4 / I-R10); Fail and Success each consume one reservation, and
// Attempt.Release returns one without counting either. A key holding a
// reservation is non-evictable (like a lock), so eviction can never drop a live
// reservation and break the bound; a reservation still in flight past Window (a
// handler that ran neither Fail, Success, nor Release) decays on the next
// refresh, so a leaked reservation self-heals instead of becoming a permanent,
// cross-peer denial.
package authlimit

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Surface names a credential-checking endpoint. The values are the design's
// enum (§2.1); SurfaceWords maps each to the operator-facing phrase used in log
// lines (C6).
type Surface string

const (
	SurfaceBasic  Surface = "basic"  // WebDAV Basic auth
	SurfaceLogin  Surface = "login"  // GUI user/password form login
	SurfaceLaunch Surface = "launch" // launch-secret redemption
	SurfaceOpen   Surface = "open"   // vault password via /api/open
	SurfaceRedeem Surface = "redeem" // recovery-phrase redeem
)

// Key identifies one bucket of attempts. Peer is the TCP remote IP (or, for
// IPv6, its /64 prefix — see PeerKey), NEVER a header value. Account is the
// username the attempt claimed, or "" for the peer-only bucket. The tuple
// {Surface, "", Account} is the per-account global ceiling (a higher threshold,
// AccountFailuresBeforeLock) that catches source-rotating attacks (C3 / I-R8).
type Key struct {
	Surface Surface
	Peer    string // TCP remote IP or IPv6 /64 prefix, never a header
	Account string // username, or ""
}

// Policy is the normalized limiter configuration. Zero or negative fields are
// filled from DefaultPolicy by New (FailureDelay is left as given, since a zero
// delay is a valid choice). LockMax is raised to at least LockStart.
type Policy struct {
	FailuresBeforeLock        int           // consecutive failures within Window that lock a peer key
	AccountFailuresBeforeLock int           // the higher ceiling for the per-account {surface,"",account} key
	Window                    time.Duration // a failure streak older than this is stale and resets
	LockStart                 time.Duration // the first lock's length
	LockMax                   time.Duration // the cap the doubling lock length is clamped to
	FailureDelay              time.Duration // the throttle sleep a caller applies after a failed verify
	MaxKeys                   int           // the map bound; oldest-idle (never a locked key) is evicted
}

// DefaultPolicy returns the design's normalized defaults (§2.1).
func DefaultPolicy() Policy {
	return Policy{
		FailuresBeforeLock:        5,
		AccountFailuresBeforeLock: 20,
		Window:                    15 * time.Minute,
		LockStart:                 30 * time.Second,
		LockMax:                   15 * time.Minute,
		FailureDelay:              250 * time.Millisecond,
		MaxKeys:                   10000,
	}
}

// normalize fills zero/negative fields from DefaultPolicy so a misconfigured
// caller can never produce a threshold of 0 (which would lock every key on its
// first attempt) or an unbounded map.
func (p Policy) normalize() Policy {
	d := DefaultPolicy()
	if p.FailuresBeforeLock <= 0 {
		p.FailuresBeforeLock = d.FailuresBeforeLock
	}
	if p.AccountFailuresBeforeLock <= 0 {
		p.AccountFailuresBeforeLock = d.AccountFailuresBeforeLock
	}
	if p.Window <= 0 {
		p.Window = d.Window
	}
	if p.LockStart <= 0 {
		p.LockStart = d.LockStart
	}
	if p.LockMax < p.LockStart {
		p.LockMax = p.LockStart
	}
	if p.FailureDelay < 0 {
		p.FailureDelay = 0
	}
	if p.MaxKeys <= 0 {
		p.MaxKeys = d.MaxKeys
	}
	return p
}

type state struct {
	failures    int       // consecutive failures in the current streak
	pending     int       // in-flight reservations (Check granted, Fail/Success not yet consumed)
	lockedUntil time.Time // zero value == not locked
	lockLen     time.Duration
	lastFailure time.Time // for Window expiry of the streak
	lastSeen    time.Time // for oldest-idle eviction
}

// Limiter is the per-process limiter. It is safe for concurrent use.
type Limiter struct {
	mu     sync.Mutex
	keys   map[Key]*state
	clock  func() time.Time
	policy Policy
}

// New builds a limiter with the (normalized) policy and an injected clock. The
// clock is the only time source the limiter reads, so tests drive lock
// expiry, window expiry, and eviction ordering deterministically. A nil clock
// falls back to time.Now.
func New(p Policy, clock func() time.Time) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{
		keys:   make(map[Key]*state),
		clock:  clock,
		policy: p.normalize(),
	}
}

func (l *Limiter) thresholdFor(k Key) int {
	if k.Peer == "" && k.Account != "" {
		return l.policy.AccountFailuresBeforeLock
	}
	return l.policy.FailuresBeforeLock
}

// FailureDelay is the throttle sleep the wiring applies after a failed
// verification (and on the throttle-only surfaces, launch and redeem, which
// never lock). It exposes the normalized policy value so a caller need not carry
// the Policy separately; it is a read-only accessor and touches no key state.
func (l *Limiter) FailureDelay() time.Duration { return l.policy.FailureDelay }

// getOrCreateLocked returns the state for k, creating it (and evicting the
// oldest idle key when the map is at MaxKeys) if absent. The caller holds mu.
func (l *Limiter) getOrCreateLocked(k Key, now time.Time) *state {
	if st, ok := l.keys[k]; ok {
		return st
	}
	if len(l.keys) >= l.policy.MaxKeys {
		l.evictOneLocked(now)
	}
	st := &state{lastSeen: now}
	l.keys[k] = st
	return st
}

// evictOneLocked keeps the map bounded by MaxKeys (I-R3). It prefers the oldest
// key that is neither locked nor holding an in-flight reservation. A key with
// pending > 0 is NEVER a victim: an in-flight reservation makes a key
// non-evictable like a lock, so eviction can never drop a live reservation and
// break the concurrency bound (I-R10 / C4). When no unlocked, non-pending victim
// exists — a spray of LOCKED source addresses would otherwise grow the map
// without bound — the oldest LOCKED (still non-pending) key is evicted instead,
// so the total-key bound holds even under a locked spray; a locked key is never
// evicted while any unlocked key remains, so a cheap spray cannot unlock the
// attacker's own key. Only when EVERY key holds a reservation (which cannot
// arise from a cheap spray) does the map grow by one rather than evict a pending
// key.
func (l *Limiter) evictOneLocked(now time.Time) {
	var (
		idle       Key
		idleSeen   time.Time
		idleFound  bool
		lockd      Key
		lockdSeen  time.Time
		lockdFound bool
	)
	for k, st := range l.keys {
		if st.pending > 0 {
			continue // in-flight reservation: non-evictable, like a lock
		}
		if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
			if !lockdFound || st.lastSeen.Before(lockdSeen) {
				lockd, lockdSeen, lockdFound = k, st.lastSeen, true
			}
			continue
		}
		if !idleFound || st.lastSeen.Before(idleSeen) {
			idle, idleSeen, idleFound = k, st.lastSeen, true
		}
	}
	switch {
	case idleFound:
		delete(l.keys, idle) // preferred: oldest unlocked, non-pending key
	case lockdFound:
		delete(l.keys, lockd) // hard total-key ceiling: oldest locked, non-pending
	}
	// else every key holds a reservation: grow by one rather than evict one.
}

// refreshLocked applies lock expiry and window expiry to st before a decision.
// When a lock has just expired it grants exactly one further attempt (failures
// set to threshold-1) while keeping the doubling memory in lockLen, so the next
// failure re-locks for the doubled duration. When the streak is stale (no
// failure within Window and not currently locked) it resets to a clean slate.
func (l *Limiter) refreshLocked(k Key, st *state, now time.Time) {
	threshold := l.thresholdFor(k)
	if !st.lockedUntil.IsZero() && !now.Before(st.lockedUntil) {
		st.lockedUntil = time.Time{}
		if st.failures >= threshold {
			st.failures = threshold - 1
		}
	}
	if st.lockedUntil.IsZero() && !st.lastFailure.IsZero() && now.Sub(st.lastFailure) >= l.policy.Window {
		st.failures = 0
		st.lockLen = 0
		st.lastFailure = time.Time{}
	}
	// Decay a leaked reservation: an unlocked key untouched for a whole Window
	// cannot have a real verification still in flight (a KDF finishes in
	// milliseconds), so a surviving pending count is a handler that ran neither
	// Fail, Success, nor Release. Dropping it here makes the leak self-heal
	// instead of wedging the key — or, for the shared account ceiling, the whole
	// account — denied forever (I-R10 hygiene). lastSeen carries the pre-refresh
	// value here (callers stamp it after this returns).
	if st.lockedUntil.IsZero() && st.pending > 0 && !st.lastSeen.IsZero() && now.Sub(st.lastSeen) >= l.policy.Window {
		st.pending = 0
	}
	// Defence in depth: Check grants only while failures+pending < threshold, so
	// pending can never legitimately exceed the threshold; a larger value is a
	// leak — clamp it so a stray reservation can never wedge a key shut.
	if st.pending > threshold {
		st.pending = threshold
	}
}

// Check is called BEFORE verifying a credential. It reserves an in-flight
// attempt and reports whether the caller may proceed. A locked key is denied
// with the remaining lock time and reserves nothing. Otherwise, if the
// completed failures plus the reservations already in flight would reach the
// threshold, the caller is denied (the concurrency guard, C4) with a short
// FailureDelay retry; a granted attempt increments pending, which Fail or
// Success later consumes.
func (l *Limiter) Check(k Key) (allowed bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	st := l.getOrCreateLocked(k, now)
	l.refreshLocked(k, st, now)
	st.lastSeen = now
	if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
		return false, st.lockedUntil.Sub(now)
	}
	if st.failures+st.pending >= l.thresholdFor(k) {
		return false, l.policy.FailureDelay
	}
	st.pending++
	return true, 0
}

// Fail is called AFTER a failed verification. It consumes one reservation,
// counts the failure, and — once the streak reaches the threshold — locks the
// key, doubling the lock length on each further failure up to LockMax. It
// returns whether the key is now locked and, if so, the lock duration.
func (l *Limiter) Fail(k Key) (locked bool, retryAfter time.Duration) {
	locked, retryAfter, _ = l.failReport(k)
	return locked, retryAfter
}

// failReport is Fail plus the post-failure consecutive-failure count for k. The
// Attempt bundle uses the count to compose the operator lock line (C6) for a key
// that just locked. It is unexported: the count is a log detail, not part of the
// stable Fail contract.
func (l *Limiter) failReport(k Key) (locked bool, retryAfter time.Duration, failures int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	st := l.getOrCreateLocked(k, now)
	l.refreshLocked(k, st, now)
	st.lastSeen = now
	if st.pending > 0 {
		st.pending--
	}
	st.failures++
	st.lastFailure = now
	if st.failures >= l.thresholdFor(k) {
		if st.lockLen <= 0 {
			st.lockLen = l.policy.LockStart
		} else {
			st.lockLen *= 2
			if st.lockLen > l.policy.LockMax {
				st.lockLen = l.policy.LockMax
			}
		}
		st.lockedUntil = now.Add(st.lockLen)
		return true, st.lockLen, st.failures
	}
	return false, l.policy.FailureDelay, st.failures
}

// Success is called AFTER a successful verification. It consumes one
// reservation and clears the key — and ONLY that key (I-R6): one client's
// success never unlocks another peer or the account ceiling.
func (l *Limiter) Success(k Key) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	st, ok := l.keys[k]
	if !ok {
		return
	}
	st.lastSeen = now
	if st.pending > 0 {
		st.pending--
	}
	st.failures = 0
	st.lockLen = 0
	st.lockedUntil = time.Time{}
	st.lastFailure = time.Time{}
}

// release returns a reservation without counting a failure or a success. It is
// used by Attempt to undo the reservations it made on the earlier keys when a
// later key denies, so a partial multi-key check never leaks a pending count.
func (l *Limiter) release(k Key) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.keys[k]; ok {
		if st.pending > 0 {
			st.pending--
		}
		st.lastSeen = l.clock()
	}
}

// SelfState reports the CALLER'S OWN current lock state on a surface WITHOUT
// reserving an attempt (unlike Check, which increments pending): it is the
// read-only query the per-viewer GUI banner polls (§2.2 / wiring-2). It consults
// only the caller's peer-keyed buckets — {surface, peer, ""} and, when
// account != "", {surface, peer, account} — NEVER another peer's key and NEVER
// the shared per-account ceiling {surface, "", account}, so one viewer can never
// learn another peer's lock state. It creates no map entry (a poll must not grow
// the map, and a locked key an attacker never touched must not be conjured) and
// returns whether the caller is currently locked on this surface and the longest
// remaining lock time. It holds and reveals no credential (I-R2).
func (l *Limiter) SelfState(surface Surface, remoteAddr, account string) (locked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	peer := PeerKey(remoteAddr)
	keys := []Key{{Surface: surface, Peer: peer}}
	if account != "" {
		keys = append(keys, Key{Surface: surface, Peer: peer, Account: account})
	}
	for _, k := range keys {
		st, ok := l.keys[k]
		if !ok {
			continue // no bucket for this key: not locked, and do not create one
		}
		l.refreshLocked(k, st, now)
		if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
			if ra := st.lockedUntil.Sub(now); ra > retryAfter {
				retryAfter = ra
				locked = true
			}
		}
	}
	return locked, retryAfter
}

// ClearedKey is a redacted description of one bucket an operator unlock removed —
// the surface, the peer, and the account only. It carries NO credential, so a
// "clear lock" response and its operator log line can name exactly what was freed
// without leaking anything (I-R2).
type ClearedKey struct {
	Surface Surface
	Peer    string
	Account string
}

// ClearPeer removes every bucket keyed to ONE peer (across all surfaces and
// accounts), so an operator can free one known-good source while every other peer
// and every per-account ceiling stays locked — the narrow self-unlock lever
// (friction W2-6) that keeps the limiter ON for everyone else. peer is
// PeerKey-normalized first, so the operator may paste either a raw address or the
// /64 form the lock line prints. It returns the cleared buckets
// (surface/peer/account only) and never a credential; a peer with no buckets
// clears nothing and returns nil.
func (l *Limiter) ClearPeer(peer string) []ClearedKey {
	norm := PeerKey(peer)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.clearMatchingLocked(func(k Key) bool { return k.Peer == norm })
}

// ClearAccount removes every bucket keyed to ONE account — the per-account
// ceiling {surface,"",account} and every {surface,peer,account} — so an operator
// can free a locked-out account without disarming the limiter for everyone else
// (friction W2-6). It returns the cleared buckets and never a credential; an
// empty account, or one with no buckets, clears nothing.
func (l *Limiter) ClearAccount(account string) []ClearedKey {
	if account == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.clearMatchingLocked(func(k Key) bool { return k.Account == account })
}

// clearMatchingLocked deletes every bucket for which match reports true and
// returns their redacted descriptions. The caller holds mu.
func (l *Limiter) clearMatchingLocked(match func(Key) bool) []ClearedKey {
	var cleared []ClearedKey
	for k := range l.keys {
		if match(k) {
			cleared = append(cleared, ClearedKey{Surface: k.Surface, Peer: k.Peer, Account: k.Account})
		}
	}
	for _, c := range cleared {
		delete(l.keys, Key{Surface: c.Surface, Peer: c.Peer, Account: c.Account})
	}
	return cleared
}

// Attempt bundles one authentication attempt across the three keys the design
// consults per request (§2.1): {surface, peer, ""} (the peer bucket),
// {surface, peer, account} (this peer against this account), and
// {surface, "", account} (the per-account global ceiling, at the higher
// AccountFailuresBeforeLock threshold). The account keys are omitted when
// account is "". Call Attempt before verifying; on the returned handle call
// Fail after a failed verification or Success after a good one.
type Attempt struct {
	l        *Limiter
	keys     []Key
	locks    []lockRecord // keys that transitioned to locked during Fail (for LockLines)
	consumed bool         // set once Fail, Success, or Release has resolved the attempt
}

// lockRecord captures what a single lock transition needs for its operator log
// line (C6): the key that locked, the lock length, and the failure count. It
// holds no credential.
type lockRecord struct {
	key      Key
	duration time.Duration
	failures int
}

// Attempt reserves an in-flight attempt on each consulted key and reports
// whether the caller may proceed. peer is computed from remoteAddr by PeerKey.
// If any key denies, the reservations already taken on the earlier keys are
// released and allowed is false with that key's retryAfter; the returned handle
// then holds no reservations and its Fail/Success are no-ops.
func (l *Limiter) Attempt(surface Surface, remoteAddr, account string) (att *Attempt, allowed bool, retryAfter time.Duration) {
	peer := PeerKey(remoteAddr)
	keys := []Key{{Surface: surface, Peer: peer}}
	if account != "" {
		keys = append(keys,
			Key{Surface: surface, Peer: peer, Account: account},
			Key{Surface: surface, Account: account},
		)
	}
	reserved := make([]Key, 0, len(keys))
	for _, k := range keys {
		ok, ra := l.Check(k)
		if !ok {
			for _, rk := range reserved {
				l.release(rk)
			}
			return &Attempt{l: l}, false, ra
		}
		reserved = append(reserved, k)
	}
	return &Attempt{l: l, keys: reserved}, true, 0
}

// Fail records a failed verification on every consulted key, returning whether
// any key is now locked and the longest lock duration.
func (a *Attempt) Fail() (locked bool, retryAfter time.Duration) {
	if a.consumed {
		return false, 0
	}
	a.consumed = true
	for _, k := range a.keys {
		lk, ra, failures := a.l.failReport(k)
		if lk {
			locked = true
			a.locks = append(a.locks, lockRecord{key: k, duration: ra, failures: failures})
		}
		if ra > retryAfter {
			retryAfter = ra
		}
	}
	return locked, retryAfter
}

// LockLines returns the operator-facing log lines (C6) for every consulted key
// that transitioned into a locked state during the preceding Fail — one line per
// newly locked key, in operator words with minutes and the remedy, and never a
// credential (I-R2). It is empty when nothing locked. Call it after Fail; a
// denied Attempt (Fail is a no-op) yields no lines.
func (a *Attempt) LockLines() []string {
	if len(a.locks) == 0 {
		return nil
	}
	lines := make([]string, 0, len(a.locks))
	for _, lr := range a.locks {
		lines = append(lines, LockLine(lr.key, lr.duration, lr.failures))
	}
	return lines
}

// Success records a successful verification, clearing every consulted key.
func (a *Attempt) Success() {
	if a.consumed {
		return
	}
	a.consumed = true
	for _, k := range a.keys {
		a.l.Success(k)
	}
}

// Release returns the reservations this Attempt holds WITHOUT counting a failure
// or a success: it decrements only the pending count on each consulted key and
// touches neither the failure streak nor the lock state. Callers use it on an
// infrastructure error — a keychain read that fails before any credential was
// judged, say — where neither Fail nor Success is the truthful outcome; resetting
// the streak there (as Success would) would wrongly clear the shared account
// ceiling on an error the attacker did not earn. Like Fail and Success it
// resolves the attempt at most once, so `defer att.Release()` no-ops once a Fail
// or Success has already run and otherwise frees a reservation a handler path
// forgot to resolve.
func (a *Attempt) Release() {
	if a.consumed {
		return
	}
	a.consumed = true
	for _, k := range a.keys {
		a.l.release(k)
	}
}

// PeerKey derives the limiter peer identity from a TCP remote address
// (host:port, as in http.Request.RemoteAddr). An IPv4 peer — including an
// IPv4-mapped IPv6 address such as ::ffff:192.0.2.7 — is keyed by its address.
// An IPv6 peer is keyed by its /64 prefix, because any IPv6 host owns a whole
// /64 and per-attempt source rotation within it would otherwise let neither key
// accumulate (C3 / I-R8). An address with no port, or an unparsable host, is
// keyed by the raw string so the limiter still buckets it deterministically.
func PeerKey(remoteAddr string) string {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	prefix := ip.Mask(net.CIDRMask(64, 128))
	return prefix.String() + "/64"
}

// SurfaceWords maps a Surface to the operator-facing phrase used in the lock
// line (C6), so a log reader never sees the raw enum.
func SurfaceWords(s Surface) string {
	switch s {
	case SurfaceBasic:
		return "WebDAV auth"
	case SurfaceLogin:
		return "GUI login"
	case SurfaceLaunch:
		return "launch link"
	case SurfaceOpen:
		return "vault open"
	case SurfaceRedeem:
		return "recovery redeem"
	default:
		return string(s)
	}
}

// LockLine formats the single operator-facing log line a lock emits (C6):
// operator words for the surface, the peer and (if any) the account username,
// the remaining time in whole minutes, the failure count, and the remedy. It
// takes no credential and emits none (I-R2) — the username is an identifier,
// not a secret, and no password, hash, secret, or phrase is a parameter.
func LockLine(k Key, d time.Duration, failures int) string {
	var who string
	switch {
	case k.Peer == "" && k.Account != "":
		// The per-account ceiling locks the account across EVERY source, so there
		// is no single peer to name; say that plainly instead of leaving an empty
		// gap (which read "for  (user …)" with a stray double space).
		who = fmt.Sprintf("account %q (from any source)", k.Account)
	case k.Account != "":
		who = fmt.Sprintf("%s (user %q)", k.Peer, k.Account)
	default:
		who = k.Peer
	}
	return fmt.Sprintf(
		"auth-limit: locked %s for %s for %s after %d failures; unlocks automatically, or restart with --auth-limit off for an incident",
		SurfaceWords(k.Surface), who, lockDurationPhrase(d), failures,
	)
}

// lockDurationPhrase renders d as a human duration for the operator lock line,
// honestly enough to agree with the Retry-After the same lock sets: a sub-minute
// lock reads in whole seconds (rounded up, floored at one second), so a
// 30-second first lock says "30 seconds" rather than a rounded-up, contradictory
// "1 minute"; a lock of a minute or more reads in whole minutes (rounded up).
func lockDurationPhrase(d time.Duration) string {
	if d < time.Minute {
		s := int((d + time.Second - 1) / time.Second)
		if s < 1 {
			s = 1
		}
		if s == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%d seconds", s)
	}
	m := int((d + time.Minute - 1) / time.Minute)
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}
