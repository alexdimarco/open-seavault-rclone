// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package authlimit

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// base is the fixed instant every test's injected clock starts from, so lock
// expiry, window expiry, and eviction ordering are deterministic.
var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// fakeClock is the injected time source. It is mutex-guarded because the
// concurrency rows (L4, L5) read it from many goroutines through the limiter.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: base} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// --- white-box test accessors (this file is package authlimit) ---

func (l *Limiter) failuresForTest(k Key) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.keys[k]; ok {
		return st.failures
	}
	return -1
}

func (l *Limiter) pendingForTest(k Key) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.keys[k]; ok {
		return st.pending
	}
	return -1
}

func (l *Limiter) lenForTest() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

func (l *Limiter) hasKeyTest(k Key) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.keys[k]
	return ok
}

// ---------------------------------------------------------------------------
// L1 — the policy table (design §2.1 / matrix L1): with an injected clock,
// assert allowed/locked and retryAfter per row; the doubling up to the cap;
// window expiry; and Success reset.
// ---------------------------------------------------------------------------

type l1step struct {
	op          string // "check", "fail", "success", "advance"
	adv         time.Duration
	wantLocked  bool          // for "fail": whether the key is now locked
	wantAllowed bool          // for "check": whether the caller may proceed
	wantRetry   time.Duration // expected retryAfter (asserted only when assertRetry)
	assertRetry bool
}

func TestL1PolicyTable(t *testing.T) {
	scenarios := []struct {
		name   string
		policy Policy
		steps  []l1step
	}{
		{
			name: "lock at threshold, report retry, double to the cap",
			policy: Policy{
				FailuresBeforeLock: 3, AccountFailuresBeforeLock: 20,
				Window: 15 * time.Minute, LockStart: time.Second, LockMax: 4 * time.Second,
				FailureDelay: 250 * time.Millisecond, MaxKeys: 100,
			},
			steps: []l1step{
				{op: "fail", wantLocked: false, wantRetry: 250 * time.Millisecond, assertRetry: true},
				{op: "fail", wantLocked: false, wantRetry: 250 * time.Millisecond, assertRetry: true},
				{op: "fail", wantLocked: true, wantRetry: time.Second, assertRetry: true},    // 3rd failure locks for LockStart
				{op: "check", wantAllowed: false, wantRetry: time.Second, assertRetry: true}, // locked, full remaining
				{op: "advance", adv: 500 * time.Millisecond},
				{op: "check", wantAllowed: false, wantRetry: 500 * time.Millisecond, assertRetry: true}, // half remaining
				{op: "advance", adv: 500 * time.Millisecond},
				{op: "check", wantAllowed: true},                                              // lock expired: exactly one retry granted
				{op: "fail", wantLocked: true, wantRetry: 2 * time.Second, assertRetry: true}, // doubles 1s -> 2s
				{op: "advance", adv: 2 * time.Second},
				{op: "check", wantAllowed: true},
				{op: "fail", wantLocked: true, wantRetry: 4 * time.Second, assertRetry: true}, // doubles 2s -> 4s (== cap)
				{op: "advance", adv: 4 * time.Second},
				{op: "check", wantAllowed: true},
				{op: "fail", wantLocked: true, wantRetry: 4 * time.Second, assertRetry: true}, // 8s clamped to LockMax 4s
			},
		},
		{
			name: "window expiry resets the streak",
			policy: Policy{
				FailuresBeforeLock: 3, AccountFailuresBeforeLock: 20,
				Window: 10 * time.Second, LockStart: time.Second, LockMax: 4 * time.Second,
				FailureDelay: 0, MaxKeys: 100,
			},
			steps: []l1step{
				{op: "fail", wantLocked: false},
				{op: "fail", wantLocked: false}, // failures == 2
				{op: "advance", adv: 10 * time.Second},
				{op: "fail", wantLocked: false}, // KEY: streak reset, this is failure #1, not #3
				{op: "fail", wantLocked: false}, // #2
				{op: "fail", wantLocked: true},  // #3 locks
			},
		},
		{
			name: "success resets only the streak count",
			policy: Policy{
				FailuresBeforeLock: 3, AccountFailuresBeforeLock: 20,
				Window: 15 * time.Minute, LockStart: time.Second, LockMax: 4 * time.Second,
				FailureDelay: 0, MaxKeys: 100,
			},
			steps: []l1step{
				{op: "fail", wantLocked: false},
				{op: "fail", wantLocked: false}, // failures == 2
				{op: "success"},                 // reset to 0
				{op: "fail", wantLocked: false}, // KEY: failure #1 after reset, not #3
				{op: "fail", wantLocked: false}, // #2
				{op: "fail", wantLocked: true},  // #3 locks
			},
		},
	}

	if len(scenarios) == 0 {
		t.Fatal("L1 table is empty; the row proves nothing")
	}
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			if len(sc.steps) == 0 {
				t.Fatalf("scenario %q has no steps", sc.name)
			}
			clk := newClock()
			l := New(sc.policy, clk.now)
			k := Key{Surface: SurfaceOpen, Peer: "192.0.2.5"}
			for i, s := range sc.steps {
				switch s.op {
				case "advance":
					clk.advance(s.adv)
				case "check":
					allowed, ra := l.Check(k)
					if allowed != s.wantAllowed {
						t.Fatalf("step %d (check): allowed=%v want %v", i, allowed, s.wantAllowed)
					}
					if s.assertRetry && ra != s.wantRetry {
						t.Fatalf("step %d (check): retryAfter=%v want %v", i, ra, s.wantRetry)
					}
				case "fail":
					locked, ra := l.Fail(k)
					if locked != s.wantLocked {
						t.Fatalf("step %d (fail): locked=%v want %v", i, locked, s.wantLocked)
					}
					if s.assertRetry && ra != s.wantRetry {
						t.Fatalf("step %d (fail): retryAfter=%v want %v", i, ra, s.wantRetry)
					}
				case "success":
					l.Success(k)
				default:
					t.Fatalf("step %d: unknown op %q", i, s.op)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// L2 — bounded memory + eviction order (I-R3 / matrix L2): spray 20,000 distinct
// peers → len(map) <= MaxKeys; the oldest-idle key was evicted first; and a
// locked key survives even though it is the oldest by lastSeen.
// ---------------------------------------------------------------------------

func TestL2SprayEvictionBounded(t *testing.T) {
	clk := newClock()
	p := Policy{
		FailuresBeforeLock: 3, AccountFailuresBeforeLock: 6,
		Window: time.Hour, LockStart: time.Hour, LockMax: time.Hour,
		FailureDelay: 0, MaxKeys: 1000,
	}
	l := New(p, clk.now)

	// Lock one key FIRST, at the oldest instant, so it is both the oldest by
	// lastSeen and locked; the never-evict-locked rule must keep it alive.
	locked := Key{Surface: SurfaceBasic, Peer: "10.0.0.1"}
	for i := 0; i < p.FailuresBeforeLock; i++ {
		l.Fail(locked)
	}
	if got := l.failuresForTest(locked); got != p.FailuresBeforeLock {
		t.Fatalf("pre-lock setup wrong: locked key failures=%d want %d", got, p.FailuresBeforeLock)
	}

	const spray = 20000
	var firstSprayed Key
	for i := 0; i < spray; i++ {
		clk.advance(time.Millisecond) // strictly increasing lastSeen
		k := Key{Surface: SurfaceBasic, Peer: fmt.Sprintf("198.51.%d.%d", i/256, i%256)}
		if i == 0 {
			firstSprayed = k
		}
		l.Fail(k) // one failure each; below the threshold, so unlocked and evictable
	}

	if got := l.lenForTest(); got > p.MaxKeys {
		t.Fatalf("map grew past MaxKeys: len=%d MaxKeys=%d (I-R3 broken)", got, p.MaxKeys)
	}
	if !l.hasKeyTest(locked) {
		t.Fatal("the locked key was evicted; a locked key must survive spray eviction (I-R3)")
	}
	if l.hasKeyTest(firstSprayed) {
		t.Fatalf("the oldest-idle sprayed key %v survived; eviction is not oldest-first", firstSprayed)
	}
	recent := Key{Surface: SurfaceBasic, Peer: fmt.Sprintf("198.51.%d.%d", (spray-1)/256, (spray-1)%256)}
	if !l.hasKeyTest(recent) {
		t.Fatal("the most-recent sprayed key was evicted; recent activity must be retained")
	}
}

// ---------------------------------------------------------------------------
// L3 — peer isolation + reset scope (I-R6 / matrix L3): two peers, one account;
// peer A locks while peer B stays allowed; A's success after unlock resets only
// A and leaves B's accumulated failures untouched.
// ---------------------------------------------------------------------------

func TestL3PeerIsolationAndResetScope(t *testing.T) {
	clk := newClock()
	p := Policy{
		FailuresBeforeLock: 3, AccountFailuresBeforeLock: 20,
		Window: 15 * time.Minute, LockStart: time.Minute, LockMax: 15 * time.Minute,
		FailureDelay: 0, MaxKeys: 100,
	}
	l := New(p, clk.now)
	const account = "vault"
	a := Key{Surface: SurfaceBasic, Peer: "192.0.2.1", Account: account}
	b := Key{Surface: SurfaceBasic, Peer: "192.0.2.2", Account: account}

	// Peer B accumulates two failures (below threshold, still allowed).
	l.Fail(b)
	l.Fail(b)
	if got := l.failuresForTest(b); got != 2 {
		t.Fatalf("setup: peer B failures=%d want 2", got)
	}

	// Hammer peer A to a lock.
	for i := 0; i < p.FailuresBeforeLock; i++ {
		allowed, _ := l.Check(a)
		if !allowed {
			t.Fatalf("peer A check %d denied before its lock", i)
		}
		locked, _ := l.Fail(a)
		if i < p.FailuresBeforeLock-1 && locked {
			t.Fatalf("peer A locked early at failure %d", i)
		}
		if i == p.FailuresBeforeLock-1 && !locked {
			t.Fatal("peer A did not lock at the threshold")
		}
	}
	if allowed, _ := l.Check(a); allowed {
		t.Fatal("peer A allowed while locked")
	}
	// Peer B, hammered on nothing, is still allowed — the keys are independent.
	if allowed, _ := l.Check(b); !allowed {
		t.Fatal("peer B was denied though only peer A was hammered (peer isolation broken)")
	}

	// Wait out A's lock; A gets one attempt and succeeds, which resets A only.
	clk.advance(p.LockStart + time.Second)
	if allowed, _ := l.Check(a); !allowed {
		t.Fatal("peer A was not granted its one attempt after the lock expired")
	}
	l.Success(a)

	if got := l.failuresForTest(a); got != 0 {
		t.Fatalf("peer A not reset by its own Success: failures=%d want 0", got)
	}
	if got := l.failuresForTest(b); got != 2 {
		t.Fatalf("peer A's Success reset peer B too: B failures=%d want 2 (I-R6 broken)", got)
	}
}

// ---------------------------------------------------------------------------
// L4 — concurrency, exact counts (matrix L4, run under -race): 50 goroutines
// hammer Check/Fail on one key; every failure is counted (no lost updates) and
// every reservation is consumed (pending balances back to zero).
// ---------------------------------------------------------------------------

func TestL4ConcurrentCountsExact(t *testing.T) {
	clk := newClock()
	// Thresholds high enough that no lock engages, so every Fail must be counted.
	p := Policy{
		FailuresBeforeLock: 1 << 30, AccountFailuresBeforeLock: 1 << 30,
		Window: time.Hour, LockStart: time.Minute, LockMax: time.Minute,
		FailureDelay: 0, MaxKeys: 100,
	}
	l := New(p, clk.now)
	k := Key{Surface: SurfaceOpen, Peer: "192.0.2.9"}

	const G = 50
	var wg sync.WaitGroup
	for i := 0; i < G; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if allowed, _ := l.Check(k); allowed {
				l.Fail(k)
			}
		}()
	}
	wg.Wait()

	if got := l.failuresForTest(k); got != G {
		t.Fatalf("concurrent Fail count wrong: got %d want %d (lost updates under race?)", got, G)
	}
	if got := l.pendingForTest(k); got != 0 {
		t.Fatalf("reservations leaked under concurrency: pending=%d want 0", got)
	}
}

// ---------------------------------------------------------------------------
// L5 — reservation bounds verifications (C4 / I-R10 / matrix L5, under -race):
// FailuresBeforeLock+K concurrent Check→verify→Fail cycles on one key reach the
// (simulated) credential verification at most FailuresBeforeLock times.
// ---------------------------------------------------------------------------

func TestL5ReservationBoundsVerifications(t *testing.T) {
	clk := newClock()
	const F = 5
	p := Policy{
		FailuresBeforeLock: F, AccountFailuresBeforeLock: 100,
		Window: time.Hour, LockStart: time.Minute, LockMax: time.Minute,
		FailureDelay: 0, MaxKeys: 100,
	}
	l := New(p, clk.now)
	k := Key{Surface: SurfaceOpen, Peer: "192.0.2.10", Account: "vault"}

	const K = 20
	const total = F + K
	var verifications int64
	// The verify phase is held behind `release` so that NO Fail runs until every
	// goroutine has finished its Check. This is what the reservation must bound:
	// were verifications gated only by the eventual lock (which needs Fails), the
	// KDF-cost multiplication C4 warns about would already have happened. With
	// Fails held back, only the pending reservation can cap how many Checks pass.
	var checksDone sync.WaitGroup
	checksDone.Add(total)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _ := l.Check(k)
			if allowed {
				// Reservation held: this attempt has reached the (expensive) verifier.
				atomic.AddInt64(&verifications, 1)
			}
			checksDone.Done()
			if !allowed {
				return
			}
			<-release // stand in for the slow credential verification
			l.Fail(k) // every attempt is wrong
		}()
	}
	checksDone.Wait() // every Check has now run, with every Fail still pending
	got := atomic.LoadInt64(&verifications)
	close(release)
	wg.Wait()

	if got > F {
		t.Fatalf("reservation did not bound verifications: %d reached the verifier before any Fail, want <= %d (C4/I-R10)", got, F)
	}
	if got == 0 {
		t.Fatal("no attempt reached the verifier; the row proved nothing")
	}
}

// ---------------------------------------------------------------------------
// K1 — source rotation ceilings (C3 / I-R8 / matrix K1): an IPv6 /64 rotation
// locks the shared peer key; an IPv4 rotation against one account trips the
// per-account ceiling at AccountFailuresBeforeLock; another account is
// unaffected.
// ---------------------------------------------------------------------------

func TestK1SourceRotationCeilings(t *testing.T) {
	newLimiter := func() (*Limiter, *fakeClock) {
		clk := newClock()
		p := Policy{
			FailuresBeforeLock: 3, AccountFailuresBeforeLock: 6,
			Window: 15 * time.Minute, LockStart: time.Minute, LockMax: 15 * time.Minute,
			FailureDelay: 0, MaxKeys: 1000,
		}
		return New(p, clk.now), clk
	}

	t.Run("ipv6 /64 rotation locks the peer key", func(t *testing.T) {
		l, _ := newLimiter()
		const account = "vault"
		// Three distinct addresses in one /64 — they collapse to one peer key.
		for i := 0; i < 3; i++ {
			addr := fmt.Sprintf("[2001:db8:1:2::%x]:%d", i+1, 40000+i)
			att, allowed, _ := l.Attempt(SurfaceBasic, addr, account)
			if !allowed {
				t.Fatalf("/64 attempt %d denied before the threshold", i)
			}
			att.Fail()
		}
		// A fourth distinct address in the SAME /64 is now locked out.
		if _, allowed, _ := l.Attempt(SurfaceBasic, "[2001:db8:1:2::99]:5000", account); allowed {
			t.Fatal("same-/64 source rotation was not locked; /64 keying failed (C3)")
		}
		// A DIFFERENT /64 against the same account is still allowed — proving it
		// was the /64 peer key that locked, not the account ceiling (only 3 < 6).
		if _, allowed, _ := l.Attempt(SurfaceBasic, "[2001:db8:3:4::1]:5000", account); !allowed {
			t.Fatal("a different /64 was denied; the peer key was not /64-scoped or the account ceiling tripped early")
		}
	})

	t.Run("ipv4 rotation trips the account ceiling; another account is unaffected", func(t *testing.T) {
		l, _ := newLimiter()
		const account = "vault"
		// AccountFailuresBeforeLock (6) distinct IPv4 peers, one failure each: no
		// single peer key locks (1 < 3), but the account ceiling accumulates.
		for i := 0; i < 6; i++ {
			addr := fmt.Sprintf("203.0.113.%d:6000", i+1)
			att, allowed, _ := l.Attempt(SurfaceBasic, addr, account)
			if !allowed {
				t.Fatalf("IPv4 rotation attempt %d denied before the account ceiling", i)
			}
			att.Fail()
		}
		// A brand-new IPv4 against the same account meets the tripped ceiling.
		if _, allowed, _ := l.Attempt(SurfaceBasic, "203.0.113.200:6000", account); allowed {
			t.Fatal("the account ceiling did not lock after rotated IPv4 sources (C3/I-R8)")
		}
		// A different account from a fresh peer is unaffected.
		if _, allowed, _ := l.Attempt(SurfaceBasic, "203.0.113.201:6000", "other"); !allowed {
			t.Fatal("a different account was locked by vault's ceiling; account isolation broken")
		}
	})
}

// ---------------------------------------------------------------------------
// PeerKey mapping (design §2.1 / C3): IPv4 by address, IPv4-mapped IPv6 as its
// IPv4, IPv6 by /64 prefix; a missing port or an unparsable host is bucketed by
// the raw string.
// ---------------------------------------------------------------------------

func TestPeerKeyMapping(t *testing.T) {
	cases := []struct {
		name, addr, want string
	}{
		{"ipv4 with port", "192.0.2.7:54321", "192.0.2.7"},
		{"ipv4 no port", "192.0.2.7", "192.0.2.7"},
		{"ipv4-mapped ipv6 keys as ipv4", "[::ffff:192.0.2.7]:9000", "192.0.2.7"},
		{"ipv6 keyed by /64", "[2001:db8:1:2:3:4:5:6]:443", "2001:db8:1:2::/64"},
		{"ipv6 same /64 different suffix", "[2001:db8:1:2:ffff:ffff:ffff:ffff]:80", "2001:db8:1:2::/64"},
		{"ipv6 different /64", "[2001:db8:1:3::1]:80", "2001:db8:1:3::/64"},
		{"unparsable host falls back to raw", "not-an-ip", "not-an-ip"},
	}
	if len(cases) == 0 {
		t.Fatal("PeerKey table is empty")
	}
	for _, c := range cases {
		got := PeerKey(c.addr)
		if got == "" {
			t.Fatalf("%s: PeerKey(%q) returned empty", c.name, c.addr)
		}
		if got != c.want {
			t.Fatalf("%s: PeerKey(%q)=%q want %q", c.name, c.addr, got, c.want)
		}
	}
	// The two same-/64 addresses must collapse to the same key.
	if PeerKey("[2001:db8:1:2:3:4:5:6]:1") != PeerKey("[2001:db8:1:2:aaaa::9]:2") {
		t.Fatal("two addresses in one /64 did not collapse to the same peer key")
	}
}

// ---------------------------------------------------------------------------
// LockLine / SurfaceWords (C6): operator words, minutes, the remedy, and never
// a credential (I-R2 — the formatter takes no credential and prints none).
// ---------------------------------------------------------------------------

func TestSurfaceWords(t *testing.T) {
	cases := []struct {
		s    Surface
		want string
	}{
		{SurfaceBasic, "WebDAV auth"},
		{SurfaceLogin, "GUI login"},
		{SurfaceLaunch, "launch link"},
		{SurfaceOpen, "vault open"},
		{SurfaceRedeem, "recovery redeem"},
	}
	for _, c := range cases {
		if got := SurfaceWords(c.s); got != c.want {
			t.Fatalf("SurfaceWords(%q)=%q want %q", c.s, got, c.want)
		}
		if got := SurfaceWords(c.s); got == string(c.s) {
			t.Fatalf("SurfaceWords(%q) leaked the raw enum %q", c.s, c.s)
		}
	}
}

func TestLockLineFormatting(t *testing.T) {
	k := Key{Surface: SurfaceBasic, Peer: "192.0.2.7", Account: "vault"}
	line := LockLine(k, 2*time.Minute, 5)
	for _, want := range []string{
		"auth-limit: locked",
		"WebDAV auth",
		"192.0.2.7",
		`user "vault"`,
		"2 minutes",
		"after 5 failures",
		"unlocks automatically",
		"--auth-limit off",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("lock line missing %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "basic") {
		t.Fatalf("lock line leaked the raw surface enum:\n%s", line)
	}

	// A sub-minute lock reads honestly in seconds (wiring-3); a lock of a minute
	// or more reads in whole minutes, rounded up. Nothing ever prints "0".
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{time.Second, "1 second"},
		{30 * time.Second, "30 seconds"},
		{45 * time.Second, "45 seconds"},
		{time.Minute, "1 minute"},
		{90 * time.Second, "2 minutes"},
		{15 * time.Minute, "15 minutes"},
	} {
		got := LockLine(Key{Surface: SurfaceOpen, Peer: "p"}, c.d, 1)
		if !strings.Contains(got, c.want) {
			t.Fatalf("LockLine duration for %v missing %q:\n%s", c.d, c.want, got)
		}
	}
	// The default first lock is 30 seconds; the operator line must NOT round it up
	// to "1 minute" (wiring-3: that would contradict the Retry-After: 30 the same
	// lock sets on its response).
	if first := LockLine(Key{Surface: SurfaceOpen, Peer: "p"}, 30*time.Second, 5); strings.Contains(first, "minute") {
		t.Fatalf("a 30-second first lock must not render minutes:\n%s", first)
	}
	// The peer-only key (no account) omits the user clause.
	if strings.Contains(LockLine(Key{Surface: SurfaceLogin, Peer: "192.0.2.8"}, time.Minute, 3), "user ") {
		t.Fatal("peer-only lock line printed an empty user clause")
	}
}

// TestLockLineFirstLockAgreesWithRetryAfter (wiring-3): for the default 30-second
// first lock the operator lock line's duration phrase must agree with the whole
// seconds a Retry-After header would carry for the same duration — no "1 minute"
// vs "Retry-After: 30" contradiction on one response.
func TestLockLineFirstLockAgreesWithRetryAfter(t *testing.T) {
	const first = 30 * time.Second
	// The Retry-After a caller derives from this lock (whole seconds, rounded up).
	retryAfterSeconds := int((first + time.Second - 1) / time.Second)
	if retryAfterSeconds != 30 {
		t.Fatalf("test premise wrong: retryAfterSeconds=%d want 30", retryAfterSeconds)
	}
	line := LockLine(Key{Surface: SurfaceBasic, Peer: "192.0.2.7"}, first, 5)
	want := fmt.Sprintf("%d seconds", retryAfterSeconds)
	if !strings.Contains(line, want) {
		t.Fatalf("first-lock line must state %q to agree with Retry-After: %d:\n%s", want, retryAfterSeconds, line)
	}
	if strings.Contains(line, "minute") {
		t.Fatalf("first-lock line rounds up to minutes, contradicting Retry-After: %d:\n%s", retryAfterSeconds, line)
	}
}

// TestLockLineAccountCeiling (lockout-dos-5): the per-account ceiling key has no
// peer (Peer==""); its lock line must name the whole-account lock plainly, with
// no empty peer and no double space, and still carry the surface words, the
// duration, and the remedy.
func TestLockLineAccountCeiling(t *testing.T) {
	k := Key{Surface: SurfaceBasic, Account: "seavault"} // Peer == "" — the ceiling
	line := LockLine(k, 2*time.Minute, 20)
	if strings.Contains(line, "for  ") {
		t.Fatalf("account-ceiling line has an empty peer / double space:\n%s", line)
	}
	for _, want := range []string{
		`account "seavault" (from any source)`,
		"WebDAV auth",
		"2 minutes",
		"after 20 failures",
		"--auth-limit off",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("account-ceiling line missing %q:\n%s", want, line)
		}
	}
	// It must not read as a peer key with an empty address followed by a user clause.
	if strings.Contains(line, `(user "seavault")`) {
		t.Fatalf("account-ceiling line used the peer+user form instead of the whole-account form:\n%s", line)
	}
}

// ---------------------------------------------------------------------------
// L2b — locked-spray total bound (lockout-dos-1 / I-R3): a spray of distinct
// peers that each LOCK must still leave the map bounded by MaxKeys. Before the
// fix, evictOneLocked skipped every locked key and getOrCreateLocked added
// anyway, so a locked spray grew the map without bound.
// ---------------------------------------------------------------------------

func TestL2LockedSprayBounded(t *testing.T) {
	clk := newClock()
	p := Policy{
		FailuresBeforeLock: 3, AccountFailuresBeforeLock: 6,
		Window: time.Hour, LockStart: time.Hour, LockMax: time.Hour,
		FailureDelay: 0, MaxKeys: 500,
	}
	l := New(p, clk.now)

	const spray = 5000
	for i := 0; i < spray; i++ {
		clk.advance(time.Millisecond) // strictly increasing lastSeen
		k := Key{Surface: SurfaceBasic, Peer: fmt.Sprintf("198.51.%d.%d", i/256, i%256)}
		for f := 0; f < p.FailuresBeforeLock; f++ {
			l.Fail(k) // lock this key (LockStart == Window == 1h, so it stays locked)
		}
	}

	if got := l.lenForTest(); got > p.MaxKeys {
		t.Fatalf("a spray of LOCKED peers grew the map past MaxKeys: len=%d MaxKeys=%d (I-R3 total bound broken)", got, p.MaxKeys)
	}
	// The most recent locked key must survive; the hard ceiling evicts the OLDEST
	// locked key, not a random or the newest one.
	recent := Key{Surface: SurfaceBasic, Peer: fmt.Sprintf("198.51.%d.%d", (spray-1)/256, (spray-1)%256)}
	if !l.hasKeyTest(recent) {
		t.Fatal("the most-recent locked key was evicted; the hard ceiling must drop the OLDEST locked key")
	}
}

// ---------------------------------------------------------------------------
// concurrency-reservation-1 (I-R10 / C4): a key holding in-flight reservations
// is never evicted. Under a small MaxKeys, a Check on a new peer must not evict a
// pending target and reset its reservation count — that would let another full
// FailuresBeforeLock reservations pass, so > FailuresBeforeLock verifications run
// on one threshold-F key. Runs under -race in the unfiltered suite.
// ---------------------------------------------------------------------------

func TestEvictionNeverDropsPendingReservations(t *testing.T) {
	clk := newClock()
	const F = 3
	p := Policy{
		FailuresBeforeLock: F, AccountFailuresBeforeLock: 20,
		Window: time.Hour, LockStart: time.Minute, LockMax: time.Minute,
		FailureDelay: 0, MaxKeys: 1, // one slot: any new key forces an eviction
	}
	l := New(p, clk.now)
	target := Key{Surface: SurfaceOpen, Peer: "192.0.2.50"}

	// Hold F reservations on the target (Checks with no Fail/Success yet).
	held := 0
	for i := 0; i < F; i++ {
		if allowed, _ := l.Check(target); allowed {
			held++
		}
	}
	if held != F {
		t.Fatalf("setup: %d reservations granted, want %d", held, F)
	}
	if got := l.pendingForTest(target); got != F {
		t.Fatalf("setup: target pending=%d want %d", got, F)
	}

	// A Check on a NEW peer at MaxKeys=1 would evict. The pending target must NOT
	// be the victim: the map grows by one instead.
	other := Key{Surface: SurfaceOpen, Peer: "192.0.2.51"}
	l.Check(other)
	if !l.hasKeyTest(target) {
		t.Fatal("a key holding in-flight reservations was evicted (I-R10/C4 broken)")
	}
	if got := l.pendingForTest(target); got != F {
		t.Fatalf("eviction dropped the target's reservations: pending=%d want %d", got, F)
	}

	// The property the finding names: after the eviction attempt, no more than
	// FailuresBeforeLock reservations can be live on the target. If eviction had
	// reset pending, these F extra Checks would all pass, giving 2F live.
	extra := 0
	for i := 0; i < F; i++ {
		if allowed, _ := l.Check(target); allowed {
			extra++
		}
	}
	if live := held + extra; live > F {
		t.Fatalf("%d live reservations on a threshold-%d key after eviction (want <= %d): pending was reset", live, F, F)
	}
}

// ---------------------------------------------------------------------------
// concurrency-reservation-2: a leaked reservation decays. Three Checks with no
// Fail/Success fill the reservation to the threshold and the key denies; after a
// whole Window of inactivity the stale reservations must decay so the key is
// usable again — a leak must self-heal, not become a permanent lockout.
// ---------------------------------------------------------------------------

func TestReservationDecaysAfterWindow(t *testing.T) {
	clk := newClock()
	p := Policy{
		FailuresBeforeLock: 3, AccountFailuresBeforeLock: 20,
		Window: 15 * time.Minute, LockStart: time.Minute, LockMax: 15 * time.Minute,
		FailureDelay: 0, MaxKeys: 100,
	}
	l := New(p, clk.now)
	k := Key{Surface: SurfaceOpen, Peer: "192.0.2.44"}

	for i := 0; i < 3; i++ {
		if allowed, _ := l.Check(k); !allowed {
			t.Fatalf("check %d denied before the reservation filled", i)
		}
	}
	if got := l.pendingForTest(k); got != 3 {
		t.Fatalf("pending=%d want 3 after three granted Checks", got)
	}
	if allowed, _ := l.Check(k); allowed {
		t.Fatal("a fourth Check must be denied while three reservations are in flight")
	}

	// No handler ever ran Fail/Success/Release (a leaked reservation). Advance past
	// the Window: the stale reservations must decay.
	clk.advance(p.Window + time.Second)
	allowed, ra := l.Check(k)
	if !allowed {
		t.Fatalf("a Window-stale leaked reservation never decayed: Check allowed=false retryAfter=%v pending=%d (permanent lockout)", ra, l.pendingForTest(k))
	}
}

// ---------------------------------------------------------------------------
// peer-spoofing-2 / concurrency-reservation-2 — Attempt.Release: it returns the
// reservations WITHOUT counting a failure or a success, so it never resets the
// failure streak or clears a lock (calling Success on an infrastructure error
// would wrongly clear the shared account ceiling). A deferred Release also
// no-ops once Fail or Success has already resolved the attempt.
// ---------------------------------------------------------------------------

func TestAttemptReleaseOnlyDecrementsPending(t *testing.T) {
	clk := newClock()
	p := Policy{
		FailuresBeforeLock: 5, AccountFailuresBeforeLock: 20,
		Window: 15 * time.Minute, LockStart: time.Minute, LockMax: 15 * time.Minute,
		FailureDelay: 0, MaxKeys: 100,
	}
	const account = "vault"

	t.Run("release keeps failures and the account ceiling", func(t *testing.T) {
		l := New(p, clk.now)
		peerAcct := Key{Surface: SurfaceLogin, Peer: "192.0.2.1", Account: account}
		acctCeil := Key{Surface: SurfaceLogin, Account: account}

		// Accrue two real failures across the account keys.
		for i := 0; i < 2; i++ {
			att, allowed, _ := l.Attempt(SurfaceLogin, "192.0.2.1:5000", account)
			if !allowed {
				t.Fatalf("attempt %d denied before the threshold", i)
			}
			att.Fail()
		}
		if got := l.failuresForTest(peerAcct); got != 2 {
			t.Fatalf("setup: peer+account failures=%d want 2", got)
		}
		if got := l.failuresForTest(acctCeil); got != 2 {
			t.Fatalf("setup: account-ceiling failures=%d want 2", got)
		}

		// A third attempt reserves, then hits an infrastructure error and RELEASES.
		att, allowed, _ := l.Attempt(SurfaceLogin, "192.0.2.1:5000", account)
		if !allowed {
			t.Fatal("third attempt denied before its Release")
		}
		if got := l.pendingForTest(acctCeil); got != 1 {
			t.Fatalf("account-ceiling pending=%d want 1 after Check", got)
		}
		att.Release()

		// Release drops only the reservations; the failure streaks stand.
		if got := l.pendingForTest(peerAcct); got != 0 {
			t.Fatalf("Release left a reservation on peer+account: pending=%d want 0", got)
		}
		if got := l.pendingForTest(acctCeil); got != 0 {
			t.Fatalf("Release left a reservation on the account ceiling: pending=%d want 0", got)
		}
		if got := l.failuresForTest(peerAcct); got != 2 {
			t.Fatalf("Release reset peer+account failures: got %d want 2 (Release must not clear the streak)", got)
		}
		if got := l.failuresForTest(acctCeil); got != 2 {
			t.Fatalf("Release reset the shared account ceiling: got %d want 2 (peer-spoofing-2)", got)
		}
	})

	t.Run("deferred release no-ops after Fail", func(t *testing.T) {
		l := New(p, clk.now)
		func() {
			att, allowed, _ := l.Attempt(SurfaceLogin, "192.0.2.2:5000", account)
			if !allowed {
				t.Fatal("attempt denied before Fail")
			}
			defer att.Release() // must no-op: Fail already consumed the attempt
			att.Fail()
		}()
		k := Key{Surface: SurfaceLogin, Peer: "192.0.2.2", Account: account}
		if got := l.failuresForTest(k); got != 1 {
			t.Fatalf("a Fail then a deferred Release must leave one counted failure, got %d (double-resolve?)", got)
		}
		if got := l.pendingForTest(k); got != 0 {
			t.Fatalf("pending=%d want 0 after Fail + deferred Release", got)
		}
	})

	t.Run("deferred release no-ops after Success", func(t *testing.T) {
		l := New(p, clk.now)
		peer := Key{Surface: SurfaceLogin, Peer: "192.0.2.3", Account: account}
		// One failure first, then a success that a deferred Release must not undo-twice.
		att, _, _ := l.Attempt(SurfaceLogin, "192.0.2.3:5000", account)
		att.Fail()
		func() {
			att, allowed, _ := l.Attempt(SurfaceLogin, "192.0.2.3:5000", account)
			if !allowed {
				t.Fatal("attempt denied before Success")
			}
			defer att.Release()
			att.Success()
		}()
		if got := l.failuresForTest(peer); got != 0 {
			t.Fatalf("Success must clear the streak; got %d", got)
		}
		if got := l.pendingForTest(peer); got != 0 {
			t.Fatalf("pending=%d want 0 after Success + deferred Release", got)
		}
	})
}
