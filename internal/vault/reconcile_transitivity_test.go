// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"sort"
	"strings"
	"testing"
)

// permute3 returns the six orderings of a three-element candidate slice, so a
// reconciliation test can prove the result is invariant under the on-disk
// WalkDir/filename order a fleet's sync clients each shuffle differently.
func permute3(in [3]manifestCandidate) [][]manifestCandidate {
	idx := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	out := make([][]manifestCandidate, 0, 6)
	for _, p := range idx {
		out = append(out, []manifestCandidate{in[p[0]], in[p[1]], in[p[2]]})
	}
	return out
}

// TestReconcileDominancePlusConcurrencyConverges is the regression for
// .
//
// Three live clocked copies of ONE path:
//   - A clock {X:2, Y:1} (STRICTLY dominates B)
//   - B clock {X:1, Y:1} (dominated by A)
//   - C clock {Y:2} (concurrent with BOTH A and B)
//
// with content keys chosen so contentKey(A) < contentKey(C) < contentKey(B).
//
// The old candidateCompare folded the dominance PARTIAL order into the winner
// sort, so the induced pairwise comparisons formed a cycle — cmp(A,B)=+1
// (dominance), cmp(B,C)=+1 (content), cmp(A,C)=-1 (content), i.e. A>B>C>A. Fed to
// sort.SliceStable that yields no canonical order: the six input permutations
// elected THREE different live winners, and in the two that won B the causally
// DOMINATED record took the live slot while its dominator A was demoted to a
// conflict copy — a causal-order inversion, and a the review /
// convergence break (two honest fleet members reconcile the same path to
// different canonical files because their sync clients renamed the copies into a
// different WalkDir order).
//
// The fix reconciles in two separate phases: dominance pruning
// leaves the maximal antichain, and only that mutually-concurrent set is sorted
// by the content key — a genuine total order. So every permutation must converge
// on the SAME live winner, and a causally-dominated record must NEVER be live.
func TestReconcileDominancePlusConcurrencyConverges(t *testing.T) {
	const (
		p    = "content/doc.txt"
		devX = "deviceX00000000000000000000000000"
		devY = "deviceY00000000000000000000000000"
		gen  = int64(100)
	)

	// contentKey is independent of the vector clock (it hashes chunk ids+sizes,
	// generation, updatedAt, deleted-ness — never the clock), so pick three chunk
	// ids by their induced content key and assign clock roles freely afterwards.
	type keyed struct {
		chunk string
		key   string
	}
	var opts []keyed
	for c := 'a'; c <= 'z'; c++ {
		chunk := strings.Repeat(string(c), 64)
		cand := liveEditCandidate(p, "/disk/probe", chunk, gen, map[string]int64{devX: 1})
		opts = append(opts, keyed{chunk, contentKey(cand.Record)})
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].key < opts[j].key })
	chunkA := opts[0].chunk           // smallest content key -> the dominator A
	chunkC := opts[len(opts)/2].chunk // middle              -> the concurrent C
	chunkB := opts[len(opts)-1].chunk // largest             -> the dominated B

	a := liveEditCandidate(p, "/disk/aa.manifest", chunkA, gen, map[string]int64{devX: 2, devY: 1})
	b := liveEditCandidate(p, "/disk/bb.manifest", chunkB, gen, map[string]int64{devX: 1, devY: 1})
	c := liveEditCandidate(p, "/disk/cc.manifest", chunkC, gen, map[string]int64{devY: 2})

	// Preconditions: A dominates B, C is concurrent with both, and the content
	// ordering is the cycle-inducing one. If any of these regress, the test is no
	// longer exercising the finding.
	if !clockDominates(a.Record.File.Clock, b.Record.File.Clock) {
		t.Fatal("precondition: A must strictly dominate B")
	}
	if clockDominates(a.Record.File.Clock, c.Record.File.Clock) || clockDominates(c.Record.File.Clock, a.Record.File.Clock) {
		t.Fatal("precondition: A and C must be causally concurrent")
	}
	if clockDominates(b.Record.File.Clock, c.Record.File.Clock) || clockDominates(c.Record.File.Clock, b.Record.File.Clock) {
		t.Fatal("precondition: B and C must be causally concurrent")
	}
	ka, kb, kc := contentKey(a.Record), contentKey(b.Record), contentKey(c.Record)
	if !(ka < kc && kc < kb) {
		t.Fatalf("precondition: need contentKey(A) < contentKey(C) < contentKey(B), got A=%s C=%s B=%s", ka[:6], kc[:6], kb[:6])
	}

	// The one causal answer, independent of on-disk order: B is dominated by A and
	// is cleanly removed; the surviving antichain is {A, C} and its content-key
	// winner is C (contentKey(C) > contentKey(A)); A survives as a conflict.
	const wantWinner = "C(chunkC)"
	firstWinner := ""
	for i, perm := range permute3([3]manifestCandidate{a, b, c}) {
		live, conflicts, removes := reconcilePathCandidates(p, perm)
		if live == nil {
			t.Fatalf("perm %d: a live winner must exist", i)
		}
		got := live.Chunks[0].ID

		// Convergence: identical live winner regardless of the
		// input (WalkDir) order.
		if firstWinner == "" {
			firstWinner = got
		} else if got != firstWinner {
			t.Fatalf("perm %d: live winner is order-dependent (non-convergence): %s vs %s", i, short(got), short(firstWinner))
		}

		// Causal-order inversion: a record that is strictly dominated by
		// another in the set must never win the live slot.
		if got == chunkB {
			t.Fatalf("perm %d: causally-DOMINATED record B won the live slot — causal-order inversion", i)
		}

		// The dominated record must be cleanly removed, never resurrected as a
		// conflict copy, and never live.
		for _, cf := range conflicts {
			if cf.Rec.Chunks[0].ID == chunkB {
				t.Fatalf("perm %d: dominated record B must be cleanly removed, not kept as a conflict", i)
			}
		}
		sawBRemoved := false
		for _, r := range removes {
			if r == b.Source {
				sawBRemoved = true
			}
		}
		if !sawBRemoved {
			t.Fatalf("perm %d: dominated record B must be planned for clean removal, removes=%v", i, removes)
		}

		// The content-key winner of the surviving antichain {A, C} is C.
		if got != chunkC {
			t.Fatalf("perm %d: antichain winner must be the content-key holder C, got %s (want %s)", i, short(got), wantWinner)
		}
	}
	if firstWinner != chunkC {
		t.Fatalf("the converged winner must be C, got %s", short(firstWinner))
	}
}

func short(chunk string) string {
	if len(chunk) >= 6 {
		return chunk[:6]
	}
	return chunk
}
