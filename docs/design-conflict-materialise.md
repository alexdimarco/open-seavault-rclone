# Design: conflict copies must not overwrite real records

Status: IMPLEMENTED (2026-10-13, maintainer delegated the decision). The chosen
trade-off is "drop": once the user edits or deletes a conflict copy, the old
losing content is not kept as a second copy.

The fix is one rule in `loadManifestIndex` (internal/vault/manifest.go): a planned
conflict whose target path already has its OWN real manifest group is suppressed
— it is neither written into the index nor handed to compact. The real record at
that path (the user's edit, or a tombstone if they deleted it) is therefore
authoritative, so compact can no longer overwrite an edited copy with the old
loser, and a deleted copy is not resurrected on reload. The losing source
manifest is left in place (not reclaimed) while it keeps regenerating a
suppressed conflict; that is untidy but never loses data. Out of scope: the
compact-vs-sync-client TOCTOU (create-if-absent on materialise) noted below,
which pre-exists for all of compact.

## Background

When two devices edit the same file, the sync client leaves two manifests for it.
Loading picks the newest generation as the main file and keeps the other as a
virtual `*.conflict-*` file (SECURITY.md "Sync conflicts"). A load computes this
in memory; an explicit `compact` ("Reclaim space") writes the conflict copy to
disk and removes the loser's source file.

## Problem

In `loadManifestIndex` (`internal/vault/manifest.go:156-166`) a loser's conflict
entry is put into the index at its conflict path regardless of what already
exists at that path. `compact` then writes it with
`saveFileManifest(c.Path, c.Rec)` unconditionally (`compact.go:92`), replacing
whatever manifest is there. `RemovePath` has no special case for conflict copies.

### Example 1: your edit is overwritten

1. Laptop and phone both edit `report.txt`. After sync, the index shows
   `report.txt` (newer) and `report.txt.conflict-1a2b` (older, not yet written).
2. You open the conflict copy over WebDAV, fix it and save. A manifest now exists
   at the conflict path with YOUR edit.
3. You press "Reclaim space". Compact writes the OLD loser over your edit. Garbage
   collection later removes the chunks of your edit. Your work is gone.

### Example 2: a deleted copy comes back

1. You delete `report.txt.conflict-1a2b`. A tombstone is written at that path.
2. The next load re-adds the copy from the loser's source file, so it reappears.
3. Compact permanently replaces the tombstone with the old loser.

## Proposal

Treat the conflict path like any other path: a materialised conflict copy never
replaces an existing record there.

When compact processes a planned conflict `(CP, loserRecord, loserSourceFile)`:

| What exists at `CP` | Action |
|---|---|
| nothing | write the conflict manifest, then remove the loser source (as today) |
| a live record with identical content/generation | already materialised: just remove the loser source |
| a different live record (you edited it) | keep yours; remove the loser source, because the copy was kept and then deliberately changed |
| a tombstone (you deleted it) | keep the tombstone; remove the loser source |

Loading applies the same rule in memory: the index entry at `CP` comes from the
real record there when one exists, so the displayed version is deterministic and
not dependent on map iteration order.

Writes use create-if-absent semantics where the platform allows, so a manifest
delivered by the sync client between planning and writing is not clobbered.

## Trade-off to decide

In the last two rows the old loser content is dropped once you have acted on its
copy. The alternative is to keep it as a second conflict copy
(`.conflict-<id>-2`). That loses nothing but can accumulate clutter every time a
copy is edited. Recommended: drop, because you consciously changed or deleted the
copy and the chunks are only reclaimed after the normal GC fence.

## Tests (prove-fail first)

- Example 1: edit a conflict copy, compact, assert the edit survives byte-for-byte.
- Example 2: delete a conflict copy, reload, assert it stays deleted; compact,
  assert the tombstone is not replaced.
- Unmodified conflict still materialises exactly once and compact is idempotent.
- Loading twice yields the same index (no dependence on map order).

## Related, not in this change

GC can delete a chunk that a second device has just re-used when sync is slow
(dedup does not cancel a pending GC intent). Separate note.
