# Content workspace and legacy vault migration

SeaVault v0.14 adds a protected virtual workspace named `content/`.

## Behaviour

- New vaults create `content/` automatically.
- `content/` is selectable and writable.
- `content/` is not deletable or movable.
- User paths that do not already start with `content/` are normalized into `content/`.
- Internal directory markers use `.seavault-dir` and are hidden from normal lists, exports, stats, and downloads.

Examples:

```text
User input: reports/q1.pdf
Stored virtual path: content/reports/q1.pdf

User input: content/reports/q1.pdf
Stored virtual path: content/reports/q1.pdf
```

## Automatic migration

When a vault is opened, SeaVault checks the decrypted manifest/index for paths outside `content/`.

If legacy root-level paths are present, SeaVault:

1. Creates the protected `content/.seavault-dir` marker if needed.
2. Saves new encrypted manifests under `content/<old-path>`.
3. Writes tombstones for the old root-level manifests so sync does not resurrect them.
4. Preserves files that were already under `content/`.
5. Handles a legacy file named exactly `content` by moving it to `content/content`.

This conversion requires write access to the vault metadata directory. If the vault is read-only, open will fail rather than silently operating against a partially migrated structure.

## Compatibility

Common user input remains compatible. After migration, these both resolve to the same file:

```bash
seavault get vault reports/q1.pdf ./q1.pdf
seavault get vault content/reports/q1.pdf ./q1.pdf
```

`seavault list` shows the canonical migrated paths under `content/`.

## Security notes

The path layer rejects traversal, absolute virtual paths, `.seavault`, and `.seavault-dir` in user-controlled paths. The WebDAV endpoint exposes only the unlocked virtual plaintext view and never the encrypted object store internals.
