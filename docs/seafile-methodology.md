# Seafile-inspired methodology used here

SeaVault borrows Seafile's performance-oriented idea of chunked storage: split files into reusable blocks, store blocks as independent objects, and update references when a file changes. This improves speed and sync efficiency because modified large files do not require rewriting one monolithic encrypted blob.

SeaVault intentionally does not copy Seafile's older encrypted-library CBC construction. Instead, it uses modern AEAD encryption for chunks and manifests.

## Adopted ideas

- Client-side encryption before data reaches server-side storage.
- Chunk/block storage rather than one encrypted file per file.
- Content-defined chunking for efficient delta behavior.
- Object reuse to avoid rewriting identical chunks.
- Local metadata describing file-to-chunk references.

## Changed security design

| Area | Seafile-style baseline | SeaVault choice |
| --- | --- | --- |
| File data encryption | Library key model with AES-CBC in documented versions | AES-256-GCM per chunk |
| Integrity | Historically limited for encrypted libraries | AEAD tags plus keyed object-ID verification |
| Metadata | File names not encrypted in Seafile encrypted libraries | Virtual paths encrypted in manifests |
| Index/storage metadata | Library metadata server-side | Local encrypted sharded manifests |
| Cloud model | Seafile server model | Any local sync-client folder |

## Why sharded manifests

A single encrypted index is simple, but it creates poor sync behavior for large vaults: every small file update rewrites the same index object. Sharded manifests keep the per-file metadata encrypted while allowing cloud sync clients to upload only changed manifests and changed chunk objects.
