# SeaVault Fast design

## Baseline

SeaVault stores encrypted data inside a normal local directory. A separate sync client moves that encrypted directory to and from the cloud. SeaVault does not need a cloud-provider API, and the provider never receives plaintext from this application.

## Encrypted local location

The configured vault directory is the encrypted storage location. A local profile is only a pointer to that directory.

```text
profile name -> local path watched by sync client -> encrypted SeaVault data -> cloud server
```

The source files and restored files are separate from the vault. Users can keep plaintext in their normal workspace, then put selected files into the encrypted vault, or use the browser GUI/WebDAV endpoint to interact with vault contents.

## Methodology

1. Initialize vault.
   - Generate random `masterKey` and `indexKey`.
   - Generate a random KDF salt.
   - Derive a key-encryption key with Argon2id, scrypt, or PBKDF2-HMAC-SHA256.
   - Wrap the random key bundle with AES-256-GCM.
   - Store KDF parameters, wrapped keys, chunk parameters, and non-secret configuration in `vault.json`.

2. Add file.
   - Stream plaintext through a gear-hash content-defined chunker.
   - For each chunk, calculate `objectID = HMAC-SHA256(indexKey, plaintextChunk)`.
   - If the object already exists, reference it without rewriting.
   - If it is new, encrypt with AES-256-GCM using a fresh random nonce and AAD containing the object type and ID.
   - Store encrypted objects under fan-out paths.
   - Write an encrypted per-file manifest under a sharded manifest path.

3. Restore file.
   - Decrypt the relevant manifest.
   - Resolve the virtual path to ordered chunk references.
   - Decrypt each chunk with AEAD authentication.
   - Recompute the keyed object ID to detect wrong-object substitution.
   - Stream plaintext to the destination.

4. Resolve sync conflicts.
   - Load every encrypted manifest variant whose filename starts with the expected manifest ID.
   - Select the newest generation as the winner.
   - Preserve non-winning live versions as virtual `*.conflict-*` files.
   - Suppress older live manifests when a newer delete tombstone exists.

## Security outcomes

- Plaintext contents are encrypted before entering the vault directory.
- Virtual paths and file metadata are encrypted in manifests.
- Chunk objects and manifests are AEAD-authenticated.
- Wrong-object substitution is detected by AAD and by recomputing the keyed object ID after decryption.
- Password changes can be added later by rewrapping keys instead of rewriting all chunks.
- Chunk deduplication is scoped to a vault because object IDs are keyed.

## Compliance-oriented notes

This prototype can help demonstrate client-side encryption and separation of cloud-provider access from plaintext access, but production use still needs independent crypto review, key-management procedures, backup and recovery testing, incident response procedures, audit logging, retention controls, privacy impact assessment, and vendor/cloud contractual review.

## Trade-offs

| Decision | Benefit | Trade-off |
| --- | --- | --- |
| Cloud folder instead of provider API | Works with any provider | Depends on sync-client conflict semantics |
| Content-defined chunks | Good delta sync after edits | Leaks duplicate-chunk equality within one vault |
| Keyed object IDs | Avoids public content hashes | Reveals object count and approximate churn |
| Encrypted sharded manifests | Better sync behavior than one large index | More filesystem objects |
| AES-GCM random nonces | Authenticated and widely available | Dedupe comes from plaintext object reuse, not deterministic ciphertext |
| Browser GUI | Easy cross-platform deployment | Not a native toolkit UI |
| Local WebDAV fallback | No kernel driver required | Not as native as FUSE/WinFsp/macFUSE |
