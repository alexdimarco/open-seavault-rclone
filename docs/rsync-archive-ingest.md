# Rsync-assisted archive ingest

SeaVault uses rsync as a local ingest helper, not as an encryption layer.

The CLI command:

```bash
seavault put --method auto VAULT SOURCE [VIRTUAL_PATH]
```

prefers rsync when it is available and falls back to the native Go ingest path when rsync is missing. Use `--method rsync` to require rsync, or `--method native` to bypass rsync.

## Why rsync is not allowed to write to `.seavault`

The encrypted vault format is not a plain directory mirror. Files must be split into content-defined chunks, encrypted, authenticated, and referenced from encrypted manifests. Rsync cannot create those encrypted objects directly.

The safe design is:

```text
source file/folder
  -> rsync copies to a temporary local staging directory
  -> SeaVault reads staged files
  -> SeaVault writes encrypted chunks and encrypted manifests into .seavault
  -> staging directory is deleted
```

The cloud provider or remote transport still receives only encrypted `.seavault` objects.

## GUI modes

The GUI supports two folder workflows:

1. Browser folder upload. This uses `<input type="file" webkitdirectory>` where the browser supports it and preserves the browser-provided relative path. The selected folder name is part of that relative path. If the selected folder is `Articles`, leave the virtual path blank or enter a parent folder such as `Archive`; do not also enter `Articles` unless `Articles/Articles/...` is intended.
2. Local path ingest. The GUI server runs locally and can read a user-provided local file or folder path. This mode supports `auto`, `rsync`, and `native` put methods. It remains useful for very large folders because browser folder pickers do not expose the real local disk path to JavaScript or the local GUI server.

The GUI displays selected-file and selected-folder summaries below the browser pickers. It also warns when the virtual path appears to duplicate the selected browser folder name. The rsync binary field is prefilled with the detected or usual rsync path for the current OS and can still be cleared to search `PATH`.

## Security notes

- Plaintext is never written into `.seavault`.
- Rsync-assisted ingest creates a temporary plaintext staging copy on the local client and deletes it after ingest.
- The source files are already plaintext on the client; the additional local staging copy is a local endpoint risk, not a cloud/server exposure.
- Do not use rsync-assisted ingest on shared or untrusted local machines unless temporary-directory policy and disk encryption are acceptable.
- Strict remote transport remains rclone/local-copy of encrypted `.seavault` only.
