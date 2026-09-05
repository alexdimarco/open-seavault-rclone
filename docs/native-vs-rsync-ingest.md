# Native vs rsync ingest

Native ingest is the recommended default. It avoids external tool dependencies and works consistently on Linux, macOS, and Windows.

Use managed rsync when you want a project-controlled local staging helper and a repeatable runtime version. Use system rsync only for administrator-controlled environments where PATH and runtime versions are already managed.

## Decision guide

| Situation | Recommended mode |
|---|---|
| Normal GUI upload | Browser upload |
| Very large local folder with typed path | `native` first, then `auto` if rsync staging is desired |
| Enterprise desktop build with packaged runtime | `managed-rsync` or `auto` |
| Linux/macOS workstation with known rsync | `system-rsync` or `auto` |
| Windows without packaged rsync | `native` |

## Safety

All modes encrypt into `.seavault`. None of the modes should place plaintext inside `.seavault`. Temporary staging directories are removed after import unless a development/debug option keeps them.
