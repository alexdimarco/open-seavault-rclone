# Remote repository threat model

## Assets protected

SeaVault protects:

- file contents
- virtual paths and encrypted manifests
- chunk references
- vault metadata needed to authenticate encrypted objects

## Assets not hidden

The remote provider can still observe:

- existence of the `.seavault` repository
- approximate vault size
- number of objects
- object churn
- upload and download timing
- source IP address and account identity

## Main design controls

| Threat | Control |
|---|---|
| Cloud provider reads files | Client-side AES-GCM encryption before transport |
| Provider sees plaintext names | Virtual paths are stored inside encrypted manifests |
| Interrupted transfer corrupts repository | Immutable chunks plus copy-safe transport; manifests are separate |
| Accidental remote deletion | `rclone copy` by default; destructive sync disabled in GUI |
| Runtime tampering | Managed rclone hash recorded and verified |
| Credential exposure in logs | Config and command outputs are redacted |
| Multi-device conflict | Conflicting manifests are preserved instead of silently overwritten |

## Canadian public-sector validation points

Security outcomes and compliance evidence are different. Client-side encryption reduces provider-side exposure, but it does not by itself satisfy Canadian public-sector governance requirements.

Validate:

- remote hosting country and region
- backup and replica region
- support access location
- administrative access controls
- subprocessors
- logging and audit retention
- breach-notification terms
- records retention and legal hold process
- endpoint key-management procedure
- lost-device recovery and revocation
