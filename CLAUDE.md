# open-seavault-rclone — working agreement

Go module (`github.com/alexdimarco/open-seavault-rclone`), GPL-3.0-or-later. A
cross-platform client-side-encrypted vault. CI runs on Linux with Windows and
macOS cross-builds — keep everything path-portable; never commit symlinks.

## Testing discipline (non-negotiable)

- The test command is `make test` (= `go test ./...`); an "unfiltered run" means
  that command with no -run/package filters.
- DESIGN.md and SECURITY.md are the normative pair. The package test suites under
  `internal/` and `cmd/` are the invariant list. NEVER weaken a gate, delete a
  test, add a suppression, or edit a fixture to make a test pass. A red gate means
  the code is wrong until a human says otherwise; if you believe the gate itself
  is wrong, STOP and say so instead of routing around it.
- A test that exercises nothing must FAIL: table-driven tests assert on every row;
  empty/zero results are failures, not vacuous passes. Real binaries over mocks:
  the rclone/rsync wrappers are tested against argv hygiene and real process
  behavior; mocks are for tempdirs, fault injection, and privilege boundaries only.
- Crypto paths use real primitives, never stubs: encrypt/decrypt round-trips are
  asserted on real data, and decode boundaries return typed errors, never crash.
- Every fix ships prove-fail -> prove-pass: write the regression test, neutralize
  the fix, confirm it FAILS for the right reason, restore, confirm it PASSES,
  commit fix + test together. A regression test never seen red is not trusted.
- Security-sensitive changes (key handling, remote config, process guarding, any
  new API surface) owe an adversarial pass; every shippable feature owes a
  friction review; security- or architecture-relevant designs owe a pre-code
  design review. When your change owes one, SAY WHICH ONE and stop at the gate.

## Repo specifics

- Build/run helpers: `Makefile` (`make test`), `compileme.sh`, `scripts/`.
- Docs live in `docs/`; design docs for in-flight work are `docs/design-*.md`.
- Commit messages end with the Co-Authored-By trailer when Claude authors changes.
