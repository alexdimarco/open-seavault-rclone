# Pre-code design review — Phase U1: the setup wizard

**What was reviewed:** `docs/design-setup-wizard.md` (Revision 1, pre-code) — a UI-agnostic `internal/setup` package (detect / plan / execute), a `seavault setup` CLI command with `--expert` and `--preset` forms, and a GUI first-run stepper.
**Repository / branch:** `open-seavault-rclone` @ `feature/setup-wizard`.
**Process run:** 10-lens pre-code design review (assurance-kit `process/design-review.md`): ten lens agents → skeptic pass → rescue pass → synthesis.
**Synthesis agent model:** claude-opus-4-8.

## Verdict: GO_WITH_CONDITIONS

No blocker survived both the skeptic and the rescue pass, so this is not a NO_GO. Everything that survived the skeptic is dischargeable by a Revision-2 design change applied before build. The rescue pass named no mechanism changes because no finding reached blocker status. Three independently re-verified facts anchor the material conditions: (1) `serveNoSession` returns **403**, not the 401 T6 asserts (server.go:742); (2) `docs/cloud-provider-notes.md` contains **no** caveat text to "lift from"; (3) `remote config create` writes only a header comment (remotes.go:323), so the rclone branch reaches no real backend from nothing.

The 14 numbered conditions are filed in full at `docs/review-setup-wizard-predesign.md`, each tagged with the findings it discharges and the test-matrix row the build must add or re-spec. The design is sound in shape (real shared `internal/setup` seam; reused KDF floor, recovery ceremony, keychain, profile, and session-auth primitives); the survivors are unbuilt-detail gaps, not architectural defects.

**Rescue outcome:** `{"rescues":[],"overall":"no blockers survived the skeptic pass; rescue not needed"}`.

The complete per-lens findings table, the refuted list with refuting quotes, and the conditions→test-row mapping are in the filed report at `docs/review-setup-wizard-predesign.md`.
