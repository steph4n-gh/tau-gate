# Tau-Gate contributor guidance

Tau-Gate is a read-only dependency-change reviewer. The Rust core uses the standard library only and does not install packages, fetch archives, or execute dependency code. Network acquisition and pull-request orchestration live in separate Python helpers. See the [README](README.md) for current formats and the [review contract](docs/review.md) for limits.

Keep unsupported or ambiguous input incomplete. A topology estimate is diagnostic, not evidence that code is safe. npm execution enforcement requires original-archive evidence and exact-instance approvals. A person reviews the candidate fingerprints and records those approvals. The tool does not approve execution by itself. Policy, helper, and workflow changes are merged by a repository administrator after review. See [docs/pr-review.md](docs/pr-review.md). pnpm and Yarn execution metadata remains unqualified.

Before changing a parser or evidence rule, add a focused behavioral case for the input and a rejection case for its nearest ambiguous form. Verify the Rust core and helper controls with the commands in the [README](README.md#validation-and-scope). The [input robustness harness](fuzz/README.md) and [qualification record](docs/qualification/PROGRAM.md) describe the broader checks and their limits.

For releases, use the [pinned Linux build and independent verification procedure](docs/release-verification.md). A local `cargo build` or the retired `reproduce.sh` does not establish byte-for-byte reproducibility. Keep release, coverage, and safety claims within the measured evidence.
