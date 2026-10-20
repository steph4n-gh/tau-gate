# Changelog

## 4.1.0 (unreleased)

- Added an independent npm reference check using original archives and scripts-disabled installs. It covers aliases, nested versions, workspaces, optional omissions, native defaults, and substituted evidence.
- Added offline, bounded SHA512, gzip/DEFLATE, and strict ustar verification to the standard-library-only Rust core. The core derives lifecycle and native-build facts from original archives and explicitly trusted source snapshots.
- Added exact-instance approval fingerprints and execution-evidence diffs. Source, integrity, artifact, manifest, lifecycle, and native-input changes invalidate approvals.
- Added a separate PR helper that captures exact Git objects, uses base-only approvals, and emits deterministic JSON and Markdown with allowed, blocked, and incomplete outcomes. Added real-Git behavioral tests and a read-only CI example with an explicit trusted-tool bootstrap.
- Tightened `--enforce` to require explicit evidence and bound approvals. Legacy coordinate whitelists no longer authorize execution. Missing or conflicting evidence remains incomplete, ahead of blocked policy.
- Qualified a conservative direct-archive URL and portable ASCII tar profile. Git preparation, unsupported archives, and filesystem aliases remain incomplete. pnpm/Yarn execution qualification and the native graph ABI are unchanged.

## 4.0.0

τ-Gate 4.0.0 is the first release under the Apache License 2.0. The dependency-review behavior is the behavior already on `main` after the `v3.0.0` tag. The crate version was still `3.0.0` until this release. Git tags `v3.1.0` and `v3.2.0` point at older commits and are not this version. After merge, tag **`v4.0.0`**.

### License

- Relicensed from the PolyForm Noncommercial License 1.0.0 to the Apache License 2.0 (`license = "Apache-2.0"`).
- Versions released before 4.0.0, including the `v3.0.0` tag, remain under PolyForm Noncommercial 1.0.0.

### Dependency review

This is the first versioned release that includes the qualified read-only review work landed after `v3.0.0`:

- npm lockfileVersion 3: installed instances, nearest `node_modules` targets, workspace links, declared install markers, and supplied root lifecycle script bodies.
- pnpm lockfileVersion 9.0: namespaced environment and project documents, importer and workspace links, exact snapshot versions, aliases, and peer and patch context. Positive build markers are kept. Transitive script metadata is unknown, so the report stays incomplete and exits 2, including with `--enforce`.
- Yarn Classic v1: exact descriptor groups, aliases, version, resolved URL, integrity, and dependency and optional maps. A supplied root manifest provides root edges. Transitive scripts are unknown (exit 2). Yarn Berry and unsupported Classic record fields are rejected.
- Base/head comparison reports version, source, integrity, and execution-marker changes, with introducer paths. Same-version artifact changes are reported. Comparisons require the same lockfile format.
- Explicit `--enforce` blocks unapproved execution markers. Approvals are exact `name@version` and do not pin artifact digests.
- Audit is read-only: it does not resolve, install, delete inputs, or write logs.

Bun, Go, the Cargo CLI, and Yarn Berry are not supported. Cargo metadata parsing remains an incomplete library preview. There is no immunity claim and no formal safety proof.

### Removed

- Unused public stubs `tau_gate::daemon` and `tau_gate::network`, and `DepGraph::build_from_network`. They only returned errors and were not on the review path. `tau-gate daemon` is still a usage error (exit 64). `--network` is still incomplete (exit 2).
- The spectral estimate used by the JSON `topology` field and the C ABI is unchanged.

### Housekeeping

- `SECURITY.md` tells reporters to email stephan@orioletech.llc.
- Historical documents that claimed verified Bun, Yarn Berry, or Cargo support, immunity, or a PolyForm strategy are marked outdated. The PolyForm argument is withdrawn.
- Local scratch was removed, including an error log that contained a machine path and accidental nested clones from one-off audits.
