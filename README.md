# Tau-Gate: Explainable dependency-change review

Tau-Gate reviews frozen **npm v3, pnpm v9 and Yarn Classic v1 lockfiles** before dependency changes are accepted. It shows which dependency records changed version, source, integrity metadata or execution markers, and the dependency paths that introduced them. Its Rust core uses only the standard library.

A completed report means extraction completed within the stated snapshot scope. It does **not** mean code is safe. Installation markers are review evidence, not malware findings. Downloaded artifacts, dependency script bodies and runtime behavior are not inspected; an absent marker does not prove absence of execution. All lockfile records are included, including dev and optional packages; host installation selection is not simulated.

## Try the review

```sh
cargo build --release --offline
./target/release/tau-gate review --base examples/review/base.json --head examples/review/head.json
./target/release/tau-gate review --base examples/review/base.json --head examples/review/head.json --json
```

The fixture changes `bridge` integrity at the **same version** and adds an install marker to `leaf`. `leaf` appears via `root → bridge → leaf` even with an unrelated disconnected package. `test-tool` is separately reported through a dev dependency. The sources and integrity strings are synthetic; no artifact safety claim follows from this example.

For a project with an existing npm lockfile:

```sh
/path/to/tau-gate audit --lock package-lock.json --manifest package.json --json
```

Capture base/head lockfiles and their root manifests from the revisions you intend to review. Providing both manifests also detects root lifecycle script body changes; omitting manifests is explicitly a format-specific `*_lock_snapshot_only` scope. Reports contain SHA-256 hashes of every consumed lockfile and manifest, full package identities, dependency edge kinds, declared execution candidates and shortest introducer paths. Changed packages also show their before/after introducing paths. JSON output is deterministic for the same bytes and options.

Audit is read-only: it never resolves, installs, deletes inputs or writes logs. `--dry-run` remains a compatibility alias. Missing inputs, malformed data, manifest disagreement, unresolved required dependencies and unqualified formats produce an incomplete report and exit 2. Network resolution and the old daemon are retired. Bun, Go, Cargo CLI and Yarn Berry are unsupported. Cargo metadata parsing remains an incomplete library preview. Multiple detected lockfiles require an explicit --lock.

## pnpm and Yarn coverage

| Format | Identity and supported topology | Execution metadata |
| --- | --- | --- |
| npm v3 | Installed lockfile instances, nearest node_modules targets, workspace links | Declared install markers; supplied root lifecycle bodies |
| pnpm v9 | Namespaced environment/project documents, importer/workspace links, exact snapshot versions, aliases, peer/patch contexts and observed resolution metadata | Transitive scripts unknown; positive build markers retained |
| Yarn Classic v1 | Exact descriptor groups, aliases, version/resolved/integrity and dependency/optional maps; supplied root manifest gives root edges | Transitive scripts unknown |

pnpm/Yarn snapshots are resolution records, not an installed node_modules tree; `installed_path` is null. Yarn root attribution is incomplete without a manifest, and workspace manifests/peer placement are not inferred. Classic records with rarer unsupported fields (including permissions/prebuiltVariants/uid/registry) are rejected visibly. See [supported contract](docs/review.md).

```sh
./target/release/tau-gate review --base base-pnpm.yaml --head head-pnpm.yaml --json
./target/release/tau-gate audit --lock yarn.lock --manifest package.json --json
```

These emit useful graphs/diffs but **exit 2** because dependency execution metadata is unknown, including with --enforce. A topology-complete pnpm/Yarn report explicitly contains:

```json
{"status":"incomplete","topology_status":"complete","execution_metadata_status":"unknown_transitive_scripts"}
```

Handle that exit code when capturing a report in a `set -e` script; inspect the JSON statuses and issues to distinguish unknown execution coverage from an unresolved graph. Comparisons require the same lockfile format because installed instances, peer-context snapshots and descriptor groups are different identities. Version changes in pnpm snapshot keys appear as removed/added records, rather than inventing an installed upgrade pairing.

Pinned real fixtures and independently computed node/edge/artifact hashes are checked into [tests/fixtures/real](tests/fixtures/real/README.md): Hono has 1,100 records and 1,545 typed edges; Yarn Classic 1.22.22 has 1,063 records and 2,074 typed edges. The tests never install dependencies or run fixture scripts.

## Optional marker policy

```toml
# tau-gate.toml; no wildcard matching or automatic trust list
whitelist = ["test-tool@1.0.0"]
```

```sh
./target/release/tau-gate audit --lock examples/review/head.json --enforce --json
```

Explicit `--enforce` blocks unapproved execution **markers**, checking every candidate independently of the spectral cut. Exact `name@version` approvals do not pin artifact digests. JSON states the outcome and unapproved coordinates. This is a limited marker policy, not a malware or artifact verification gate. Legacy `mode` and `threshold_percentage` configuration values are validated for compatibility but no longer select/block a topology policy; enforcement requires the flag.

| Exit | Meaning |
| --- | --- |
| 0 | Completed advisory report, or explicit marker policy allowed |
| 1 | Explicit marker policy blocked |
| 2 | Incomplete extraction or invalid input/configuration |
| 64 | Invalid command/options |

## Topology and native interface

The sparse solver returns a bounded **Rayleigh estimate**, residual, convergence flag and iteration count. Residual convergence does not certify the second eigenpair. A disconnected graph's zero connectivity is handled exactly. Topology cannot distinguish benign and malicious code with the same dependency shape and is never used to hide execution candidates or certify safety.

The C ABI is documented in [include/tau_gate.h](include/tau_gate.h). NULL names and invalid endpoints/counts are rejected; a NULL edge pointer is accepted for zero edges. Result ownership is explicit. The existing four-field result prefix is retained and diagnostics are appended. Rebuild bindings for the new fields. Valid pointers remain the caller's responsibility. The former index-based daemon pruning policy is retired; no TSP/MLX workload benefit is claimed or validated by these tests.

## Validation and scope

```sh
cargo test --release --offline --all-targets
cargo fmt -- --check
./e2e_zero.sh
./prove-it.sh
```

Tests cover input preservation, missing/unsupported extraction, nested/workspace resolution, optional/peer/dev paths, strict Unicode JSON, configuration validation, root script and same-version artifact changes, all-candidate reporting, FFI ownership and solver nonconvergence. See [docs/review.md](docs/review.md) for the contract and next work. Older research/marketing documents and ecosystem scripts are historical, unverified prototypes, not current validation evidence.

There is no formal safety proof, immunity claim, XZ detector, automatic quarantine or validated VRAM optimization here. The strongest current use is an explainable dependency-change review. Next priorities are manifest-backed dependency capabilities across formats, host installation agreement, digest-pinned approvals and representative benign/adversarial workloads with simple baselines.
