# Tau-Gate: Explainable dependency-change review

Tau-Gate reviews frozen **npm v3, pnpm v9 and Yarn Classic v1 lockfiles** before dependency changes are accepted. It shows which dependency records changed version, source, integrity metadata or execution markers, and the dependency paths that introduced them. Its Rust core uses only the standard library.

A completed report means extraction completed within the stated snapshot scope. It does **not** mean code is safe. With explicit npm evidence, v4.2 verifies original archive bytes and inventories lifecycle bodies and native-build inputs. Without that evidence, dependency install markers remain advisory and an absent marker leaves execution unknown. All lockfile records are included, including dev and optional packages. Host installation selection and runtime behavior are not simulated.

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
| npm v3 | Installed lockfile instances, nearest node_modules targets, workspace links | Original archive and source-snapshot evidence when supplied; otherwise advisory markers |
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

## npm evidence and bound approvals

Collect original archives and source manifests with the separate Python helper. The Rust auditor independently verifies their binding to the lock and derives execution facts. It runs offline and never installs, extracts, invokes programs, or writes files.

```sh
python3 tools/npm_evidence.py collect \
  --lock package-lock.json --project . --output /tmp/tau-gate-evidence
/path/to/tau-gate audit --lock package-lock.json --manifest package.json \
  --evidence /tmp/tau-gate-evidence/index.json --json
```

Review the candidate fingerprints before recording approvals in the [explicit approval schema](docs/execution-evidence.md#approval-schema-and-outcomes). Then enforce that policy.

```sh
/path/to/tau-gate audit --lock package-lock.json --manifest package.json \
  --evidence /tmp/tau-gate-evidence/index.json \
  --approvals .tau-gate/approvals.json --enforce --json
```

Approvals bind the exact instance, source, integrity, original archive, manifest bytes, lifecycle bodies, and native metadata. Changed evidence needs approval again. Workspace targets require one approval, while their structural links remain visible. Missing, conflicting, or unsupported evidence takes precedence over approvals. Legacy coordinate whitelists cannot authorize v4.1 enforcement. Existing configuration values are still validated for compatibility.

For pull requests containing root or workspace install scripts, use the [trusted Git PR helper](docs/pr-review.md). It additionally binds the entire tracked source tree because an unchanged lifecycle command can run changed local script files.

The qualified archive profile is deliberately narrow. It requires SHA512 SRI, direct HTTP(S) archive sources, a single gzip member, and portable ASCII ustar paths. Unsupported source kinds, archive extensions, or ambiguous paths remain incomplete. Source manifests retain caller trust. Integrity does not authenticate a publisher or establish artifact safety. See the [execution contract](docs/execution-evidence.md) and [collection and independent checks](docs/npm-reference.md).

| Exit | Meaning |
| --- | --- |
| 0 | Completed advisory report, or all qualified candidates approved |
| 1 | Complete evidence with an unapproved execution candidate |
| 2 | Incomplete extraction/evidence, missing enforcement inputs, or invalid input/configuration |
| 64 | Invalid command/options |

## Review exact Git revisions

The separate [PR helper](docs/pr-review.md) captures lockfiles, source manifests, and native inputs directly from base and head Git objects. Dirty working files cannot change the captured bytes. The approval file always comes from the trusted base revision. A head-side approval edit cannot approve its own new fingerprints.

The helper writes deterministic `report.json` and `summary.md` into an explicit output directory outside the repository. It preserves allowed, blocked, and incomplete outcomes. [The CI example](docs/examples/npm-pr-review.yml) uses read-only permissions and trusted base tools. It requires a supplied checker binary with a pinned hash and a trusted workflow configuration. It is an example for npm applications, not an active npm job in this Rust repository.

## Topology and native interface

The sparse solver returns a bounded **Rayleigh estimate**, residual, convergence flag and iteration count. Residual convergence does not certify the second eigenpair. A disconnected graph's zero connectivity is handled exactly. Topology cannot distinguish benign and malicious code with the same dependency shape and is never used to hide execution candidates or certify safety.

The C ABI is documented in [include/tau_gate.h](include/tau_gate.h). NULL names and invalid endpoints/counts are rejected; a NULL edge pointer is accepted for zero edges. Result ownership is explicit. The existing four-field result prefix and appended diagnostics are retained. v4.1 does not change this interface or the solver. Valid pointers remain the caller's responsibility. The former index-based daemon pruning policy is retired; no TSP/MLX workload benefit is claimed or validated by these tests.

## Validation and scope

```sh
cargo test --release --offline --all-targets
cargo fmt -- --check
./e2e_zero.sh
./prove-it.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_pr_review.py' -v
```

Tests cover input preservation, missing/unsupported extraction, nested/workspace resolution, optional/peer/dev paths, strict Unicode JSON, configuration validation, archive verification, evidence-bound approval invalidation, all-candidate reporting, FFI ownership and solver nonconvergence. [The independent npm reference and core corpus](docs/npm-reference.md) provide separate replay commands. See [docs/review.md](docs/review.md) for the contract. Older research/marketing documents and ecosystem scripts are historical, unverified prototypes, not current validation evidence. Each of those documents is marked outdated at the top. Do not cite them for supported formats, safety, or the license.

There is no formal safety proof, immunity claim, XZ detector, automatic quarantine or validated VRAM optimization here. The strongest current use is an explainable dependency-change review. Further qualification needs representative projects, host installation agreement, and benign/adversarial controls with simple baselines. pnpm and Yarn execution evidence remains unqualified.

## License

τ-Gate 4.0.0 and later are distributed under the [Apache License 2.0](LICENSE). Copyright 2026 Stephan Arrington / ORIOLETECH LLC. See [NOTICE](NOTICE).

Versions released before 4.0.0, including the `v3.0.0` tag, were distributed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). Those terms apply only to those earlier versions. This tree, and releases from 4.0.0 onward, are Apache-2.0.

Report security issues as described in [SECURITY.md](SECURITY.md).
