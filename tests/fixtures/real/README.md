# Frozen real lockfile fixtures

These generated lockfiles and root manifests are test data, never an instruction to install packages or execute scripts. Licenses and exact provenance are adjacent. `provenance.json` records source commit and input hashes plus independent node, typed-edge and artifact-table SHA-256 oracles.

Hono's pnpm v9 fixture contains separate environment and project documents. Yarn's fixture is from Yarn Classic 1.22.22. Both have unknown transitive execution metadata. Supported topology is a resolution snapshot, not an installed node_modules tree or artifact-body verification.

Canonical oracle encoding sorts rows lexically, then appends a newline to every row: node labels; `from<TAB>to<TAB>kind`; `label<TAB>name<TAB>version<TAB>source<TAB>integrity`. Artifact source for pnpm is deterministic JSON of observed non-integrity resolution fields; no registry URL is inferred. Oracle tables were built independently with PyYAML and, for Classic grouped selectors, CSV preprocessing. The core parser did not generate expectations.
