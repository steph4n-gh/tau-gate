# Frozen 200-project parser replay

The November 9, 2026 replay reads **all 152 discovered lockfiles**, up from 102. **148 have complete topology**, up from 92. The remaining four inputs produce inventories with specific disagreements or missing references. No reader rejects remain in this frozen cohort.

| Format | Lockfiles | Parsed before | Parsed now | Complete topology before | Complete topology now |
| --- | ---: | ---: | ---: | ---: | ---: |
| npm v1 | 6 | 0 | 6 | 0 | 6 |
| npm v2 | 21 | 0 | 21 | 0 | 20 |
| npm v3 | 60 | 60 | 60 | 57 | 58 |
| pnpm v6 | 1 | 0 | 1 | 0 | 1 |
| pnpm v9 | 38 | 30 | 38 | 26 | 38 |
| Yarn Classic v1 | 13 | 12 | 13 | 9 | 12 |
| Yarn Berry | 13 | 0 | 13 | 0 | 13 |
| **Total** | **152** | **102** | **152** | **92** | **148** |

The set contains 200 distinct repository identities, selected by the best-ranked npm package from the pinned heatmap dataset. It reaches package rank 577; it is not the original 200 package names collapsed into a few monorepos. Repository redirects were deduplicated. The replay preserves the original commits and discovery results: 149 repositories have 152 locks, 49 have no project lockfile within the recorded discovery scope, and two GitHub repositories were unavailable. Of the 149 with locks, 145 have complete topology for every discovered lock, one has a mixture, and three have no complete lock. The mixed repository is Less, whose pnpm lock resolves while its npm lock disagrees with the manifest.

## Changes and retained limits

npm v1 now preserves the recursive installed hierarchy, exact nearest targets, aliases, sources and integrity. Root dependency kinds come from the supplied manifest; transitive `requires` edges retain an explicitly unknown kind. npm v2 uses its authoritative `packages` map. A linked local target may omit a version, without excusing missing registry-package versions. The [npm lockfile specification](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/) describes those format distinctions.

pnpm v6 reads dependency edges embedded in package records; v9 retains separate snapshots and environment/project namespaces. Both preserve exact peer/patch contexts, aliases and typed references. Observed checksum fields, importer directory settings, build metadata and runtime platform resolutions are retained. Supplied configuration verifies unconditional overrides and source catalog replacements. Publish-directory links resolve only to a unique declared importer; other local links require supplied manifests. Unencoded dependency placement stays unresolved.

Yarn Classic now accepts the observed `uid` field, explicit local links and source workspaces. Workspace selection uses conservative supported semver comparisons, including validated exact prereleases; unsupported combinations remain unresolved. Missing declared exact workspaces remain incomplete. Berry supports emitted metadata versions 6, 8 and 10, exact descriptor groups/locators, catalogs, resolutions, patch bindings, optional metadata and peer constraints. Source manifests recover workspace development/optional kinds; absent source uses a neutral `workspaceDependencies` kind. Cache checksums are retained as Yarn cache checksums, never npm archive SRI.

Project context is explicit through `--project-inputs`, or separate base/head indices. The core hashes the index and every supplied file, rejects conflicting root manifests and unsafe locators, and performs no filesystem discovery, network resolution, installation or lifecycle execution. The experiment supplied 2,903 source files from the same frozen commits. Its receipts retain acquisition diagnostics, including truncated trees fetched through explicit pnpm targets and generated publish directories absent from Git. Supplied context is not proof of a complete filesystem or host installation. See the [input contract](review.md#explicit-project-inputs).

Execution qualification and evidence-bound approvals remain **npm v3 only**. Added formats remain incomplete for execution, even when topology is complete. Berry peer constraints do not establish installed peer placement. The audit retains every lock record; it does not predict platform or install selection. This is measured coverage of the observed formats, not universal support for all possible lockfile syntax or ecosystems.

## Four remaining input findings

| Repository / lock | Evidence | Outcome |
| --- | --- | --- |
| `less/less.js` / npm v3 | Root manifest declares `@typescript-eslint/eslint-plugin`, `@typescript-eslint/parser` and `eslint`; the lock root omits them. | Preserve manifest/lock disagreement. Its pnpm lock is topology complete. |
| `webpack/webpack-dev-middleware` / npm v3 | Lock root declares `ws: 8.22.1`; root manifest omits it. | Preserve manifest/lock disagreement. |
| `react/create-react-app` / npm v2 | `fork-ts-checker-webpack-plugin` and `tsutils` require TypeScript peers; no TypeScript target record exists in the supplied lock. | Preserve two unresolved peer edges. |
| `meta/flow` / Yarn Classic | `packages/flow-remove-types/package.json` requires `flow-enums-runtime@^0.0.6`, `flow-parser@^0.339.0` and `source-map-support@^0.5.21`; their required descriptor/workspace targets are absent. | Preserve three unresolved source references. |

These are input consistency or resolution findings, not malware or vulnerability determinations. No repository inputs were repaired to make the experiment pass.

## Verification and reproducibility

The replay contains 150,982 package records and 334,283 directed topology edges. Independent Python JSON/PyYAML and official Yarn readers checked all 152 lockfile inventories: 150,862 record identities (including ten source-derived pnpm local links), 250,916 npm/pnpm typed edges and 45,882 Yarn descriptors. Locked artifact fields were compared for npm/pnpm records and Yarn descriptors; the ten pnpm local links were additionally checked against their supplied source manifests. Source-added Yarn roots/workspaces account for the additional 120 records. Yarn checks compare complete descriptor/artifact inventories, not an independent edge resolver. Tests cover source-derived Yarn edges and their ambiguous forms. No project dependency installation or host-selection agreement was tested.

The repaired solver reports residual convergence for all 152 inventories. Its source is byte-identical to the completed math evaluation; this does not extend that study's evidence of incremental review value. Residual convergence remains distinct from certification of the second eigenpair. See the [math evaluation](math-evaluation.md).

Validation passed: 132 release Rust tests, formatting, Clippy with warnings denied, CLI fixtures (`e2e_zero.sh`, `prove-it.sh`) and 21 PR-helper tests. Independent review reproduced three Yarn attribution defects; focused tests failed before their fixes and passed afterward. Review also checked npm/pnpm preservation, source confinement/hashes and the npm-v3-only evidence boundary.

The measured parser candidate is core commit `dcd985e97aa2bea50428a9df3562f8bc0eb700bb`. Local macOS arm64 checker SHA-256: `ff21799d859da084e586bad19589b2593a8a91f0935f0d075c740febeea40ab6`. This is local validation, not hosted CI, publication or a new release qualification.

Frozen local evidence is under `ecosystem_audit/parser-expansion-20261109/`: `candidate/receipt.json`, `sources.json`, `replay.json`, `independent-inventories.json`, `findings.json`, `projects.json`, `REPORT.md`, validation logs and independent review. The 200-row report accounts for every selected repository. A [committed decision trail](qualification/parser-expansion-20261109.tsv) records the checkpoints; its evidence paths refer to the local experiment directory. Independent cross-model review ended with no unresolved findings. Original evidence remains under `ecosystem_audit/top200-repositories-20261109/`. Large downloaded inputs and generated reports are local experiment artifacts; they are not included in Git.

With those frozen inputs present, regenerate the experiment using the external helpers:

```sh
python3 -m venv /tmp/tau-parser-reference
/tmp/tau-parser-reference/bin/pip install -r tools/parser-requirements.txt
npm install --prefix /tmp/tau-yarn-reference --ignore-scripts --no-audit --no-fund \
  --save-exact @yarnpkg/lockfile@1.1.0 @yarnpkg/parsers@3.0.3

/tmp/tau-parser-reference/bin/python tools/parser_corpus.py acquire \
  --corpus ecosystem_audit/top200-repositories-20261109 \
  --output /tmp/tau-parser-replay
/tmp/tau-parser-reference/bin/python tools/parser_corpus.py replay \
  --corpus ecosystem_audit/top200-repositories-20261109 \
  --output /tmp/tau-parser-replay --binary /path/to/pinned/tau-gate
/tmp/tau-parser-reference/bin/python tools/parser_reference.py \
  --output /tmp/tau-parser-replay \
  --node-modules /tmp/tau-yarn-reference/node_modules
/tmp/tau-parser-reference/bin/python tools/parser_corpus.py summarize \
  --corpus ecosystem_audit/top200-repositories-20261109 \
  --output /tmp/tau-parser-replay
```

Acquisition uses read-only GitHub APIs/raw files at original commits and may require authenticated `gh` for repository trees. Reference npm installation above installs only the parser utilities in an isolated tool directory, with scripts disabled. It does not install or run any scanned project. The Rust auditor remains standard-library-only and offline.
