# Eight losses and fresh repository validation

The bridge-assisted candidate reduces the original eight ratio-cut losses to one. The fresh test supports an incremental spectral contribution on unseen projects: pure spectral cuts beat the fixed basic method on 26 of 83 primary projects, tie 52 and lose 5. All 26 wins reduce ratio cut by more than 1%; the median reduction among those wins is 22.6%. Combining spectral and bridge cuts gives 26 wins, 57 ties and zero losses. Bridge recovery is structural; it is not counted as a new spectral win.

This supports structural grouping against this specified BFS/bridge/degree baseline. It does not establish superiority over every graph algorithm, maliciousness detection, or better human review outcomes.

## Why the remaining eight lost

Numerical checks found no separating projection for the best basic partitions in the tested two-direction embedding. Expanding to 16 regular projection axes recovers none of the eight; linear feasibility checks find no positive separation margin for those basic partitions in the tested approximate Ritz space. Those checks are numerical diagnostics, not a general impossibility theorem. Splitting components of the four best cuts recovers only two.

Seven basic winners are one-edge bridge cuts. The simplest supported improvement is an exact bridge scan alongside the unchanged spectral family. It searches all bridges, instead of adding more angles or case-specific rules. The remaining async winner crosses three edges and is a BFS subtree. The candidate improves async ratio cut from 0.12866748 to 0.12619904, still worse than the basic 0.11082836. It does not add a duplicate of the entire basic candidate family to manufacture zero losses.

The bridge scan uses iterative low-link DFS, skips exactly one parent occurrence to respect parallel and reciprocal edges, and stores subtree intervals. It adds O(n+m) work and O(n) state, with no recursion, dependencies or eigensolver iterations. Ratio cut selects the primary partition, with conductance as tiebreaker and spectral provenance retained on equality. The conductance alternative remains a separately selected partition.

`topology.cut_diagnostics.source` identifies `spectral` or `bridge`. A bridge has null projection; its prior spectral result appears as `spectral_alternative`. A bridge alternative has null JSON threshold. The legacy C layout is unchanged and uses tau 0 for structural cuts. Public Rust projection fields become the typed `CutOrigin`, a source compatibility change for direct Rust callers. The first Rayleigh score, convergence semantics, tolerance and work caps remain unchanged. This is a local source change, not a qualified release.

## Prospective protocol and freshness

All original 152 inventories were development evidence for this step. Candidate code, comparators, objective, eligibility, resource limits and cohort selection were frozen before collecting fresh project snapshots. The [protocol](math-fresh-protocol.md) and [decision trail](qualification/math-fresh-validation-20261109.tsv) record the details.

The cohort contains 200 canonical GitHub repository identities not present among any of the original 200. It is the next distinct GitHub slice in the same pinned heatmap/ecosyste.ms critical npm ranking, spanning package ranks 578–871. Redirect aliases are deduplicated. Failed/no-lock projects are retained rather than replaced to reach a desired number of successful scans. All 200 were accessible in this acquisition; 105 contained locks in the fixed discovery scope and 95 did not. The 105 repositories supplied 109 lock inventories.

One primary lock per repository was preselected by fixed filename priority. Primary cases require a complete connected graph with more than one node, converged first-direction diagnostics and an independently matching numerical reference. Exact labeled undirected multigraph overlaps with old or preceding primary graphs are excluded; none occurred among the otherwise eligible primaries here. Shared transitive packages and graph isomorphism are not excluded. The primary sample is 83 projects, not 200 successful math comparisons.

| Accounting for 109 lock inventories | Count |
| --- | ---: |
| Primary projects | 83 |
| Additional eligible locks in the same repositories | 3 |
| Incomplete topology | 6 |
| No parsed graph | 5 |
| Disconnected graphs | 10 |
| Singletons | 2 |
| Numeric validation failures /  study resource limits /  evaluation failures | 0 |

The five no-graph cases remain visible: googleapis/google-cloud-node-core and vercel/arg have unsupported pnpm fields; webpack/node-libs-browser has an invalid resolved field under current rules; lukeed/sirv supplies a non-UTF8 lock; quantizor/markdown-to-jsx is rejected by the current JSON parser. No parser was changed to improve the fresh denominator after exposure.

Independent preflight review produced two amendments before acquisition: preserve per-case failures and pin comparator hashes/profile accounting. A third harness correction occurred after snapshot acquisition started but before any fresh outcome evaluation. Parser CLI graph order differs from the canonical sorted-label C-ABI graph order; initial solver directions depend on index. The correction separates CLI provenance/profiles from canonical scoring and checks each against its own comparator. Candidate code, selection, eligibility and acceptance rules did not change. Every prior freeze is preserved and linked by hash. The cohort points to the acquisition freeze; the fresh result points to the final pre-evaluation freeze. No candidate or harness code changed after fresh outcomes were exposed.

## Results against the fixed basic method

The unchanged basic method considers deterministic rooted BFS-subtree cuts, including bridges/components, and degree thresholds. Candidate families have different search budgets. The primary comparison uses the same canonical sorted-label node ordering as the original study; CLI profiles below are separately labeled.

| Corpus and objective | Pure spectral wins /  ties /  losses | Bridge-assisted wins /  ties /  losses |
| --- | ---: | ---: |
| Original 118 eligible graphs: ratio cut | 33 / 77 / 8 | 33 / 84 / 1 |
| Fresh 83 primary projects: ratio cut | 26 / 52 / 5 | 26 / 57 / 0 |
| Fresh 86 eligible locks: ratio cut | 28 / 53 / 5 | 28 / 58 / 0 |
| Fresh 83 primary projects: conductance | 28 / 40 / 15 | 24 / 43 / 16 |

The fresh primary sample selects 78 spectral cuts and 5 bridge cuts. The five bridge recoveries are useful, but the hybrid's absence of ratio losses is not itself proof of mathematical value: bridges are already among the basic candidates. The evidence for an additional spectral contribution is the 26 strict wins over the full basic family. All 26 exceed 1% relative ratio improvement; the smallest is 2.14%. The median 22.6% gain describes those 26 wins only; the median across all 83 cases is zero because most tie.

Examples make the structural effect concrete:

| Fresh project | Nodes | Basic ratio cut | Spectral ratio cut | Reduction |
| --- | ---: | ---: | ---: | ---: |
| mapbox/node-pre-gyp | 494 | 0.07900208 | 0.02418901 | 69.4% |
| alexei/sprintf.js | 434 | 0.16900312 | 0.07437329 | 56.0% |
| alangpierce/sucrase | 465 | 0.20217391 | 0.12999720 | 35.7% |

For node-pre-gyp, the spectral cut separates 105 nodes across 2 edges; the best basic cut separates 13 nodes across 1 edge. The larger region has the better normalized boundary score. This is a structural fact, not evidence that either region is dangerous or semantically coherent.

The primary ratio objective still trades away conductance. Relative to pure spectral selection, fresh conductance improves once, ties 78 times and worsens 4 times: file-loader, graceful-fs, url-loader and node-portfinder. The separate parser-order CLI conductance profile beats the fixed basic conductance on 47 primary projects and ties 36. It uses a different cut and must not be substituted into the primary conductance result. Canonical and CLI selected-source counts happen to match; general equivalence across their node orderings is not asserted.

## Verification and limits

The new 36-node witness fails before at ratio 0.5625 and passes after at 36/68. Exhaustive four-node connected graph controls compare every one-edge cut, with extra parallel edges and self loops. All 139 Rust tests pass, along with Clippy, formatting, e2e, prove-it, 21 PR-helper tests and 4 optional Python math tests.

All 109 fresh CLI exit codes and non-topology reports match the frozen baseline. All 104 extracted graphs pass independent numerical checks. Five interleaved baseline/candidate repetitions are deterministic. No speedup claim is made. All 309 captured raw files and 204 source-context records match their receipts. Every case receipt matches the aggregate result.

On the original corpus, all 152 CLI exits/non-topology reports and all 145 historical scalar/combined alert decisions remain unchanged. Historical artifact-event detection therefore remains 1/4 scalar and 2/4 combined, versus 4/4 exact artifact metadata. There are no fresh harmfulness, artifact-event or human-review labels in this study.

The evidence supports a useful combination of spectral and basic structural methods on this held-out ranked npm slice. It is not a random population sample, another ecosystem, or proof of generalization to every dependency graph. Five parser rejections and six incomplete inventories also limit coverage. Future tuning consumes this cohort as development data; another prospective claim needs another untouched cohort.

Local evidence lives in `ecosystem_audit/math-fresh-validation-20261109`: preserved freezes, old/fresh evaluations, all 200 snapshot records, 109 case receipts, source hashes, numerical references, tests, `receipt.json`, `results.json`, `REPORT.md` and independent `REVIEW.md`. Large inputs remain ignored by Git; a fresh checkout needs that corpus to reproduce the full result. `tools/math_fresh_validation.py` acquires/evaluates without installs; `tools/math_fresh_report.py` verifies the completed receipts and emits the report without rerunning the experiment.
