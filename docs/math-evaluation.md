# Dependency-graph math evaluation

The solver repair passes the numerical checks on the available graphs from the frozen 200-repository cohort. Spectral partitioning sometimes improves a structural cut objective over the tested basic graph methods. This study does not establish better security decisions or faster human reviews.

Experiment date: November 9, 2026. Baseline source revision: `91728dd`. Reference runtime: NumPy 2.3.4 and SciPy 1.16.3, installed only in the ignored experiment directory. The Rust core retains zero external dependencies.

## What changed

The previous solver used a power iteration whose step size was constrained by maximum degree. It often exhausted its iteration budget before resolving the low end of the Laplacian spectrum. The replacement uses two search vectors, diagonal preconditioning, reorthogonalization against the constant vector, and a Rayleigh–Ritz update over at most six basis vectors. Its small projected eigenproblem uses Jacobi rotations.

The absolute residual threshold remains `1e-9`. The outer-iteration cap remains `min(5000, max(1, 20_000_000 / (nodes + directed_edges)))`. A block iteration does more work than an old power iteration, so equal iteration counts do not mean equal computational cost. Exhausting the budget still returns the measured residual and an explicit nonconvergence flag. Disconnected and singleton graphs retain their exact zero-connectivity result.

The C ABI layout, dependency extraction, execution evidence, and approval policy are unchanged. The maximum-gap partition rule is unchanged. Math still operates on an undirected view of the graph and does not incorporate edge kinds into its operator.

## Numerical results

The same 200-project cohort supplies 102 graph inventories, of which 92 have complete topology within their reported scope. The other projects retain their acquisition, missing-lock, or unsupported-format outcomes. No parser coverage was added.

Repositories were split by a fixed hash before algorithm selection: 29 graph inventories for development and 73 held out. Only development cases were used to select the solver. Comparison uses identical canonical node ordering for each solver, with five alternating native calls per case.

| Check | Baseline | Final candidate |
|---|---:|---:|
| Convergence criterion met, all available inventories | 17 / 102 | 102 / 102 |
| Iterative solves meeting the criterion | 2 / 87 | 87 / 87 |
| Held-out inventories meeting the criterion | 13 / 73 | 73 / 73 |
| Complete-topology held-out inventories meeting the criterion | 11 / 67 | 67 / 67 |
| Agreement with independent reference eigenvalues | 17 / 102 | 102 / 102 |

Fifteen cases use the exact disconnected/singleton shortcut, rather than an iterative solve. Candidate maximum absolute eigenvalue error against the reference was below `4.52e-16`; the maximum reported residual was below `1e-9`. All five repetitions per graph were deterministic. Forty separately generated connected graph controls also agreed with the numerical reference.

The reference constructs the weighted symmetric Laplacian independently and uses dense `eigh` for small cases and ARPACK shift-invert for larger connected cases. It checks its own eigenvector residuals. The native ABI does not expose the candidate eigenvector, so the corpus harness checks native eigenvalues and reported residuals, rather than independently reconstructing every native-vector residual. Analytic tests and the bounded-budget regression separately check the residual calculation. These checks do not constitute a formal eigenpair certificate.

Evidence: [frozen inputs and split](../ecosystem_audit/math-evaluation-20261109/graphs.json), [five-run comparison](../ecosystem_audit/math-evaluation-20261109/comparison.json), and [additional numerical controls](../ecosystem_audit/math-evaluation-20261109/numerical-controls.json).

## Structural value over basic graph methods

The basic methods consider every subtree cut of a deterministic rooted BFS spanning tree in each component, including bridge-separated branches, plus degree-threshold cuts. They receive the same graph as the spectral method. Each basic method's best candidate is selected separately for each structural objective. Smaller ratio cut and conductance values are better under those mathematical definitions. Partition balance and crossing-edge counts are retained as well.

The primary comparison contains the 57 connected, topology-complete held-out graphs. Disconnected graphs and incomplete inventories remain in the artifacts but are excluded from this structural-quality comparison.

| Objective | Spectral better | Equal | Basic methods better |
|---|---:|---:|---:|
| Ratio cut | 9 | 32 | 16 |
| Conductance | 9 | 30 | 18 |

The math sometimes identifies a cut spanning several ordinary dependency-tree branches. It loses to the basic methods more often than it wins. These are results against the specified baselines, not all possible graph algorithms. A better cut value does not by itself establish a more useful review grouping or an unsafe dependency.

For example, the Prism snapshot's spectral side contains 93 records and has three crossing edges, with conductance about `0.00491` versus the basic candidates' best `0.01587`. Its boundary includes `jsdom -> form-data`, `npm-run-all -> string.prototype.padend`, and `is-core-module -> hasown`. This is evidence of additional structural grouping, not an execution or impact finding.

Evidence: [all structural partitions and metrics](../ecosystem_audit/math-evaluation-20261109/structural.json).

## Historical dependency changes

For each of the 92 eligible frozen snapshots, acquisition selected the latest commit changing its lockfile at or before the frozen head and that commit's first parent. This yielded 89 complete graph pairs. Three base locks were absent: TypeStrong/ts-loader, Handlebars, and Moment. The selected commits are historical lockfile changes, not a claim that every change was a dependency-update PR.

Independent npm labels were available for 56 pairs, including 37 in the held-out group. The scoped events were changed marker-positive registry instances verified as execution candidates in their exact archives, root lifecycle body changes, and same-version locator changes. Marker-negative package artifacts were not inspected. These labels are neither maliciousness labels nor evidence of actual script execution. Negative labels do not establish absence of other execution changes.

The initial event check considered only marker additions, root hook-body changes, and same-version locator changes and found no positives. It omitted changed versions of already-marked packages, even though approvals bind exact artifact evidence. The target was corrected to include those changed candidates and checked against original SHA-512-matching archives. Consequently, this value analysis is exploratory. It is not a preregistered detection-accuracy result.

Four held-out changes updated verified executable artifacts. Exact record comparisons selected all four for review. A thresholded connectivity-change signal selected one and missed three. It also selected six other held-out npm changes outside the scoped event target. The sample is small, and the basic checks directly observe the metadata used to select artifact verification. No general precision, recall, or safety claim follows from these counts.

| Historical change | Verified changed artifact | Connectivity-change signal |
|---|---|---|
| [jQuery](https://github.com/jquery/jquery/commit/32bf84bcbb82c6d24d18107b85a534fd8bb0d6f1) | `@swc/core` 1.16.2 and `core-js-bundle` 3.50.0 | Changed |
| [TypeScript](https://github.com/microsoft/TypeScript/commit/a3a20704642a0021a74bc56d266ef05be0604813) | `dprint` 0.64.3, `postinstall: node ./install.cjs` | Unchanged within threshold |
| [webpack-cli](https://github.com/webpack/webpack-cli/commit/efe73134daf1b3d66fe0f87f9b58e1e8de5b8974) | `@swc/core` 1.16.21, `postinstall: node postinstall.js` | Unchanged within threshold |
| [webpack-dev-server](https://github.com/webpack/webpack-dev-server/commit/dd970959debd2dc0f9dda5327620e07cf1fab4b4) | `puppeteer` 25.16.0, `postinstall: node install.mjs` | Unchanged within threshold |

The Python inspector and final Rust auditor independently derive matching manifest and lifecycle hashes for these five artifacts. Each has a qualified execution-evidence fingerprint. The study does not establish that the commands themselves were newly introduced. The targeted audits retain incomplete outcomes for the other missing evidence. Existing approvals in these public projects were not evaluated, so a changed artifact is not labelled an observed approval violation.

Evidence: [acquisition receipts](../ecosystem_audit/math-evaluation-20261109/updates.json), [exploratory update results and archive facts](../ecosystem_audit/math-evaluation-20261109/update-value.json), and [the original metadata-only check](../ecosystem_audit/math-evaluation-20261109/update-value-metadata-v1.json).

## Validation and cost

All 152 original lockfile audits were replayed. Exit codes and every report field outside `topology` matched the frozen baseline. All frozen source-file hashes remained unchanged. This includes unsupported inputs and incomplete reports, which continue to fail visibly.

The release Rust suite passed 89 tests. The 21 Python PR-helper tests, formatting check, `e2e_zero.sh`, and `prove-it.sh` passed. Path and cycle analytic tests failed before the repair and pass afterward. Additional cases cover repeated eigenvalues, vertex permutation, budget exhaustion, and the two-node multigraph exposed by independent review.

Native cost was measured with five alternating calls per solver per graph. The median of candidate per-graph medians was about 12.2 ms, with the largest per-graph median about 165.3 ms on this Mac. Ten deterministic process-level audit cases were also run five times per binary, including parsing and JSON output. Their candidate per-case medians ranged from about 9.9 to 120.0 ms. These are warm local observations under concurrent desktop load, not service latency guarantees. No accuracy-equivalent speedup is claimed against the baseline's unconverged estimates.

A separate sampled profile on Puppeteer places the CPU work in the native iteration and orthogonalization. Profiling calls are excluded from reported timings. Basic-method timings in interpreted Python are not compared with native Rust as an algorithm speed benchmark.

Evidence: [unchanged non-math audit fields](../ecosystem_audit/math-evaluation-20261109/audit-replay.json), [process-level measurements](../ecosystem_audit/math-evaluation-20261109/end-to-end-timing.json), [sampled native profile](../ecosystem_audit/math-evaluation-20261109/native-profile.txt), and [decision trail](../ecosystem_audit/math-evaluation-20261109/decisions.tsv).

## Reproduce the local evaluation

The ignored experiment directory preserves the original and final native binaries, exact graph files, independent references, source snapshots, historical revisions, and scientific-runtime installation receipt. The scripts operate on that frozen directory rather than rediscovering today's upstream heads. The optional Python reference dependencies are pinned in [tools/math-requirements.txt](../tools/math-requirements.txt).

```sh
study=ecosystem_audit/math-evaluation-20261109
runtime="$study/runtime/bin/python"
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 "$runtime" \
  tools/math_corpus.py compare --output "$study" \
  --library "$study/candidate-final/libtau_gate.dylib" --repeats 5
"$runtime" tools/math_corpus.py structural --output "$study"
"$runtime" tools/math_corpus.py controls --output "$study" \
  --library "$study/candidate-final/libtau_gate.dylib"
"$runtime" tools/math_corpus.py audit-replay --output "$study" \
  --binary "$study/candidate-final/tau-gate"
"$runtime" tools/math_update_study.py analyze --output "$study" \
  --library "$study/candidate-final/libtau_gate.dylib"
```

The numerical repair was independently reviewed with the requested `gpt-6-astra` model. Its reproduced scalar-projection bug was fixed and given a regression case. The review was artifacts-only because no local chat-transcript file was supplied. [Review and limitations](../ecosystem_audit/math-evaluation-20261109/REVIEW.md).

The supported conclusion is to retain spectral output as structural context while keeping exact changes, dependency paths, original-artifact verification, and evidence-bound approvals as the basis for review decisions. Human review benefit and actual runtime impact remain unmeasured.
