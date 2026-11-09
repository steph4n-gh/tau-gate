# Math versus basic dependency analysis on all 152 lockfiles

The expanded experiment supports **occasional additional structural grouping**. It does **not establish better dependency-risk decisions or human review outcomes than basic dependency analysis**. The strongest measured review facts still come from exact changes and verified artifacts.

All 152 frozen lockfile inventories were measured. All matched independent numerical reference values and repeated deterministically. The main structural comparison contains 118 complete, connected graphs: math beat the tested basic methods on 19 graphs, tied on roughly half, and lost more often than it won.

Experiment: November 9, 2026. This follows the [parser expansion](parser-coverage.md) and [original 102-inventory evaluation](math-evaluation.md). No solver, residual threshold, partition rule, evidence rule or approval behavior changed in this experiment.

## Scope and fixed methods

The input set remains the same 200 repository identities: 149 repositories supply 152 locks, 49 have no discovered project lock, and two are unavailable. The same frozen commits and expanded-parser reports were used. Four graph inventories remain incomplete; every one is still measured and listed. Thirty-two inventories are disconnected or singleton graphs, including two of the four incomplete inventories. Their exact zero-connectivity results do not supply useful global spectral separation. Thus 118 graphs are both complete and connected with at least two nodes.

The native solver and maximum-gap partition are fixed. Each directed nonself edge contributes to the symmetric weighted Laplacian; dependency kinds and direction do not otherwise inform its operator. Basic candidates are the existing deterministic BFS spanning-tree subtree cuts (including bridges/components) and degree-threshold cuts. The best basic candidate is selected separately for each objective. Both methods receive identical graph inputs. Lower ratio cut and conductance are better only under those definitions. This is not a comparison against every possible graph-clustering algorithm.

The original repository-hash split was retained. The 82 complete connected holdout graphs are a fixed-split descriptive check, not a fresh blinded trial. Fifty graph inventories are newly parseable; four previously available inventories have changed graph/root inputs. Thirty-three new-or-changed graphs meet the primary complete/connected scope. No parameters were tuned using these results.

## Structural comparison

| Scope and objective | Math better | Equal | Basic better |
| --- | ---: | ---: | ---: |
| All 118 eligible graphs: ratio cut | 19 | 61 | 38 |
| All 118 eligible graphs: conductance | 19 | 56 | 43 |
| Fixed holdout, 82 graphs: ratio cut | 14 | 44 | 24 |
| Fixed holdout, 82 graphs: conductance | 14 | 40 | 28 |
| New/changed eligible graphs, 33: ratio cut | 6 | 15 | 12 |
| New/changed eligible graphs, 33: conductance | 7 | 14 | 12 |

The wins can be substantial as mathematical groupings. In the Yargs graph, the spectral side contains 93 of 563 records behind three boundary edges. Its ratio cut is `0.03864`, versus the best basic candidate's `0.16846`; conductance is `0.00464`, versus `0.07317`. The group contains JavaScript compatibility helpers such as `es-abstract` and `call-bind`. Its three boundary edges are `hashish → traverse`, `is-core-module → hasown` and `resolve → es-errors`.

That is additional grouping beyond the tested single-tree/degree cuts. It does not establish that a reviewer would understand a change faster, make fewer mistakes, or identify harmful behavior. No blinded grouping preferences or human-review timing were collected.

Evidence: `ecosystem_audit/math-comparison-152-20261109/snapshots.json`, per-case partitions in `snapshots/`, graph inputs in `graphs/`, and the [all-152 table](../ecosystem_audit/math-comparison-152-20261109/REPORT.md). The complete table also retains disconnected, incomplete and mathematically undefined cut-objective cases.

## Historical dependency-change review

The experiment attempted a historical pair for **all 152 locks**, selecting the newest lock-changing commit at or before its frozen head and that commit's first parent. Existing exact revision receipts were reused where available. Both sides were audited with the expanded parsers and manifests/configuration from their own commits. These are historical lock-changing commits, not necessarily dependency-update PRs.

There are **145 complete, compatible graph pairs**. Seven remain incomplete: three missing base locks (Handlebars, Moment and ts-loader), plus Less's npm lock, Create React App, Flow and webpack-dev-middleware. Their receipts and diagnoses remain visible. No historical cases were replaced to improve a result.

The primary numerical alert remains the original fixed threshold:

```text
abs(lambda_head - lambda_base) > 1e-8 + 1e-6 * max(abs(lambda_head), abs(lambda_base))
```

Independent transitive review labels are available for **57 npm-v3 pairs**, including 38 in the fixed holdout. They cover changed marker-positive registry instances verified against original matching archives, root lifecycle changes and same-version locator changes. Four cases changed verified executable artifacts. Marker-negative archives were not inspected. The other lockfile formats do not become negative execution or safety labels. This target was corrected during the original study, so these are exploratory explanatory-capability checks, not a preregistered security-accuracy benchmark.

A separate independent root-manifest comparison covers all 145 complete pairs. One changes a root lifecycle command.

| Observed fact | Exact metadata checks | Fixed scalar alert | Exploratory scalar-or-partition alert |
| --- | ---: | ---: | ---: |
| Changed verified executable artifacts: 4 cases in 57 npm-v3 pairs | 4 / 4 | 1 / 4 | 2 / 4 |
| Root lifecycle command changed: 1 case in 145 pairs | 1 / 1 | 0 / 1 | 1 / 1 |

The four artifact cases are unchanged from the original study: jQuery, TypeScript, webpack-cli and webpack-dev-server. The scalar signal flags jQuery. Adding partition-membership changes also flags TypeScript; webpack-cli and webpack-dev-server remain unflagged. The verified facts describe changed candidate artifacts, not necessarily newly introduced install commands or actual execution. The Python archive inspector and Rust auditor again agree on their manifest/lifecycle facts and qualified per-artifact fingerprints.

The root case is [SWC commit `56f4407`](https://github.com/swc-project/swc/commit/56f4407325fbda4f13e6db43232881c19d748707). Its `prepare` changes from `husky install . && …` to `husky && …`. Both graphs are disconnected, so global connectivity stays exactly zero. Partition membership changes, but neither scalar nor partition output explains the command change; the manifest diff does.

The secondary partition signal was added **after inspecting the initial results and known cases**, because the shipped math exposes a partition as well as a scalar. It compares orientation-normalized sides using exact node identities; a side/complement flip alone is not a change. It is explicitly post-hoc and includes identity changes in resolution records. It does not establish new predictive accuracy or separate topological changes from changed record keys.

Across the 57 labeled npm pairs, the scalar alert selects 12 additional cases outside the scoped target; scalar-or-partition selects 14. Those are not established false alarms: the labels do not cover all possible consequences. Across all 145 pairs, exact package/typed-edge/root-lifecycle comparison changes in 142, the scalar alerts in 41, and scalar-or-partition alerts in 71. Every math-alerted pair is already among the basic exact-change cases. Selectivity alone is not evidence of useful prioritization when known review facts are missed and most consequences are unlabelled.

Evidence: `updates.json`, `updates/*/receipt.json`, `update-value.json`, saved archives and targeted Rust evidence reports in `ecosystem_audit/math-comparison-152-20261109/`.

## Numerical and evidence checks

Five fresh native calls were run per frozen graph: **760 calls, all deterministic apart from timing**, all residual-converged and within the fixed numerical-reference agreement tolerance. Thirty-two cases use the exact disconnected/singleton shortcut. Maximum absolute eigenvalue disagreement was below `1.21e-15`. Independent references use the same established NumPy/SciPy construction and verify their own vector residuals.

Both sides of all 145 complete historical pairs were also checked against independent numerical references: 290 reference comparisons, with all 145 scalar alert decisions agreeing with reference-derived decisions. The ABI does not expose the native eigenvector; this is not an independent reconstruction of every native-vector residual or a formal second-eigenpair certificate.

Graph/report hashes, the original 152 input identities, candidate bytes and 5,802 historical context files were checked. Rust runtime source remains unchanged. Numerical dependencies remain external: NumPy 2.3.4, SciPy 1.16.3 and PyYAML 6.0.3. No scanned project was installed or executed.

The first historical runner attempt could not execute the copied checker because `copyfile` had dropped its executable mode. All 152 failures were harness failures before audit execution. That attempt and its receipts were preserved, candidate mode was restored, new copies use `copy2`, and the collector now preflights the executable. The final acquisition/audit results above come from the corrected run. This error did not affect the separately completed native-library structural measurements.

This study is not a speed comparison. Native timings are retained as local observations, but interpreted-Python baseline costs are not compared with native-Rust solver costs. Local results are distinct from hosted CI, installation agreement, release qualification and production impact.

## Reproduction and decision

Frozen artifacts are in `ecosystem_audit/math-comparison-152-20261109/`, including `settings.json`, `results.json`, `REPORT.md`, all 152 snapshot results, 152 historical receipts, references, archived evidence, operational-failure receipts and the decision trail. Candidate core revision is `dcd985e97aa2bea50428a9df3562f8bc0eb700bb`; library SHA-256 is `53380a864d28b2c981737c4dc709d8e1d8986f83bd12f85264947b33940602fc`, checker SHA-256 is `ff21799d859da084e586bad19589b2593a8a91f0935f0d075c740febeea40ab6`. Inputs and large generated evidence remain local experiment artifacts.

With the frozen parser and original study directories present:

```sh
python3 -m venv /tmp/tau-math-reference
/tmp/tau-math-reference/bin/pip install \
  -r tools/math-requirements.txt -r tools/parser-requirements.txt

study=ecosystem_audit/math-comparison-152-20261109
runtime=/tmp/tau-math-reference/bin/python
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 "$runtime" \
  tools/math_full_comparison.py snapshots --output "$study" \
  --parser-run ecosystem_audit/parser-expansion-20261109 \
  --previous-study ecosystem_audit/math-evaluation-20261109 --repeats 5
"$runtime" tools/math_full_comparison.py collect --output "$study"
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 "$runtime" \
  tools/math_full_comparison.py analyze-updates --output "$study"
"$runtime" tools/math_full_comparison.py report --output "$study"
```

The acquisition helper uses public pinned-commit files and authenticated GitHub tree/history APIs. Artifact analysis may acquire original archives and verifies them without installation or execution. No approval profile was widened.

The supported product judgment is to retain math as optional structural context. Exact state changes, typed dependency paths and artifact evidence remain the justified basis for dependency review. A claim of better review grouping or prioritization still needs independently evaluated reviewer tasks; this corpus does not supply that outcome evidence.
