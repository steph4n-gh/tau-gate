# Improving spectral cut selection

The main weakness was the step that turned a numerically accurate eigenvector into one partition. Replacing the largest-coordinate-gap heuristic with a ratio-cut threshold sweep halves losses to the tested basic methods on the primary objective: **38 → 19** across 118 complete, connected graphs. Conductance losses also fall, **43 → 28**, with six individual conductance regressions disclosed below.

The new rule is implemented in the source branch. Parser behavior, exact dependency changes, artifact evidence, approval policy, eigenvalue estimates, residuals and iteration counts are unchanged. This improves structural grouping; it does not establish better security or human-review outcomes.

## Why the previous method lost

1. **Cut selection discarded useful thresholds.** The old rule chose the largest gap between adjacent eigenvector coordinates without measuring graph-cut quality. The basic comparator searched many subtree/bridge and degree-threshold cuts and selected its best result. An accurately solved eigenvector did not make that one rounding choice optimal.
2. **The objectives reward different structures.** Ratio cut balances boundary edges against node counts. Conductance balances them against edge volume. A one-edge leaf has conductance 1, even though the old isolation test deliberately expects that leaf to be separated. Changing the primary objective changes behavior, rather than simply fixing numerical accuracy.
3. **One ordering is still a limited candidate family.** Even an exhaustive threshold sweep cannot select a basic cut whose vertices are interleaved in that spectral ordering. Nineteen complete connected cases still lose on ratio cut after the change. This is not a claim of a global minimum cut.
4. **The graph omits package contents.** Coordinate rounding cannot make a scalar notice content-only changes, and disconnected graphs still have zero global connectivity. This limitation is separate from grouping quality.

Diagnosis used the 36 eligible development graphs. An analysis-only probe extracted vectors from the exact frozen native solver; their residuals were independently reconstructed and their old maximum-gap cuts reproduced. Searching thresholds on the same vectors rescued six of 14 development ratio-cut losses. A conductance-first sweep rescued 11 of 15 conductance losses, demonstrating that rounding accounted for much of the gap.

## Chosen change

Sort the existing native Fiedler coordinates and sweep every threshold between distinct coordinates. Select the lowest ratio cut; ties prefer lower conductance, then the first threshold. Return the smaller side and a separating coordinate threshold. Equal coordinates stay together; an invalid constant embedding produces no invented cut. Parallel edges retain their weights.

The unnormalized Laplacian is the continuous relaxation associated with RatioCut; the discrete rounding step remains a separate choice. See [von Luxburg's tutorial, section 5](https://arxiv.org/abs/0711.0189). This change optimizes rounding on the current vector; it introduces no new eigenproblem, graph weighting, external Rust dependency or basic-method fallback.

A conductance-first production prototype was rejected: it failed the existing connected-leaf isolation test and worsened four development ratio cuts. The selected ratio rule aligns with the existing model, preserves every existing math test and improves both comparison objectives overall. It does not promise both objectives improve on every graph.

The cut stage sorts once and updates boundary/volume counts incrementally: `O(n log n + m)` time with an additional `O(n)` membership vector. The eigensolver, residual threshold `1e-9`, outer iteration/work limits and FFI layout are unchanged. `tau` now marks the selected ratio-cut threshold, rather than the largest coordinate gap. This source-branch behavior predates any new release qualification.

## Results

The method was selected using 36 development graphs before examining its new outcomes on the 82 eligible holdout graphs. This remains an engineering check on an already studied corpus, not a fresh blinded experiment. The initial source freeze and hashes are retained in `frozen-method-selected.json`. A later equivalent Clippy cleanup changed only the smaller-side condition; all 152 non-timing results matched before and after that cleanup.

| Scope / objective | Old math / equal / basic wins | New math / equal / basic wins |
| --- | ---: | ---: |
| All 118 eligible: ratio cut | 19 / 61 / 38 | **31 / 68 / 19** |
| All 118 eligible: conductance | 19 / 56 / 43 | **34 / 56 / 28** |
| Holdout 82: ratio cut | 14 / 44 / 24 | **22 / 49 / 11** |
| Holdout 82: conductance | 14 / 40 / 28 | **22 / 41 / 19** |

Against the shipped partition itself, ratio cut improves on 37 graphs and ties on 81, with no regression. Conductance improves on 30, ties on 82 and worsens on six. The basic methods and their per-objective selection remain unchanged. The new math now also searches a family of thresholds; these results describe those concrete candidate families, not every graph-clustering algorithm.

A rescued example is Regenerator: the old four-record side had ratio cut `0.50554`, worse than the basic candidate's `0.12780`. The new 166-record side has ratio cut `0.09944`. This is better grouping under the specified objective, not evidence of a more useful reviewer decision.

### Conductance tradeoffs

| Repository | Old conductance | New conductance |
| --- | ---: | ---: |
| node-postgres | 0.012048 | 0.019608 |
| Cheerio | 0.024390 | 0.028571 |
| http-proxy-middleware | 0.025641 | 0.028571 |
| Immer | 0.010101 | 0.018868 |
| he | 0.021277 | 0.024390 |
| Luxon | 0.025907 | 0.028571 |

These are genuine secondary-objective regressions, including two holdout cases. They are not removed from the totals. The ratio cut improves in all six, consistent with the declared primary objective. The current experiment does not supply human labels to decide which grouping a reviewer would prefer.

## Verification and remaining limits

All 152 original inventories were evaluated, including four incomplete and 32 disconnected/singleton cases; those categories overlap. The 118 complete connected cases are the primary grouping scope. Disconnected/singleton results remain exactly unchanged.

Five alternating native calls per library per graph were made: 1,520 calls. Every run converged, agreed with the established numerical reference and repeated deterministically apart from timings. Connectivity score, residual, convergence flag and iteration count were exactly unchanged. All 120 iterative partitions matched an independent enumeration of thresholds on the same exact native vector. Native vector residuals were also checked using the independently constructed Laplacian, rather than relying only on reported scalar residuals.

All 152 actual CLI audits retained the same exit codes and every report field outside `topology`. All 145 complete historical pairs retained their scalar diagnostics and every combined-alert boolean. On the 57 npm-v3 pairs with scoped artifact labels, scalar detection remains 1/4 and scalar-or-partition detection 2/4; exact metadata checks still cover all four known cases. The one root command change is also unchanged. Marker-negative artifacts and unqualified transitive formats remain unlabelled for this target. Better partitions have not produced new verified review facts.

The seven-node rounding regression failed under the old implementation at ratio cut `2.33333`, versus a threshold attaining `1.75`, and passes with the sweep. Additional tests cover equal/constant coordinates and independently enumerated parallel-edge cuts. All existing math tests, including connected-leaf isolation and bounded nonconvergence, pass. The release Rust suite passes 135 tests; formatting and Clippy pass. CLI/FFI fixtures and Python helper checks are retained in the study logs.

Final narrative review found a serialization-only metadata error: a summary-loop variable shadowed the selected objective, labeling three frozen measurement headers `conductance`. Their native algorithm, threshold checks and results used **ratio cut**, as the source and freeze records establish. The frozen files and hashes are preserved; `objective-metadata-erratum.json` identifies the incorrect labels and correct method, and `results.json` carries the erratum. The future writer is fixed. A separate fresh 36-case serialization check writes `ratio_cut` correctly and reproduces every non-timing result. No scientific count or production code changed for this correction.

The solver source region is byte-identical to the frozen baseline. The current parser/evidence/approval paths are unchanged. Local validation does not establish release qualification, host installation agreement, actual execution, or faster/more accurate human reviews. Native timings are preserved as local observations; no speedup claim is made.

## Evidence and reproduction

Frozen local evidence lives in `ecosystem_audit/math-cut-improvement-20261109/`: baseline sources/binaries, native-vector probe, development-only diagnosis and rejected prototype, initial/final method freezes, all-152 before/after results, candidate CLI audits, historical replay, test logs and independent review. The [all-152 table](../ecosystem_audit/math-cut-improvement-20261109/REPORT.md) and `results.json` retain all cases and six tradeoffs. Large inputs and generated artifacts are local, not checked into Git. Independent review is recorded in the [core review](../ecosystem_audit/math-cut-improvement-20261109/REVIEW.md), [narrative review](../ecosystem_audit/math-cut-improvement-20261109/REVIEW-FINAL.md), and [final metadata closure](../ecosystem_audit/math-cut-improvement-20261109/REVIEW-METADATA.md). The final closure resolves the preserved raw-header issue; no blocking finding remains. A [committed decision trail](qualification/math-cut-improvement-20261109.tsv) records the checkpoints and disclosures.

Candidate source is `ed5080f4cb6b47c8fac51710d48823b535a70004`; its binary/library hashes are recorded in `frozen-method.json`. The choice freeze is source `76a9d5cfc80a36656bfd52c08459de0085aa2eb7`. The later freeze/validation TSV rows were appended after the runs; their logging timestamps are not the selection timestamps. Source commits, preserved freeze artifacts and the evaluation records provide the chronology. The previous [152-lockfile evaluation](math-evaluation-152.md) remains unchanged as the baseline study.

With the frozen study directories and scientific runtime present, the modes below regenerate outputs. Use a working copy of the experiment artifacts when reproducing rather than modifying reviewed frozen evidence.

```sh
study=ecosystem_audit/math-cut-improvement-20261109
input=ecosystem_audit/math-comparison-152-20261109
runtime=ecosystem_audit/math-evaluation-20261109/runtime/bin/python

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 "$runtime" \
  tools/math_cut_experiment.py diagnose --study "$input" --output "$study"
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 "$runtime" \
  tools/math_cut_experiment.py evaluate-all --study "$input" --output "$study" \
  --library "$study/candidate/libtau_gate.dylib" --objective ratio_cut --repeats 5
"$runtime" tools/math_cut_experiment.py audit-replay --study "$input" --output "$study" \
  --binary "$study/candidate/tau-gate"
"$runtime" tools/math_cut_experiment.py historical --study "$input" --output "$study" \
  --library "$study/candidate/libtau_gate.dylib"
"$runtime" tools/math_cut_experiment.py report --study "$input" --output "$study"
```

The runtime dependencies remain the existing external NumPy/SciPy/PyYAML reference environment. The Rust runtime remains std-only, read-only and offline. No project installation or lifecycle execution occurred.
