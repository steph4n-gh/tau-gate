# Remaining spectral losses and conductance tradeoffs

This branch extends the ratio-cut sweep using the second direction that the existing block solver already computes. It reduces the remaining basic-method ratio-cut wins from 19 to 8 on the 118 eligible graphs. It does not improve the historical artifact-event detection result.

## What caused the losses

On the 19 loss cases, independently computed reference Fiedler-vector orderings recover none of the basic wins. The basic winning partitions interleave that direction’s coordinates, by much more than the observed native/reference vector differences. This tests those reference orderings; it is not a proof that every numerical solver would give the same cut. Seventeen original winners are bridge cuts and two are BFS-subtree cuts. A more accurate first vector alone is not the supported repair.

The block solver already retains two orthogonal Ritz search directions during iteration. The previous cut step discarded the second. On the 36 original development cases, searching the first direction alone leaves 8 ratio losses, both axes leave 5, and the four fixed projections leave 3. The selected family is x, y, x+y, x−y. It was frozen before the new 82-case validation replay. This cohort has already been studied repeatedly: these are engineering consistency checks, not fresh blinded validation.

## Implementation and contract

The solver loop, first Rayleigh score, residual tolerance 1e-9 and iteration/work caps are unchanged. Retaining the second direction adds no eigensolver iteration. Four sorts and incremental threshold sweeps select the lowest ratio cut, breaking equal ratios by conductance and then existing projection/threshold order. Each sweep respects equal coordinates and weighted edge multiplicity; self loops remain ignored. Work is O(4(n log n+m)) beyond the existing solver, plus one Laplacian multiplication to report the second direction’s residual. This is a fixed search family, not a search over all angles or a globally optimal cut.

The second direction need not have converged to the third eigenvector. `topology.cut_diagnostics` reports its residual, the selected projection, ratio cut and conductance. `topology.score` and `residual_converged` still concern only the first Rayleigh estimate. Disconnected/singleton component fallbacks have null cut diagnostics. Two-node graphs use only the first direction.

The primary returned partition remains ratio-oriented. A separate `conductance_alternative` appears when the same candidate family offers strictly lower conductance. It contains its own partition, threshold, projection and both quality scores; it can have a worse ratio cut. It is not silently substituted into the primary result. The C layout stays unchanged and exposes the primary partition; C `tau` is now a threshold on the selected Ritz projection. Audit JSON exposes the added provenance and alternative. This source change has not been release-qualified.

## Full-corpus result

All 152 inventories are replayed. The primary comparison remains 118 complete connected graphs; the 82-case validation split is reused. The basic BFS-subtree/bridge/component and degree-cut candidates, metrics and per-objective selection are unchanged. No structural fallback is counted as a spectral win. These numbers compare the specified candidate families, with different search budgets; they do not establish superiority over every basic graph algorithm.

| Scope and objective | Previous math / equal / basic wins | Four-projection primary math / equal / basic wins |
| --- | ---: | ---: |
| 118 eligible: ratio cut | 31 / 68 / 19 | **33 / 77 / 8** |
| 118 eligible: conductance | 34 / 56 / 28 | 33 / 63 / 22 |
| 82 validation: ratio cut | 22 / 49 / 11 | 23 / 54 / 5 |
| 82 validation: conductance | 22 / 41 / 19 | 22 / 43 / 17 |

Against the prior ratio sweep, ratio cut improves on 16 graphs and ties on 102; it worsens on none. Eleven of the 19 losses are recovered. Conductance improves on 12, ties on 103 and worsens on 3: async, Cypress and regenerator. Both objectives cannot be read as simultaneous wins.

The separately selected conductance profile scores 59 math wins / 58 ties / 1 basic win on 118 graphs (validation 42 / 39 / 1). This compares a different cut under the conductance objective. The primary partition still loses 22 conductance comparisons.

## The original six conductance regressions

| Repository | Original maximum-gap conductance | Prior ratio sweep | New primary | Separate conductance profile |
| --- | ---: | ---: | ---: | ---: |
| brianc/node-postgres | 0.012048193 | 0.019607843 | 0.019607843 | 0.012048193 |
| cheeriojs/cheerio | 0.024390244 | 0.028571429 | 0.028571429 | 0.018867925 |
| chimurai/http-proxy-middleware | 0.025641026 | 0.028571429 | 0.028571429 | 0.024390244 |
| immerjs/immer | 0.01010101 | 0.018867925 | 0.018867925 | 0.01010101 |
| mathiasbynens/he | 0.021276596 | 0.024390244 | 0.024390244 | 0.021276596 |
| moment/luxon | 0.025906736 | 0.028571429 | 0.021276596 | 0.01980198 |

The new primary fixes Luxon. The other five persist; Cypress adds a new conductance regression, leaving 6 against the original maximum-gap rule. The separate conductance profile matches or improves all six original values and never worsens that original conductance on an eligible graph, because its threshold family includes the original cut. This is an alternative, not a claim that the default regressions disappeared.

For he, the tradeoff is provably unavoidable if current ratio quality must be preserved. With 44 nodes and current ratio 44/483, every cut of at least 2 edges has ratio at least 8/44, which is larger. Any no-worse cut must therefore cross exactly 1 edge, hence be a bridge cut. Exhaustive enumeration of all 33 bridges finds none with ratio<=44/483 and conductance<=1/47 (the old conductance). The bridge oracle was checked against all connected four-node simple graphs, including duplicate-edge and self-loop variants, and independently checked by edge deletion on he. No global impossibility claim is made for the other five cases. Chimurai has a basic bridge satisfying both bounds, outside the four-projection family.

## The eight remaining ratio losses

| Repository | Split | New ratio cut | Best basic ratio cut | Basic candidate |
| --- | --- | ---: | ---: | --- |
| TypeStrong/ts-node | holdout | 0.1155754 | 0.085535977 | bridge |
| caolan/async | development | 0.12866748 | 0.11082836 | bfs_subtree |
| chimurai/http-proxy-middleware | development | 0.05751634 | 0.049591434 | bridge |
| cure53/DOMPurify | development | 0.10786212 | 0.10127551 | bridge |
| dequelabs/axe-core | holdout | 0.077947667 | 0.072454212 | bridge |
| npm/cli | holdout | 0.070229971 | 0.06334317 | bridge |
| reactjs/react-transition-group | holdout | 0.20043917 | 0.16710603 | bridge |
| reduxjs/react-redux | holdout | 0.053225806 | 0.050855294 | bridge |

Seven winners are bridges and one is a BFS subtree. Their better cuts are outside the selected projection thresholds. A bridge/BFS fallback could recover them by reusing the basic method; it would be a hybrid result, and would not demonstrate additional mathematical value. The experiment keeps that distinction.

## Verification and evidence

The eight-node behavioral witness has parallel edges: the old sweep returns ratio 1.6, while a combined direction attains 4/3. The test also verifies a distinct lower-conductance alternative has a worse ratio. Existing leaf-isolation tests remain intact, with additional two-node/component controls. All 137 Rust tests, Clippy, formatting, e2e, prove-it, 21 PR-helper tests and 4 optional Python math tests pass.

Every one of the 152 inventories matches the independent four-projection threshold oracle for connected inputs or retains the exact component fallback. Score, residual, convergence flag and iteration count match the previous source exactly. All 152 CLI exits and non-topology fields match. All 145 complete historical pairs preserve the scalar and scalar-or-primary-partition alert booleans: 4 known artifact events remain 1/4 scalar and 2/4 combined, versus 4/4 exact artifact metadata. None of the combined alerts adds an event beyond exact changes. The new conductance alternative is not promoted to an unvalidated update alert. No security, harmfulness, human-review or runtime-impact benefit is established.

The selected run and the final verified run remain separate. Clippy required four equivalent `map_or(true, ...)` to `is_none_or(...)` cleanups after initial selection; final binaries were frozen and replayed separately, and all non-timing results were compared. Five interleaved A/B repetitions support determinism; the short local timings do not support a speedup claim.

Local evidence directory: `ecosystem_audit/math-remaining-losses-20261109`. Root files preserve diagnosis, development comparisons, exact bridge tradeoffs, selected freeze and first replay. `verified/` holds the final source/binary hashes, all 152 evaluations, audit replay, historical replay and equivalence receipt. `decisions.tsv` records choices and rejected approaches; `REVIEW.md` records independent review. The large local corpus is ignored by Git; this document and the reproducible helper are tracked.

The committed [decision trail](qualification/math-remaining-losses-20261109.tsv) records the checkpoints. Reproduce in a new local output directory with `tools/math_remaining_losses.py` modes `diagnose`, `development`, `tradeoffs`, then `evaluate` after copying/freezing the candidate. The helper refuses existing result files and input-study output paths. The `report` mode compares the selected run against a separately replayed `verified/` run. The external scientific environment and frozen corpus are required; the Rust core stays std-only.
