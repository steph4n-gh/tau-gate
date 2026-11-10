# Third npm v3 cohort: frozen unseen result

This run tests the exact post-repair Tau-Gate binary on **100 repository identities absent from the prior 500**. Selection, scoring, candidate bytes and the 80% completion floor were frozen before new update outcomes. The result **fails** that floor: **20/30 update pairs complete (66.7%)**. The [compact scorecard](evidence/npm3-unseen-20261110.json) retains the 150 run hashes, per-case results, controls and raw-receipt hashes. The earlier [25/30 repair result](npm3-gap-repair.md) remains a known-case regression, not the fresh result.

| Measure | Fresh result |
| --- | ---: |
| Repositories selected / with an npm v3 lock | 100 / 18 |
| Update pairs / distinct repositories supplying them | 30 / 14 |
| Pairs with complete independent labels | 23/30 |
| Pairs completing Tau-Gate comparison | **20/30** |
| Assessable events matched | **2,429/2,447 (99.3%)** |
| Fact mismatches / unexpected allowed outcomes | 0 / 0 |
| Frozen 80% completion floor | **Fail** |

The 100 were selected from the pinned ecosyste.ms critical npm ranking after excluding three prior cohorts totaling 500 canonical repository identities. Sixty-five had no project lockfile in the fixed discovery scope; 35 had locks; 18 had npm v3 lockfiles. The deterministic history rule retained 65 no-lock attempts, 14 non-v3 attempts and five unavailable/invalid attempts while selecting the first 30 eligible pairs. The pairs are clustered in 14 repositories and are not 30 independent projects.

All 2,087 unique archive identities were acquired without exceeding the 4 GiB budget. The independent oracle was run **before** candidate replay and found 23 complete pairs. Its seven partial pairs contain 4,097 unknown package-side records: 4,096 missing evidence locators and one manifest/lock dependency mismatch. These are repeated snapshot records. The frozen 80% floor was therefore unreachable even with perfect candidate agreement. Collector validation accepted 42 of 60 snapshot sides and retained 18 rejected or incomplete sides.

The frozen candidate completed 20 pairs. Among the three additional product-incomplete pairs with complete reference labels, two omitted **18 manifest-hash changes** in `@typescript-eslint/*` packages; there were no fact mismatches. Their archives use a `ustar  \0` header spelling that Python's tar reader accepts but Tau-Gate's current POSIX-only inspector rejects. Tau-Gate left those records unqualified. A third pair had the same archive-profile limitation without a missed event. Two other rejected package-side records used unsupported tar links or special records. These are coverage findings, not observed unsafe approvals. All 18 missed events were labelled non-lifecycle package changes. The independent labels found **no lifecycle-command changes anywhere in these 30 updates**, so this cohort cannot establish reviewer benefit for the core install-behavior promise.

## Checks and comparison boundary

The five-round replay used three isolated workers. All 150 executions had valid protocol outcomes; each pair's stdout was byte-identical across rounds. Every saved stdout, stderr and process-metrics hash was checked against the receipts. The candidate executable SHA256 is `ae8310fb422f7b7f9d88a00490d847690772415c67d465e6bc7cb42cb104f415`, built from core source `0c707606dbae42256758c7fd745bdc286a2758aa`. The selector and pair protocol were frozen at source `3c3c0f4360b0b8b26c72db22a1fa1764baad29da`; no product code changed during this cohort.

On all 18 captured npm v3 inventories, Tau-Gate matched npm Arborist's instance paths and resolved edge pairs, plus comparable package coordinates from the hosted ecosyste.ms parser. This is scoped graph correspondence, not proof that the graph or math helps a reviewer. The same exact candidate binary had already passed 320 archive/evidence, 20 trusted-wrapper and 17 native npm controlled cases; their hashed receipts were reused rather than presented as new cohort tests. Public pair reviews were advisory with no supplied approvals, so zero unexpected `allowed` outcomes here does **not** measure an incorrect-approval rate. The controlled cases remain the approval-protection evidence.

Acquisition charged 1,855,499,436 bytes, including 877,538,002 newly downloaded and 968,376,440 reused from the read-only cache. The median of per-case local replay medians was 8.74 seconds and the maximum process peak RSS was 124,764,160 bytes. These runs used warm local inputs and three concurrent workers; they are descriptive costs, not a speed comparison. The separate continuous tar ASan process still exceeds the 512 MiB RSS cap. Twelve bounded five-second windows pass but do not qualify that continuous gate.

## Decision and reproduction

Keep this **20/30, 18-miss result frozen**. A later candidate may support the observed tar dialect only after validating exact archive semantics, negative controls, old fingerprints and approval behavior. It must be tested on a *new* held-out cohort; rescoring these 30 as unseen would erase the failure. The 4,097 reference unknowns need a separately declared locator strategy or an explicit lower bound on achievable completion, without treating weak evidence as approved. Human review advantage, external maintainer use, continuous tar fuzz compliance and a new signed release remain open.

The local raw evidence is under `ecosystem_audit/npm3-unseen-20261110`; it includes original source bytes and archives, independent labels, five report rounds, graph-reference responses, the [decision trail](npm3-unseen-20261110.tsv) and saved failures. To reproduce from those inputs, run `python3 tools/npm3_sprint_pairs.py replay --output /absolute/path/to/pair-qualification --binary /absolute/path/to/frozen/tau-gate --rounds 5 --jobs 3`, then `python3 tools/npm3_unseen_scorecard.py --output /absolute/path/to/npm3-unseen-20261110`. The committed scorecard is compact evidence, not a copy of the raw corpus. Full originating chronology, independent operation and outside reviewer identity are not certified by this local run.
