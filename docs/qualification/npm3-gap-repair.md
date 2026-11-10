# npm v3 remaining-gap qualification

The same 30 historical npm v3 update pairs now complete **25/30 reviews (83.3%)**, up from 22/30 after the archive repair. This meets the frozen 80% completion floor on these **known cases**. Five pairs remain incomplete for documented input reasons. This is a local repair regression, not a fresh holdout or a release qualification. The [previous archive repair](npm3-archive-repair.md) and [initial scorecard](npm3-sprint-scorecard.md) remain intact.

| Measure | Previous repair | This rerun |
| --- | ---: | ---: |
| Completed pairs | 22/30 | 25/30 |
| Incomplete pairs | 8 | 5 |
| Unknown package-side records | 11 | 8 |
| Assessable events matched | 4,311/4,311 | 4,312/4,312 |
| Frozen 80% floor | Fail | Pass |

The 30 original input pairs, 11 repository identities, selection and protocol are unchanged. The [compact evidence receipt](evidence/npm3-gap-repair-20261109.json) contains the frozen core hashes, 150 replay output hashes, comparisons, controls and fuzz results. Five rounds ran with three isolated workers. All 150 reports have valid protocol outcomes, no fact mismatches or unexpected allowed outcomes, and each pair's stdout is byte-identical across rounds. All 4,311 previously assessable events still match. One root-manifest change becomes assessable in `webpack/loader-runner r063-9711d5c84b26`. These events are correlated facts from 30 updates, not independent security trials. Concurrent host load and additional completed work rule out a sequential speed comparison.

## What changed

Three bases were incomplete solely because npm's root lock version lagged the actual source `package.json` version; their dependency maps agreed. Tau-Gate now treats only that root **source-project** version disagreement as non-authoritative metadata. The locked version remains `snapshot.packages[].version`; the actual source version is `execution_evidence[].facts.version`. Both and the source-manifest digest remain bound to the approval fingerprint, and the report displays the disagreement. Archive and workspace identities, root names, all four dependency maps, missing or malformed differing versions, archive bytes, and approval checks remain strict. Native npm 12.2.2 accepts the three stale root versions but rejects the separate development-dependency mismatch. All 21,274 previously qualified package-side records retain identical facts, state, candidate flag and fingerprint; exactly three root records newly qualify.

The other five historical pairs are **still incomplete**:

| Reason | Records | Pairs |
| --- | ---: | ---: |
| SHA1-only `is-extglob@2.1.1` locator | 6 | Three `microsoft/node-jsonc-parser` pairs |
| HTTP-resolved, SHA1-only `lodash@3.9.3` locator | 1 | One `jhchen/fast-diff` pair |
| Actual root `devDependencies` mismatch (`@paulmillr/jsbt`) | 1 | One `paulmillr/readdirp` pair |

Separate, **unapproved counterfactual** lock proposals replace only the seven weak locator strings after checking canonical HTTPS registry metadata, original SHA1 consistency, current SHA512, manifest identity and complete archive profiles. All four proposed pair reviews complete, but they receive **zero credit** for the original historical pairs. No new trusted pin, approval or lifecycle execution was created. The actual `readdirp` dependency-map inconsistency needs a corrected source/lock update; Tau-Gate continues to reject it.

## Verification and tar fuzzing

Core source was frozen at `0c707606dbae42256758c7fd745bdc286a2758aa`; the tested executable SHA256 is `ae8310fb422f7b7f9d88a00490d847690772415c67d465e6bc7cb42cb104f415`. The local checks passed 151 Rust tests, 110 Python tests, 320 archive/evidence controls, 20 trusted-wrapper controls, and 17 native npm comparisons. Clippy and formatting passed. The separate native observer initially failed during macOS temporary-directory cleanup after its cases had run; the retained-fixture rerun exited cleanly with all 17 comparisons and actual Node/npm versions recorded. Exact core controls and old-record compatibility were checked against the frozen binary.

The tar fuzz harness now borrows ordinary input, reuses one bounded repair scratch buffer and actually reaches its checksum-repair branch. A minimized fuzz case exposed a reference-library dialect mismatch: a USTAR entry with a blank size field is accepted by the production inspector, Python tarfile, system tar and npm's tar reader, while the Rust `tar` reference rejects it. The harness normalizes only blank size fields **on a reference copy after production inspection**; original package bytes, SRI and production facts are untouched. A malformed octal field remains rejected. The saved crash now replays successfully, and all 27 fuzz-crate tests pass.

The 512 MiB **continuous** ASan tar profile remains unresolved. Before the reference correction, five 60-second attempts yielded one pass, three RSS failures and one reference assertion. After correction, a new continuous run again failed at 519 MiB after 1,488,474 units, with no semantic assertion. The original failures and saved inputs are retained. In the separately labelled **bounded-process operational profile**, 12 five-second windows all passed under the same 64 KiB input, two-second timeout, 512 MiB per-process cap and default ASan quarantine. They executed 2,363,225 post-initialization mutation units, with peak process RSS 369,246,208 bytes; the prior crash was included in the seed corpus. Process restarts reset allocator retention and mutation history, and scheduled time includes startup and seed replay. This profile does **not** qualify a continuous 60-second process. The measured live heap stayed near 25–27 MB while allocator backing grew toward the cap in an instrumented diagnostic; that supports retention as a contributor, not a proven sole cause.

## Reproduction and limits

Raw input bytes, logs, failed attempts, controls and the append-only [decision trail](npm3-gap-repair-20261109.tsv) are in the ignored local `ecosystem_audit/npm3-gap-repair-20261109` directory. The committed compact receipt does not replace the original corpus. To replay the original pairs after restoring that corpus, run `tools/npm3_sprint_pairs.py replay --output /absolute/path/to/pair-qualification --binary /absolute/path/to/frozen/tau-gate --rounds 5 --jobs 3`, then `tools/npm3_archive_repair.py summarize --original /absolute/path/to/npm3-sprint/pair-qualification --output /absolute/path/to/pair-qualification`.

Human review benefit, independent adoption, full originating chronology, continuous tar fuzz compliance, and a signed release remain unqualified. A separate read-only agent reviewed the core controls, original inputs, replay hashes and compatibility; it identifies as Codex (GPT-6), and a distinct model family is not attested. The later fuzz-reference correction received focused regression and campaign checks but no independent cross-family review.
