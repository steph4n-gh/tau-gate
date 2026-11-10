# Fourth npm v3 qualification cohort

The frozen candidate **does not qualify for release**. It explains every independently assessable change in this cohort and completes every pair with a complete historical oracle, but only **10/30** selected reviews complete end to end. The unchanged 80% floor fails. One of five exact-source continuous tar ASan runs also exceeds the 512 MiB RSS cap. The [compact evidence receipt](evidence/npm3-full-sprint-20261110.json) binds the results below to retained local inputs and logs under `ecosystem_audit/npm3-full-sprint-20261110`.

The tested core is commit `4fc111b30ee066567ca6eff4970ac26d1229da76`, macOS release binary SHA256 `68984faa78311ff3d649bd86ce911153ceaef521d460b719b0a25e6973c9561d`. The [predeclared protocol](npm3-fourth-protocol.md) selected the next 300 canonical repository identities from the pinned ecosyste.ms critical npm ranking after excluding 600 earlier identities. It retained unavailable and no-lock repositories, then took the first eligible historical npm v3 update from each repository, with at most three attempted lock-changing commits. This yielded **30 pairs from 30 distinct repositories**. Selection, acquisition, independent labeling, and candidate replay were frozen in that order. No public package lifecycle command was executed.

The implementation reduces tar-path allocations, stores a SHA256 digest of non-checksum tar header metadata for dot-alias comparison, and reuses bounded fuzz-reference buffers. The alias equality check therefore relies on SHA256 collision resistance rather than direct comparison of the stored header fields. Original archive bytes remain bound to lock integrity and approval fingerprints, and the alias-conflict and stale-approval controls passed. These memory changes did not close the continuous fuzz gate.

| Check | Result | Gate |
| --- | ---: | --- |
| Repository coverage | 90/300 captured project lockfiles; 35 npm v3 locks | Descriptive |
| Independent historical labels | 10/30 pairs complete | Availability reported separately |
| Full reviews, all selected pairs | 10/30 (33.3%) | **Fail** 80% floor |
| Full reviews, oracle-complete pairs | 10/10 (100%) | Pass 95% conditional floor; small denominator |
| Independently assessable events | 2,791/2,791 matched; zero fact mismatches | Pass in measured scope |
| Five-round replay | 30/30 byte-identical outputs; no invalid exits or timeouts | Pass |
| Authored protection controls | 327/327 evidence, 20/20 trusted wrapper, 17/17 native comparison cases | Pass; no unexpected outcomes |
| Graph references | 35/35 npm Arborist instance-path and resolved-edge sets; five local workspace name differences across two repositories; 33/35 ecosyste.ms coordinate sets | Mixed scoped correspondence |
| Continuous tar ASan | Four passes; one run reached 517 MiB under a 512 MiB cap | **Fail** five-of-five gate |
| Human review benefit and outside adoption | Not measured | Open |

The five replay rounds used the same binary, three concurrent workers, local archives and ordinary operating-system caches. The median of per-pair median process times was 4.42 seconds; the slowest process took 100.17 seconds and peak process RSS was 1,298,743,296 bytes. These are local processing costs, not comparisons with an equivalent native-review workload. Acquisition took 209.85 seconds and charged the full 4 GiB cap: 3.18 GB of new unique compressed downloads and 1.05 GB of read-only cache reuse. The independent collector validated 31 of 60 snapshot sides; the other 29 were rejected or incomplete.

## What limits completion

The independent oracle marked 20 pairs partial, so the candidate could not pass the raw floor on this frozen sample. Across both sides of the 30 pairs, 3,385 package-side records have unknown exact facts. Of these, 3,290 lack an acquired evidence locator: 3,074 repeated records lack canonical SHA512 integrity in their historical lock, 214 hit the declared aggregate budget, one exceeded the snapshot evidence-read cap, and one requires a custom registry archive not in the offline cache. Other unknowns comprise 78 unsafe relative paths, ten archives above the expanded-size limit, four above the member-count limit, two manifests with duplicate JSON keys, and one manifest/lock dependency disagreement. These are package-side records, not distinct packages or repositories. A current registry response cannot retrospectively bind missing historical bytes; prospective lock revision must be scored separately.

The graph comparison matches Arborist's installed paths and resolved edge pairs for all 35 captured npm v3 locks. Tau-Gate names five local workspace records by path where Arborist uses their package names. The hosted ecosyste.ms comparison differs on `tsconfig-paths` and `@smithy/hash-node` coordinates in two cases; the exact hosted responses are retained, and the cause is not assigned here. These findings preclude a claim of perfect graph correspondence or unique graph extraction.

## A real changed command

In `aws/aws-sdk-js-crypto-helpers`, the locked route is **root → lerna → nx** (`devDependencies`, then `dependencies`). The historical update changes `nx` from 17.2.8 to 22.6.0 and its `postinstall` body from `node ./bin/post-install` to `node ./bin/post-install || exit 0`. Independent package manifests and the candidate agree on that event. The original archives match their lock integrity, and Tau-Gate reports distinct before/after approval fingerprints. [The readable case view](../../ecosystem_audit/npm3-full-sprint-20261110/nx-real-update-v2.html) shows the exact source, route, hashes and remaining unknowns. This pair's overall review remains **incomplete**; the view grants no approval and makes no safety claim. Native version/source approval rules also notice this version movement. Tau-Gate's measured addition here is the exact command and evidence-bound, project-specific explanation, not a demonstrated human time saving.

## Controls, regressions, and decision

The added GNU USTAR controls cover an exact approved archive, changed command, changed non-lifecycle payload, bad header checksum and tar link under an old approval. All passed on the frozen binary. The same binary repeated the older known cohorts at 25/30 and 22/30 complete, matched 4,312/4,312 and 2,447/2,447 assessable events, and kept **21,277** and **12,982** previously qualified package-side facts, candidate flags and approval fingerprints unchanged. These are known-case regressions, not new holdout scores. The Rust suite passed 152 tests, Python passed 113, the fuzz seed suite passed 30, and formatting and Clippy passed.

The exact-source tar binary passed four uninterrupted 60-second runs at reported peaks of 457, 477, 475 and 509 MiB; another stopped at 517 MiB after 1,334,997 inputs. All used 64 KiB maximum inputs, a two-second input timeout, the fixed seed, the 512 MiB RSS cap and default sanitizer quarantine. The earlier diagnostic series also varied. We do not infer that the memory problem is solved from the four passes.

Tau-Gate's supported extra protection remains exact evidence-bound approval under the controlled same-version/same-URL changes that native rules allowed; native rules already blocked tested new versions, source movement and original-integrity tampering. The review burden of byte-only reapproval is still unmeasured with users. The next engineering work is a **trustworthy byte-locator path for historical locks**, a durable fix for continuous tar fuzz memory, and the local workspace name discrepancy. Re-run those changes on a newly frozen sample before improving a qualification claim. No new signed release, consumer rollout, or outside-maintainer study was performed for this failed candidate.

The case-view helper received a presentation-only wording correction after the core/source freeze so it describes this real command accurately and discloses incomplete reviews. The core binary, frozen labels, scoring code and replay outputs were not changed. Its hash and the generated view hash are in the compact receipt. Full reproduction needs the locally retained source snapshots and archives; the committed receipt identifies their frozen manifests and outputs, but does not embed those large inputs.
