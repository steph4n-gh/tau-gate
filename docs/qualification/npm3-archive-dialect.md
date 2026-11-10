# Exact GNU USTAR archive regression

The third npm v3 cohort remains a **frozen 20/30 fresh-holdout failure**. This later candidate accepts one additional, exact tar header spelling found in that cohort. Replaying those same cases is a **known-case regression**, not a new unseen score. The [compact receipt](evidence/npm3-archive-dialect-20261110.json) binds the candidate, original inputs, controls, replay summaries and fuzz results to local raw evidence under `ecosystem_audit/npm3-archive-dialect-20261110`.

## What changed

Eleven unique SRI-verified npm archives, repeated in 43 package-side records, used the eight-byte GNU USTAR magic/version `ustar  \0`. Their 1,117 members were regular files; independent Python `tarfile` and npm tar readers accepted representative contents. Tau-Gate's core and Python collector had required only POSIX `ustar\0` plus version `00`. They now accept those **two exact spellings**. Existing checksum, size, path, type, link, reserved-field, padding and archive-bound checks still apply. Near spellings, a bad checksum and a link type remain rejection controls. The collector's manifest bytes match independent `tarfile` reads for all eleven archives.

The core candidate is source commit `b830b275a006260f8bce0340751929bac00d1a7a`, binary SHA256 `95d9cfbaf0c629ef82be856b25bbdc5341a22b1b2b156861decc1379e0e425ce`. The subsequent fuzz-harness commit `d1d6bd7` adds a generated GNU seed and teaches only its reference checksum repair to recognize the same two spellings. It does not change the core binary.

## Known-case results

| Frozen input set replayed with candidate | Original result | New regression result | Assessable events matched | Previously qualified records unchanged |
| --- | ---: | ---: | ---: | ---: |
| Earlier 30-pair repair set | 25/30 | 25/30 | 4,312/4,312 | 21,277 |
| Formerly unseen 30-pair set | 20/30 | 22/30 | 2,447/2,447 | 12,982 |

The newly accepted archives qualify 43 repeated package-side records and recover all 18 previously missed, non-lifecycle manifest-hash changes. There were zero fact mismatches and zero unexpected `allowed` outcomes in these advisory replays. All previously qualified records kept identical state, facts, candidate flag and approval fingerprint. These results do **not** replace the published [fresh result](npm3-unseen.md), and its absence of observed lifecycle-command changes still prevents a claim about reviewer benefit.

Eight of the formerly unseen pairs remain incomplete. Six contain 4,096 repeated locked instances across `octokit/request.js` (96) and `webpack/schema-utils` (4,000) with neither a `resolved` URL nor an `integrity` value. A current registry lookup cannot bind the exact historical package bytes, so these remain incomplete pending a trusted evidence source or an explicit lock revision. One pair has a source manifest/lock dependency mismatch. One has two tar link or special records outside the supported archive profile. These counts are snapshot records, not distinct packages or repositories. The seven pairs with incomplete independent labels mean this cohort could not have reached the frozen 80% completion floor even with perfect core extraction.

## Safety and resource checks

The exact core binary passed 322 archive/evidence controls, 20 trusted-wrapper controls and 17 native npm comparison canaries. These include changed commands and bytes, stale integrity, missing evidence and a policy self edit. The full Rust suite, 111 Python tests, formatting and Clippy also passed. The updated fuzz crate passed 29 seed tests, including the GNU archive and independent tar reference.

The **continuous tar ASan memory gate remains failed**. Five uninterrupted 60-second attempts used 64 KiB maximum inputs, a two-second input timeout, a 512 MiB process RSS cap, the same fixed seed and default ASan quarantine. Two passed at 498 and 491 MiB peak reported RSS; three stopped after reaching 520, 526 and 524 MiB. A single passing attempt does not close this inconsistent gate. The old bounded-process result is a separate operating profile.

## Decision

Keep the exact GNU USTAR repair as a narrow coverage improvement. Keep missing locators, manifest/lock disagreement and link-bearing archives incomplete. This candidate is **not qualified for release**: the formerly unseen set is now a regression, its 22/30 completion remains below the frozen 80% floor, the continuous tar memory gate fails, and no new repository-disjoint cohort or human review study has been run for it. Next work must resolve the memory gate without relaxing its limits, identify a trustworthy locator strategy, then freeze another candidate before selecting a genuinely new cohort. Approval checks remain unchanged.

To reproduce the two known regressions from the retained local inputs, run `python3 tools/npm3_sprint_pairs.py replay --output /absolute/path/to/prior-regression --binary /absolute/path/to/candidate/tau-gate --rounds 1 --jobs 3` and the same command for `unseen-regression`. The copied selection, acquisition, protocol and independent labels in those directories retain their original hashes. `python3 tools/npm3_archive_repair.py summarize --original /absolute/path/to/original/pair-qualification --output /absolute/path/to/regression` verifies old fingerprints and exact-byte observations. No public package lifecycle commands were executed.
