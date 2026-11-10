# npm v3 qualification comparison scorecard

The candidate demonstrates additional exact-evidence approval binding, but **fails the ordinary completed-review gate: 13/30 (43.3%), against the frozen 80% floor**. Human advantage remains unmeasured.

| Area | Measured result | Conclusion |
| --- | --- | --- |
| Controlled protection | 307 evidence controls; 20 trusted Git-object wrapper controls; 17 cases comparing native and Tau-Gate decisions | Expected outcomes pass in declared fixture scope |
| Native shared protection | Strict npm exact-URL and exact-version rules reject the tested hook-bearing version update, unapproved hook and original-SRI tamper; exact-URL also rejects source movement | Credit both tools; no unique-protection claim here |
| Added binding | Same approved URL/version, changed command or bytes, updated lock integrity: native permits; old Tau fingerprint rejects | Extra evidence binding under these fixture conditions |
| Approval cost | Hook-bearing metadata-only archive change: native permits; Tau requests new approval | Conservative reapproval burden; not proof of danger |
| Real-update completion | 13/30 complete; 17 incomplete retained | FAIL frozen 80% floor |
| Known fact reporting | 4291/4301 matched; 10 raw artifact hash changes omitted; 89 unknown package-side facts | Unknown execution relevance for misses; incomplete is not approval |
| Actual hook-body changes | 2 known changes matched | Small bounded observation, not malware-detection validation |
| Graph correspondence | 20/20 match npmArborist common instance/edge fields and ecosyste.ms common coordinates | Scoped extraction evidence; hosted parser does not supply equivalent execution review |
| Local Linux repeatability | Two offline builds; executable/archive/SBOM/checksums match; Debian and tamper controls pass | Same-operator repeatability; no new signed release |
| Finite ASan robustness | 7/8 targets complete; tar exceeds the 512 MiB process RSS cap | Primary resource failure retained; diagnostic success does not replace it |
| Local cached-input core cost | Median of case medians 10.20 s; peak 557.4 MiB | Automated processing only; no equivalent-work speedup claim |
| Human review/adoption | Not measured | Open evidence gate |

## Strong native policy comparison

Native entries describe whether the controlled script ran; Tau entries describe its offline approval decision. They are different operations, so this table is not an execution/performance equivalence claim. Native uses strict npm 12.2.2 with a trusted-base exact tarball URL policy. The exact-version column is retained as a secondary comparator. Installed npm 11.19.1 produced the same observed outcomes.

| Controlled case | Native exactURL | Native exactversion | Tau-Gate |
| --- | --- | --- | --- |
| unchanged | executed | executed | allowed |
| command_changed | executed | executed | blocked |
| version_changed | blocked | blocked | blocked |
| archive_payload_changed | executed | executed | blocked |
| hook_metadata_changed | executed | executed | blocked |
| source_changed | blocked | executed | blocked |
| integrity_tamper | blocked | blocked | incomplete |
| missing_evidence | executed | executed | incomplete |
| no_hook_metadata_changed | no_execution | no_execution | allowed |
| no_hook_version_changed | no_execution | no_execution | allowed |
| new_unapproved_hook | blocked | blocked | blocked |
| legitimate_command_approved | executed | executed | allowed |
| legitimate_version_approved | executed | executed | allowed |
| policy_self_edit | blocked | blocked | blocked |
| root_unchanged | executed | executed | allowed |
| root_command_changed | executed | executed | blocked |
| legitimate_root_approved | executed | executed | allowed |

## Processing and acquisition cost

Five round-major runs alternate case order. Archives are local and OS caches are not flushed. Costs are descriptive for this host/load; native fixture installation and a full evidence review do different work. Failed/incomplete runs remain in the totals.

Acquisition: 100.2s; 1288.7 MiBnew unique compressed downloads and 1106.4 MiBread-only cache reuse. All 2704 original archive identities were available. No acquisition-budget exhaustion.
Core all-run wall range: 0.25–19.65s. Per-case median range: 0.27–19.37s. Peak core RSS: 557.4 MiB.

## Limits and next decision

The 100 new repository cohort contains 54 without a lockfile in fixed scope, 46 with locks and 20 npm3 inventories. The 30 update pairs are clustered in 11 repositories. Keep these denominators separate. No public package lifecycle script was run; public reports were advisory and used no fabricated approvals.
The independent label/reference layer contains only two actual lifecycle-body changes. Most of the 4301 known facts concern versions, sources, hashes and additions/removals. The ten omitted raw artifact changes occur in an incomplete domhandler review for oversized Biome platform archives; full execution facts are unknown. This is a reporting gap, not demonstrated unsafe authorization.
Exact-byte approval binding adds protection and review churn. The next engineering priority is usable evidence coverage and preservation of known byte-change facts when execution parsing is incomplete. No profile bound was raised or case replaced to improve this result.
The extra ASan campaign is finite evidence, not a safety proof. Its tar target exceeded the 512 MiB process RSS cap; preserve that failure separately from successful targets and any resource diagnostics.

Raw source snapshots, original archives, labels, per-run outputs, corrections and receipts remain local under this study directory. The committed scorecard and helper sources identify the method; full independent replay also requires these inputs.

## Current native versions and comparison boundaries

The current-version refresh pinned npm 12.2.2 and pnpm 12.18.0 from registry metadata and verified their official tool-package integrity. Native dependency scripts executed only locally authored harmless canaries. npm 12.2.2 produced the same 17 case outcomes as installed npm 11.19.1. Both exact-version and exact-URL policies ran with strict approval settings and trusted-base policy restoration. This is evidence about those settings and fixtures, not a claim of a native vulnerability.

Current pnpm 12.18.0 passed 5/5 adjunct cases using exact-version `permissions.build`: unchanged approved and newly approved packages ran; a changed command at the same URL/version with updated integrity also ran; an unapproved new version and stale-integrity tamper were blocked. Older pnpm 10.33.4 also suppressed unapproved execution, although its tested rebuild path returned exit 0 for one new-version case. That CI-exit difference was retained and investigated; it is not an execution bypass. Tau-Gate does not qualify pnpm execution evidence, so these are adjacent native-policy observations rather than a supported pnpm replacement claim.

The new binding shown by Tau-Gate concerns the exact artifact/source and derived execution evidence. Byte-only payload and metadata changes can trigger approval even when the command is unchanged. The operational benefit and review burden both need real users to evaluate. New-version/source movement and original-SRI tampering already have native protection and are credited to it.

## A concrete report someone can review

The [readable real update](../../ecosystem_audit/npm3-sprint-20261109/example-review.html) shows source-map-loader changing unrs-resolver 1.9.0 to 1.11.1 through the development path `root → jest → @jest/core → jest-resolve → unrs-resolver`. Its archive declares `postinstall` changing from `napi-postinstall unrs-resolver 1.9.0 check` to `napi-postinstall unrs-resolver 1.11.1 check`. The view includes typed edges, independently checked original artifact integrity, manifest/command hashes and changed approval fingerprints. It explicitly grants no approval and notes that native version/source rules also notice this version change. Browser rendering and evidence disclosure were checked. This is an internal usability demonstration, not measured human advantage.

## Qualification decision

Keep the exact-evidence binding and project-specific explanation as the demonstrated technical additions. Do not claim the chosen ordinary-review completion promise is qualified: 13/30 fails the 80% gate. Prioritize preserving known raw-byte changes in incomplete reports and investigating bounded inspection of large optional binary archives. Root manifest/lock inconsistencies and missing locators also need explicit handling. No profile bound was raised, no update replaced and no product code changed to improve this frozen result.

The 30 pairs come from 11 repositories in a later slice of the same critical npm ranking; they are not 30 independent repositories or a population-wide coverage estimate. The 4301 known events are correlated facts: versions, sources, integrity, manifests, artifacts, additions and removals. Only two are lifecycle-body changes. The 89 unknown package-side records remain unassessed, and the ten omitted archive-hash changes have unknown execution relevance. Recall does not establish precision, maliciousness detection, host execution selection or safety. Public reviews were advisory, so absence of historical `allowed` outcomes is not evidence against incorrect authorization. That question is measured only in controlled enforcement tests here.

## Reproduction and corrections

The [decision trail](npm3-sprint-20261109.tsv) and [scorecard receipt](../../ecosystem_audit/npm3-sprint-20261109/scorecard-receipt.json) identify the local source, inputs and results. Candidate source is f1ceb5065e9cff509260de2709add024cc5c32e6; macOS binary SHA256 is 096cf0a6a96bc66f5c4f5589dcd9ac1770ca3613cb01bd86fe4c9daaaa48ba86. `tools/npm3_sprint.py` acquires the new cohort, `tools/npm3_sprint_pairs.py` captures and independently labels update pairs before replay, and `tools/npm3_scorecard.py` verifies completed receipts. Large inputs remain local and ignored by Git; a fresh checkout needs the frozen corpus for full replay.

The original npm comparison retained 13 observer failures from a compact-versus-pretty JSON hash error; all native/Tau decisions were unchanged. The corrected observer run is separate and backed by a regression test. Reusing that helper for npm 12 left obsolete 11.19.1 version prose in its raw summary; an explicit hash-bound erratum and current-version report preserve and correct it. The frozen historical runner remains under `pair-qualification/frozen-tools`; a later standalone-harness cleanup removes an unnecessary NumPy/SciPy import and changes future discovery timeout 60→90 seconds, without replaying or reinterpreting these cases. Initial latest-tool invocation failures and all fuzz failures remain in their receipts.

Linux executable, archive, SBOM and checksums are reproducible across two clean local offline builds, with 139 Rust tests passing in each. Debian extraction, executable verification and tamper rejection passed. Both builds had the same operator; this is neither an independent-operator rebuild nor a new signed/published release. The finite ASan tar resource failure remains open despite the separate reduced-quarantine diagnostic success.

No outside maintainer participated, and no human review-time advantage, independent adoption or sustained-use duration is established by this sprint. The [independent source/artifact review](../../ecosystem_audit/npm3-sprint-20261109/REVIEW.md) also distinguishes artifact verification from unavailable full-transcript chronology.

An unreported three-second sample of the slowest complete case located busy stacks in archive inspection, DEFLATE inflation and Huffman decoding. Its output matched the measured run byte for byte. This supports archive processing as a cost driver in that case; it does not establish a global speed comparison. The [profile receipt](../../ecosystem_audit/npm3-sprint-20261109/profile/receipt.json) retains the invocation.

A [compact committed evidence record](evidence/npm3-sprint-20261109.json) preserves the candidate freeze, selected repository identities, source pairs, label summaries, per-case results and receipt hashes. The large raw corpus remains local.

The recorded graph-reference helper is preserved in `graph-comparison/frozen-tools` with hashes matching its protocol. The tracked helper later replaces operator-specific tool paths with explicit `--node`/`--npm` options for future runs; no recorded comparison was rerun or rescored.
