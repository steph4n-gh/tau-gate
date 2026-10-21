# Qualification and adoption program

This program starts from v4.1 commit `4fcf535fd1b52922fd4b0d2584bc0d2fb8bbbbe0`.
The Rust core remains offline, read-only, and free of runtime dependencies.

## Workflow

- [x] Read the Principles section of the poteto-mode skill.
- [x] Phase A: Frame.
- [x] Phase B: Design the workflow.
- [ ] Phase C: Run the loop.
- [ ] Phase D: Keep the audit trail.
- [ ] Phase E: Verify and hand back.

Architectural changes follow Ground, Sketch, Agree, Implement, and Scrap.
Independent design candidates precede implementation. Agreement proceeds without a human checkpoint.

## Done predicates

1. Account for 90 frozen historical update pairs across 30 public npm v3 projects. Preserve unsupported cases in the denominator. Label policy-relevant events independently of Tau-Gate output. Preserve the unchanged v4.1 baseline.
2. Qualify demonstrated compatibility repairs and the full input chain. Record differential and fuzz campaigns, aggregate resource checks, minimized failures, and zero unresolved false allowed outcomes in mandatory controls.
3. Verify installation, trusted approvals, merge, cleanup, and upgrades in two consumer repositories. Untrusted policy, helper, workflow, binary, and evidence changes must not silently authorize execution. Main stays valid during approval transitions.
4. Rebuild a declared Linux x86_64 release payload in two clean environments. Compare bytes. Verify signatures, provenance, SBOM, installation, and tamper rejection. Distinguish independently provisioned builders from independently operated rebuilds.
5. Deliver a pilot kit and start self-pilots in two owned npm projects, following the user steering on 2026-10-20. Exercise genuine dependency updates and record setup and review effort. Automated or historical runs do not satisfy sustained-use evidence. Four weeks of actual use and independent external maintainer feedback remain separate future evidence gates.

All numerical targets are proposed qualification criteria, not existing results.
A milestone closes only with inspectable artifacts. An incomplete or unavailable result is never a pass.

## Milestone status

- [x] M1 measurement. All 90 unchanged baseline reviews are accounted for, with independently checked input/output hashes and corrected event scoring. The product baseline is unqualified. See [the baseline](baseline.md).
- [x] M2 repairs, differential controls, fuzzing, and resource qualification. The [frozen candidate and holdout](m2.md) preserve 11 known reporting misses and limited comparison coverage; mandatory controls found no false allowed outcome. A later [v4.2.1 qualification replay](evidence/marker-repair-replay.json) reached 38 core-complete and 17 comparison-complete pairs, with the same 11 misses.
- [x] M3 trusted approvals and consumer CI lifecycle. Schema 2, the trusted-base workflow, and local stage/update/cleanup controls pass. Both owned consumers have v4.2.1 helpers and required `tau-gate` checks. The [live REA stage/update/cleanup sequence](pilots.md) and final merged-main CI passed. REA's separate product CI was disabled during the staged-policy merge and again after the final green run. It was restored, but the recurring toggle remains unexplained.
- [x] M4 final Linux release payload and verification. v4.2.1 is published at the exact merged source commit; two clean local builds and the GitHub candidate matched byte for byte. Signatures, provenance, CycloneDX schema, clean Debian 12 install, and tamper rejection passed. The [release receipt](evidence/release-v4.2.1.json) records hashes and the independent-operator limitation.
- [ ] M5 two owned-repository self-pilots and a sustained-use record. The [pilot record](pilots.md) lists live results and open evidence; four weeks of use have not elapsed.

## Execution order

1. Freeze selection rules, corpus input records, event taxonomy, and a holdout split.
2. Replay the unchanged v4.1 baseline and classify every selected pair.
3. Repair measured blockers one at a time and rerun their negative controls.
4. Run differential, fuzz, and aggregate resource campaigns.
5. Implement and verify the complete trusted approval lifecycle and consumer workflow.
6. Qualify the final release payload, installer, provenance, and reproducibility recipe.
7. Prepare the pilot materials, record actual participation and elapsed use, and publish bounded conclusions.

Release recipe experiments may run independently before step 6. Final release qualification covers the final code.
Do not run public package lifecycle scripts. Keep acquisition separate from the core.
Self-pilots in owned projects are authorized. External maintainer recruitment is deferred. Prepare a reviewable release candidate before any final publication gate.

## Verification record

The canonical decision trail is `docs/qualification/decisions.tsv`.
Large downloaded source trees, archives, and raw experiment outputs stay outside Git.
Committed manifests, receipts, and replay tools identify inputs and outcomes.

## Chosen design

Use immutable per-case receipts with advisory corpus replay. Public projects have no Tau-Gate policy, so primary coverage does not invent approvals. Preserve independent event labels and separate capture, acquisition, oracle, collector, core, and comparison statuses. Freeze original SRI-verified archives before strict profile validation. Each worker owns a separate worktree and each case owns its output directory.

The architecture arena selected snapshot-first candidate B with acquisition and stage-status details from A. Both candidates converged on exact-path reviewed fingerprint sets for the later approval transition. Actual trusted automatic workflow enforcement remains an experiment to verify, not an assumption.

For resource repairs, the second design arena selected two reusable byte vectors owned by the existing sequential evidence loader. Returned facts own their bytes. A new inspector object or artifact cache is unnecessary. Verify unchanged report bytes before adding cumulative work limits or changing archive compatibility. Charge failed and repeated inspection attempts. Choose fixed limits from the development census before opening holdout failure details.

The measured legacy archive repair keeps strict text parsing and accepts one consistent top-level directory. A narrow empty-prefix timestamp layout may be accepted only after validating its exact fields. Mixed roots, aliases, parent conflicts, links, extensions, original-byte integrity failures, and incomplete scans remain unsupported. The independent npm reference provides correspondence evidence for the specific legacy examples.
