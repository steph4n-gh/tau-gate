# Qualification and adoption program

This program starts from v4.1 commit `4fcf535fd1b52922fd4b0d2584bc0d2fb8bbbbe0`.
The Rust core remains offline, read-only, and free of runtime dependencies.

## Workflow

- [x] Read the Principles section of the poteto-mode skill.
- [x] Phase A: Frame.
- [ ] Phase B: Design the workflow.
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
5. Deliver a pilot kit and record genuine maintainer use. The proposed evaluation needs three to five independent maintainers over four weeks and at least 20 real updates collectively. Automated or historical runs do not satisfy sustained-use evidence.

All numerical targets are proposed qualification criteria, not existing results.
A milestone closes only with inspectable artifacts. An incomplete or unavailable result is never a pass.

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
Do not contact maintainers or publish a final release without concrete authorization for those external actions.

## Verification record

The canonical decision trail is `docs/qualification/decisions.tsv`.
Large downloaded source trees, archives, and raw experiment outputs stay outside Git.
Committed manifests, receipts, and replay tools identify inputs and outcomes.
