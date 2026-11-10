# npm v3 PR review product milestone

## Promise and scope

A maintainer reviewing an npm v3 dependency PR gets one readable answer: what the project locks, what changed in the proposed head, the shortest typed dependency route, the exact package files supporting any install behavior, what remains unknown, and the next review action. The tool never executes package scripts. npm v1/v2, pnpm and Yarn remain graph and metadata previews; they do not gain an execution-approval claim in this milestone.

The historical fourth cohort stays failed at 10/30 end-to-end. Its independent oracle was complete for only ten pairs. Parser work cannot reconstruct missing historical SHA512 integrity. Prospective PR qualification will use a separately frozen cohort and will not replace that result.

## Done predicates

1. A clean Git repository with a proposed npm v3 update yields a deterministic, readable PR report from trusted Git objects. The report distinguishes current, proposed and unknown evidence; it shows exact before/after lifecycle bodies and a dependency route when verified. It never says a partial project review is complete.
2. A maintainer can authorize exact proposed evidence through a single trusted action without editing fingerprint JSON or staging and cleaning up policy PRs. Changed head, package bytes, commands, sources, or trusted tools invalidate that authorization. A PR cannot authorize itself.
3. Existing missing-evidence, stale-approval, head-policy-edit, and corrupt-archive controls still reject. A fresh prospective set reports completed reviews and misses with unsupported inputs retained. Continuous tar ASan stays under the existing five-run 512 MiB gate.
4. At least five maintainers use the report on real updates, and a blinded comparison measures whether it improves review accuracy or time. Outside participation and release remain separate gates until performed.

## Execution order

1. Preserve the current Git-object and approval control baseline. Define the report data contract and make a real update view from the existing trusted report.
2. Implement the report as a deterministic output of the existing PR helper. Keep unknowns and policy outcomes explicit. Verify against real and authored changed-hook PRs, including HTML escaping and incomplete cases.
3. Design the smallest trusted one-action approval store and its threat controls. Build and test it only after the evidence subject can be identified without a circular dependency on the policy outcome.
4. Trace continuous tar ASan allocation growth to a measured source, fix it without changing rejection semantics, then rerun the exact five-run gate and core controls.
5. Freeze a new prospective repository-disjoint evaluation and compare with native npm and ordinary PR review. Publish bounded results; use external maintainer work only after authorization and recruitment.

Each unit ends with a real report or command run and a retained receipt. A failing gate remains failed; there is no release or consumer rollout based on partial completion.
