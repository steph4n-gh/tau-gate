# Fourth npm v3 qualification protocol

This protocol is for a **new** candidate after the GNU USTAR repair and tar memory work. The previous 30-pair unseen result remains 20/30; its later 22/30 replay is a known regression. Freeze the candidate binary, this protocol, selector, independent oracle and scoring code by SHA256 before selecting repositories or opening update results.

## Selection and denominators

Use the pinned ecosyste.ms critical npm source from the prior sprint. Exclude all 600 canonical repository identities in the first three cohort groups. Take the next **300 distinct canonical GitHub repository identities** in ranking order. Retain unavailable, no-lock and non-v3 repositories in the 300, without replacements. For each captured repository, inspect at most three newest lock-changing commits using the first parent and frozen path order. Take only its **first eligible npm v3 update pair**. Stop at **30 pairs from 30 repositories**. If 300 identities do not yield 30 pairs, record the shortfall; do not extend the sample after seeing outcomes.

Independently label every selected pair before candidate replay. An oracle-valid pair has matching source manifest and lock specifications and exact package bytes bound by the historical lock or pinned source tree. Valid archive features that the independent reader accepts remain oracle-valid even if Tau-Gate rejects them. Missing URL and integrity on an external historical package leave the label incomplete; a current registry lookup is not a historical byte binding. An explicit new lock revision is a prospective case and cannot improve historical completion.

Report three separate counts with all failure reasons and repository identities:

1. Independent-label availability: oracle-valid pairs / all selected pairs.
2. Conditional product completion: fully matched Tau-Gate reviews / oracle-valid pairs. The predeclared floor is **95%**.
3. End-to-end completion: fully matched Tau-Gate reviews / all selected pairs. Keep the original **80%** floor as a usability gate; do not replace the frozen earlier failures.

If fewer than 30 pairs are selected, or no oracle-valid pair exists, neither completion floor passes. Keep unsupported and unavailable attempts in the selection manifest. Report npm v3 prevalence among the 300 separately; it is not a pair-completion denominator.

## Mandatory checks

- Use one exact candidate binary for all five replay rounds; each case's stdout must be byte-identical across rounds, with no timeout or invalid exit.
- Require zero fact mismatches on qualified records and zero missed assessable events. Unknown facts remain visible and excluded from event recall, never treated as matched.
- Require zero false `allowed` outcomes in the authored evidence, trusted-wrapper and native npm controls, including changed GNU USTAR install commands and bytes, stale approvals, corrupt headers and links. Public replay is advisory and does not estimate an incorrect-approval rate.
- Compare existing qualified facts, candidate flags and approval fingerprints against both known 30-pair regressions. Changed parser coverage may add qualified records, but must not alter old qualified evidence.
- Keep the 4 GiB acquisition budget, 64 MiB per-source-file bound and existing core work limits. Separate network acquisition from local processing cost; report wall time and peak RSS with concurrency stated.
- Pass five uninterrupted 60-second tar ASan runs with the existing 64 KiB input, two-second input timeout, 512 MiB RSS cap and default sanitizer quarantine. Retain every run and crash input. Bounded restarted windows do not satisfy this gate.

Graph correspondence with npm Arborist and ecosyste.ms, human decision benefit and release verification are reported as separate claims. Do not execute public package lifecycle scripts. A fresh cohort passing these gates would qualify the measured npm v3 evidence and review scope; it would not establish package safety, malware detection, reviewer speed or broad ecosystem coverage.
