# Security policy

## Supported versions

Security fixes are considered for the latest code on `main`. Once `v4.0.0` is tagged, that is the supported release. Older tags, including releases under the PolyForm Noncommercial License, are not maintained.

## Reporting a vulnerability

Email [stephan@orioletech.llc](mailto:stephan@orioletech.llc). Include the affected version or commit, what you expected, and a way to reproduce the issue if you have one.

Do not open a public issue for an undisclosed vulnerability.

There is no bug-bounty program and no guaranteed response window. A report will be acknowledged, and a fix will be coordinated before public disclosure when the issue is accepted.

## Out of scope

τ-Gate is a read-only lockfile reviewer. It does not inspect dependency script bodies, downloaded artifacts, or runtime behavior, and it does not certify that a dependency is safe. Those limits are documented in the README. A report that the tool failed to detect malware, or that a historical document overstated coverage, is not a vulnerability in the current reviewer.
