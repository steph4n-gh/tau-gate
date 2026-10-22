# Security policy

## Supported versions

Security fixes are considered for the latest code on `main` and the latest published release, currently `v4.2.1`. Older tags, including releases under the PolyForm Noncommercial License, are not maintained.

## Reporting a vulnerability

Submit a [private vulnerability report on GitHub](https://github.com/steph4n-gh/tau-gate/security/advisories/new) or email [stephan@orioletech.llc](mailto:stephan@orioletech.llc). Include the affected version or commit, what you expected, and a way to reproduce the issue if you have one.

Do not open a public issue for an undisclosed vulnerability.

There is no bug-bounty program and no guaranteed response window. A report will be acknowledged, and a fix will be coordinated before public disclosure when the issue is accepted.

## Out of scope

Tau-Gate is a read-only dependency-change reviewer. With explicit npm evidence, it verifies original archive bytes and inventories lifecycle script bodies and native-build inputs. It does not execute those scripts, simulate a host installation, or certify that a dependency is safe. The [README](README.md) describes the supported scope.

Reports of an incorrect allowed result, an approval or evidence bypass, unsafe input handling, or resource exhaustion are in scope. A failure to detect malware without a violated documented review or enforcement rule is not, by itself, a security vulnerability in Tau-Gate.
