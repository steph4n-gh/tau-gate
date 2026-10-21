> **Historical research note.** The claims and commands below do not describe the current product. Use the [README](../README.md) and [review contract](review.md) for supported behavior.
>
> **Supported now:** read-only review of npm v3, pnpm v9, and Yarn Classic v1 lockfiles. Bun, Yarn Berry, Go, and the Cargo CLI are unsupported. Cargo metadata parsing is an incomplete library preview. There is no immunity, formal verification, or safety proof.
>
> **License:** [Apache License 2.0](../LICENSE). Any argument below for the PolyForm Noncommercial License is withdrawn. Versions before 4.0.0 were released under PolyForm Noncommercial 1.0.0.
>
> Current scope: [README](../README.md) and [review contract](review.md).

# $\tau$-Gate: Strategy & Truth Audit (v3.0.0)

This document provides a technical audit and discussion points for the self-contained security model.

## 🛡️ The Technical Truth Audit

This audit evaluates the v3.0.0 implementation against sophisticated threat actors.

### 1. Self-Contained Integrity
*   **Zero External Dependencies:** v3.0.0 is built with 0 external crates. This removes transitive supply chain risk in $\tau$-Gate's own runtime.
*   **Formal Reproducibility:** Every build is byte-for-byte identical. Users can verify that the binary on their machine matches the source code.
*   **Minimal-Action CI/CD:** We have eliminated 3rd-party GitHub Actions from our pipeline, utilizing native system tools to reduce infrastructure-level supply chain risk.

### 2. Core Security Pillars
*   **Structural Secrecy Detection:** $\tau$-Gate identifies the mathematical "hiding spots" used by zero-day supply chain attackers.
*   **Entropy Engine:** Identifies "Sleeper Cells" that hide malicious payloads in high-entropy metadata.
*   **Transitive Translucency:** ~~Native, verified support for `npm`, `pnpm`, `Bun`, `Yarn Berry`, and `Cargo` (Rust).~~ **Withdrawn.** Current support is npm v3, pnpm v9, and Yarn Classic v1 only.

### 3. Constraints & Scoping
*   **Installation Pipeline Audit:** $\tau$-Gate audits the **Shape of Trust** during installation. It is not a runtime monitor or a source-code logic scanner.
*   **The "Loud" Attack Defense:** v3.0.0 uses the **Connectivity Score ($\lambda_2$)** to identify "Bloated Trojans"—addressing the paradox where an infiltrator tries to bypass size thresholds by adding dependencies.

---

## 📢 Discussion Guide

### 🎯 The Elevator Pitch
~~"$\tau$-Gate is a mathematical audit tool for your software supply chain. Instead of matching against a list of known viruses, it uses Spectral Graph Theory to find 'hidden tunnels' built by attackers to bypass security. By utilizing a self-contained architecture, it is designed to be immune to its own supply chain."~~

**Withdrawn.** τ-Gate does not claim immunity, and topology is not a detector of malicious code.

### 👦 Stakeholder Q&A
*   **Q: Why do we need this alongside existing scanners?**
    *   **A:** Scanners look for "known criminals." $\tau$-Gate identifies "suspicious behavior" (isolation and privilege escalation), catching attackers before they are even reported.
*   **Q: Impact on development velocity?**
    *   **A:** Negligible. The bespoke $O(E)$ sparse solver processes thousands of nodes in milliseconds. It provides a silent gate.
*   **Q: Is it safe for internal use?**
    *   **A:** ~~Yes. It is 100% offline, zero-dependency, and licensed specifically for free internal corporate protection.~~ **Withdrawn as a license claim.** The tool is offline and has no Rust dependencies. It is Apache-2.0, not a noncommercial license.

---

## License
The source-available strategy and the argument for the PolyForm Noncommercial License 1.0.0 that used to appear in this section are withdrawn. τ-Gate 4.0.0 is Apache License 2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
