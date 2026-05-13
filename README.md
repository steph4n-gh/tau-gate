# $\tau$-Gate (v2.0.1)
**Geometric Zero-Trust: Integrity in Code and Deployment.**

[![Security Audit](https://github.com/steph4n-gh/tau-gate/actions/workflows/release.yml/badge.svg)](https://github.com/steph4n-gh/tau-gate/actions)
[![Dependencies: 0](https://img.shields.io/badge/Dependencies-0-00f3ff?style=flat-square)](https://github.com/steph4n-gh/tau-gate/blob/main/Cargo.toml)
[![τ-Gate: Secured](https://img.shields.io/badge/τ--Gate-Secured-00f3ff?style=flat-square)](https://github.com/steph4n-gh/tau-gate)

---

> ### 👦 **Explain Like I'm 6**
> Imagine your computer is a big city. When you download a new app, it's like a new person moving into town. Most people move into busy neighborhoods and make lots of friends. But sometimes, a **bad guy** tries to sneak in. He stays in a tiny, hidden basement, doesn't talk to anyone, and tries to build a secret tunnel to the city's bank vault.
> 
> **$\tau$-Gate is an audit tool for your city.** It looks at the "map" of where everyone lives. If it sees someone hiding in a tiny, lonely corner while trying to build a secret tunnel, it **slams the gates shut** and kicks them out before they can do any damage.

---

## 🛡️ v2.0.1: Architectural Self-Sufficiency
$\tau$-Gate v2.0 implements a self-contained security model designed to address the "Auditor's Paradox"—the risk that a security tool itself is compromised by its own dependencies.

### Technical Integrity Features:
*   **Zero External Dependencies:** Every line of code, from the $O(E)$ sparse solver to the lockfile extractors, is implemented using the **Rust Standard Library.** This eliminates transitive supply chain risk in the auditor itself.
*   **Minimal-Action CI/CD:** The release pipeline utilizes native system utilities (`git`, `rustup`, `gh`) instead of 3rd-party GitHub Actions, reducing the infrastructure attack surface.
*   **Formal Reproducibility:** Byte-for-byte identical binary generation using `reproduce.sh`. Verification proof that your binary matches our source code.
*   **Entropy Engine:** Natively detects obfuscated (high-entropy) payloads in metadata by looking for long continuous strings (>128 chars) with high character variance (>16 distinct chars), catching "Sleeper Cells" while preventing false positives on mock packages.

---

## 🚩 The Problem: Structural Attacks
Modern supply chain attacks (TanStack Query, XZ Utils) bypass traditional scanners because they hide in **Transitive Secrecy**. They establish structural bottlenecks deep in your tree to execute malicious code.

## 🛡️ The Solution: $\tau$-Gate
$\tau$-Gate analyzes the **Shape of your Dependencies** before untrusted code can run.

### 🧠 Core Methodology

#### **Level 1: The Social Network (Intuitive)**
Trusted software forms a dense "Mainland." Attackers form tiny "Islands." If an isolated island requests system power (execution scripts or build hooks), the math flags it and blocks it.

#### **Level 2: Spectral Bisection (Technical)**
We model your project as a **Graph Laplacian ($L = D - A$)** and solve for the **Fiedler Vector** ($\lambda_2$) using a high-performance $O(E)$ sparse iterative solver. We identify the **Maximum Spectral Gap** to mathematically identify structural isolation.

---

## 🚀 Quick Start

1.  **Install Globally:**
    ```bash
    curl -L https://raw.githubusercontent.com/steph4n-gh/tau-gate/main/install.sh | bash
    ```
2.  **Audit Your Project:**
    ```bash
    tau-gate --dry-run
    ```

---

## 📖 Resource Hub

| Documentation | Description |
| :--- | :--- |
| **[Setup & Integration](./docs/setup.md)** | Installation, CLI flags, and Zero-Action CI/CD. |
| **[Governance & Policy](./docs/policy.md)** | Configuration guide, Advisory Mode, and attack scenarios. |
| **[The Mathematics](./docs/whitepaper.md)** | In-depth technical whitepaper on Spectral Bisection. |
| **[Empirical Validation](./docs/validation.md)** | Performance and accuracy data from real-world audits. |
| **[Strategy Audit](./docs/marketing.md)** | Stakeholder talking points and competitive analysis. |
| **[v3.0 Roadmap](./docs/roadmap_v3.md)** | Future architecture: Network-Level Resolution Engine. |
| **[Extensibility Guide](./docs/extensibility.md)** | How to add support for new package managers. |

---

## ⚖️ License: Free for People, Not for Profit
$\tau$-Gate is licensed under the **Polyform Non-Commercial License 1.0.0**.

*   **Individuals & Researchers:** 100% Free. Use it, hack it, share it.
*   **Organizations:** 100% Free for **internal use** to protect your own pipelines.
*   **Commercial Use:** You may **not** sell $\tau$-Gate or build a commercial product/service based on this source code.
