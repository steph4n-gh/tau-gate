# $\tau$-Gate (v2.0.0)
**Geometric Zero-Trust: Supply Chain Security with Absolute Integrity.**

---

> ### 👦 **Explain Like I'm 6**
> Imagine your computer is a big city. When you download a new app, it's like a new person moving into town. Most people move into busy neighborhoods and make lots of friends. But sometimes, a **bad guy** tries to sneak in. He stays in a tiny, hidden basement, doesn't talk to anyone, and tries to build a secret tunnel to the city's bank vault.
> 
> **$\tau$-Gate is an audit tool for your city.** It looks at the "map" of where everyone lives. If it sees someone hiding in a tiny, lonely corner while trying to build a secret tunnel, it **slams the gates shut** and kicks them out before they can do any damage.

---

## 🛡️ v2.0.0: The "Absolute Zero" Release
$\tau$-Gate v2.0 represents a new standard in security engineering: **Absolute Zero Dependencies.** 

Most security tools are built on hundreds of third-party packages, making them vulnerable to the very supply chain attacks they try to block. $\tau$-Gate v2.0 has been surgically refactored to rely **exclusively on the Rust Standard Library.**

### Why v2.0 earns your trust:
*   **Zero Dependencies:** 0 external crates. No `serde`, no `petgraph`, no `anyhow`. The attack surface of the auditor is zero.
*   **Reproducible Builds:** Byte-for-byte identical binary generation using `reproduce.sh`. You can prove the binary matches the source code.
*   **Entropy Engine:** Natively detects obfuscated (high-entropy) payloads in package metadata, catching "Sleeper Cells" that try to look structurally normal.
*   **Signed Integrity:** Every release is cryptographically signed and verified against build-time Git hashes.

---

## 🚩 The Problem: Structural Attacks
Modern supply chain attacks (like **TanStack Query** or **XZ Utils**) bypass traditional scanners because they don't use "known-bad" code. Instead, they use **Transitive Secrecy**. 
They hide deep in your dependency tree, establishing structural bottlenecks to execute malicious code.

## 🛡️ The Solution: $\tau$-Gate
$\tau$-Gate is a mathematical proxy wrapper for your package manager. It analyzes the **Shape of your Dependencies** before untrusted code can run.

### 🧠 Core Methodology

#### **Level 1: The Social Network (Intuitive)**
Trusted software forms a dense "Mainland." Attackers form tiny "Islands." If an isolated island requests system power (execution scripts or build hooks), the math flags it and blocks it.

#### **Level 2: Spectral Bisection (Technical)**
We model your project as a **Graph Laplacian ($L = D - A$)** and solve for the **Fiedler Vector** ($\lambda_2$) using a high-performance $O(E)$ sparse iterative solver. The tool identifies the **Maximum Spectral Gap** to mathematically identify structural isolation.

---

## 🚀 Quick Start

1.  **Install Globally:**
    ```bash
    curl -L https://github.com/steph4n-gh/tau-gate/releases/latest/download/install.sh | bash
    ```
2.  **Audit Your Project:**
    ```bash
    tau-gate --dry-run
    ```

---

## 📖 Resource Hub

| Documentation | Description |
| :--- | :--- |
| **[Setup & Integration](./docs/setup.md)** | Detailed installation, CI/CD configs, and CLI flags. |
| **[Governance & Policy](./docs/policy.md)** | Configuration guide, Advisory Mode, and attack scenarios. |
| **[The Mathematics](./docs/whitepaper.md)** | In-depth technical whitepaper on Spectral Bisection. |
| **[Empirical Validation](./docs/validation.md)** | Performance and accuracy data from real-world audits. |
| **[Strategy Audit](./docs/marketing.md)** | Stakeholder talking points and competitive analysis. |
| **[Extensibility Guide](./docs/extensibility.md)** | How to add support for new package managers. |

---

## ⚖️ License: Free for People, Not for Profit
$\tau$-Gate is licensed under the **Polyform Non-Commercial License 1.0.0**.

*   **Individuals & Researchers:** 100% Free. Use it, hack it, share it.
*   **Organizations:** 100% Free for **internal use** to protect your own pipelines.
*   **Commercial Use:** You may **not** sell $\tau$-Gate or build a commercial product/service based on this source code.
