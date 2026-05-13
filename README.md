# $\tau$-Gate (v2.0.0)
**Geometric Zero-Trust: Absolute Integrity in Code and Deployment.**

---

> ### 👦 **Explain Like I'm 6**
> Imagine your computer is a big city. When you download a new app, it's like a new person moving into town. Most people move into busy neighborhoods and make lots of friends. But sometimes, a **bad guy** tries to sneak in. He stays in a tiny, hidden basement, doesn't talk to anyone, and tries to build a secret tunnel to the city's bank vault.
> 
> **$\tau$-Gate is an audit tool for your city.** It looks at the "map" of where everyone lives. If it sees someone hiding in a tiny, lonely corner while trying to build a secret tunnel, it **slams the gates shut** and kicks them out before they can do any damage.

---

## 🛡️ v2.0.0: The "Absolute Zero" Standard
$\tau$-Gate v2.0 represents the ultimate evolution in security engineering. We have physically eliminated the "Auditor's Paradox"—where a security tool is vulnerable to its own supply chain.

### Why v2.0 is the Gold Standard:
*   **Absolute Zero Dependencies:** 0 external Rust crates. The entire math core and all parsers rely **100% on the Rust Standard Library.**
*   **Zero-Action CI/CD:** Our release pipeline has eliminated all 3rd-party GitHub Actions. We use only native system tools (`git`, `rustup`, `gh`), achieving a zero-dependency infrastructure.
*   **Reproducible Builds:** Byte-for-byte identical binary generation using `reproduce.sh`. Formal proof that your binary matches our source code.
*   **Entropy Engine:** Natively detects obfuscated (high-entropy) payloads in metadata, catching "Sleeper Cells" that try to look structurally normal.

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
| **[Setup & Integration](./docs/setup.md)** | Installation, CLI flags, and Zero-Action CI/CD. |
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
