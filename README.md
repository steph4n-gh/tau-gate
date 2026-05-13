# $\tau$-Gate (v1.1.0)
**Zero-Trust Supply Chain Security powered by Spectral Graph Theory.**

---

> ### 👦 **Explain Like I'm 6**
> Imagine your computer is a big city. When you download a new app, it's like a new person moving into town. Most people move into busy neighborhoods and make lots of friends. But sometimes, a **bad guy** tries to sneak in. He stays in a tiny, hidden basement, doesn't talk to anyone, and tries to build a secret tunnel to the city's bank vault.
> 
> **$\tau$-Gate is an audit tool for your city.** It looks at the "map" of where everyone lives. If it sees someone hiding in a tiny, lonely corner while trying to build a secret tunnel, it **slams the gates shut** and kicks them out before they can do any damage.

---

## 🛡️ The Mission: Structural Zero-Trust
Modern supply chain attacks (TanStack, XZ Utils) bypass traditional scanners because they don't use "known-bad" code. Instead, they use **Transitive Secrecy**.

$\tau$-Gate is a mathematical proxy wrapper for your package manager (`npm`, `pnpm`, `Bun`, `Yarn`, `Cargo`). It analyzes the **Shape of your Dependencies** before untrusted code can run.

---

## 🧠 Core Methodology

### Level 1: The Social Network (Intuitive)
Trusted software forms a dense "Mainland." Attackers form tiny "Islands." If an isolated island requests system power (execution scripts), the math flags it and blocks it.

### Level 2: Spectral Bisection (Technical)
We model your project as a **Graph Laplacian ($L = D - A$)** and solve for the **Fiedler Vector** ($\lambda_2$) using a high-performance $O(E)$ sparse iterative solver. The tool identifies the **Maximum Spectral Gap** to mathematically prove structural isolation.

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

## 🤝 How to Contribute & Extend
$\tau$-Gate v1.1.0 introduces an **Extensible Architecture**. Adding support for a new language (like Python or Go) is now a simple 4-step process:
1.  **Define the Engine:** Add your language to `EngineType` in `src/graph.rs`.
2.  **Transitive Extraction:** Implement a `build_from_lang()` method using your language's metadata tool.
3.  **Map Execution Sinks:** Identify your language's "install-time" scripts (e.g., `setup.py` or `build.rs`).
4.  **Register:** Link it in the `DepGraph::build()` discovery loop.

We welcome contributions for:
*   🦀 **Native Rust (Cargo) support** (Included in v1.1.0 - Dogfooding enabled!)
*   🐍 **Python (Pip/Poetry) support** (Roadmap)
*   📈 **Mathematical optimizations** for the sparse iterative solver.

Check out the [source code architecture](https://github.com/steph4n-gh/tau-gate/tree/main/src) to get started.

---

## 📖 Resource Hub

| Documentation | Description |
| :--- | :--- |
| **[Setup & Integration](./docs/setup.md)** | Detailed installation, CI/CD configs, and CLI flags. |
| **[Governance & Policy](./docs/policy.md)** | Configuration guide and real-world attack scenarios. |
| **[The Mathematics](./docs/whitepaper.md)** | In-depth technical whitepaper on Spectral Bisection. |
| **[Empirical Validation](./docs/validation.md)** | Performance and accuracy data from real-world audits. |
| **[Extensibility Guide](./docs/extensibility.md)** | How to add support for new package managers (Python, Go, etc.). |
| **[Strategy Audit](./docs/marketing.md)** | Stakeholder talking points and competitive analysis. |

---

## 🌍 The Future: Multi-Language Roadmap (v3.0+)
The underlying Spectral Graph Theory is **language-agnostic**. A dependency graph is a DAG whether it's written in JavaScript or Rust. 

Future versions will introduce native support for:
*   **Rust (Cargo):** Bridging packages with `build.rs` to the execution sink. (RELEASED in v1.1.0)
*   **Python (Pip/Poetry):** Detecting `setup.py` anomalies.
*   **Ruby (Gems):** Mapping native extensions (`extconf.rb`).

---

## ⚖️ License: Free for People, Not for Profit
$\tau$-Gate is licensed under the **Polyform Non-Commercial License 1.0.0**.

*   **Individuals & Researchers:** 100% Free.
*   **Organizations:** 100% Free for **internal use** to protect your own pipelines.
*   **Commercial Use:** You may **not** sell $\tau$-Gate or build a commercial product/service based on this source code.
