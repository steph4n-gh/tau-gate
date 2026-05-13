# $\tau$-Gate (v1.0.0)
**Zero-Trust Supply Chain Security powered by Spectral Graph Theory.**

---

> ### 👦 **Explain Like I'm 6**
> Imagine your computer is a big city. When you download a new app, it's like a new person moving into town. Most people move into busy neighborhoods and make lots of friends. But sometimes, a **bad guy** tries to sneak in. He stays in a tiny, hidden basement, doesn't talk to anyone, and tries to build a secret tunnel to the city's bank vault.
> 
> **$\tau$-Gate is an audit tool for your city.** It looks at the "map" of where everyone lives. If it sees someone hiding in a tiny, lonely corner while trying to build a secret tunnel, it **slams the gates shut** and kicks them out before they can do any damage.

---

## 🚩 The Problem: Structural Attacks
Modern supply chain attacks (like **TanStack Query** or **XZ Utils**) bypass traditional scanners because they don't use "known-bad" code. Instead, they use **Transitive Secrecy**. 
They hide deep in your dependency tree, staying isolated and quiet until they execute a `postinstall` script to exfiltrate your secrets.

## 🛡️ The Solution: $\tau$-Gate
$\tau$-Gate is a mathematical proxy wrapper for your package manager. It analyzes the **Shape of your Dependencies** before untrusted code can run.

### 🧠 How it Works (Choose your depth)

#### **Level 1: The Social Network (Simple)**
$\tau$-Gate calculates how "connected" every package is. Trusted software forms a dense "Mainland." Attackers form tiny "Islands." If a package on a tiny island asks for system power (execution), the math flags it as a spy and blocks it.

#### **Level 2: Spectral Bisection (Technical)**
We model your project as a **Graph Laplacian ($L = D - A$)**.
1.  **Topology Mapping:** We build a Directed Graph of your entire dependency tree.
2.  **Connectivity Analysis:** We use an $O(E)$ Sparse Solver to find the **Fiedler Vector** ($\lambda_2$), representing the algebraic connectivity of the graph.
3.  **The $\tau$-Cut:** We identify the **Maximum Spectral Gap** in the Fiedler Vector to bisect the graph. 
4.  **Isolation Detection:** We check the smaller partition (the "Island"). If it contains packages requesting execution privileges (lifecycle scripts), the gate slams shut.

---

## 🚀 Key Features
*   **Big Four Support:** Native engines for `npm`, `pnpm` (v9+), `Bun`, and `Yarn Berry` (v4).
*   **Linear Performance:** Sparse iteration math processes 10,000+ nodes in $<50\text{ms}$ on modern hardware.
*   **Structural Parsing:** Falls back to ASCII tree parsing + physical `package.json` audits if JSON output fails.
*   **Algebraic Stability:** Optimized $\alpha$-bounded power iteration ensures convergence across varying graph topologies.

---

## 🛠️ Getting Started

### 1. Installation
```bash
# Build the release binary and link globally
./install.sh
```

### 2. Basic Usage
Simply run `tau-gate` instead of your usual install command:
```bash
cd my-project
tau-gate
```

**Dry-Run Mode (Passive Audit):**
If you want to see the results of the mathematical audit without actually performing an installation, use the `--dry-run` or `-d` flag:
```bash
tau-gate --dry-run
```

**Integrity Check:**
Verify your binary build hash and version:
```bash
tau-gate --verify
```

### 3. CI/CD Integration (GitHub Actions)
```yaml
- name: Security Audit
  run: tau-gate
```

---

## ⚙️ Configuration (`tau-gate.toml`)
Create a policy in your project root to fine-tune the gate:

```toml
# Threshold: Size % of the anomaly partition (Default 15.0)
threshold_percentage = 15.0

# Whitelist: Trust entire scopes using Glob patterns
whitelist = ["@astrojs/*", "@types/*", "vite"]
```

---

## 🛡️ Case Study: The TanStack Attack
In the 2026 TanStack compromise, a malicious version of `@tanstack/query-core` used a `postinstall` script to steal secrets. 
*   **Traditional Scanners:** Identified the package as safe as it was a new reporting.
*   **$\tau$-Gate:** Identifies tiny, isolated packages requesting `execution` rights. The math isolates the package in a **~0.1% partition** and blocks execution based on topological isolation.

---

## ❓ FAQ
*   **Does this replace `npm audit`?** No. Use both. `npm audit` is a "Wanted List"; $\tau$-Gate is an "X-Ray Machine."
*   **Does it work offline?** Yes. It audits your local lockfile and `node_modules` manifests.
*   **Why $\tau$ (tau)?** It represents the "Cut" point in mathematics where the gate decides your fate.
*   **Is this "Open Source"?** Technically, it is **Source-Available, Free for Internal Use**. Because the Polyform license restricts commercial selling, it doesn't meet the strict OSI definition. 
*   **Can I use this at my corporate job?** **Yes.** The license explicitly allows internal business use to protect your own infrastructure. You just can't sell it.
*   **Why not use MIT or Apache?** We want to prevent "Vampire Products"—third-party companies profiting by selling our research back to you.

---
## ⚖️ License: Free for People, Not for Profit
$\tau$-Gate is licensed under the **Polyform Non-Commercial License 1.0.0**.

*   **Individuals & Researchers:** 100% Free. Use it, hack it, share it.
*   **Organizations:** 100% Free for **internal use** to protect your own pipelines.
*   **Commercial Use:** You may **not** sell $\tau$-Gate or build a commercial product/service based on this source code.

---
**For a deep dive into the math, see [whitepaper.md](./docs/whitepaper.md).**
**For stakeholder talking points, see [marketing.md](./docs/marketing.md).**
**For real-world performance data, see [validation.md](./docs/validation.md).**
**For attack pattern breakdowns, see [scenarios.md](./docs/scenarios.md).**

---

## 🤝 How to Contribute
We welcome contributions for native extraction engines (Rust, Python, Go) and mathematical optimizations. Check out the [source code architecture](https://github.com/steph4n-gh/tau-gate/tree/main/src) to get started.

---

## 🌍 The Future: Multi-Language Roadmap (v3.0+)
Future versions will introduce native support for:
*   **Rust (Cargo):** Bridging packages with `build.rs` to the execution sink.
*   **Python (Pip/Poetry):** Detecting `setup.py` anomalies.
*   **Ruby (Gems):** Mapping native extensions (`extconf.rb`).
