# 🛡️ τ-Gate (v3.0.0)

**Geometric Zero-Trust: Integrity in Code and Deployment.**

[![Security Audit](https://github.com/steph4n-gh/tau-gate/actions/workflows/release.yml/badge.svg)](https://github.com/steph4n-gh/tau-gate/actions)
[![Dependencies: 0](https://img.shields.io/badge/Dependencies-0-00f3ff?style=flat-square)](https://github.com/steph4n-gh/tau-gate/blob/main/Cargo.toml)
[![τ-Gate: Secured](https://img.shields.io/badge/τ--Gate-Secured-00f3ff?style=flat-square)](https://github.com/steph4n-gh/tau-gate)

A dependency auditor that blocks supply chain attacks before they execute. It builds an in-memory graph of your package tree and uses spectral bisection to sever malicious, isolated packages attempting to run unauthorized build hooks.

---

## 🚀 Quick Start

1.  **Install Globally:**
    ```bash
    curl -L https://raw.githubusercontent.com/steph4n-gh/tau-gate/main/install.sh | bash
    ```
2.  **Audit Your Project (Network Mode):**
    ```bash
    tau-gate --network
    ```

---

## ✨ Key Features

*   **Zero External Dependencies:** Every line of code, from the $O(E)$ sparse solver to the concurrent HTTP resolution engine, is implemented using the **Rust Standard Library.** This eliminates transitive supply chain risk in the auditor itself.
*   **Network-Level Resolution:** Achieves ultimate architectural self-sufficiency by building dependency graphs entirely in-memory via direct API calls to package registries, completely bypassing the vulnerabilities and unstandardized behaviors of local package managers (like `npm` and `yarn`).
*   **Topological Execution Detection:** Natively intercepts `preinstall`, `install`, and `postinstall` hooks embedded within mathematically isolated nodes before untrusted code can run.

---

## 🧠 The Problem & Solution (Explain Like I'm 6)

### The Problem: Transitive Secrecy
Modern supply chain attacks (like **Dependency Confusion** or **Typosquatting**) bypass traditional scanners because they hide in **Transitive Secrecy**. Attackers establish structural bottlenecks deep in your dependency tree to execute malicious code quietly.

### The Solution: $\tau$-Gate
Imagine your computer is a big city. When you download a new app, it's like a new person moving into town. Most people move into busy neighborhoods and make lots of friends. But sometimes, a **bad guy** tries to sneak in. He stays in a tiny, hidden basement, doesn't talk to anyone, and tries to build a secret tunnel to the city's bank vault.

**$\tau$-Gate is an audit tool for your city.** It analyzes the **Shape of your Dependencies**. It looks at the "map" of where everyone lives. If it sees someone hiding in a tiny, lonely corner (an isolated node) while trying to build a secret tunnel (execute a build script), it **slams the gates shut** and kicks them out before they can do any damage.

---

## 📚 Documentation & Deep Dives

*   **[📖 The Whitepaper](./docs/whitepaper.md)**: A deep dive into Topological Isolation, the Spectral Gap, and how graph mathematics solve Transitive Secrecy.
*   **[🛠️ Setup & Configuration](./docs/setup.md)**: How to configure the `tau-gate.toml` policy file for your environments.
*   **[🔍 Validation Methodology](./docs/validation.md)**: A guide to how the auditor evaluates scripts and structural risk.
