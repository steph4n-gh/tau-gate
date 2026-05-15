# $\tau$-Gate (v3.0.0)
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

## 🚀 Quick Start

1.  **Install Globally:**
    ```bash
    curl -L https://raw.githubusercontent.com/steph4n-gh/tau-gate/main/install.sh | bash
    ```
2.  **Audit Your Project (Network Mode):**
    ```bash
    tau-gate --dry-run --network
    ```

---

## 🛡️ v3.0.0: The Network-Level Resolution Engine
$\tau$-Gate v3.0 achieves ultimate architectural self-sufficiency. It builds dependency graphs entirely in-memory by interfacing directly with package registries via a multi-threaded OS subprocess pool, completely bypassing the vulnerabilities, stdout corruption, and unstandardized behaviors of local package managers (like `npm` and `yarn`).

### Technical Integrity Features:
*   **Zero External Dependencies:** Every line of code, from the $O(E)$ sparse solver to the concurrent HTTP resolution engine, is implemented using the **Rust Standard Library.** This eliminates transitive supply chain risk in the auditor itself.
*   **Topological Execution Detection:** Natively intercepts `preinstall`, `install`, and `postinstall` hooks embedded within mathematically isolated nodes.
*   **Minimal-Action CI/CD:** The release pipeline utilizes native system utilities instead of 3rd-party GitHub Actions.
*   **Formal Reproducibility:** Byte-for-byte identical binary generation using `reproduce.sh`. Verification proof that your binary matches our source code.

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

## 🏛️ Dual-Mode Architecture (The TSP Integration)

$\tau$-Gate was originally designed as a supply chain auditing tool, but in `v3.0.0` it was fundamentally re-architected into a dual-purpose mathematical engine. It now serves as the high-performance, zero-latency **FFI mathematical core** for the [**$\tau$-Spectral Pruner (TSP)**](https://github.com/steph4n-gh/tsp-mlx) project.

In the TSP ecosystem (Neuro-Symbolic Paging), `tau-gate` is dynamically linked to Python and C++ inference engines. As the LLM generates tokens, `tau-gate` natively calculates the Fiedler vector ($\lambda_2$) of the model's internal attention graph in real-time, mathematically identifying and evicting dead context from the GPU's KV cache.

$\tau$-Gate is designed to be embedded into any software stack, operating in two distinct modes:

### 1. Daemon Mode (Inter-Process)
For Python, Node.js, or networked applications, $\tau$-Gate runs as a lightweight UNIX subprocess, accepting NDJSON payloads over standard I/O for secure, language-agnostic integration.

### 2. Native Library Mode (Zero-Latency FFI)
For high-performance applications (like C++ MLX engines or `llama.cpp` forks), $\tau$-Gate can be compiled as a static C library (`libtau_gate.a`), providing $O(1)$ memory access and zero serialization overhead.

To build the static library:
```bash
cargo build --release
# Outputs: target/release/libtau_gate.a
```

#### C/C++ API Reference (`tau_gate.h`)
When embedding the static library, use the following C-compatible interface:

```c
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char** nodes;              // Array of strings (Island node names)
    size_t nodes_count;        // Number of nodes in the island
    double tau;                // The Fiedler value
    double connectivity_score; // Algebraic connectivity metric (\lambda_2)
} FFIPartitionResult;

// Analyze a graph natively
FFIPartitionResult* tau_gate_analyze(
    const int* edges_ptr,      // Flattened array of edge pairs: [u1, v1, u2, v2...]
    size_t edges_count,        // Number of edge *pairs* (length of array / 2)
    const char** nodes_ptr,    // Array of node name strings
    size_t nodes_count         // Number of nodes
);

// ⚠️ CRITICAL: Memory Ownership
// You MUST call this function to free the result struct. 
// Rust allocates the strings; C++ cannot use `free()` or `delete`.
void tau_gate_free_result(FFIPartitionResult* ptr);

#ifdef __cplusplus
}
#endif
```

> **⚠️ CRITICAL MEMORY WARNING:** When using the FFI bridge, the Rust allocator owns the memory for the returned strings in `FFIPartitionResult`. You **must** pass the pointer back to `tau_gate_free_result()` when you are done. Attempting to free this memory from C/C++ will cause segmentation faults or memory leaks.

---

## 📖 Resource Hub

| Documentation | Description |
| :--- | :--- |
| **[Setup & Integration](./docs/setup.md)** | Installation, CLI flags, and Zero-Action CI/CD. |
| **[Governance & Policy](./docs/policy.md)** | Configuration guide, Advisory Mode, and attack scenarios. |
| **[The Mathematics](./docs/whitepaper.md)** | In-depth technical whitepaper on Spectral Bisection. |
| **[v3.0 Architecture](./docs/v3_engine.md)** | How the Network-Level Resolution Engine bypasses package managers. |
| **[Empirical Findings](./docs/v3_findings.md)** | Insights on execution hooks, parallelization, and topological math traps. |
| **[Mass Audit Benchmark](./docs/benchmark.md)** | Performance and accuracy data from auditing the Top 500 repositories. |
| **[Interpreting Anomalies](./docs/interpretation.md)** | How to understand the graph output and manage your whitelist. |