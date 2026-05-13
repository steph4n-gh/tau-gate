# Gemini CLI: Developer Guide for $\tau$-Gate

This guide establishes the architectural standards and best practices for extending $\tau$-Gate. Maintain these patterns to ensure mathematical stability and multi-runtime compatibility.

## 🏗️ Architectural Core

The project is divided into three strict layers. Do not bleed logic across these boundaries.

1.  **The Extraction Layer (`src/graph.rs`):** Converts package manager lockfiles into a `petgraph::DiGraph`. 
    *   *Best Practice:* Engines must be "Physical-First." Do not rely purely on CLI output; verify findings against `package.json` manifests on disk to handle terminal noise.
2.  **The Math Layer (`src/math.rs`):** Pure graph theory. Accepts a graph, returns a bisection.
    *   *Best Practice:* Keep this layer side-effect free. It should never touch the filesystem or network. Use the `Max Spectral Gap` for all bisections.
3.  **The Orchestration Layer (`src/main.rs`):** CLI management and policy enforcement.
    *   *Best Practice:* Use `dry-run` as the default test vector for all new features.

## 🛠️ Extending the Tool

### Adding a New Language Engine (e.g., Rust/Cargo)
1.  **Enum Update:** Add `EngineType::Cargo` to `src/graph.rs`.
2.  **Extraction Logic:** Implement `build_from_cargo()`. Use `cargo metadata --format-version 1` to get the transitive tree.
3.  **Sink Definition:** Identify the Rust execution vector (usually packages containing a `build.rs` file) and add them to the `execution_packages` set.
4.  **Integration:** Update `DepGraph::build()` to detect `Cargo.lock`.

### Mathematical Hardening
*   The **Connectivity Score ($\lambda_2$)** is the primary metric for structural integrity. 
*   If modifying the power iteration, you MUST maintain the $\alpha$ bound: $1 / (2 \cdot d_{max} + 1.1)$ to prevent divergence.

## 🧪 Testing Protocol
*   **Math Unit Tests:** Any change to bisection logic must pass the `test_dumbbell_bisection` and `test_anomaly_isolation` suites.
*   **Integration Tests:** Use `tests/integration_test.rs` to mock filesystem layouts. Do not perform actual network installations in CI.

## ⚠️ High-Integrity Guidelines
*   **No Placebos:** Never assume a package manager's `--json` flag works as documented. Always implement a structural fallback.
*   **Zero-Panic Policy:** Use `Result` for all IO and Math operations. A security tool must never crash the developer's environment due to an unhandled edge case.
*   **Realistic Claims:** Describe the tool as a **Topological Auditor**. It detects structural isolation; it does not "prove" code is safe.
