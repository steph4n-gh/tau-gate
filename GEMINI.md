# Gemini CLI: Developer Guide for $\tau$-Gate

This guide establishes the architectural standards and best practices for extending $\tau$-Gate. Maintain these patterns to ensure mathematical stability and multi-runtime compatibility.

---

## 🛡️ The Ultimate Goal: Zero-Dependency Architecture (v2.0+)

**The Paradox:** $\tau$-Gate is designed to protect systems from supply chain attacks. However, if $\tau$-Gate itself relies on third-party Rust crates (e.g., `serde`, `petgraph`, `anyhow`), a sophisticated attacker could compromise one of those crates with a `build.rs` backdoor specifically designed to disable $\tau$-Gate during its own compilation. 

To achieve true **Geometric Zero-Trust**, the long-term architectural goal for $\tau$-Gate is to reach **Zero Dependencies** (relying only on the Rust Standard Library).

### Phased Zero-Dependency Execution Plan:

#### Phase 1: Eliminate Utility Crates (Near-Term)
*   **Target:** `anyhow`, `glob`, `indicatif`
*   **Action:** Replace `anyhow` with standard `std::result::Result` and custom Error enums. Rewrite glob-matching with basic string pattern checking. Replace the spinner with a simple stdout flushing macro.

#### Phase 2: Bespoke Graph Engine (Mid-Term)
*   **Target:** `petgraph`
*   **Action:** We do not need a massive, generalized graph library. We only need a Directed Graph that can output an Adjacency List for the Sparse Iterative Solver. We will write a bare-metal, memory-safe `AdjacencyList` struct using raw standard library `Vec`s.

#### Phase 3: The Parser Purge (Long-Term)
*   **Target:** `serde`, `serde_json`, `serde_yaml`, `toml`
*   **Action:** This is the hardest step. We must write a custom, highly-restricted Lexer/Parser that *only* understands the exact fields we need (`dependencies`, `scripts`, `hasInstallScript`) and ignores everything else. It does not need to be a fully compliant JSON/YAML spec parser, only a "Metadata Extractor."

**All future contributions must prioritize standard library solutions over adding new crates.**

---

## 🏗️ Architectural Core

The project is divided into three strict layers. Do not bleed logic across these boundaries.

1.  **The Extraction Layer (`src/graph.rs`):** Converts package manager lockfiles into a Directed Graph.
    *   *Best Practice:* Engines must be "Physical-First." Do not rely purely on CLI output; verify findings against `package.json` manifests on disk to handle terminal noise.
2.  **The Math Layer (`src/math.rs`):** Pure graph theory. Accepts a graph, returns a bisection.
    *   *Best Practice:* Keep this layer side-effect free. It should never touch the filesystem or network. Use the `Max Spectral Gap` for all bisections.
3.  **The Orchestration Layer (`src/main.rs`):** CLI management and policy enforcement.
    *   *Best Practice:* Use `dry-run` as the default test vector for all new features.

## 🧪 Testing Protocol
*   **Math Unit Tests:** Any change to bisection logic must pass the `test_dumbbell_bisection` and `test_anomaly_isolation` suites.
*   **Integration Tests:** Use `tests/integration_test.rs` to mock filesystem layouts. Do not perform actual network installations in CI.

## ⚠️ High-Integrity Guidelines
*   **No Placebos:** Never assume a package manager's `--json` flag works as documented. Always implement a structural fallback.
*   **Zero-Panic Policy:** Use `Result` for all IO and Math operations. A security tool must never crash the developer's environment due to an unhandled edge case.
*   **Realistic Claims:** Describe the tool as a **Topological Auditor**. It detects structural isolation; it does not "prove" code is safe.
