# Gemini CLI: Developer Guide for $\tau$-Gate (v3.0.0)

This guide establishes the architectural standards for the **Absolute Zero** security primitive. Maintain these patterns to ensure mathematical stability and zero-dependency integrity.

---

## 🛡️ The Absolute Zero Standard (v3.0.0+)

$\tau$-Gate v3.0 is a self-contained security primitive. To protect against "Auditor's Paradox" supply chain attacks, the project follows a strict **Zero-Dependency** mandate.

### The TSP Integration Mandate
$\tau$-Gate now serves a dual purpose: it is both a CLI supply chain auditor and the high-speed FFI mathematical core (`cdylib`) for the `tsp-mlx` (Neuro-Symbolic Paging) project. Any changes to the `tau_gate_analyze` FFI bridge or the underlying Laplacian math must be rigorously tested to ensure they do not break the real-time VRAM pruning operations of the TSP Python and C++ inference engines.

### ⚠️ Mandatory Constraints:
1.  **Rust Standard Library Only:** No external crates are allowed in the core binary.
2.  **No Generalized Parsers:** All JSON/YAML/TOML extraction must use the bespoke `MiniParser` in `src/parser.rs`.
3.  **No Generalized Graph Libraries:** All graph operations must use the bare-metal `DiGraph` implementation in `src/graph_impl.rs`.
4.  **Zero-Action CI/CD:** The release pipeline must only use native system tools (`git`, `rustup`, `gh`).

---

## 🔄 Git & Workflow Protocol
1.  **Pull Requests Mandatory:** Do not push code changes directly to the `main` branch. All code updates, features, and bug fixes must be developed on a separate branch and merged via a Pull Request.
2.  **Documentation Exception:** Direct pushes to `main` are permissible *only* for minor documentation updates (e.g., `README.md`, `docs/*.md`).

---

## 🏗️ Architectural Core

The project is divided into three strict layers. Do not bleed logic across these boundaries.

1.  **The Extraction Layer (`src/graph.rs`):** Converts lockfiles into a Directed Graph.
    *   *Rule:* Verification MUST be physical. Verify findings against `package.json` or `Cargo.toml` manifests on disk to handle terminal noise.
2.  **The Math Layer (`src/math.rs`):** Pure graph theory. Accepts a graph, returns a bisection.
    *   *Rule:* Must be side-effect free. Use the **Maximum Spectral Gap** for all bisections.
3.  **The Orchestration Layer (`src/main.rs`):** CLI management and policy enforcement.
    *   *Rule:* Use `dry-run` as the default test vector for all new features.

## 🧪 Testing Protocol
*   **Math Unit Tests:** Any change to bisection logic must pass the `test_dumbbell_bisection` and `test_anomaly_isolation` suites in `src/math.rs`.
*   **Engine Verification:** Any new engine must be validated against a known large-scale project using the `e2e_zero.sh` validation suite.

## ⚠️ High-Integrity Guidelines
*   **No Placebos:** Never assume a package manager's `--json` flag works as documented. Always implement a structural fallback.
*   **Zero-Panic Policy:** Use `Result` for all IO and Math operations. A security tool must never crash the developer's environment.
*   **Realistic Claims:** $\tau$-Gate identifies **Topological Isolation**; it does not "prove" code is safe.
