# τ-Gate (v3.0.0)

**Absolute Zero Security for the Modern Supply Chain.**

τ-Gate is a high-integrity security primitive designed to identify topological anomalies via **Deep Graphing**—a recursive analysis that maps the complete transitive execution surface of your software. By resolving deep, multi-level dependency chains into a single mathematical system, τ-Gate eliminates the "Auditor's Paradox" while operating under a strict **Zero-Dependency Mandate** (pure Rust, std-only) to ensure the auditor itself never becomes a vector for the very attacks it detects.

This surface encompasses:
- **Transitive Relationships:** The deep, recursive "hidden" connections where a trusted library pulls in a compromised sub-dependency.
- **Execution Vectors:** Every point where code can run outside your control—including lifecycle scripts (`preinstall`, `postinstall`), build-time macros (`build.rs`), and native binary shims.

---

## 🛡️ Deep Graphing & The Transitive Explosion

Most security tools fail because they only see what you *tell* them to install. In modern ecosystems like npm, the average project has a **4.32x Dependency Amplification Factor**—for every 1 package you declare, you pull in over 4 transitive ones. 

With an average dependency depth of **4.4 levels** (and some reaching 20+), the true "security perimeter" of your project is hidden deep in the transitive tree. This is where attackers hide.

**τ-Gate is a Deep Graphing engine.** It recursively resolves every transitive relationship into a single, interconnected mathematical system (the Laplacian Matrix). This allows τ-Gate to identify "Topological Islands" that are trying to hide in the deep brush of your dependency tree.

---

## 🛡️ Why τ-Gate? (The XZ Utils Problem)
...
Standard security tools look for *known* vulnerabilities (CVEs). τ-Gate looks for **Topological Anomalies**—structural shifts that indicate an attacker is trying to "hide" malicious logic in your dependency graph.

### Case Study: The XZ Utils Backdoor (2024)
The XZ Utils attack succeeded because it was structurally subtle. An attacker introduced a complex build-time dependency that linked a compression library (`liblzma`) to a high-privilege system daemon (`sshd`). 
- **The Anomaly:** In a healthy topology, a compression utility should be a highly-connected, "central" utility node. The attack created a specific, isolated path that only activated under certain build conditions.
- **How τ-Gate Solves This:** τ-Gate's Laplacian Engine identifies these "Islands of Isolation." By computing the **Maximum Spectral Gap** on the **complete topological graph**, τ-Gate would have flagged the XZ build-time environment as having a high-entropy, topologically isolated component with execution privileges—stopping the backdoor before it could be linked.

---

## 🛡️ The Absolute Zero Standard
- **Zero Dependencies:** No external crates. No generalized parsers. No `node_modules` required for the auditor itself.
- **Physical Verification:** Audits manifests and lockfiles directly on disk.
- **Mathematical Isolation:** Uses Spectral Graph Theory (Fiedler Vector + Maximum Spectral Gap) to identify "Islands" or clusters of topologically isolated, execution-privileged packages.

## 🚀 Quick Start

```bash
# Build the high-integrity binary
cargo build --release

# Run a dry-run audit on the current project
./target/release/tau-gate --dry-run

# Audit a project via the Network Engine (no lockfile required)
./target/release/tau-gate --network

# Combine modes for a passive, network-verified audit
./target/release/tau-gate --network --dry-run
```

## ⚙️ Core Engines

### 1. Static Extraction Layer
τ-Gate supports native extraction for the most common ecosystems:
- **NPM / PNPM / Bun:** Bespoke JSON and YAML parsers for lockfiles.
- **Yarn (v1 & Berry):** Dual-mode support with structural fallback for legacy v1 trees.
- **Cargo:** Direct integration with `cargo metadata`.
- **Go:** Parser for `go mod graph`.

### 2. The Network Engine (`--network`)
When a local lockfile is missing, corrupted, or suspect, the Network Engine fetches metadata directly from the NPM registry.
- Resolves full transitive trees via parallelized registry queries.
- Bypasses local environment noise to provide a "Registry Truth" baseline.
- Ideal for auditing shallow clones or CI environments where `node_modules` are not yet populated.
- **Note:** Can be combined with `--dry-run` to perform a passive audit without attempting a post-audit install.

### 3. Mathematical Layer (The Laplacian Engine)
τ-Gate builds a Laplacian matrix of your dependency graph and computes its second-smallest eigenvalue ($\lambda_2$). 
- **Connectivity Score ($\lambda_2$):** A lower score indicates higher structural isolation.
- **Bisection:** Uses the **Maximum Spectral Gap** on the Fiedler Vector to pinpoint exactly which nodes are trying to "hide" in your topology.

## 🔧 Configuration (`tau-gate.toml`)

```toml
# Minimum anomaly threshold (percentage of total graph)
threshold_percentage = 15.0

# Trusted scopes or pinned versions
whitelist = ["@types/*", "vite@5.0.0"]

# Enforcement Mode: "enforcement" (abort build) or "advisory" (warn only)
mode = "enforcement"
```

## 🏗️ FFI & Integration
τ-Gate includes a `cdylib` target for high-performance integration into Python/C++ inference engines (e.g., `tsp-mlx`). It exposes a safe C FFI for real-time topological pruning.

## 📚 Documentation
- [Architecture & V3 Engine Deep Dive](docs/v3_engine.md)
- [Policy Enforcement Guide](docs/policy.md)
- [FFI & Mathematical Interpretation](docs/interpretation.md)
- [Validation & Benchmarking](docs/validation.md)

---
**τ-Gate:** *Topology is Truth.*
