# Whitepaper: The Spectral Bisection of Supply Chains (v3.0.0)
**Mathematical Foundations of the $\tau$-Gate Security Model**

## Abstract
Traditional supply chain security relies on "Known-Bad" databases (CVEs). This paper proposes a "Shape-of-Trust" model using **Spectral Graph Theory**. By modeling the dependency tree as a manifold and calculating the **Fiedler Vector** of the Graph Laplacian, we can mathematically identify structural anomalies—isolated clusters requesting system privileges—pre-execution.

---

## 1. The Mathematical Model

### 1.1 The Dependency Graph ($G$)
We define a directed graph $G = (V, E)$ representing the project's transitive dependencies.
*   $V$ is the set of packages (nodes).
*   $E$ represents dependency relationships.
*   **Execution Risks** are identified via post-extraction manifest verification (lifecycle scripts in Node.js, `build.rs` in Rust).

### 1.2 The Graph Laplacian ($L$)
To analyze connectivity, we convert $G$ into a symmetrized Laplacian matrix:
$$L = D - W$$
Where $W$ is the Symmetrized Adjacency Matrix and $D$ is the Degree Matrix.

### 1.3 The Sparse Iterative Solver
We solve for the **Fiedler Vector** ($\mathbf{v}_2$) using a shifted sparse iteration on the operator $M = I - \alpha L$. 

**v3.0.0 Hardening:** The shift parameter $\alpha$ is bounded by $1 / (2 \cdot d_{max} + 1.1)$ to ensure convergence across all topologies.

---

## 2. Structural Analysis Scenarios

### Scenario A: Standard Dependency Web
Trusted software creates a dense "continent" with high algebraic connectivity ($\lambda_2$).

### Scenario B: Structural Isolation (The Island)
An isolated malicious package results in $\lambda_2 \approx 0$. The **Maximum Spectral Gap** algorithm identifies the numerical "cliff" between the island and the core mainland.

### Scenario C: The Bloated Trojan (Evasion Resistance)
If an attacker adds fake dependencies to bypass size thresholds, $\lambda_2$ remains extremely low. v3.0.0 uses this **Algebraic Connectivity Score** as an absolute trigger for isolation detection, even if the partition is large.

---

## 3. Implementation Integrity: Self-Contained Architecture

In v3.0.0, $\tau$-Gate achieves **Architectural Self-Sufficiency**. Every line of code, from the $O(E)$ sparse solver to the native lockfile parsers, is implemented using the **Rust Standard Library**. 

To ensure absolute mathematical determinism across all executions, the engine strictly utilizes `BTreeMap` and `BTreeSet` over Hash-based collections. This guarantees a consistent alphabetical topological sorting of the adjacency matrix, resulting in byte-for-byte identical Fiedler Vector calculations.

This eliminates the "Auditor's Paradox"—ensuring the tool cannot be compromised by the same supply chain attacks it is designed to audit.

---

## 4. Conclusion

$\tau$-Gate implements **Spectral Bisection** to audit software supply chains. By calculating $\lambda_2$ and the Maximum Spectral Gap, we provide a measurable, provable upper bound on the **Conductance** of a project's execution paths.

**The math is the judge. The topology is the evidence.**
