# Whitepaper: The Spectral Bisection of Supply Chains (v2.0.0)
**Mathematical Foundations of the $\tau$-Gate Security Model**

## Abstract
Traditional supply chain security relies on "Known-Bad" databases (CVEs). This paper proposes a "Shape-of-Trust" model using **Spectral Graph Theory**. By modeling the dependency tree as a manifold and calculating the **Fiedler Vector** of the Graph Laplacian, we can mathematically identify structural anomalies—isolated clusters requesting system privileges—pre-execution.

---

## 1. The Mathematical Model

### 1.1 The Dependency Graph ($G$)
We define a directed graph $G = (V, E)$ representing the project's transitive dependencies.
*   $V$ is the set of packages (nodes).
*   $E$ represents dependency relationships.
*   "Execution Risks" are tracked in a metadata set $S \subset V$. In Node.js, these are `postinstall` scripts; in Rust, these are `build.rs` (custom-build) targets.

### 1.2 The Graph Laplacian ($L$)
To analyze connectivity, we convert $G$ into a symmetrized Laplacian matrix:
$$L = D - W$$
Where:
*   $W$ is the Symmetrized Adjacency Matrix ($w_{ij} = 1$ if a dependency edge exists).
*   $D$ is the Degree Matrix (a diagonal matrix where $d_{ii}$ is the number of edges connected to node $i$).

### 1.3 The Sparse Iterative Solver
We solve for the **Fiedler Vector** ($\mathbf{v}_2$)—the eigenvector corresponding to the second-smallest eigenvalue $\lambda_2$. We use a shifted sparse iteration on the operator $M = I - \alpha L$. 

**v2.0.0 Refinement:** The shift parameter $\alpha$ is bounded by $1 / (2 \cdot d_{max} + 1.1)$. This respects the Gershgorin Circle Theorem, ensuring all shifted eigenvalues are strictly within $[0, 1]$, guaranteeing convergence to $\lambda_2$ after mean-orthogonalization.

---

## 2. Structural Analysis Scenarios

### Scenario A: Standard Dependency Web
*   **Structure:** High algebraic connectivity.
*   **Math Result:** The Fiedler Vector values are distributed smoothly. The **Maximum Spectral Gap** identifies standard architectural boundaries.
*   **Verdict:** NOMINAL.

### Scenario B: Malicious Structural Isolation
*   **Structure:** An isolated package (`evil-lib`) with no sub-dependencies, connected only to the root.
*   **Math Result:** $\lambda_2$ approaches $0$. The Fiedler Vector shows a massive numerical "cliff" between the island and the project core.
*   **The Cut:** $\tau$-Gate identifies the gap and bisects.
*   **Verdict:** ANOMALY. The package is mathematically isolated. If it requests escalation (scripts or build hooks), the gate slams shut.

### Scenario C: The "Bloated Trojan"
*   **Structure:** Attacker adds many fake dependencies to an isolated malicious node to bypass size thresholds.
*   **Math Result:** While the partition size might exceed 15%, the **Connectivity Score ($\lambda_2$)** remains extremely low ($< 10^{-4}$).
*   **Verdict:** ANOMALY. The tool identifies extreme isolation (Structural Bottleneck) regardless of cluster size.

---

## 3. Implementation Integrity: Absolute Zero

In v2.0.0, the implementation itself is part of the security proof. By achieving **Zero Dependencies**, $\tau$-Gate eliminates the "Auditor's Paradox"—where the security tool itself is vulnerable to the attacks it monitors. The entire mathematical core and extraction logic are implemented using 100% Rust Standard Library code.

---

## 4. Conclusion: Topological Evidence

$\tau$-Gate implements **Spectral Bisection** to audit software supply chains. By calculating $\lambda_2$, we provide a measurable upper bound on the **Conductance** of the graph (Cheeger's Inequality).

The tool operates on the principle that for an attacker to remain stealthy, they must remain isolated. $\tau$-Gate makes this isolation mathematically visible across Node.js and Rust ecosystems.
