# τ-Gate: Mass Ecosystem Benchmark (Draft)

## Objective
To empirically validate the speed, mathematical determinism, and zero-dependency extraction layer of `tau-gate` v3.0.0 by running a passive audit against the top 500 JavaScript and TypeScript repositories on GitHub.

## Methodology
The `mass_audit.sh` script dynamically queries the GitHub GraphQL/REST API for the top 500 most starred JS/TS repositories globally. It performs a shallow clone of each repository and executes `tau-gate --dry-run` to parse their root lockfiles, construct the Graph Laplacian, and solve for the Fiedler Vector using the Shifted Power Iteration algorithm.

## Results
The benchmark has successfully completed its audit of the top 500 JS/TS repositories globally.

### Overall Gate Performance
*   **Total Repositories Audited:** 500
*   **Passed (Gate Opened):** 319 (63.8%)
*   **Failed (Gate Closed - Anomalies / Parser Failures):** 181 (36.2%)

### Math Engine Performance
Of the 319 repositories that passed, 269 had dependency graphs large enough (≥ 3 nodes) to trigger the core `math.rs` Spectral Gap engine.
*   **Average Graph Size:** 1,568 nodes
*   **Average Math Execution Time:** 538 ms
*   **Fastest Execution:** 2 ms 

### Outliers (Stress Testing)
The longest executions highlighted graph topologies with incredibly dense edge connections:
1.  **`nrwl/nx`**: 55.3 seconds *(578 nodes)*
2.  **`tusen-ai/naive-ui`**: 17.8 seconds *(1,258 nodes)*
3.  **`airbnb/react-sketchapp`**: 13.7 seconds *(2,023 nodes)*
4.  **`getmaxun/maxun`**: 11.2 seconds *(853 nodes)*
5.  **`CapSoftware/Cap`**: 10.4 seconds *(1,163 nodes)*