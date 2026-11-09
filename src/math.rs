use crate::error::{GateError, Result};
use crate::graph_impl::DiGraph;

/// Result of a graph bisection analysis.
pub struct PartitionResult {
    /// Nodes in the "Island" or Anomaly Partition.
    pub partition_b: Vec<String>,
    /// The calculated bisection point (Max Spectral Gap).
    pub tau: f64,
    /// A Rayleigh estimate; residual convergence does not certify the second eigenpair.
    /// Close to 0.0 indicates a severe structural bottleneck.
    pub connectivity_score: f64,
    pub converged: bool,
    pub residual: f64,
    pub iterations: usize,
}

/// Estimates a Fiedler vector using a bounded, diagonally preconditioned block
/// iteration in the constant vector's orthogonal complement.
pub fn analyze_graph(graph: &DiGraph) -> Result<PartitionResult> {
    let n = graph.node_count();
    if n < 1 {
        return Err(GateError::Math(
            "Graph is too small for meaningful structural analysis.".to_string(),
        ));
    }

    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut degrees = vec![0.0; n];

    for &(u, v) in graph.edges() {
        if u >= n || v >= n {
            return Err(GateError::Math("Invalid edge endpoint".into()));
        }
        if u != v {
            adj[u].push(v);
            adj[v].push(u);
            degrees[u] += 1.0;
            degrees[v] += 1.0;
        }
    }

    let mut seen = vec![false; n];
    let mut components = Vec::new();
    for root in 0..n {
        if seen[root] {
            continue;
        }
        let mut stack = vec![root];
        seen[root] = true;
        let mut component = Vec::new();
        while let Some(u) = stack.pop() {
            component.push(u);
            for &v in &adj[u] {
                if !seen[v] {
                    seen[v] = true;
                    stack.push(v);
                }
            }
        }
        components.push(component);
    }
    if components.len() > 1 || n == 1 {
        components.sort_by_key(Vec::len);
        return Ok(PartitionResult {
            partition_b: components[0]
                .iter()
                .filter_map(|&i| graph.node_weight(i).cloned())
                .collect(),
            tau: 0.0,
            connectivity_score: 0.0,
            converged: true,
            residual: 0.0,
            iterations: 0,
        });
    }
    let iterations = 5000.min((20_000_000usize / (n + graph.edges().len()).max(1)).max(1));
    let estimate = solve(&adj, &degrees, iterations);
    let fiedler_value = estimate.value;
    let residual = estimate.residual;
    let converged = residual < 1e-9;
    let used = estimate.iterations;
    let fiedler_vector = estimate.vector;

    let mut indexed_fiedler: Vec<(usize, f64)> =
        fiedler_vector.iter().copied().enumerate().collect();
    indexed_fiedler.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut max_gap = -1.0;
    let mut cut_idx = 0;
    for i in 0..(n - 1) {
        let gap = (indexed_fiedler[i + 1].1 - indexed_fiedler[i].1).abs();
        if gap > max_gap {
            max_gap = gap;
            cut_idx = i;
        }
    }

    let tau = (indexed_fiedler[cut_idx].1 + indexed_fiedler[cut_idx + 1].1) / 2.0;

    let mut side_small = Vec::new();
    let mut side_large = Vec::new();

    for (i, val) in indexed_fiedler.iter().enumerate() {
        if let Some(node_name) = graph.node_weight(val.0) {
            if i <= cut_idx {
                side_small.push(node_name.clone());
            } else {
                side_large.push(node_name.clone());
            }
        }
    }

    if side_small.len() > side_large.len() {
        Ok(PartitionResult {
            partition_b: side_large,
            tau,
            connectivity_score: fiedler_value,
            converged,
            residual,
            iterations: used,
        })
    } else {
        Ok(PartitionResult {
            partition_b: side_small,
            tau,
            connectivity_score: fiedler_value,
            converged,
            residual,
            iterations: used,
        })
    }
}

struct Estimate {
    vector: Vec<f64>,
    value: f64,
    residual: f64,
    iterations: usize,
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(a, b)| a * b).sum()
}

fn multiply(adj: &[Vec<usize>], vector: &[f64]) -> Vec<f64> {
    adj.iter()
        .enumerate()
        .map(|(i, row)| row.iter().map(|&j| vector[i] - vector[j]).sum())
        .collect()
}

fn orthogonalize(mut vector: Vec<f64>, basis: &[Vec<f64>]) -> Option<Vec<f64>> {
    let scale = dot(&vector, &vector).sqrt();
    if scale == 0.0 {
        return None;
    }
    for value in &mut vector {
        *value /= scale;
    }
    // Reorthogonalization keeps small residual directions independent of the
    // already converged vectors, and explicitly removes the zero eigenvector.
    for _ in 0..2 {
        let mean = vector.iter().sum::<f64>() / vector.len() as f64;
        for value in &mut vector {
            *value -= mean;
        }
        for column in basis {
            let projection = dot(&vector, column);
            for (value, component) in vector.iter_mut().zip(column) {
                *value -= projection * component;
            }
        }
    }
    let norm = dot(&vector, &vector).sqrt();
    if norm < 1e-10 {
        return None;
    }
    for value in &mut vector {
        *value /= norm;
    }
    Some(vector)
}

fn solve(adj: &[Vec<usize>], degrees: &[f64], limit: usize) -> Estimate {
    let n = adj.len();
    let block = 2.min(n - 1);
    let mut vectors = Vec::new();
    let mut seed = 0x243f6a8885a308d3u64;
    for _ in 0..block {
        let vector = (0..n)
            .map(|_| {
                seed = seed.wrapping_add(0x9e3779b97f4a7c15);
                let mut value = seed;
                value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
                value ^= value >> 31;
                ((value >> 11) as f64) / ((1u64 << 53) as f64) - 0.5
            })
            .collect();
        vectors.push(orthogonalize(vector, &vectors).expect("independent starting vectors"));
    }
    let mut previous: Vec<Vec<f64>> = Vec::new();
    let mut used = 0;
    for step in 0..limit {
        let mut basis = vectors.clone();
        let mut images: Vec<_> = basis.iter().map(|v| multiply(adj, v)).collect();
        let values: Vec<_> = (0..block).map(|j| dot(&basis[j], &images[j])).collect();
        let residuals: Vec<Vec<_>> = (0..block)
            .map(|j| {
                images[j]
                    .iter()
                    .zip(&basis[j])
                    .map(|(av, v)| av - values[j] * v)
                    .collect()
            })
            .collect();
        if dot(&residuals[0], &residuals[0]).sqrt() < 1e-9 {
            break;
        }
        for residual in residuals {
            let direction = residual.iter().zip(degrees).map(|(r, d)| r / d).collect();
            if let Some(direction) = orthogonalize(direction, &basis) {
                basis.push(direction);
            }
        }
        for direction in previous {
            if let Some(direction) = orthogonalize(direction, &basis) {
                basis.push(direction);
            }
        }
        images.extend(basis[block..].iter().map(|v| multiply(adj, v)));
        let mut projected = vec![vec![0.0; basis.len()]; basis.len()];
        for i in 0..basis.len() {
            for j in 0..=i {
                let value = (dot(&basis[i], &images[j]) + dot(&basis[j], &images[i])) / 2.0;
                projected[i][j] = value;
                projected[j][i] = value;
            }
        }
        let coefficients = smallest_vectors(projected, block);
        vectors.clear();
        previous = Vec::new();
        for column in coefficients {
            let mut vector = vec![0.0; n];
            let mut direction = vec![0.0; n];
            for (j, weight) in column.iter().enumerate() {
                for i in 0..n {
                    vector[i] += weight * basis[j][i];
                    if j >= block {
                        direction[i] += weight * basis[j][i];
                    }
                }
            }
            vectors.push(orthogonalize(vector, &vectors).expect("orthogonal Ritz vectors"));
            previous.push(direction);
        }
        used = step + 1;
    }
    let vector = vectors.remove(0);
    let image = multiply(adj, &vector);
    let value = dot(&vector, &image);
    let residual = image
        .iter()
        .zip(&vector)
        .map(|(av, v)| (av - value * v).powi(2))
        .sum::<f64>()
        .sqrt();
    Estimate {
        vector,
        value,
        residual,
        iterations: used,
    }
}

// The projected problem has at most six rows, so Jacobi rotations need no
// general-purpose linear algebra dependency.
fn smallest_vectors(mut matrix: Vec<Vec<f64>>, count: usize) -> Vec<Vec<f64>> {
    let n = matrix.len();
    if n == 1 {
        return vec![vec![1.0]];
    }
    let mut vectors = vec![vec![0.0; n]; n];
    for (i, row) in vectors.iter_mut().enumerate() {
        row[i] = 1.0;
    }
    for _ in 0..80 * n * n {
        let mut p = 0;
        let mut q = 1;
        for i in 0..n {
            for j in i + 1..n {
                if matrix[i][j].abs() > matrix[p][q].abs() {
                    p = i;
                    q = j;
                }
            }
        }
        let off = matrix[p][q];
        if off.abs() < 1e-15 {
            break;
        }
        let delta = (matrix[q][q] - matrix[p][p]) / (2.0 * off);
        let t = if delta >= 0.0 { 1.0 } else { -1.0 } / (delta.abs() + delta.hypot(1.0));
        let c = 1.0 / (1.0 + t * t).sqrt();
        let s = t * c;
        matrix[p][p] -= t * off;
        matrix[q][q] += t * off;
        matrix[p][q] = 0.0;
        matrix[q][p] = 0.0;
        for k in 0..n {
            if k != p && k != q {
                let a = c * matrix[k][p] - s * matrix[k][q];
                let b = s * matrix[k][p] + c * matrix[k][q];
                matrix[k][p] = a;
                matrix[p][k] = a;
                matrix[k][q] = b;
                matrix[q][k] = b;
            }
            let a = c * vectors[k][p] - s * vectors[k][q];
            let b = s * vectors[k][p] + c * vectors[k][q];
            vectors[k][p] = a;
            vectors[k][q] = b;
        }
    }
    let mut order: Vec<_> = (0..n).collect();
    order.sort_by(|&i, &j| matrix[i][i].total_cmp(&matrix[j][j]));
    order
        .into_iter()
        .take(count)
        .map(|j| vectors.iter().map(|row| row[j]).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_impl::DiGraph;

    #[test]
    fn test_dumbbell_bisection() {
        let mut graph = DiGraph::new();

        let a0 = graph.add_node("A0".to_string());
        let a1 = graph.add_node("A1".to_string());
        let a2 = graph.add_node("A2".to_string());
        graph.add_edge(a0, a1);
        graph.add_edge(a1, a2);
        graph.add_edge(a2, a0);

        let b0 = graph.add_node("B0".to_string());
        let b1 = graph.add_node("B1".to_string());
        let b2 = graph.add_node("B2".to_string());
        graph.add_edge(b0, b1);
        graph.add_edge(b1, b2);
        graph.add_edge(b2, b0);

        graph.add_edge(a0, b0);

        let result = analyze_graph(&graph).expect("Analysis failed");
        assert_eq!(result.partition_b.len(), 3);
    }

    #[test]
    fn test_anomaly_isolation() {
        let mut graph = DiGraph::new();

        let nodes: Vec<_> = (0..20).map(|i| graph.add_node(format!("M{}", i))).collect();
        for i in 0..20 {
            graph.add_edge(nodes[i], nodes[(i + 1) % 20]);
            graph.add_edge(nodes[i], nodes[(i + 5) % 20]);
        }

        let island = graph.add_node("ISLAND".to_string());
        graph.add_edge(nodes[0], island);

        let result = analyze_graph(&graph).expect("Analysis failed");

        assert_eq!(result.partition_b.len(), 1);
        assert_eq!(result.partition_b[0], "ISLAND");
    }

    #[test]
    fn test_no_edges_graceful() {
        let mut graph = DiGraph::new();
        graph.add_node("A".to_string());
        graph.add_node("B".to_string());
        graph.add_node("C".to_string());

        let result = analyze_graph(&graph).expect("Should handle no edges");
        assert_eq!(result.connectivity_score, 0.0);
        assert_eq!(result.partition_b.len(), 1);
    }
}

#[cfg(test)]
mod convergence_regressions {
    use super::*;
    #[test]
    fn analytical_two_nodes() {
        let mut g = DiGraph::new();
        g.add_node("a".into());
        g.add_node("b".into());
        g.add_edge(0, 1);
        let r = analyze_graph(&g).unwrap();
        assert!(r.converged);
        assert!((r.connectivity_score - 2.0).abs() < 1e-9);
        assert!(r.residual < 1e-9);
    }
    #[test]
    fn long_path_matches_analytic_connectivity() {
        let mut g = DiGraph::new();
        for i in 0..400 {
            g.add_node(i.to_string());
            if i > 0 {
                g.add_edge(i - 1, i);
            }
        }
        let r = analyze_graph(&g).unwrap();
        let expected = 2.0 - 2.0 * (std::f64::consts::PI / 400.0).cos();
        assert!(r.converged, "residual {}", r.residual);
        assert!(r.residual < 1e-9);
        assert!((r.connectivity_score - expected).abs() < 1e-10);
    }
    #[test]
    fn cycle_matches_analytic_connectivity_with_repeated_eigenvalue() {
        let mut g = DiGraph::new();
        for i in 0..128 {
            g.add_node(i.to_string());
        }
        for i in 0..128 {
            g.add_edge(i, (i + 1) % 128);
        }
        let r = analyze_graph(&g).unwrap();
        let expected = 2.0 - 2.0 * (2.0 * std::f64::consts::PI / 128.0).cos();
        assert!(r.converged, "residual {}", r.residual);
        assert!(r.residual < 1e-9);
        assert!((r.connectivity_score - expected).abs() < 1e-10);
    }
    #[test]
    fn star_and_clique_match_analytic_connectivity() {
        for (n, clique, expected) in [(100, false, 1.0), (8, true, 8.0)] {
            let mut g = DiGraph::new();
            for i in 0..n {
                g.add_node(i.to_string());
                for j in 0..i {
                    if clique || j == 0 {
                        g.add_edge(i, j);
                    }
                }
            }
            let r = analyze_graph(&g).unwrap();
            assert!(r.converged, "n={n}: residual {}", r.residual);
            assert!(r.residual < 1e-9);
            assert!((r.connectivity_score - expected).abs() < 1e-10);
        }
    }
    #[test]
    fn exhausted_budget_preserves_the_actual_residual() {
        let n = 400;
        let mut adj = vec![Vec::new(); n];
        for i in 1..n {
            adj[i - 1].push(i);
            adj[i].push(i - 1);
        }
        let degrees: Vec<_> = adj.iter().map(|row| row.len() as f64).collect();
        let result = solve(&adj, &degrees, 1);
        assert_eq!(result.iterations, 1);
        assert!(result.residual > 1e-9);
        let mut image = vec![0.0; n];
        for i in 1..n {
            let difference = result.vector[i] - result.vector[i - 1];
            image[i] += difference;
            image[i - 1] -= difference;
        }
        let expected = image
            .iter()
            .zip(&result.vector)
            .map(|(av, v)| (av - result.value * v).powi(2))
            .sum::<f64>()
            .sqrt();
        assert!((expected - result.residual).abs() < 1e-12);
    }
    #[test]
    fn vertex_permutation_preserves_the_connectivity_estimate() {
        for multiplier in [1, 7, 19] {
            let n = 61;
            let mut graph = DiGraph::new();
            for i in 0..n {
                graph.add_node(i.to_string());
            }
            for i in 1..n {
                graph.add_edge((i * multiplier) % n, ((i - 1) * multiplier) % n);
            }
            let result = analyze_graph(&graph).unwrap();
            let expected = 2.0 - 2.0 * (std::f64::consts::PI / n as f64).cos();
            assert!(result.converged);
            assert!((result.connectivity_score - expected).abs() < 1e-10);
        }
    }
    #[test]
    fn two_node_multigraph_keeps_nonconvergence_explicit() {
        let mut graph = DiGraph::new();
        graph.add_node("a".into());
        graph.add_node("b".into());
        for _ in 0..3_000_000 {
            graph.add_edge(0, 1);
        }
        let result = analyze_graph(&graph).unwrap();
        assert!(result.connectivity_score.is_finite());
        assert!((result.connectivity_score - 6_000_000.0).abs() < 0.01);
        assert!(result.residual.is_finite());
        assert_eq!(result.converged, result.residual < 1e-9);
        assert_eq!(result.partition_b.len(), 1);
        assert!(result.iterations <= 6);
    }
    #[test]
    fn invalid_self_edge_rejected() {
        let mut g = DiGraph::new();
        g.add_node("a".into());
        g.add_edge(99, 99);
        assert!(analyze_graph(&g).is_err());
    }
}
