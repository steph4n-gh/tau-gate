use crate::error::{GateError, Result};
use crate::graph_impl::DiGraph;

/// Result of a graph bisection analysis.
pub struct PartitionResult {
    /// Nodes on the smaller side of the selected diagnostic cut.
    pub partition_b: Vec<String>,
    /// A threshold on the selected projection of the Ritz search directions.
    pub tau: f64,
    /// A Rayleigh estimate; residual convergence does not certify the second eigenpair.
    /// Close to 0.0 indicates a severe structural bottleneck.
    pub connectivity_score: f64,
    pub converged: bool,
    pub residual: f64,
    pub iterations: usize,
    /// Absent for the exact component fallback. These are cut diagnostics only.
    pub cut_diagnostics: Option<CutDiagnostics>,
}

pub struct CutDiagnostics {
    pub projection: &'static str,
    pub ratio_cut: f64,
    pub conductance: f64,
    /// The second search direction need not have converged to an eigenvector.
    pub secondary_direction_residual: Option<f64>,
    pub conductance_alternative: Option<AlternativeCut>,
}

pub struct AlternativeCut {
    pub partition_b: Vec<String>,
    pub tau: f64,
    pub projection: &'static str,
    pub ratio_cut: f64,
    pub conductance: f64,
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
            cut_diagnostics: None,
        });
    }
    let iterations = 5000.min((20_000_000usize / (n + graph.edges().len()).max(1)).max(1));
    let estimate = solve(&adj, &degrees, iterations);
    let fiedler_value = estimate.value;
    let residual = estimate.residual;
    let converged = residual < 1e-9;
    let used = estimate.iterations;
    let secondary_direction_residual = estimate.secondary.as_ref().map(|vector| {
        let image = multiply(&adj, vector);
        let value = dot(vector, &image);
        image
            .iter()
            .zip(vector)
            .map(|(av, v)| (av - value * v).powi(2))
            .sum::<f64>()
            .sqrt()
    });
    let (primary, boundary) = select_cuts(&adj, &estimate.vector, estimate.secondary.as_deref())
        .ok_or_else(|| {
            GateError::Math("No distinct spectral threshold has positive volume".into())
        })?;
    let alternative = (boundary.quality.conductance < primary.quality.conductance)
        .then(|| boundary.describe(graph));
    let selected = primary.describe(graph);
    Ok(PartitionResult {
        partition_b: selected.partition_b,
        tau: selected.tau,
        connectivity_score: fiedler_value,
        converged,
        residual,
        iterations: used,
        cut_diagnostics: Some(CutDiagnostics {
            projection: selected.projection,
            ratio_cut: selected.ratio_cut,
            conductance: selected.conductance,
            secondary_direction_residual,
            conductance_alternative: alternative,
        }),
    })
}

#[derive(Clone, Copy)]
struct CutQuality {
    index: usize,
    ratio_cut: f64,
    conductance: f64,
}

struct SelectedCut {
    ordered: Vec<(usize, f64)>,
    quality: CutQuality,
    projection: &'static str,
}

impl SelectedCut {
    fn describe(&self, graph: &DiGraph) -> AlternativeCut {
        let cut = self.quality.index;
        let (low, high) = (self.ordered[cut].1, self.ordered[cut + 1].1);
        let midpoint = low + (high - low) / 2.0;
        let side = if cut < self.ordered.len() / 2 {
            &self.ordered[..=cut]
        } else {
            &self.ordered[cut + 1..]
        };
        AlternativeCut {
            partition_b: side
                .iter()
                .filter_map(|&(i, _)| graph.node_weight(i).cloned())
                .collect(),
            tau: if midpoint < high { midpoint } else { low },
            projection: self.projection,
            ratio_cut: self.quality.ratio_cut,
            conductance: self.quality.conductance,
        }
    }
}

fn select_cuts(
    adj: &[Vec<usize>],
    primary: &[f64],
    secondary: Option<&[f64]>,
) -> Option<(SelectedCut, SelectedCut)> {
    let mut ratio: Option<SelectedCut> = None;
    let mut boundary: Option<SelectedCut> = None;
    for (projection, a, b) in [
        ("primary", 1.0, 0.0),
        ("secondary", 0.0, 1.0),
        ("sum", 1.0, 1.0),
        ("difference", 1.0, -1.0),
    ] {
        if b != 0.0 && secondary.is_none() {
            continue;
        }
        let mut ordered: Vec<_> = primary
            .iter()
            .enumerate()
            .map(|(i, &x)| (i, a * x + b * secondary.map_or(0.0, |y| y[i])))
            .collect();
        ordered.sort_by(|a, b| a.1.total_cmp(&b.1));
        let Some((r, c)) = sweep_cuts(adj, &ordered) else {
            continue;
        };
        if ratio.as_ref().is_none_or(|old| {
            (r.ratio_cut, r.conductance) < (old.quality.ratio_cut, old.quality.conductance)
        }) {
            ratio = Some(SelectedCut {
                ordered: ordered.clone(),
                quality: r,
                projection,
            });
        }
        if boundary.as_ref().is_none_or(|old| {
            (c.conductance, c.ratio_cut) < (old.quality.conductance, old.quality.ratio_cut)
        }) {
            boundary = Some(SelectedCut {
                ordered,
                quality: c,
                projection,
            });
        }
    }
    ratio.zip(boundary)
}

// One pass measures every distinct-coordinate threshold under both objectives.
fn sweep_cuts(adj: &[Vec<usize>], ordered: &[(usize, f64)]) -> Option<(CutQuality, CutQuality)> {
    let n = adj.len();
    let total_volume: usize = adj.iter().map(Vec::len).sum();
    let mut inside = vec![false; n];
    let mut cut_edges = 0;
    let mut volume = 0;
    let mut ratio: Option<CutQuality> = None;
    let mut boundary: Option<CutQuality> = None;
    for (index, &(u, value)) in ordered.iter().take(n - 1).enumerate() {
        cut_edges += adj[u].len();
        for &v in &adj[u] {
            if inside[v] {
                cut_edges -= 2;
            }
        }
        volume += adj[u].len();
        inside[u] = true;
        if value == ordered[index + 1].1 {
            continue;
        }
        let denominator = volume.min(total_volume - volume);
        if denominator == 0 {
            continue;
        }
        let size = index + 1;
        let quality = CutQuality {
            index,
            ratio_cut: cut_edges as f64 * (1.0 / size as f64 + 1.0 / (n - size) as f64),
            conductance: cut_edges as f64 / denominator as f64,
        };
        if ratio
            .is_none_or(|r| (quality.ratio_cut, quality.conductance) < (r.ratio_cut, r.conductance))
        {
            ratio = Some(quality);
        }
        if boundary
            .is_none_or(|c| (quality.conductance, quality.ratio_cut) < (c.conductance, c.ratio_cut))
        {
            boundary = Some(quality);
        }
    }
    ratio.zip(boundary)
}

#[cfg(test)]
fn sweep_cut(adj: &[Vec<usize>], ordered: &[(usize, f64)]) -> Option<usize> {
    sweep_cuts(adj, ordered).map(|(r, _)| r.index)
}

struct Estimate {
    secondary: Option<Vec<f64>>,
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
    let secondary = vectors.pop();
    let image = multiply(adj, &vector);
    let value = dot(&vector, &image);
    let residual = image
        .iter()
        .zip(&vector)
        .map(|(av, v)| (av - value * v).powi(2))
        .sum::<f64>()
        .sqrt();
    Estimate {
        secondary,
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

#[cfg(test)]
mod partition_regressions {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn rounding_finds_a_better_ratio_cut_without_changing_the_eigenvalue() {
        let mut graph = DiGraph::new();
        for i in 0..7 {
            graph.add_node(i.to_string());
        }
        for (u, v) in [
            (1, 0),
            (2, 1),
            (3, 0),
            (4, 0),
            (4, 2),
            (4, 3),
            (5, 1),
            (5, 2),
            (6, 2),
            (6, 4),
        ] {
            graph.add_edge(u, v);
        }
        let result = analyze_graph(&graph).unwrap();
        assert!(result.converged);
        let side: BTreeSet<_> = result
            .partition_b
            .iter()
            .map(|s| s.parse::<usize>().unwrap())
            .collect();
        let mut cut = 0;
        for &(u, v) in graph.edges() {
            cut += usize::from(side.contains(&u) != side.contains(&v));
        }
        let size = side.len();
        let ratio_cut = cut as f64 * (1.0 / size as f64 + 1.0 / (7 - size) as f64);
        assert!(
            ratio_cut <= 1.75 + 1e-12,
            "selected ratio cut {ratio_cut}; a spectral threshold attains 1.75"
        );
    }

    #[test]
    fn combined_search_direction_recovers_a_cut_missing_from_both_axes() {
        let mut graph = DiGraph::new();
        for i in 0..8 {
            graph.add_node(i.to_string());
        }
        for (u, v) in [
            (1, 0),
            (2, 0),
            (3, 2),
            (4, 0),
            (5, 3),
            (6, 5),
            (7, 0),
            (2, 0),
            (2, 1),
            (6, 4),
            (7, 4),
            (7, 6),
        ] {
            graph.add_edge(u, v);
        }
        let result = analyze_graph(&graph).unwrap();
        let side: BTreeSet<_> = result.partition_b.iter().cloned().collect();
        let crossing = graph
            .edges()
            .iter()
            .filter(|&&(u, v)| side.contains(&u.to_string()) != side.contains(&v.to_string()))
            .count();
        let ratio = crossing as f64 * (1.0 / side.len() as f64 + 1.0 / (8 - side.len()) as f64);
        assert!((ratio - 4.0 / 3.0).abs() < 1e-12, "ratio cut {ratio}");
        let diagnostics = result.cut_diagnostics.unwrap();
        assert_eq!(diagnostics.projection, "sum");
        assert!((diagnostics.ratio_cut - ratio).abs() < 1e-12);
        let alternative = diagnostics.conductance_alternative.unwrap();
        assert!(alternative.conductance < diagnostics.conductance);
        assert!(alternative.ratio_cut > diagnostics.ratio_cut);
        assert!(diagnostics.secondary_direction_residual.is_some());
    }

    #[test]
    fn one_direction_and_component_fallback_keep_their_scope() {
        let mut graph = DiGraph::new();
        graph.add_node("a".into());
        assert!(analyze_graph(&graph).unwrap().cut_diagnostics.is_none());
        graph.add_node("b".into());
        assert!(analyze_graph(&graph).unwrap().cut_diagnostics.is_none());
        graph.add_edge(0, 1);
        graph.add_edge(1, 1);
        let diagnostics = analyze_graph(&graph).unwrap().cut_diagnostics.unwrap();
        assert_eq!(diagnostics.projection, "primary");
        assert_eq!(diagnostics.ratio_cut, 2.0);
        assert_eq!(diagnostics.conductance, 1.0);
        assert!(diagnostics.secondary_direction_residual.is_none());
        assert!(diagnostics.conductance_alternative.is_none());
    }

    #[test]
    fn thresholds_do_not_split_equal_coordinates_or_invent_a_constant_cut() {
        let adj = vec![vec![1], vec![0, 2], vec![1, 3], vec![2]];
        assert_eq!(
            sweep_cut(&adj, &[(0, -1.0), (1, -1.0), (2, 1.0), (3, 1.0)]),
            Some(1)
        );
        assert_eq!(
            sweep_cut(&adj, &[(0, 1.0), (1, 1.0), (2, 1.0), (3, 1.0)]),
            None
        );
    }

    #[test]
    fn sweep_quality_matches_enumerated_ratio_cuts_with_parallel_edges() {
        let adj = vec![
            vec![1, 1, 2],
            vec![0, 0, 2],
            vec![0, 1, 3],
            vec![2, 4, 4],
            vec![3, 3],
        ];
        let ordered = [(0, -2.0), (1, -1.0), (2, 0.0), (3, 1.0), (4, 2.0)];
        let quality = |index: usize| {
            let side: BTreeSet<_> = ordered[..=index].iter().map(|v| v.0).collect();
            let cut = side
                .iter()
                .map(|&u| adj[u].iter().filter(|v| !side.contains(v)).count())
                .sum::<usize>();
            let volume = side.iter().map(|&u| adj[u].len()).sum::<usize>();
            let total = adj.iter().map(Vec::len).sum::<usize>();
            (
                cut as f64 * (1.0 / side.len() as f64 + 1.0 / (adj.len() - side.len()) as f64),
                cut as f64 / volume.min(total - volume) as f64,
            )
        };
        let chosen = sweep_cut(&adj, &ordered).unwrap();
        let expected = (0..ordered.len() - 1)
            .min_by(|&a, &b| quality(a).partial_cmp(&quality(b)).unwrap())
            .unwrap();
        assert_eq!(quality(chosen), quality(expected));
    }
}
