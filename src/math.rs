use crate::error::{GateError, Result};
use petgraph::graph::DiGraph;

/// Result of a graph bisection analysis.
pub struct PartitionResult {
    /// Nodes in the "Island" or Anomaly Partition.
    pub partition_b: Vec<String>,
    /// The calculated bisection point (Max Spectral Gap).
    pub tau: f64,
    /// V2.7 Hardening: The Algebraic Connectivity score (lambda_2).
    /// Close to 0.0 indicates a severe structural bottleneck.
    pub connectivity_score: f64,
}

/// Computes the Fiedler Vector and bisects the graph using an O(E) Sparse Iterative Solver.
pub fn analyze_graph(graph: &DiGraph<String, ()>) -> Result<PartitionResult> {
    let n = graph.node_count();
    if n < 3 {
        return Err(GateError::Math("Graph is too small for meaningful structural analysis.".to_string()));
    }

    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut degrees = vec![0.0; n];

    for edge in graph.raw_edges() {
        let u = edge.source().index();
        let v = edge.target().index();
        if u != v {
            adj[u].push(v);
            adj[v].push(u); 
            degrees[u] += 1.0;
            degrees[v] += 1.0;
        }
    }

    let max_degree = degrees.iter().copied().fold(0.0, f64::max);
    if max_degree == 0.0 {
        return Ok(PartitionResult {
            partition_b: Vec::new(),
            tau: 0.0,
            connectivity_score: 0.0,
        });
    }

    let alpha = 1.0 / (2.0 * max_degree + 1.1);
    let mut v = vec![0.0; n];

    for i in 0..n { v[i] = (i as f64).sin(); }

    let iterations = 1000;
    let tolerance = 1e-9;
    let mut fiedler_value = 0.0;

    for _ in 0..iterations {
        let sum: f64 = v.iter().sum();
        let mean = sum / (n as f64);
        for x in &mut v { *x -= mean; }

        let mut v_next = vec![0.0; n];
        for i in 0..n {
            v_next[i] = (1.0 - alpha * degrees[i]) * v[i];
            for &neighbor in &adj[i] {
                v_next[i] += alpha * v[neighbor];
            }
        }

        let norm: f64 = v_next.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm < 1e-15 { break; }

        let mut max_diff = 0.0;
        for i in 0..n {
            v_next[i] /= norm;
            max_diff = f64::max(max_diff, (v_next[i] - v[i]).abs());
        }

        let mut v_l_v = 0.0;
        for i in 0..n {
            let mut row_sum = degrees[i] * v_next[i];
            for &neighbor in &adj[i] {
                row_sum -= v_next[neighbor];
            }
            v_l_v += v_next[i] * row_sum;
        }
        fiedler_value = v_l_v;

        v = v_next;
        if max_diff < tolerance { break; }
    }

    let fiedler_vector = v;

    let mut indexed_fiedler: Vec<(usize, f64)> = fiedler_vector.iter().copied().enumerate().collect();
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
        let node_name = graph.node_weight(petgraph::graph::NodeIndex::new(val.0)).unwrap().clone();
        if i <= cut_idx { side_small.push(node_name); } else { side_large.push(node_name); }
    }

    if side_small.len() > side_large.len() {
        Ok(PartitionResult { partition_b: side_large, tau, connectivity_score: fiedler_value })
    } else {
        Ok(PartitionResult { partition_b: side_small, tau, connectivity_score: fiedler_value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::DiGraph;

    #[test]
    fn test_dumbbell_bisection() {
        let mut graph = DiGraph::new();
        let a0 = graph.add_node("A0".to_string());
        let a1 = graph.add_node("A1".to_string());
        let a2 = graph.add_node("A2".to_string());
        graph.add_edge(a0, a1, ());
        graph.add_edge(a1, a2, ());
        graph.add_edge(a2, a0, ());
        let b0 = graph.add_node("B0".to_string());
        let b1 = graph.add_node("B1".to_string());
        let b2 = graph.add_node("B2".to_string());
        graph.add_edge(b0, b1, ());
        graph.add_edge(b1, b2, ());
        graph.add_edge(b2, b0, ());
        graph.add_edge(a0, b0, ());
        let result = analyze_graph(&graph).expect("Analysis failed");
        assert_eq!(result.partition_b.len(), 3);
    }

    #[test]
    fn test_anomaly_isolation() {
        let mut graph = DiGraph::new();
        let nodes: Vec<_> = (0..20).map(|i| graph.add_node(format!("M{}", i))).collect();
        for i in 0..20 {
            graph.add_edge(nodes[i], nodes[(i + 1) % 20], ());
            graph.add_edge(nodes[i], nodes[(i + 5) % 20], ());
        }
        let island = graph.add_node("ISLAND".to_string());
        graph.add_edge(nodes[0], island, ());
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
        assert_eq!(result.partition_b.len(), 0);
    }
}
