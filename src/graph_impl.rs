/// A bespoke, zero-dependency Directed Graph implementation for Tau-Gate.
/// Replaces 'petgraph' to ensure architectural isolation.
#[derive(Clone)]
pub struct DiGraph {
    nodes: Vec<String>,
    edges: Vec<(usize, usize)>,
}

impl Default for DiGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DiGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, name: String) -> usize {
        self.nodes.push(name);
        self.nodes.len() - 1
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        self.edges.push((from, to));
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn _edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn node_weight(&self, index: usize) -> Option<&String> {
        self.nodes.get(index)
    }

    pub fn _node_weights(&self) -> impl Iterator<Item = &String> {
        self.nodes.iter()
    }

    pub fn edges(&self) -> &[(usize, usize)] {
        &self.edges
    }

    /// v3.0.7: Returns a new graph containing only the nodes in the provided list of weights.
    /// Used for Recursive Spectral Bisection.
    pub fn subgraph(&self, weights: &[String]) -> Self {
        let mut new_graph = Self::new();
        let mut old_to_new = std::collections::BTreeMap::new();

        for weight in weights {
            if let Some(old_idx) = self.nodes.iter().position(|n| n == weight) {
                let new_idx = new_graph.add_node(weight.clone());
                old_to_new.insert(old_idx, new_idx);
            }
        }

        for &(u, v) in &self.edges {
            if let (Some(&u_new), Some(&v_new)) = (old_to_new.get(&u), old_to_new.get(&v)) {
                new_graph.add_edge(u_new, v_new);
            }
        }

        new_graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digraph_basic() {
        let mut g = DiGraph::new();
        let a = g.add_node("A".to_string());
        let b = g.add_node("B".to_string());
        g.add_edge(a, b);

        assert_eq!(g.node_count(), 2);
        assert_eq!(g._edge_count(), 1);
        assert_eq!(g.node_weight(a), Some(&"A".to_string()));
        assert_eq!(g.edges()[0], (a, b));
    }
}
