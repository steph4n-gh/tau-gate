/// A bespoke, zero-dependency Directed Graph implementation for Tau-Gate.
/// Replaces 'petgraph' to ensure architectural isolation.
pub struct DiGraph {
    nodes: Vec<String>,
    edges: Vec<(usize, usize)>,
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
}
