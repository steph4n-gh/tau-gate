use std::{collections::BTreeSet, fs, path::Path};
use tau_gate::{
    digest::sha256,
    parser::{JsonNode as J, MiniParser},
    review::Snapshot,
};
fn hash_rows(mut rows: Vec<String>) -> String {
    rows.sort();
    sha256(format!("{}\n", rows.join("\n")).as_bytes())
}
#[test]
fn frozen_resolution_locks_match_independent_oracles() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real");
    let p =
        MiniParser::parse_json(&fs::read_to_string(dir.join("provenance.json")).unwrap()).unwrap();
    for name in ["pnpm", "yarn"] {
        let expected = p.get(name).unwrap();
        let field = |n: &str| expected.get(n).and_then(J::as_str).unwrap();
        let lock = dir.join(field("lock"));
        let manifest = dir.join(field("manifest"));
        assert_eq!(sha256(&fs::read(&lock).unwrap()), field("lock_sha256"));
        assert_eq!(
            sha256(&fs::read(&manifest).unwrap()),
            field("manifest_sha256")
        );
        let s = Snapshot::load(&lock, Some(&manifest)).unwrap();
        let d = &s.graph;
        let nodes = (0..d.graph.node_count())
            .map(|i| d.graph.node_weight(i).unwrap().clone())
            .collect::<Vec<_>>();
        assert_eq!(hash_rows(nodes), field("node_sha256"));
        let mut edges = BTreeSet::new();
        for (&(u, v), kinds) in &d.edge_kinds {
            for kind in kinds {
                edges.insert(format!(
                    "{}\t{}\t{kind}",
                    d.graph.node_weight(u).unwrap(),
                    d.graph.node_weight(v).unwrap()
                ));
            }
        }
        assert_eq!(hash_rows(edges.into_iter().collect()), field("edge_sha256"));
        let artifacts = d
            .packages
            .iter()
            .map(|(label, p)| {
                format!(
                    "{label}\t{}\t{}\t{}\t{}",
                    p.name, p.version, p.source, p.integrity
                )
            })
            .collect();
        assert_eq!(hash_rows(artifacts), field("artifact_sha256"));
        let r = s.report();
        assert_eq!(r.get("status").and_then(J::as_str), Some("incomplete"));
        assert_eq!(
            r.get("topology_status").and_then(J::as_str),
            Some("complete")
        );
        assert_eq!(
            r.get("execution_metadata_status").and_then(J::as_str),
            Some("unknown_transitive_scripts")
        );
        assert!(r
            .get("packages")
            .and_then(J::as_array)
            .unwrap()
            .iter()
            .all(|p| p.get("installed_path") == Some(&J::Null)));
        assert_eq!(d.issues.len(), 1, "{name}: {:?}", d.issues);
    }
}
