use std::collections::BTreeSet;
use tau_gate::graph::DepGraph;
use tau_gate::parser::MiniParser;

fn edges(graph: &DepGraph) -> BTreeSet<(String, String)> {
    graph
        .graph
        .edges()
        .iter()
        .map(|&(from, to)| {
            (
                graph.graph.node_weight(from).unwrap().clone(),
                graph.graph.node_weight(to).unwrap().clone(),
            )
        })
        .collect()
}

#[test]
fn npm_v2_uses_packages_instead_of_conflicting_legacy_data() {
    let graph = DepGraph::parse_npm_lockfile(
        r#"{"lockfileVersion":2,"packages":{
            "":{"dependencies":{"alias":"npm:real@1.2.3"}},
            "node_modules/alias":{"name":"real","version":"1.2.3",
                "resolved":"https://registry.npmjs.org/real/-/real-1.2.3.tgz",
                "integrity":"sha512-original","hasInstallScript":true}
        },"dependencies":{"alias":{"version":"9.9.9"}}}"#,
    )
    .unwrap();
    let package = &graph.packages["node_modules/alias"];
    assert_eq!(package.name, "real");
    assert_eq!(package.version, "1.2.3");
    assert_eq!(package.integrity, "sha512-original");
    assert!(graph.execution_packages.contains("node_modules/alias"));
    assert!(edges(&graph).contains(&("root".into(), "node_modules/alias".into())));
    assert!(graph
        .issues
        .iter()
        .any(|issue| issue.starts_with("Execution capabilities unknown:")));
}

#[test]
fn npm_v2_without_authoritative_packages_is_rejected() {
    assert!(DepGraph::parse_npm_lockfile(
        r#"{"lockfileVersion":2,"dependencies":{"a":{"version":"1.0.0"}}}"#
    )
    .is_err());
}

#[test]
fn npm_v1_preserves_nested_instances_and_nearest_requires_without_direct_guessing() {
    let graph = DepGraph::parse_npm_lockfile(
        r#"{"name":"project","version":"1.0.0","lockfileVersion":1,"dependencies":{
            "a":{"version":"1.0.0","requires":{"x":"^2","hoisted":"1"},
                "dependencies":{"x":{"version":"2.0.0"}}},
            "hoisted":{"version":"1.0.0"},"x":{"version":"1.0.0"}
        }}"#,
    )
    .unwrap();
    let edges = edges(&graph);
    assert_eq!(graph.packages.len(), 5);
    assert!(edges.contains(&(
        "node_modules/a".into(),
        "node_modules/a/node_modules/x".into()
    )));
    assert!(edges.contains(&("node_modules/a".into(), "node_modules/hoisted".into())));
    assert!(!edges.iter().any(|(source, _)| source == "root"));
    assert!(graph
        .issues
        .iter()
        .any(|s| s.starts_with("Root attribution incomplete:")));
    assert!(graph
        .issues
        .iter()
        .any(|s| s.starts_with("Execution capabilities unknown:")));
    assert!(graph
        .edge_kinds
        .values()
        .all(|kinds| kinds.contains("requires")));
}

#[test]
fn npm_v1_unresolved_requires_stays_incomplete_without_guessing_an_edge() {
    let graph = DepGraph::parse_npm_lockfile(
        r#"{"lockfileVersion":1,"dependencies":{
            "a":{"version":"1.0.0","requires":{"missing":"^1"}},
            "other":{"version":"1.0.0","dependencies":{"missing":{"version":"1.0.0"}}}
        }}"#,
    )
    .unwrap();
    assert!(edges(&graph).is_empty());
    assert!(graph
        .issues
        .iter()
        .any(|s| s.contains("unresolved requires")));
}

#[test]
fn npm_workspace_target_can_be_versionless_only_when_linked_local() {
    let graph = DepGraph::parse_npm_lockfile(
        r#"{"lockfileVersion":3,"packages":{
            "":{"devDependencies":{"@test/loader":"file:test/loader"}},
            "node_modules/@test/loader":{"resolved":"test/loader","link":true},
            "test/loader":{"name":"@test/loader","dev":true}
        }}"#,
    )
    .unwrap();
    assert!(graph.issues.is_empty(), "{:?}", graph.issues);
    assert_eq!(graph.packages["test/loader"].version, "");
    assert!(edges(&graph).contains(&("node_modules/@test/loader".into(), "test/loader".into())));
}

#[test]
fn npm_versionless_installed_registry_record_is_incomplete_even_when_linked() {
    let graph = DepGraph::parse_npm_lockfile(
        r#"{"lockfileVersion":3,"packages":{
            "":{},"node_modules/a":{"link":true,"resolved":"node_modules/target"},
            "node_modules/target":{"name":"target","resolved":"https://registry.npmjs.org/target/-/target.tgz"}
        }}"#,
    )
    .unwrap();
    assert!(graph
        .issues
        .iter()
        .any(|s| s == "missing version: node_modules/target"));
}

#[test]
fn npm_v1_manifest_attributes_only_declared_roots_and_keeps_alias_sources() {
    let manifest = MiniParser::parse_json(
        r#"{
        "name":"project","version":"1.0.0",
        "dependencies":{"alias":"npm:@scope/real@1.2.3","local":"file:local"},
        "devDependencies":{"dev":"^2"},
        "optionalDependencies":{"absent":"*"}
    }"#,
    )
    .unwrap();
    let graph = DepGraph::parse_npm_lockfile_with_manifest(
        r#"{"lockfileVersion":1,"dependencies":{
            "alias":{"version":"npm:@scope/real@1.2.3","integrity":"sha512-original",
                "resolved":"https://registry.npmjs.org/@scope/real/-/real-1.2.3.tgz"},
            "local":{"version":"file:local"},
            "dev":{"version":"2.0.0","dev":true,"requires":{"hoisted":"^3"}},
            "hoisted":{"version":"3.1.0","dev":true}
        }}"#,
        Some(&manifest),
    )
    .unwrap();
    let edges = edges(&graph);
    assert_eq!(edges.iter().filter(|(from, _)| from == "root").count(), 3);
    assert!(!edges.contains(&("root".into(), "node_modules/hoisted".into())));
    assert_eq!(graph.packages["node_modules/alias"].name, "@scope/real");
    assert_eq!(graph.packages["node_modules/alias"].version, "1.2.3");
    assert_eq!(
        graph.packages["node_modules/alias"].integrity,
        "sha512-original"
    );
    assert_eq!(graph.packages["node_modules/local"].source, "file:local");
    assert_eq!(graph.packages["node_modules/local"].version, "file:local");
    assert_eq!(
        graph.resolution_metadata["node_modules/alias"]
            .get("version")
            .unwrap()
            .as_str(),
        Some("npm:@scope/real@1.2.3")
    );
    assert!(!graph
        .issues
        .iter()
        .any(|s| s.starts_with("Root attribution incomplete:")));
    assert_eq!(graph.optional_omissions.len(), 1);
    assert!(graph
        .issues
        .iter()
        .any(|s| s.starts_with("Dependency kinds unknown:")));
}

#[test]
fn npm_v1_scoped_ancestor_resolution_does_not_cross_sibling_trees() {
    let graph = DepGraph::parse_npm_lockfile(
        r#"{"lockfileVersion":1,"dependencies":{
        "@scope/a":{"version":"1.0.0","requires":{"@scope/b":"^1"},
            "dependencies":{"@scope/b":{"version":"1.1.0","requires":{"ancestor":"1"}},
                "ancestor":{"version":"1.0.0"}}},
        "@scope/b":{"version":"2.0.0"}
    }}"#,
    )
    .unwrap();
    let edges = edges(&graph);
    assert!(edges.contains(&(
        "node_modules/@scope/a".into(),
        "node_modules/@scope/a/node_modules/@scope/b".into()
    )));
    assert!(edges.contains(&(
        "node_modules/@scope/a/node_modules/@scope/b".into(),
        "node_modules/@scope/a/node_modules/ancestor".into()
    )));
    assert!(!edges.iter().any(|(_, to)| to == "node_modules/@scope/b"));
}

#[test]
fn npm_v1_invalid_maps_names_and_aliases_are_rejected() {
    for input in [
        r#"{"lockfileVersion":1,"dependencies":{"a":{"version":true}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1","requires":true}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1","requires":{"b":null}}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1","dependencies":[]}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{"a/../b":{"version":"1"}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"npm:real"}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"npm:@scope/real@"}}}"#,
        r#"{"lockfileVersion":1,"dependencies":{},"packages":{"":{}}}"#,
    ] {
        assert!(DepGraph::parse_npm_lockfile(input).is_err(), "{input}");
    }
}

#[test]
fn npm_v1_missing_installed_version_and_required_manifest_root_stay_incomplete() {
    let manifest = MiniParser::parse_json(r#"{"dependencies":{"missing":"1"}}"#).unwrap();
    let graph = DepGraph::parse_npm_lockfile_with_manifest(
        r#"{"lockfileVersion":1,"dependencies":{"empty":{"dev":true}}}"#,
        Some(&manifest),
    )
    .unwrap();
    assert_eq!(graph.packages["node_modules/empty"].version, "");
    assert!(graph
        .issues
        .iter()
        .any(|s| s == "missing version: node_modules/empty"));
    assert!(graph
        .issues
        .iter()
        .any(|s| s.contains("unresolved dependencies: root -> missing")));
    assert!(edges(&graph).is_empty());
}

#[test]
fn npm_versionless_unlinked_or_registry_sourced_workspace_record_stays_incomplete() {
    for packages in [
        r#"{"":{},"packages/a":{"name":"a"}}"#,
        r#"{"":{},"node_modules/a":{"link":true,"resolved":"packages/a"},"packages/a":{"resolved":"https://registry.npmjs.org/a/-/a.tgz"}}"#,
    ] {
        let graph = DepGraph::parse_npm_lockfile(&format!(
            r#"{{"lockfileVersion":3,"packages":{packages}}}"#
        ))
        .unwrap();
        assert!(graph
            .issues
            .iter()
            .any(|s| s == "missing version: packages/a"));
    }
}

#[test]
fn npm_v1_empty_lock_inventory_needs_no_fabricated_records() {
    let manifest = MiniParser::parse_json(r#"{"name":"empty","version":"1.0.0"}"#).unwrap();
    let graph = DepGraph::parse_npm_lockfile_with_manifest(
        r#"{"name":"empty","version":"1.0.0","lockfileVersion":1}"#,
        Some(&manifest),
    )
    .unwrap();
    assert_eq!(graph.packages.len(), 1);
    assert!(edges(&graph).is_empty());
    assert!(!graph.issues.iter().any(|s| s.contains("unresolved")));
    assert!(DepGraph::parse_npm_lockfile(r#"{"lockfileVersion":1,"dependencies":null}"#).is_err());
}

#[test]
fn npm_v1_record_and_reference_limits_do_not_truncate_inventory() {
    let records = (0..9999)
        .map(|i| format!(r#""p{i}":{{"version":"1.0.0"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let lock = format!(r#"{{"lockfileVersion":1,"dependencies":{{{records}}}}}"#);
    assert_eq!(
        DepGraph::parse_npm_lockfile(&lock).unwrap().packages.len(),
        10000
    );
    let lock = format!(
        r#"{{"lockfileVersion":1,"dependencies":{{{records},"over":{{"version":"1.0.0"}}}}}}"#
    );
    assert!(DepGraph::parse_npm_lockfile(&lock).is_err());
    let references = (0..50000)
        .map(|i| format!(r#""p{i}":"1.0.0""#))
        .collect::<Vec<_>>()
        .join(",");
    let manifest =
        MiniParser::parse_json(&format!(r#"{{"optionalDependencies":{{{references}}}}}"#)).unwrap();
    let lock = r#"{"lockfileVersion":1}"#;
    assert_eq!(
        DepGraph::parse_npm_lockfile_with_manifest(lock, Some(&manifest))
            .unwrap()
            .optional_omissions
            .len(),
        50000
    );
    let manifest = MiniParser::parse_json(&format!(
        r#"{{"optionalDependencies":{{{references}}},"dependencies":{{"over":"1"}}}}"#
    ))
    .unwrap();
    assert!(DepGraph::parse_npm_lockfile_with_manifest(lock, Some(&manifest)).is_err());
}
