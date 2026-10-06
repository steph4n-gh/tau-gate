use crate::error::{GateContext, GateError, Result};
use crate::graph_impl::DiGraph;
use crate::parser::{JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Supported package manager engines.
#[derive(Debug, Clone, Copy)]
pub enum EngineType {
    Npm,
    Pnpm,
    Bun,
    Yarn,
    Cargo,
    Network,
    Go,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub path: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub integrity: String,
    pub capabilities: Vec<String>,
}

/// A directed graph representing the project's dependency topology.
pub struct DepGraph {
    pub graph: DiGraph,
    /// V2.6 Hardening: Track packages with execution scripts separately.
    pub execution_packages: BTreeSet<String>,
    /// V2.7 Hardening: Track packages with high-entropy metadata.
    pub suspicious_packages: BTreeSet<String>,
    pub packages: BTreeMap<String, PackageInfo>,
    pub issues: Vec<String>,
    pub optional_omissions: Vec<String>,
    pub edge_kinds: BTreeMap<(usize, usize), BTreeSet<String>>,
}

impl DepGraph {
    /// Discovers the project type and builds the dependency graph using the appropriate engine.
    pub fn build(use_network: bool) -> Result<(Self, EngineType)> {
        if use_network {
            return Err(GateError::Graph("INCOMPLETE: network exploration is not an exact install snapshot; provide npm v3 lockfile".into()));
        }
        if Path::new("Cargo.toml").exists() {
            Err(GateError::Graph(
                "INCOMPLETE: Cargo CLI audit is not qualified; no package manager was invoked"
                    .into(),
            ))
        } else if Path::new("pnpm-lock.yaml").exists() {
            Ok((Self::build_from_pnpm()?, EngineType::Pnpm))
        } else if Path::new("bun.lockb").exists()
            || Path::new("bun.lock").exists()
            || Path::new("yarn.lock").exists()
            || Path::new("go.mod").exists()
        {
            Err(GateError::Graph("INCOMPLETE: this adapter is not qualified for read-only auditing; no package manager was invoked".into()))
        } else {
            Ok((Self::build_from_npm()?, EngineType::Npm))
        }
    }

    fn build_from_npm() -> Result<Self> {
        let lockfile_path = "package-lock.json";
        if !Path::new(lockfile_path).exists() {
            return Err(GateError::Graph("INCOMPLETE: missing package-lock.json; audit never generates or installs dependencies".into()));
        }
        let content = fs::read_to_string(lockfile_path)?;
        Self::parse_npm_lockfile(&content)
    }

    /// Internal logic for npm parsing to allow unit testing without disk IO
    pub fn parse_npm_lockfile(content: &str) -> Result<Self> {
        let root = MiniParser::parse_json(content)?;
        if root.get("lockfileVersion") != Some(&JsonNode::Number(3.0)) {
            return Err(GateError::Graph(
                "INCOMPLETE: only npm lockfileVersion 3 is supported for exact review".into(),
            ));
        }
        let packages = root
            .get("packages")
            .and_then(JsonNode::as_object)
            .context("INCOMPLETE: missing packages")?;
        if !packages.contains_key("") {
            return Err(GateError::Graph(
                "INCOMPLETE: lockfile root package is missing".into(),
            ));
        }
        let mut graph = DiGraph::new();
        let mut indices = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let mut execution_packages = BTreeSet::new();
        let mut suspicious_packages = BTreeSet::new();
        let mut issues = Vec::new();
        let mut optional_omissions = Vec::new();
        let mut edge_kinds = BTreeMap::<(usize, usize), BTreeSet<String>>::new();
        for (path, details) in packages {
            if details.as_object().is_none() {
                return Err(GateError::Graph(format!("Invalid package record {path}")));
            }
            if path == "root" {
                return Err(GateError::Graph(
                    "INCOMPLETE: workspace path root conflicts with root label".into(),
                ));
            }
            for key in ["name", "version", "resolved", "integrity"] {
                if details.get(key).is_some_and(|v| v.as_str().is_none()) {
                    return Err(GateError::Graph(format!("Invalid {key} in {path}")));
                }
            }
            for key in ["link", "hasInstallScript"] {
                if details.get(key).is_some_and(|v| v.as_bool().is_none()) {
                    return Err(GateError::Graph(format!("Invalid {key} in {path}")));
                }
            }
            let label = if path.is_empty() { "root" } else { path };
            indices.insert(path.clone(), graph.add_node(label.into()));
            let mut caps = Vec::new();
            if let Some(flag) = details.get("hasInstallScript") {
                if flag.as_bool().is_none() {
                    return Err(GateError::Graph("Invalid install-script marker".into()));
                }
                if flag.as_bool() == Some(true) {
                    caps.push("install-lifecycle-script (body not inspected)".into());
                    execution_packages.insert(label.into());
                }
            }
            if details.get("bin").is_some() {
                caps.push("binary-entrypoint (not automatic installation execution)".into());
            }
            if MiniParser::detect_obfuscation(label) {
                suspicious_packages.insert(label.into());
            }
            let name = details
                .get("name")
                .and_then(JsonNode::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    path.rsplit("node_modules/")
                        .next()
                        .unwrap_or(path)
                        .to_string()
                });
            let version = details
                .get("version")
                .and_then(JsonNode::as_str)
                .unwrap_or("")
                .into();
            if !path.is_empty()
                && details.get("link").and_then(JsonNode::as_bool) != Some(true)
                && details.get("version").and_then(JsonNode::as_str).is_none()
            {
                issues.push(format!("missing version: {path}"));
            }
            identities.insert(
                label.into(),
                PackageInfo {
                    path: path.clone(),
                    name,
                    version,
                    source: details
                        .get("resolved")
                        .and_then(JsonNode::as_str)
                        .unwrap_or("")
                        .into(),
                    integrity: details
                        .get("integrity")
                        .and_then(JsonNode::as_str)
                        .unwrap_or("")
                        .into(),
                    capabilities: caps,
                },
            );
        }
        for (path, details) in packages {
            let source = indices[path];
            if details.get("link").and_then(JsonNode::as_bool) == Some(true) {
                let target = details
                    .get("resolved")
                    .and_then(JsonNode::as_str)
                    .unwrap_or("");
                if let Some(&idx) = indices.get(target) {
                    edge_kinds
                        .entry((source, idx))
                        .or_default()
                        .insert("workspaceLink".into());
                } else {
                    issues.push(format!("unresolved workspace link {path} -> {target}"));
                }
            }
            for kind in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                if let Some(value) = details.get(kind) {
                    let deps = value.as_object().context("Invalid dependency map")?;
                    for (name, req) in deps {
                        if kind == "dependencies"
                            && details
                                .get("optionalDependencies")
                                .and_then(JsonNode::as_object)
                                .is_some_and(|m| m.contains_key(name))
                        {
                            continue;
                        }
                        if req.as_str().is_none() {
                            return Err(GateError::Graph("Invalid dependency requirement".into()));
                        }
                        let mut search = path.as_str();
                        let mut target = None;
                        loop {
                            let candidate = if search.is_empty() {
                                format!("node_modules/{name}")
                            } else {
                                format!("{search}/node_modules/{name}")
                            };
                            if search.rsplit('/').next() != Some("node_modules") {
                                if let Some(&idx) = indices.get(&candidate) {
                                    target = Some(idx);
                                    break;
                                }
                            }
                            if search.is_empty() {
                                break;
                            }
                            search = search
                                .rsplit_once('/')
                                .map(|(parent, _)| parent)
                                .unwrap_or("");
                        }
                        if let Some(target) = target {
                            edge_kinds
                                .entry((source, target))
                                .or_default()
                                .insert(kind.into());
                        } else {
                            let optional_peer = kind == "peerDependencies"
                                && details
                                    .get("peerDependenciesMeta")
                                    .and_then(|m| m.get(name))
                                    .and_then(|m| m.get("optional"))
                                    .and_then(JsonNode::as_bool)
                                    == Some(true);
                            if optional_peer || kind == "optionalDependencies" {
                                optional_omissions.push(format!("absent {kind}: {path} -> {name}"));
                            } else {
                                issues.push(format!("unresolved {kind}: {path} -> {name}"));
                            }
                        }
                    }
                }
            }
        }
        for &(u, v) in edge_kinds.keys() {
            graph.add_edge(u, v);
        }
        Ok(Self {
            graph,
            execution_packages,
            suspicious_packages,
            packages: identities,
            issues,
            optional_omissions,
            edge_kinds,
        })
    }

    fn build_from_pnpm() -> Result<Self> {
        let content = fs::read_to_string("pnpm-lock.yaml")?;
        Self::parse_pnpm_lockfile(&content)
    }

    pub fn parse_pnpm_lockfile(content: &str) -> Result<Self> {
        crate::pnpm::parse(content, None)
    }

    pub fn build_from_network() -> Result<Self> {
        Err(GateError::Graph("INCOMPLETE: network resolver is retired until exact resolver/capability agreement is validated; provide a frozen npm v3 snapshot".into()))
    }

    pub fn parse_cargo_metadata(stdout: &str) -> Result<Self> {
        let json_str = if let Some(idx) = stdout.find('{') {
            &stdout[idx..]
        } else {
            stdout
        };
        let root = MiniParser::parse_json(json_str).context("Failed to parse Cargo metadata.")?;
        let mut graph = DiGraph::new();
        let mut node_indices = BTreeMap::new();
        let mut execution_packages = BTreeSet::new();
        let mut suspicious_packages = BTreeSet::new();

        if let Some(packages) = root.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let Some(id) = pkg.get("id").and_then(|v| v.as_str()) {
                    let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                    let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                    let full_name = format!("{}@{}", name, version);
                    node_indices.insert(id.to_string(), graph.add_node(full_name.clone()));
                    if MiniParser::detect_obfuscation(&full_name) {
                        suspicious_packages.insert(full_name.clone());
                    }

                    let mut has_build_script = false;
                    if let Some(targets) = pkg.get("targets").and_then(|t| t.as_array()) {
                        for target in targets {
                            if let Some(kind) = target.get("kind").and_then(|k| k.as_array()) {
                                if kind.iter().any(|k| {
                                    matches!(k.as_str(), Some("custom-build" | "proc-macro"))
                                }) {
                                    has_build_script = true;
                                }
                            }
                        }
                    }
                    if has_build_script {
                        execution_packages.insert(full_name);
                    }
                }
            }
        }
        if let Some(nodes) = root
            .get("resolve")
            .and_then(|r| r.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                if let Some(id) = node.get("id").and_then(|v| v.as_str()) {
                    if let Some(&source_idx) = node_indices.get(id) {
                        if let Some(deps) = node.get("dependencies").and_then(|d| d.as_array()) {
                            for dep_id in deps {
                                if let Some(dep_id_str) = dep_id.as_str() {
                                    if let Some(&target_idx) = node_indices.get(dep_id_str) {
                                        graph.add_edge(source_idx, target_idx);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Self {
            graph,
            execution_packages,
            suspicious_packages,
            packages: BTreeMap::new(),
            issues: vec![
                "Cargo metadata preview: artifact/capability review is not qualified".into(),
            ],
            optional_omissions: Vec::new(),
            edge_kinds: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_extraction() {
        let content = r#"{
            "lockfileVersion": 3, "packages": {
                "": { "dependencies": { "a": "1.0.0" } },
                "node_modules/a": { "version": "1.0.0", "hasInstallScript": true }
            }
        }"#;
        let dg = DepGraph::parse_npm_lockfile(content).unwrap();
        assert_eq!(dg.graph.node_count(), 2);
        assert!(dg.execution_packages.contains("node_modules/a"));
    }

    #[test]
    fn test_pnpm_extraction() {
        let content="lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    requiresBuild: true\n  b@1.0.0: {}\nsnapshots:\n  a@1.0.0:\n    dependencies:\n      b: 1.0.0\n  b@1.0.0: {}\n";
        let d = DepGraph::parse_pnpm_lockfile(content).unwrap();
        assert_eq!(d.graph.node_count(), 3);
        assert!(d
            .execution_packages
            .contains("pnpm:project:snapshot:a@1.0.0"));
        assert!(d.issues[0].starts_with("Execution capabilities unknown:"));
    }

    #[test]
    fn test_cargo_extraction() {
        let content = r#"{
            "packages": [
                { "id": "a", "name": "a", "version": "1.0.0", "targets": [{ "kind": ["custom-build"] }] }
            ],
            "resolve": {
                "nodes": [
                    { "id": "a", "dependencies": [] }
                ]
            }
        }"#;
        let dg = DepGraph::parse_cargo_metadata(content).unwrap();
        assert_eq!(dg.graph.node_count(), 1);
        assert!(dg.execution_packages.contains("a@1.0.0"));
    }
}

#[cfg(test)]
mod exact_regressions {
    use super::*;
    fn edges(d: &DepGraph) -> BTreeSet<(String, String)> {
        d.graph
            .edges()
            .iter()
            .map(|&(u, v)| {
                (
                    d.graph.node_weight(u).unwrap().clone(),
                    d.graph.node_weight(v).unwrap().clone(),
                )
            })
            .collect()
    }
    #[test]
    fn nested_versions_workspaces_and_kinds() {
        let d=DepGraph::parse_npm_lockfile(r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"1","w":"*"},"devDependencies":{"x":"1"},"optionalDependencies":{"missing":"1"}},"node_modules/a":{"version":"1","dependencies":{"x":"2"},"peerDependencies":{"p":"1"}},"node_modules/a/node_modules/x":{"version":"2","hasInstallScript":true},"node_modules/x":{"version":"1"},"node_modules/p":{"version":"1"},"node_modules/w":{"link":true,"resolved":"packages/w"},"packages/w":{"name":"w","version":"1","hasInstallScript":true,"dependencies":{"x":"1"}}}}"#).unwrap();
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(d.optional_omissions.len(), 1);
        let e = edges(&d);
        for pair in [
            ("node_modules/a", "node_modules/a/node_modules/x"),
            ("root", "node_modules/x"),
            ("node_modules/a", "node_modules/p"),
            ("root", "node_modules/w"),
            ("node_modules/w", "packages/w"),
            ("packages/w", "node_modules/x"),
        ] {
            assert!(e.contains(&(pair.0.into(), pair.1.into())));
        }
        assert_eq!(d.execution_packages.len(), 2);
        assert!(d
            .packages
            .values()
            .any(|p| p.name == "x" && p.version == "2"));
        assert!(d.edge_kinds.values().any(|k| k.contains("devDependencies")));
    }
    #[test]
    fn pnpm_exact_versions_peer_context_and_document_reset() {
        let content="lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages:\n  a@1.0.0: {}\n  b@1.0.0: {}\n  b@2.0.0: {}\nsnapshots:\n  a@1.0.0(p@2.0.0):\n    dependencies:\n      b: 2.0.0(p@2.0.0)\n  b@1.0.0: {}\n  b@2.0.0(p@2.0.0): {}\nsettings:\n  autoInstallPeers: true\n";
        let d = DepGraph::parse_pnpm_lockfile(content).unwrap();
        assert_eq!(d.graph.node_count(), 4);
        assert!(edges(&d).contains(&(
            "pnpm:project:snapshot:a@1.0.0(p@2.0.0)".into(),
            "pnpm:project:snapshot:b@2.0.0(p@2.0.0)".into()
        )));
    }
    #[test]
    fn cargo_proc_macros_execution() {
        let d=DepGraph::parse_cargo_metadata(r#"{"packages":[{"id":"macro","name":"macro","version":"1","targets":[{"kind":["proc-macro"]}]}],"resolve":{"nodes":[{"id":"macro","dependencies":[]}]}}"#).unwrap();
        assert!(d.execution_packages.contains("macro@1"));
        assert!(!d.issues.is_empty());
    }
    #[test]
    fn no_duplicate_topology_weights() {
        let d=DepGraph::parse_npm_lockfile(r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"1"},"devDependencies":{"a":"1"},"optionalDependencies":{"a":"2"}},"node_modules/a":{"version":"2"}}}"#).unwrap();
        assert_eq!(d.graph.edges().len(), 1);
        assert_eq!(d.edge_kinds.values().next().unwrap().len(), 2);
    }
}
