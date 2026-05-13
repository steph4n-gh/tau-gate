use crate::error::{GateContext, GateError, Result};
use crate::graph_impl::DiGraph;
use crate::parser::{JsonNode, MiniParser};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Supported package manager engines.
#[derive(Debug, Clone, Copy)]
pub enum EngineType {
    Npm,
    Pnpm,
    Bun,
    Yarn,
    Cargo,
}

/// A directed graph representing the project's dependency topology.
pub struct DepGraph {
    pub graph: DiGraph,
    /// V2.6 Hardening: Track packages with execution scripts separately.
    pub execution_packages: HashSet<String>,
    /// V2.7 Hardening: Track packages with high-entropy metadata.
    pub suspicious_packages: HashSet<String>,
}

impl DepGraph {
    /// Discovers the project type and builds the dependency graph using the appropriate engine.
    pub fn build() -> Result<(Self, EngineType)> {
        if Path::new("Cargo.toml").exists() {
            Ok((Self::build_from_cargo()?, EngineType::Cargo))
        } else if Path::new("pnpm-lock.yaml").exists() {
            Ok((Self::build_from_pnpm()?, EngineType::Pnpm))
        } else if Path::new("bun.lockb").exists() || Path::new("bun.lock").exists() {
            Ok((Self::build_from_bun()?, EngineType::Bun))
        } else if Path::new("yarn.lock").exists() {
            Ok((Self::build_from_yarn()?, EngineType::Yarn))
        } else {
            Ok((Self::build_from_npm()?, EngineType::Npm))
        }
    }

    fn build_from_npm() -> Result<Self> {
        let lockfile_path = "package-lock.json";
        if !Path::new(lockfile_path).exists() {
            let status = Command::new("npm").args(&["install", "--package-lock-only", "--ignore-scripts"]).status().context("Failed to execute npm.")?;
            if !status.success() { return Err(GateError::Graph("Failed to generate package-lock.json.".to_string())); }
        }
        let content = fs::read_to_string(lockfile_path)?;
        Self::parse_npm_lockfile(&content)
    }

    /// Internal logic for npm parsing to allow unit testing without disk IO
    fn parse_npm_lockfile(content: &str) -> Result<Self> {
        let root = MiniParser::parse_json(content)?;
        let packages = root.get("packages").and_then(|p| p.as_object()).context("Invalid npm lockfile format")?;

        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        let mut execution_packages = HashSet::new();
        let mut suspicious_packages = HashSet::new();

        for (path, details) in packages {
            let name = if path.is_empty() { "root".to_string() } else { path.clone() };
            node_indices.entry(name.clone()).or_insert_with(|| graph.add_node(name.clone()));

            if details.get("hasInstallScript").and_then(|v| v.as_bool()).unwrap_or(false) {
                execution_packages.insert(name.clone());
            }
            if MiniParser::detect_obfuscation(&name) {
                suspicious_packages.insert(name);
            }
        }
        for (path, details) in packages {
            let source_name = if path.is_empty() { "root".to_string() } else { path.clone() };
            let source_idx = *node_indices.get(&source_name).context("Logic error: node not found")?;
            if let Some(deps) = details.get("dependencies").and_then(|d| d.as_object()) {
                for (dep_name, _) in deps {
                    let mut current_search_path = path.clone();
                    let mut found_target = None;
                    loop {
                        let candidate = if current_search_path.is_empty() { format!("node_modules/{}", dep_name) } else { format!("{}/node_modules/{}", current_search_path, dep_name) };
                        if node_indices.contains_key(&candidate) { found_target = Some(candidate); break; }
                        if let Some(last_idx) = current_search_path.rfind("/node_modules/") { current_search_path = current_search_path[0..last_idx].to_string(); } else if !current_search_path.is_empty() && current_search_path != "root" { current_search_path = "".to_string(); } else { break; }
                    }
                    if let Some(target_name) = found_target {
                        if let Some(target_idx) = node_indices.get(&target_name) { graph.add_edge(source_idx, *target_idx); }
                    }
                }
            }
        }
        Ok(Self { graph, execution_packages, suspicious_packages })
    }

    fn build_from_pnpm() -> Result<Self> {
        let content = fs::read_to_string("pnpm-lock.yaml")?;
        Self::parse_pnpm_lockfile(&content)
    }

    fn parse_pnpm_lockfile(content: &str) -> Result<Self> {
        let meta = MiniParser::parse_pnpm_yaml(content)?;
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        let mut execution_packages = HashSet::new();
        let mut suspicious_packages = HashSet::new();

        for id in meta.snapshots.keys() {
            let idx = graph.add_node(id.clone());
            node_indices.insert(id.clone(), idx);
            if let Some(pkg) = meta.packages.get(id) {
                if pkg.has_install_script { execution_packages.insert(id.clone()); }
            }
            if MiniParser::detect_obfuscation(id) { suspicious_packages.insert(id.clone()); }
        }

        let mut dep_cache = HashMap::new();
        for snap_id in node_indices.keys() {
            let stripped = if snap_id.starts_with('/') { &snap_id[1..] } else { snap_id.as_str() };
            let name = if stripped.starts_with('@') {
                if let Some(second_at) = stripped[1..].find('@') {
                    &stripped[..second_at + 1]
                } else {
                    stripped
                }
            } else {
                if let Some(first_at) = stripped.find('@') {
                    &stripped[..first_at]
                } else {
                    stripped
                }
            };
            dep_cache.insert(name.to_string(), snap_id.clone());
        }

        for (id, snap) in &meta.snapshots {
            let source_idx = *node_indices.get(id).context("Source node not found in pnpm engine")?;
            for dep_name in &snap.dependencies {
                if let Some(target_id) = dep_cache.get(dep_name) {
                    let target_idx = *node_indices.get(target_id).unwrap();
                    graph.add_edge(source_idx, target_idx);
                }
            }
        }
        Ok(Self { graph, execution_packages, suspicious_packages })
    }

    fn build_from_bun() -> Result<Self> {
        let output = Command::new("bun").env("TERM", "dumb").args(&["pm", "ls", "--all", "--json"]).output()?;
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        Self::parse_bun_output(&stdout_str)
    }

    fn parse_bun_output(stdout: &str) -> Result<Self> {
        if let Some(json_start) = stdout.find('{') {
            if let Ok(root) = MiniParser::parse_json(&stdout[json_start..]) {
                let mut graph = DiGraph::new();
                let mut node_indices = HashMap::new();
                let mut execution_packages = HashSet::new();
                let mut suspicious_packages = HashSet::new();
                Self::parse_bun_json_dependencies(&root, &mut graph, &mut node_indices, None, &mut execution_packages, &mut suspicious_packages);
                return Ok(Self { graph, execution_packages, suspicious_packages });
            }
        }
        Self::build_from_bun_tree_with_recovery(stdout)
    }

    fn build_from_bun_tree_with_recovery(tree_output: &str) -> Result<Self> {
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        let mut execution_packages = HashSet::new();
        let mut suspicious_packages = HashSet::new();
        let mut stack: Vec<(usize, usize)> = Vec::new();
        for line in tree_output.lines() {
            if line.trim().is_empty() || line.starts_with('/') { continue; }
            let depth = if let Some(pos) = line.chars().position(|c| c == '─') { pos / 4 } else { 0 };
            let package_info = line.replace('├', "").replace('└', "").replace('│', "").replace('─', "").trim().to_string();
            if package_info.is_empty() { continue; }
            let current_idx = *node_indices.entry(package_info.clone()).or_insert_with(|| graph.add_node(package_info.clone()));
            if MiniParser::detect_obfuscation(&package_info) { suspicious_packages.insert(package_info.clone()); }

            let package_name = if let Some(idx) = package_info.rfind('@') { if idx > 0 { &package_info[0..idx] } else { &package_info } } else { &package_info };
            if let Some(pkg_json_path) = find_package_json(package_name) {
                if let Ok(content) = fs::read_to_string(pkg_json_path) {
                    if let Ok(pkg_json) = MiniParser::parse_json(&content) {
                        let has_scripts = pkg_json.get("scripts").and_then(|s| s.as_object()).map(|s| { s.contains_key("postinstall") || s.contains_key("prepare") || s.contains_key("install") }).unwrap_or(false);
                        if has_scripts || pkg_json.get("hasInstallScript").and_then(|v| v.as_bool()).unwrap_or(false) { execution_packages.insert(package_info.clone()); }
                        if MiniParser::detect_obfuscation(&content) { suspicious_packages.insert(package_info.clone()); }
                    }
                }
            }
            while let Some((d, _)) = stack.last() { if *d >= depth { stack.pop(); } else { break; } }
            if let Some((_, parent_idx)) = stack.last() { graph.add_edge(*parent_idx, current_idx); }
            stack.push((depth, current_idx));
        }
        Ok(Self { graph, execution_packages, suspicious_packages })
    }

    fn build_from_yarn() -> Result<Self> {
        let output = Command::new("yarn").args(&["npm", "ls", "--all", "--json"]).output().context("Failed to execute 'yarn npm ls'.")?;
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        Self::parse_yarn_output(&stdout_str)
    }

    fn parse_yarn_output(stdout: &str) -> Result<Self> {
        let root = MiniParser::parse_json(stdout)?;
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        let mut execution_packages = HashSet::new();
        let mut suspicious_packages = HashSet::new();
        Self::parse_yarn_json_recursive(&root, &mut graph, &mut node_indices, None, &mut execution_packages, &mut suspicious_packages);
        Ok(Self { graph, execution_packages, suspicious_packages })
    }

    fn parse_yarn_json_recursive(val: &JsonNode, graph: &mut DiGraph, node_indices: &mut HashMap<String, usize>, parent_idx: Option<usize>, execution_packages: &mut HashSet<String>, suspicious_packages: &mut HashSet<String>) {
        if let Some(id) = val.get("value").and_then(|v| v.as_str()) {
            let current_idx = *node_indices.entry(id.to_string()).or_insert_with(|| graph.add_node(id.to_string()));
            if let Some(p_idx) = parent_idx { graph.add_edge(p_idx, current_idx); }
            if MiniParser::detect_obfuscation(id) { suspicious_packages.insert(id.to_string()); }

            let package_name = if let Some(idx) = id.rfind('@') { if idx > 0 { &id[0..idx] } else { id } } else { id };
            if let Some(pkg_json_path) = find_package_json(package_name) {
                if let Ok(content) = fs::read_to_string(pkg_json_path) {
                    if let Ok(pkg_json) = MiniParser::parse_json(&content) {
                        let has_scripts = pkg_json.get("scripts").and_then(|s| s.as_object()).map(|s| { s.contains_key("postinstall") || s.contains_key("prepare") || s.contains_key("install") }).unwrap_or(false);
                        if has_scripts || pkg_json.get("hasInstallScript").and_then(|v| v.as_bool()).unwrap_or(false) { execution_packages.insert(id.to_string()); }
                        if MiniParser::detect_obfuscation(id) { suspicious_packages.insert(id.to_string()); }
                    }
                }
            }
            if let Some(children) = val.get("children").and_then(|c| c.as_object()) {
                for (_, child) in children { Self::parse_yarn_json_recursive(child, graph, node_indices, Some(current_idx), execution_packages, suspicious_packages); }
            }
        }
    }

    fn build_from_cargo() -> Result<Self> {
        let output = Command::new("cargo").args(&["metadata", "--format-version", "1"]).output().context("Failed to execute cargo metadata.")?;
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        Self::parse_cargo_metadata(&stdout_str)
    }

    fn parse_cargo_metadata(stdout: &str) -> Result<Self> {
        let root = MiniParser::parse_json(stdout).context("Failed to parse Cargo metadata.")?;
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        let mut execution_packages = HashSet::new();
        let mut suspicious_packages = HashSet::new();

        if let Some(packages) = root.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let Some(id) = pkg.get("id").and_then(|v| v.as_str()) {
                    let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                    let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                    let full_name = format!("{}@{}", name, version);
                    node_indices.insert(id.to_string(), graph.add_node(full_name.clone()));
                    if MiniParser::detect_obfuscation(&full_name) { suspicious_packages.insert(full_name.clone()); }

                    let mut has_build_script = false;
                    if let Some(targets) = pkg.get("targets").and_then(|t| t.as_array()) {
                        for target in targets {
                            if let Some(kind) = target.get("kind").and_then(|k| k.as_array()) {
                                if kind.iter().any(|k| k.as_str() == Some("custom-build")) { has_build_script = true; }
                            }
                        }
                    }
                    if has_build_script { execution_packages.insert(full_name); }
                }
            }
        }
        if let Some(nodes) = root.get("resolve").and_then(|r| r.get("nodes")).and_then(|n| n.as_array()) {
            for node in nodes {
                if let Some(id) = node.get("id").and_then(|v| v.as_str()) {
                    if let Some(&source_idx) = node_indices.get(id) {
                        if let Some(deps) = node.get("dependencies").and_then(|d| d.as_array()) {
                            for dep_id in deps {
                                if let Some(dep_id_str) = dep_id.as_str() {
                                    if let Some(&target_idx) = node_indices.get(dep_id_str) { graph.add_edge(source_idx, target_idx); }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Self { graph, execution_packages, suspicious_packages })
    }

    fn parse_bun_json_dependencies(val: &JsonNode, graph: &mut DiGraph, node_indices: &mut HashMap<String, usize>, parent_idx: Option<usize>, execution_packages: &mut HashSet<String>, suspicious_packages: &mut HashSet<String>) {
        if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
            let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            let full_name = format!("{}({})", name, version);
            let current_idx = *node_indices.entry(full_name.clone()).or_insert_with(|| graph.add_node(full_name.clone()));
            if let Some(p_idx) = parent_idx { graph.add_edge(p_idx, current_idx); }
            if MiniParser::detect_obfuscation(&full_name) { suspicious_packages.insert(full_name.clone()); }

            if let Some(scripts) = val.get("scripts").and_then(|s| s.as_object()) {
                if scripts.contains_key("postinstall") || scripts.contains_key("prepare") { execution_packages.insert(full_name.clone()); }
            }
            if let Some(dependencies) = val.get("dependencies").and_then(|d| d.as_array()) {
                for dep in dependencies { Self::parse_bun_json_dependencies(dep, graph, node_indices, Some(current_idx), execution_packages, suspicious_packages); }
            }
        }
    }
}

fn find_package_json(package_name: &str) -> Option<PathBuf> {
    let mut current_dir = std::env::current_dir().ok()?;
    let standard_path = Path::new("node_modules").join(package_name).join("package.json");
    if standard_path.exists() { return Some(standard_path); }
    for _ in 0..5 {
        let alt_path = current_dir.join("node_modules").join(package_name).join("package.json");
        if alt_path.exists() { return Some(alt_path); }
        if let Some(parent) = current_dir.parent() { current_dir = parent.to_path_buf(); } else { break; }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_extraction() {
        let content = r#"{
            "packages": {
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
        let content = r#"
packages:
  /a@1.0.0:
    hasInstallScript: true
snapshots:
  /a@1.0.0:
    dependencies:
      b: 1.0.0
  /b@1.0.0: {}
"#;
        let dg = DepGraph::parse_pnpm_lockfile(content).unwrap();
        assert_eq!(dg.graph.node_count(), 2);
        assert!(dg.execution_packages.contains("/a@1.0.0"));
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

    #[test]
    fn test_bun_json_extraction() {
        let content = r#"{"name": "test", "version": "1.0.0", "scripts": {"postinstall": "echo"}, "dependencies": []}"#;
        let dg = DepGraph::parse_bun_output(content).unwrap();
        assert_eq!(dg.graph.node_count(), 1);
        assert!(dg.execution_packages.contains("test(1.0.0)"));
    }

    #[test]
    fn test_yarn_json_extraction() {
        let content = r#"{"value": "root@1.0.0", "children": {"a@1.0.0": {"value": "a@1.0.0", "children": {}}}}"#;
        let dg = DepGraph::parse_yarn_output(content).unwrap();
        assert_eq!(dg.graph.node_count(), 2);
    }
}
