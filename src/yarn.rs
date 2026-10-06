//! Read-only Yarn Classic v1 descriptor snapshots. This is not an installed tree.
use crate::error::{GateError, Result};
use crate::graph::{DepGraph, PackageInfo};
use crate::graph_impl::DiGraph;
use crate::parser::{json_string, JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Record {
    selectors: BTreeSet<String>,
    fields: BTreeMap<String, String>,
    dependencies: BTreeMap<String, String>,
    optional_dependencies: BTreeMap<String, String>,
    sections: BTreeSet<String>,
}

fn incomplete(message: impl Into<String>) -> GateError {
    GateError::Graph(format!("INCOMPLETE: Yarn Classic: {}", message.into()))
}

/// Parse an exact descriptor graph without resolving, installing, or reading packages.
pub fn parse(lock: &str, manifest: Option<&JsonNode>) -> Result<DepGraph> {
    MiniParser::parse_yarn_classic(lock, manifest)
}

impl MiniParser {
    /// Extraction for Yarn's generated v1 lock syntax, deliberately bounded to known fields.
    pub fn parse_yarn_classic(lock: &str, manifest: Option<&JsonNode>) -> Result<DepGraph> {
        if lock.len() > 64 * 1024 * 1024 {
            return Err(incomplete("lockfile exceeds 64 MiB"));
        }
        let records = read_records(lock)?;
        let mut graph = DiGraph::new();
        let root = graph.add_node("root".into());
        let mut packages = BTreeMap::new();
        let mut selectors = BTreeMap::<String, usize>::new();
        let mut indices = BTreeMap::new();
        let mut issues = vec!["Execution capabilities unknown: Yarn Classic lockfiles do not encode dependency lifecycle scripts or binaries; an empty execution inventory is not proof of absence".into()];
        let mut optional_omissions = Vec::new();
        let mut edge_kinds = BTreeMap::<(usize, usize), BTreeSet<String>>::new();

        for (label, record) in &records {
            let idx = graph.add_node(label.clone());
            indices.insert(label.clone(), idx);
            let mut actual_names = BTreeSet::new();
            for selector in &record.selectors {
                let (name, range) = descriptor(selector)?;
                actual_names.insert(actual_name(name, range)?);
                if selectors.insert(selector.clone(), idx).is_some() {
                    return Err(incomplete(format!("duplicate selector {selector}")));
                }
            }
            if actual_names.len() != 1 {
                return Err(incomplete(format!(
                    "grouped selectors have different package names: {label}"
                )));
            }
            let name = actual_names
                .into_iter()
                .next()
                .ok_or_else(|| incomplete("empty selector record"))?;
            let version = record
                .fields
                .get("version")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| incomplete(format!("missing version for {label}")))?
                .clone();
            packages.insert(
                label.clone(),
                PackageInfo {
                    path: label.clone(),
                    name,
                    version,
                    source: record.fields.get("resolved").cloned().unwrap_or_default(),
                    integrity: record.fields.get("integrity").cloned().unwrap_or_default(),
                    capabilities: vec![
                        "unknown (lockfile does not encode lifecycle scripts or binaries)".into(),
                    ],
                },
            );
        }

        for (label, record) in &records {
            let from = indices[label];
            for (kind, deps) in [
                ("dependencies", &record.dependencies),
                ("optionalDependencies", &record.optional_dependencies),
            ] {
                for (name, range) in deps {
                    // Yarn optional dependencies override dependencies of the same name.
                    if kind == "dependencies" && record.optional_dependencies.contains_key(name) {
                        continue;
                    }
                    add_reference(
                        from,
                        label,
                        name,
                        range,
                        kind,
                        &selectors,
                        &mut edge_kinds,
                        &mut issues,
                        &mut optional_omissions,
                    )?;
                }
            }
        }

        if let Some(manifest) = manifest {
            let object = manifest
                .as_object()
                .ok_or_else(|| incomplete("root manifest must be an object"))?;
            for key in ["name", "version"] {
                if object.get(key).is_some_and(|x| x.as_str().is_none()) {
                    return Err(incomplete(format!("invalid root manifest {key}")));
                }
            }
            packages.insert(
                "root".into(),
                PackageInfo {
                    path: String::new(),
                    name: manifest
                        .get("name")
                        .and_then(JsonNode::as_str)
                        .unwrap_or("root")
                        .into(),
                    version: manifest
                        .get("version")
                        .and_then(JsonNode::as_str)
                        .unwrap_or("")
                        .into(),
                    source: String::new(),
                    integrity: String::new(),
                    capabilities: Vec::new(),
                },
            );
            for kind in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(value) = manifest.get(kind) {
                    let deps = value
                        .as_object()
                        .ok_or_else(|| incomplete(format!("invalid root {kind}")))?;
                    for (name, range) in deps {
                        if kind == "dependencies"
                            && manifest
                                .get("optionalDependencies")
                                .and_then(JsonNode::as_object)
                                .is_some_and(|m| m.contains_key(name))
                        {
                            continue;
                        }
                        let range = range.as_str().ok_or_else(|| {
                            incomplete(format!("invalid root requirement for {name}"))
                        })?;
                        add_reference(
                            root,
                            "root",
                            name,
                            range,
                            kind,
                            &selectors,
                            &mut edge_kinds,
                            &mut issues,
                            &mut optional_omissions,
                        )?;
                    }
                }
            }
            if let Some(peers) = manifest.get("peerDependencies") {
                let peers = peers
                    .as_object()
                    .ok_or_else(|| incomplete("invalid root peerDependencies"))?;
                if !peers.is_empty() {
                    issues.push("Unresolved peer placement: Yarn Classic does not auto-install peers and its lockfile does not encode their installed placement".into());
                }
            }
            if let Some(workspaces) = manifest.get("workspaces") {
                if !matches!(workspaces, JsonNode::Array(a) if a.is_empty()) {
                    issues.push("Root attribution incomplete: Yarn Classic workspace manifests are not supplied; their root edges cannot be attributed".into());
                }
            }
        } else {
            issues.push("Root attribution incomplete: Yarn Classic lockfiles do not identify root requirements without the root manifest".into());
            packages.insert(
                "root".into(),
                PackageInfo {
                    path: String::new(),
                    name: "root".into(),
                    version: String::new(),
                    source: String::new(),
                    integrity: String::new(),
                    capabilities: Vec::new(),
                },
            );
        }
        for &(from, to) in edge_kinds.keys() {
            graph.add_edge(from, to);
        }
        Ok(DepGraph {
            graph,
            execution_packages: BTreeSet::new(),
            suspicious_packages: BTreeSet::new(),
            packages,
            issues,
            optional_omissions,
            edge_kinds,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn add_reference(
    from: usize,
    label: &str,
    name: &str,
    range: &str,
    kind: &str,
    selectors: &BTreeMap<String, usize>,
    edges: &mut BTreeMap<(usize, usize), BTreeSet<String>>,
    issues: &mut Vec<String>,
    omissions: &mut Vec<String>,
) -> Result<()> {
    let selector = format!("{name}@{range}");
    descriptor(&selector)?;
    if let Some(&to) = selectors.get(&selector) {
        edges.entry((from, to)).or_default().insert(kind.into());
    } else {
        let missing = format!("unresolved {kind}: {label} -> {selector}");
        if kind == "optionalDependencies" {
            omissions.push(missing);
        } else {
            issues.push(missing);
        }
    }
    Ok(())
}

fn descriptor(selector: &str) -> Result<(&str, &str)> {
    let offset = usize::from(selector.starts_with('@'));
    let split = selector
        .get(offset..)
        .and_then(|s| s.find('@'))
        .map(|i| i + offset)
        .ok_or_else(|| incomplete(format!("invalid descriptor {selector}")))?;
    let (name, suffix) = selector.split_at(split);
    let range = &suffix[1..];
    if name.is_empty()
        || range.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, ':' | ',' | '"' | '\\'))
        || (name.starts_with('@') && name.split('/').count() != 2)
        || (!name.starts_with('@') && name.contains('/'))
    {
        return Err(incomplete(format!("invalid descriptor {selector}")));
    }
    Ok((name, range))
}

fn actual_name(name: &str, range: &str) -> Result<String> {
    if let Some(alias) = range.strip_prefix("npm:") {
        let (actual, _) = descriptor(alias)?;
        Ok(actual.into())
    } else {
        Ok(name.into())
    }
}

fn read_records(lock: &str) -> Result<BTreeMap<String, Record>> {
    let mut has_header = false;
    let mut records = BTreeMap::<String, Record>::new();
    let mut current = None::<String>;
    let mut section = None::<String>;
    for (line_no, original) in lock.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = original.trim_end_matches('\r');
        if line.contains('\t') {
            return Err(incomplete(format!(
                "tabs are unsupported at line {}",
                line_no + 1
            )));
        }
        let comment = line.trim();
        if comment.starts_with("# yarn lockfile v") {
            if comment != "# yarn lockfile v1" || has_header {
                return Err(incomplete(
                    "only one Yarn Classic lockfile v1 header is supported",
                ));
            }
            has_header = true;
            continue;
        }
        if comment.is_empty() || comment.starts_with('#') {
            continue;
        }
        if comment.starts_with("__metadata:") {
            return Err(incomplete(
                "Berry lockfiles are unsupported; provide Yarn Classic v1",
            ));
        }
        if ["<<<<<<<", "=======", ">>>>>>>", "|||||||"]
            .iter()
            .any(|p| comment.starts_with(p))
        {
            return Err(incomplete("merge-conflicted lockfile"));
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        let value = line.trim_start_matches(' ');
        match indent {
            0 => {
                if !has_header {
                    return Err(incomplete("missing Yarn Classic v1 header"));
                }
                let selectors = read_selectors(value)?;
                let label = format!(
                    "yarn:[{}]",
                    selectors
                        .iter()
                        .map(|s| json_string(s))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                if records
                    .insert(
                        label.clone(),
                        Record {
                            selectors,
                            ..Record::default()
                        },
                    )
                    .is_some()
                {
                    return Err(incomplete("duplicate resolution record"));
                }
                current = Some(label);
                section = None;
            }
            2 => {
                let key = current
                    .as_ref()
                    .ok_or_else(|| incomplete("field before record"))?;
                let record = records
                    .get_mut(key)
                    .ok_or_else(|| incomplete("missing current record"))?;
                if value == "dependencies:" || value == "optionalDependencies:" {
                    let name = value.trim_end_matches(':').to_string();
                    if !record.sections.insert(name.clone()) {
                        return Err(incomplete("duplicate dependency section"));
                    }
                    section = Some(name);
                } else {
                    let (name, value) = read_pair(value)?;
                    if !matches!(name.as_str(), "version" | "resolved" | "integrity") {
                        return Err(incomplete(format!("unsupported record field {name}")));
                    }
                    if record.fields.insert(name, value).is_some() {
                        return Err(incomplete("duplicate record field"));
                    }
                    section = None;
                }
            }
            4 => {
                let key = current
                    .as_ref()
                    .ok_or_else(|| incomplete("dependency before record"))?;
                let record = records
                    .get_mut(key)
                    .ok_or_else(|| incomplete("missing dependency record"))?;
                let (name, range) = read_pair(value)?;
                let deps = match section.as_deref() {
                    Some("dependencies") => &mut record.dependencies,
                    Some("optionalDependencies") => &mut record.optional_dependencies,
                    _ => return Err(incomplete("dependency outside known section")),
                };
                if deps.insert(name, range).is_some() {
                    return Err(incomplete("duplicate dependency name"));
                }
            }
            _ => {
                return Err(incomplete(format!(
                    "unsupported indentation at line {}",
                    line_no + 1
                )))
            }
        }
    }
    if !has_header {
        return Err(incomplete("missing Yarn Classic v1 header"));
    }
    Ok(records)
}

fn read_selectors(line: &str) -> Result<BTreeSet<String>> {
    let mut rest = line;
    let mut selectors = BTreeSet::new();
    loop {
        let (token, after) = read_atom(rest, true)?;
        descriptor(&token)?;
        if !selectors.insert(token) {
            return Err(incomplete("duplicate grouped selector"));
        }
        rest = after.trim_start_matches(' ');
        if let Some(after) = rest.strip_prefix(',') {
            rest = after.trim_start_matches(' ');
        } else if let Some(after) = rest.strip_prefix(':') {
            if !trailing_comment(after) {
                return Err(incomplete("trailing content after resolution header"));
            }
            return Ok(selectors);
        } else {
            return Err(incomplete("resolution header requires colon"));
        }
    }
}

fn read_pair(line: &str) -> Result<(String, String)> {
    let (key, rest) = read_atom(line, false)?;
    if !rest.starts_with(' ') {
        return Err(incomplete("field requires space before scalar value"));
    }
    let (value, rest) = read_atom(rest.trim_start_matches(' '), false)?;
    if !trailing_comment(rest) {
        return Err(incomplete("trailing content after scalar value"));
    }
    Ok((key, value))
}

fn trailing_comment(rest: &str) -> bool {
    rest.trim_matches(' ').is_empty()
        || (rest.starts_with(' ') && rest.trim_start_matches(' ').starts_with('#'))
}

fn read_atom(input: &str, selector: bool) -> Result<(String, &str)> {
    if input.starts_with('"') {
        let mut escaped = false;
        let mut end = None;
        for (idx, c) in input.char_indices().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
            } else if c == '"' {
                end = Some(idx + 1);
                break;
            }
        }
        let end = end.ok_or_else(|| incomplete("unterminated quoted string"))?;
        let node = MiniParser::parse_json(&input[..end])?;
        let value = node
            .as_str()
            .ok_or_else(|| incomplete("invalid quoted string"))?
            .to_owned();
        Ok((value, &input[end..]))
    } else {
        let end = input
            .find(|c: char| c.is_whitespace() || (selector && matches!(c, ',' | ':')))
            .unwrap_or(input.len());
        let value = &input[..end];
        if value.is_empty()
            || value
                .chars()
                .any(|c| matches!(c, '"' | '\'' | '\\' | '[' | ']' | '{' | '}'))
        {
            return Err(incomplete("unsupported scalar syntax"));
        }
        Ok((value.into(), &input[end..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(s: &str) -> JsonNode {
        MiniParser::parse_json(s).unwrap()
    }
    fn fixture(body: &str) -> String {
        format!("# yarn lockfile v1\n{body}")
    }
    fn label(selector: &str) -> String {
        format!("yarn:[{}]", json_string(selector))
    }
    fn edge_names(g: &DepGraph) -> BTreeSet<(String, String)> {
        g.graph
            .edges()
            .iter()
            .map(|(a, b)| {
                (
                    g.graph.node_weight(*a).unwrap().clone(),
                    g.graph.node_weight(*b).unwrap().clone(),
                )
            })
            .collect()
    }

    #[test]
    fn grouped_scoped_selectors_and_nested_versions_are_exact() {
        let lock = fixture("parent@1:\n  version \"1.0.0\"\n  dependencies:\n    leaf \"^1\"\n    \"@scope/thing\" \"~1\"\nleaf@^1, leaf@~1:\n  version \"1.2.0\"\nleaf@^2:\n  version \"2.0.0\"\n\"@scope/thing@~1\":\n  version \"1.0.0\"\n  dependencies:\n    leaf \"^2\"\n");
        let root = manifest(r#"{"dependencies":{"parent":"1","leaf":"~1"}}"#);
        let g = parse(&lock, Some(&root)).unwrap();
        assert_eq!(g.graph.node_count(), 5);
        let group = "yarn:[\"leaf@^1\",\"leaf@~1\"]".to_string();
        assert_eq!(
            edge_names(&g),
            BTreeSet::from([
                ("root".into(), label("parent@1")),
                ("root".into(), group.clone()),
                (label("parent@1"), group),
                (label("parent@1"), label("@scope/thing@~1")),
                (label("@scope/thing@~1"), label("leaf@^2"))
            ])
        );
        assert_eq!(g.issues.len(), 1);
    }
    #[test]
    fn same_name_version_different_resolutions_do_not_collapse() {
        let lock = fixture("a@^1:\n  version \"1.0.0\"\n  resolved \"https://one/a.tgz\"\na@~1:\n  version \"1.0.0\"\n  resolved \"https://two/a.tgz\"\n");
        let g = parse(
            &lock,
            Some(&manifest(
                r#"{"dependencies":{"a":"^1"},"devDependencies":{"a":"~1"}}"#,
            )),
        )
        .unwrap();
        assert_eq!(g.graph.node_count(), 3);
        assert_eq!(g.graph.edges().len(), 2);
        assert_ne!(
            g.packages[&label("a@^1")].source,
            g.packages[&label("a@~1")].source
        );
    }
    #[test]
    fn optional_absence_is_explicit_and_required_absence_is_incomplete() {
        let lock = fixture("a@1:\n  version \"1\"\n  dependencies:\n    required \"1\"\n  optionalDependencies:\n    absent \"1\"\n");
        let g = parse(&lock, Some(&manifest(r#"{"dependencies":{"a":"1"}}"#))).unwrap();
        assert!(g.issues.iter().any(|s| s.contains("required@1")));
        assert_eq!(g.optional_omissions.len(), 1);
        assert!(g.optional_omissions[0].contains("absent@1"));
    }
    #[test]
    fn aliases_preserve_descriptor_and_actual_package_identity() {
        let lock = fixture(
            "\"alias@npm:@scope/real@^1\":\n  version \"1.3.0\"\n  integrity sha512-example\n",
        );
        let g = parse(
            &lock,
            Some(&manifest(
                r#"{"dependencies":{"alias":"npm:@scope/real@^1"}}"#,
            )),
        )
        .unwrap();
        assert_eq!(
            g.packages[&label("alias@npm:@scope/real@^1")].name,
            "@scope/real"
        );
        assert_eq!(g.graph.edges().len(), 1);
    }
    #[test]
    fn berry_conflicts_duplicates_and_unknown_structures_are_rejected() {
        for lock in [
            "__metadata:\n  version: 8\n",
            "# yarn lockfile v2\na@1:\n  version \"1\"",
            "# yarn lockfile v1\n<<<<<<< HEAD",
            "# yarn lockfile v1\na@1:\n  version \"1\"\na@1:\n  version \"2\"",
            "# yarn lockfile v1\na@1:\n  version \"1\"\n  checksum hash",
            "# yarn lockfile v1\na@1:\n   version \"1\"",
        ] {
            assert!(parse(lock, None).is_err(), "{lock}");
        }
    }
    #[test]
    fn missing_manifest_and_unknown_scripts_do_not_mean_no_execution() {
        let g = parse(&fixture("a@1:\n  version \"1\"\n"), None).unwrap();
        assert!(g.execution_packages.is_empty());
        assert!(g
            .issues
            .iter()
            .any(|s| s.starts_with("Execution capabilities unknown:")));
        assert!(g
            .issues
            .iter()
            .any(|s| s.starts_with("Root attribution incomplete:")));
        assert!(g.packages[&label("a@1")].capabilities[0].starts_with("unknown"));
    }
    #[test]
    fn comments_and_escaped_strings_preserve_artifact_metadata() {
        let lock = fixture("\"a@^1\": # grouped record\n  version \"1.0.0\" # version\n  resolved \"https://registry/a.tgz#hash\"\n  integrity \"sha512-a sha1-b\"\n");
        let g = parse(&lock, Some(&manifest("{}"))).unwrap();
        assert_eq!(
            g.packages[&label("a@^1")].source,
            "https://registry/a.tgz#hash"
        );
        assert_eq!(g.packages[&label("a@^1")].integrity, "sha512-a sha1-b");
    }
}
