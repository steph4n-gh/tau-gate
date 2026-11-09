//! Read-only Yarn Classic v1 descriptor snapshots. This is not an installed tree.
use crate::error::{GateError, Result};
use crate::graph::{DepGraph, PackageInfo, ProjectInputs};
use crate::graph_impl::DiGraph;
use crate::parser::{json_string, JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};

#[path = "yarn_berry.rs"]
pub mod berry;

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
    parse_with_inputs(lock, manifest, &ProjectInputs::new())
}

/// Parse with explicitly supplied project-relative source manifests.
pub fn parse_with_inputs(
    lock: &str,
    manifest: Option<&JsonNode>,
    inputs: &ProjectInputs,
) -> Result<DepGraph> {
    parse_classic(lock, manifest, inputs)
}

impl MiniParser {
    /// Extraction for Yarn's generated v1 lock syntax, deliberately bounded to known fields.
    pub fn parse_yarn_classic(lock: &str, manifest: Option<&JsonNode>) -> Result<DepGraph> {
        parse_with_inputs(lock, manifest, &ProjectInputs::new())
    }
}

fn parse_classic(
    lock: &str,
    manifest: Option<&JsonNode>,
    inputs: &ProjectInputs,
) -> Result<DepGraph> {
    let source_root = inputs
        .get("package.json")
        .map(|b| source_manifest(b, "package.json"))
        .transpose()?;
    if manifest
        .zip(source_root.as_ref())
        .is_some_and(|(m, s)| m != s)
    {
        return Err(incomplete(
            "root manifest differs from supplied package.json",
        ));
    }
    let manifest = manifest.or(source_root.as_ref());
    if lock.len() > 64 * 1024 * 1024 {
        return Err(incomplete("lockfile exceeds 64 MiB"));
    }
    let records = read_records(lock)?;
    let mut graph = DiGraph::new();
    let root = graph.add_node("root".into());
    let mut packages = BTreeMap::new();
    let mut resolution_metadata = BTreeMap::new();
    let mut selectors = BTreeMap::<String, usize>::new();
    let mut indices = BTreeMap::new();
    let mut issues = vec!["Execution capabilities unknown: Yarn Classic lockfiles do not encode dependency lifecycle scripts or binaries; an empty execution inventory is not proof of absence".into()];
    let mut optional_omissions = Vec::new();
    let mut edge_kinds = BTreeMap::<(usize, usize), BTreeSet<String>>::new();

    if records.len() > 10_000 {
        return Err(incomplete("more than 10000 resolution records"));
    }
    if records
        .values()
        .map(|r| r.dependencies.len() + r.optional_dependencies.len())
        .sum::<usize>()
        > 50_000
    {
        return Err(incomplete("more than 50000 dependency references"));
    }
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
        let local = record
            .selectors
            .iter()
            .filter_map(|s| descriptor(s).ok().map(|(_, r)| r))
            .filter(|r| r.starts_with("link:"))
            .collect::<BTreeSet<_>>();
        if local.len() > 1 {
            return Err(incomplete("conflicting local link sources"));
        }
        if let (Some(local), Some(resolved)) = (local.first(), record.fields.get("resolved")) {
            if *local != resolved {
                return Err(incomplete("local link conflicts with resolved source"));
            }
        }
        let source = record
            .fields
            .get("resolved")
            .cloned()
            .or_else(|| local.first().map(|r| r.to_string()))
            .unwrap_or_default();
        let mut retained = record
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), JsonNode::String(v.clone())))
            .collect::<BTreeMap<_, _>>();
        retained.insert(
            "descriptors".into(),
            JsonNode::Array(
                record
                    .selectors
                    .iter()
                    .map(|s| JsonNode::String(s.clone()))
                    .collect(),
            ),
        );
        resolution_metadata.insert(label.clone(), JsonNode::Object(retained));
        packages.insert(
            label.clone(),
            PackageInfo {
                path: label.clone(),
                name,
                version,
                source,
                integrity: record.fields.get("integrity").cloned().unwrap_or_default(),
                capabilities: vec![
                    "unknown (lockfile does not encode lifecycle scripts or binaries)".into(),
                ],
            },
        );
    }

    let mut workspaces = BTreeMap::new();
    let mut source_records = Vec::new();
    let mut source_bytes = 0;
    if let Some(manifest) = manifest {
        for (path, source) in workspace_manifests(manifest, inputs)? {
            let name = source
                .get("name")
                .and_then(JsonNode::as_str)
                .ok_or_else(|| incomplete(format!("workspace name missing at {path}")))?
                .to_string();
            let version = source
                .get("version")
                .and_then(JsonNode::as_str)
                .unwrap_or("")
                .to_string();
            let label = format!("yarn:workspace:{path}");
            let idx = graph.add_node(label.clone());
            if workspaces
                .insert(name.clone(), (idx, version.clone()))
                .is_some()
            {
                return Err(incomplete(format!("duplicate workspace name {name}")));
            }
            packages.insert(
                label.clone(),
                PackageInfo {
                    path: label.clone(),
                    name,
                    version,
                    source: format!("workspace:{path}"),
                    integrity: String::new(),
                    capabilities: Vec::new(),
                },
            );
            let mut source_metadata = source.as_object().cloned().unwrap_or_default();
            source_metadata.insert("sourcePath".into(), JsonNode::String(path.clone()));
            resolution_metadata.insert(label.clone(), JsonNode::Object(source_metadata));
            source_records.push((idx, label, path, source, true));
        }
    }
    for (label, record) in &records {
        let from = indices[label];
        if let Some(path) = packages[label].source.strip_prefix("link:") {
            let path = project_path(path)?;
            let key = manifest_path(&path);
            if let Some(bytes) = inputs.get(&key) {
                source_bytes += bytes.len();
                if source_bytes > 64 * 1024 * 1024 {
                    return Err(incomplete("local source manifests exceed 64 MiB"));
                }
                let source = source_manifest(bytes, &key)?;
                if let Some(JsonNode::Object(metadata)) = resolution_metadata.get_mut(label) {
                    metadata.insert("sourceManifest".into(), source.clone());
                    metadata.insert("sourcePath".into(), JsonNode::String(path.clone()));
                }
                source_records.push((from, label.clone(), path, source, false));
            } else {
                issues.push(format!(
                    "Source attribution incomplete: local link manifest not supplied: {key}"
                ));
            }
        }
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
                    &workspaces,
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
                        &workspaces,
                        &mut edge_kinds,
                        &mut issues,
                        &mut optional_omissions,
                    )?;
                }
            }
        }
        resolution_metadata.insert("root".into(), manifest.clone());
        retain_peers("root", manifest, &mut resolution_metadata)?;
        if let Some(value) = manifest.get("workspaces") {
            let patterns = value
                .get("packages")
                .unwrap_or(value)
                .as_array()
                .ok_or_else(|| incomplete("invalid workspace patterns"))?;
            for (index, pattern) in patterns.iter().enumerate() {
                let pattern = pattern
                    .as_str()
                    .ok_or_else(|| incomplete("invalid workspace pattern"))?;
                if pattern.starts_with('!') || pattern.contains(['*', '?']) {
                    continue;
                }
                let path = project_path(pattern.trim_end_matches('/'))?;
                let excluded = patterns[index + 1..]
                    .iter()
                    .filter_map(JsonNode::as_str)
                    .filter_map(|p| p.strip_prefix('!'))
                    .any(|p| glob(p.trim_end_matches('/'), &path));
                if !excluded && !packages.contains_key(&format!("yarn:workspace:{path}")) {
                    issues.push(format!("Root attribution incomplete: Yarn Classic declared workspace manifest not supplied: {path}/package.json"));
                }
            }
        }
        if manifest.get("workspaces").is_some() && workspaces.is_empty() {
            issues.push("Root attribution incomplete: Yarn Classic workspace manifests are not supplied; their edges cannot be attributed".into());
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
    if graph.node_count() > 10_001 {
        return Err(incomplete(
            "more than 10000 package records including workspaces",
        ));
    }
    let mut source_references = manifest
        .map(manifest_reference_count)
        .transpose()?
        .unwrap_or(0);
    let locked_references = records
        .values()
        .map(|r| r.dependencies.len() + r.optional_dependencies.len())
        .sum::<usize>();
    if source_references + locked_references > 50_000 {
        return Err(incomplete(
            "more than 50000 dependency references including source manifests",
        ));
    }
    for (from, label, _path, source, workspace) in source_records {
        source_references += manifest_reference_count(&source)?;
        if source_references + locked_references > 50_000 {
            return Err(incomplete(
                "more than 50000 dependency references including source manifests",
            ));
        }
        retain_peers(&label, &source, &mut resolution_metadata)?;
        for kind in ["dependencies", "devDependencies", "optionalDependencies"] {
            if kind == "devDependencies" && !workspace {
                continue;
            }
            if let Some(value) = source.get(kind) {
                let deps = value
                    .as_object()
                    .ok_or_else(|| incomplete(format!("invalid {kind} in {label}")))?;
                for (name, range) in deps {
                    if kind == "dependencies"
                        && source
                            .get("optionalDependencies")
                            .and_then(JsonNode::as_object)
                            .is_some_and(|m| m.contains_key(name))
                    {
                        continue;
                    }
                    let range = range
                        .as_str()
                        .ok_or_else(|| incomplete("invalid source requirement"))?;
                    add_reference(
                        from,
                        &label,
                        name,
                        range,
                        kind,
                        &selectors,
                        &workspaces,
                        &mut edge_kinds,
                        &mut issues,
                        &mut optional_omissions,
                    )?;
                }
            }
        }
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
        resolution_metadata,
    })
}

#[allow(clippy::too_many_arguments)]
fn add_reference(
    from: usize,
    label: &str,
    name: &str,
    range: &str,
    kind: &str,
    selectors: &BTreeMap<String, usize>,
    workspaces: &BTreeMap<String, (usize, String)>,
    edges: &mut BTreeMap<(usize, usize), BTreeSet<String>>,
    issues: &mut Vec<String>,
    omissions: &mut Vec<String>,
) -> Result<()> {
    let selector = format!("{name}@{range}");
    descriptor(&selector)?;
    let workspace = if let Some((idx, version)) = workspaces.get(name) {
        match workspace_range_matches(range, version) {
            Some(true) => Some(*idx),
            Some(false) => None,
            None => {
                issues.push(format!("unresolved workspace version selection: {label} -> {selector}; supplied workspace version {version} needs unsupported semver evaluation"));
                return Ok(());
            }
        }
    } else {
        None
    };
    if let Some(to) = workspace.or_else(|| selectors.get(&selector).copied()) {
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
        if let Ok((actual, _)) = descriptor(alias) {
            Ok(actual.into())
        } else {
            descriptor(&format!("{alias}@*"))?;
            Ok(alias.into())
        }
    } else {
        Ok(name.into())
    }
}

fn read_records(lock: &str) -> Result<BTreeMap<String, Record>> {
    let mut has_header = false;
    let mut records = BTreeMap::<String, Record>::new();
    let mut current = None::<String>;
    let mut section = None::<String>;
    let mut reference_count = 0;
    let mut selector_count = 0;
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
                if records.len() >= 10_000 {
                    return Err(incomplete("more than 10000 resolution records"));
                }
                let selectors = read_selectors(value)?;
                selector_count += selectors.len();
                if selector_count > 50_000 {
                    return Err(incomplete("more than 50000 descriptors"));
                }
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
                    if !matches!(name.as_str(), "version" | "resolved" | "integrity" | "uid") {
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
                reference_count += 1;
                if reference_count > 50_000 {
                    return Err(incomplete("more than 50000 dependency references"));
                }
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
        if selectors.len() > 50_000 {
            return Err(incomplete("more than 50000 grouped descriptors"));
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

pub(super) fn project_path(path: &str) -> Result<String> {
    if path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(incomplete(format!("invalid project-relative path {path}")));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(incomplete("source path escapes project"));
                }
            }
            _ => parts.push(part),
        }
    }
    Ok(if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    })
}
pub(super) fn manifest_path(path: &str) -> String {
    if path == "." {
        "package.json".into()
    } else {
        format!("{path}/package.json")
    }
}
pub(super) fn source_manifest(bytes: &[u8], path: &str) -> Result<JsonNode> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(incomplete(format!("source manifest exceeds 4 MiB: {path}")));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| incomplete(format!("non-UTF-8 source manifest {path}")))?;
    let node = MiniParser::parse_json(text)?;
    let object = node
        .as_object()
        .ok_or_else(|| incomplete(format!("invalid source manifest {path}")))?;
    for key in ["name", "version"] {
        if object.get(key).is_some_and(|v| v.as_str().is_none()) {
            return Err(incomplete(format!("invalid {key} in {path}")));
        }
    }
    Ok(node)
}
fn retain_peers(
    label: &str,
    manifest: &JsonNode,
    metadata: &mut BTreeMap<String, JsonNode>,
) -> Result<()> {
    let mut retained = metadata
        .get(label)
        .and_then(JsonNode::as_object)
        .cloned()
        .unwrap_or_default();
    for key in ["peerDependencies", "peerDependenciesMeta"] {
        if let Some(value) = manifest.get(key) {
            let object = value
                .as_object()
                .ok_or_else(|| incomplete(format!("invalid {key} in {label}")))?;
            for (name, value) in object {
                descriptor(&format!("{name}@*"))?;
                if key == "peerDependencies" {
                    if value.as_str().is_none() {
                        return Err(incomplete("invalid peer requirement"));
                    }
                } else {
                    let flags = value
                        .as_object()
                        .ok_or_else(|| incomplete("invalid peer metadata"))?;
                    for (flag, value) in flags {
                        if flag != "optional" || value.as_bool().is_none() {
                            return Err(incomplete("unsupported peer metadata"));
                        }
                    }
                }
            }
            retained.insert(key.into(), value.clone());
            retained.insert("peerTopology".into(), JsonNode::String("constraints only; Yarn Classic does not auto-install peers or encode their installed placement".into()));
        }
    }
    metadata.insert(label.into(), JsonNode::Object(retained));
    Ok(())
}
fn workspace_manifests(
    manifest: &JsonNode,
    inputs: &ProjectInputs,
) -> Result<Vec<(String, JsonNode)>> {
    let Some(value) = manifest.get("workspaces") else {
        return Ok(Vec::new());
    };
    let value = value.get("packages").unwrap_or(value);
    let patterns = value
        .as_array()
        .ok_or_else(|| incomplete("invalid workspace patterns"))?;
    if patterns.len() > 1000 || inputs.len() > 10_000 {
        return Err(incomplete("workspace source limits exceeded"));
    }
    let mut result = Vec::new();
    let mut glob_budget = 20_000_000usize;
    let mut source_bytes = 0;
    for (key, bytes) in inputs {
        let Some(path) = key.strip_suffix("/package.json") else {
            continue;
        };
        let mut matched = false;
        for pattern in patterns {
            let pattern = pattern
                .as_str()
                .ok_or_else(|| incomplete("invalid workspace pattern"))?;
            let negative = pattern.starts_with('!');
            let pattern = pattern
                .strip_prefix('!')
                .unwrap_or(pattern)
                .trim_end_matches('/');
            if pattern.len() > 1024
                || path.len() > 2048
                || pattern.contains("**")
                || pattern.contains(['[', ']', '{', '}', '\\'])
            {
                return Err(incomplete("unsupported workspace glob"));
            }
            let pattern = project_path(pattern)?;
            glob_budget = glob_budget
                .checked_sub((pattern.len() + 1) * (path.len() + 1))
                .ok_or_else(|| incomplete("workspace glob comparison budget exceeded"))?;
            if glob(&pattern, path) {
                matched = !negative;
            }
        }
        if matched {
            source_bytes += bytes.len();
            if source_bytes > 64 * 1024 * 1024 {
                return Err(incomplete("workspace source manifests exceed 64 MiB"));
            }
            result.push((project_path(path)?, source_manifest(bytes, key)?));
        }
    }
    Ok(result)
}
fn glob(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let mut previous = vec![false; v.len() + 1];
    previous[0] = true;
    let mut i = 0;
    while i < p.len() {
        let mut next = vec![false; v.len() + 1];

        if p[i] == b'*' {
            next[0] = previous[0];
            for j in 0..v.len() {
                next[j + 1] = previous[j + 1] || (next[j] && (v[j] != b'/'));
            }
        } else {
            for j in 0..v.len() {
                next[j + 1] = previous[j] && (p[i] == v[j] || (p[i] == b'?' && v[j] != b'/'));
            }
        }
        previous = next;
        i += 1;
    }
    previous[v.len()]
}
fn workspace_range_matches(range: &str, version: &str) -> Option<bool> {
    if version.is_empty() || range.contains(':') {
        return Some(false);
    }
    fn parts(v: &str) -> Option<Vec<u64>> {
        v.split('.')
            .map(|s| {
                if s.is_empty() || (s.len() > 1 && s.starts_with('0')) {
                    None
                } else {
                    s.parse().ok()
                }
            })
            .collect()
    }
    let stable = version.split('+').next()?;
    let have = parts(stable.split('-').next()?)?;
    if have.len() != 3 {
        return None;
    }
    if range == "*" {
        return Some(!stable.contains('-'));
    }
    // Complex prerelease comparisons require semantics this bounded matcher does not implement.
    if stable.contains('-') {
        return None;
    }
    let (kind, requested) = match range.as_bytes().first() {
        Some(b'^' | b'~') => (&range[..1], &range[1..]),
        _ => {
            let want = parts(range.split('+').next()?)?;
            return (want.len() == 3).then_some(want == have);
        }
    };
    let want = parts(requested)?;
    if want.is_empty() || want.len() > 3 {
        return None;
    }
    let mut lower = [0; 3];
    for (i, n) in want.iter().enumerate() {
        lower[i] = *n;
    }
    let have = [have[0], have[1], have[2]];
    let mut upper = lower;
    let index = if kind == "~" {
        usize::from(want.len() > 1)
    } else {
        lower
            .iter()
            .position(|n| *n != 0)
            .unwrap_or(want.len() - 1)
            .min(want.len() - 1)
    };
    upper[index] = upper[index].checked_add(1)?;
    for n in &mut upper[index + 1..] {
        *n = 0;
    }
    Some(have >= lower && have < upper)
}

fn manifest_reference_count(manifest: &JsonNode) -> Result<usize> {
    let mut count = 0;
    for kind in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(value) = manifest.get(kind) {
            count += value
                .as_object()
                .ok_or_else(|| incomplete(format!("invalid source {kind}")))?
                .len();
        }
    }
    Ok(count)
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

    #[test]
    fn classic_link_uid_and_peer_constraints_are_retained() {
        let lock = fixture("\"local@link:./tools/local\":\n  version \"0.0.0\"\n  uid \"\"\n");
        let g = parse(&lock, Some(&manifest(r#"{"dependencies":{"local":"link:./tools/local"},"peerDependencies":{"react":"*"}}"#))).unwrap();
        assert_eq!(
            g.packages[&label("local@link:./tools/local")].source,
            "link:./tools/local"
        );
        assert!(g.resolution_metadata["root"]
            .get("peerDependencies")
            .is_some());
        assert!(!g.issues.iter().any(|s| s.starts_with("Unresolved peer")));
        assert!(parse(
            &fixture("local@1:\n  version \"1\"\n  uid \"\"\n  uid \"other\"\n"),
            None
        )
        .is_err());
    }
    #[test]
    fn supplied_workspaces_and_links_add_only_declared_source_edges() {
        let lock = fixture("leaf@1:\n  version \"1\"\n\"local@link:./tools/local\":\n  version \"0.0.0\"\n  uid \"\"\n");
        let root = manifest(
            r#"{"name":"app","workspaces":["packages/*"],"dependencies":{"member":"^1","local":"link:./tools/local"}}"#,
        );
        let inputs = ProjectInputs::from([
            ("packages/member/package.json".into(), br#"{"name":"member","version":"1.2.0","dependencies":{"leaf":"1"}}"#.to_vec()),
            ("tools/local/package.json".into(), br#"{"name":"local","dependencies":{"leaf":"1"},"peerDependencies":{"absent-peer":"*"}}"#.to_vec()),
            ("fixtures/deep/package.json".into(), b"invalid unused fixture".to_vec()),
        ]);
        let g = parse_with_inputs(&lock, Some(&root), &inputs).unwrap();
        assert_eq!(g.graph.edges().len(), 4);
        assert_eq!(
            g.packages["yarn:workspace:packages/member"].path,
            "yarn:workspace:packages/member"
        );
        assert!(g.resolution_metadata[&label("local@link:./tools/local")]
            .get("sourceManifest")
            .is_some());
        assert_eq!(g.issues.len(), 1);
        let missing = parse_with_inputs(&lock, Some(&root), &ProjectInputs::new()).unwrap();
        assert!(missing.issues.iter().any(|s| s.contains("member@^1")));
        let mut duplicate = inputs.clone();
        duplicate.insert(
            "packages/duplicate/package.json".into(),
            br#"{"name":"member","version":"1.2.0"}"#.to_vec(),
        );
        assert!(parse_with_inputs(&lock, Some(&root), &duplicate).is_err());
        let escape = fixture("\"local@link:../../outside\":\n  version \"0\"\n");
        assert!(parse_with_inputs(&escape, Some(&manifest("{}")), &inputs).is_err());
        let conflict = lock.replace(
            "  uid \"\"",
            "  uid \"\"\n  resolved \"https://registry/local.tgz\"",
        );
        assert!(parse_with_inputs(&conflict, Some(&root), &inputs).is_err());
    }
    #[test]
    fn shorthand_aliases_and_source_root_are_supported_without_peer_edges() {
        let lock = fixture("\"alias@npm:real\":\n  version \"1.0.0\"\npeer@1:\n  version \"1\"\n");
        let source =
            br#"{"dependencies":{"alias":"npm:real"},"peerDependencies":{"peer":"1"}}"#.to_vec();
        let inputs = ProjectInputs::from([("package.json".into(), source)]);
        let g = parse_with_inputs(&lock, None, &inputs).unwrap();
        assert_eq!(g.packages[&label("alias@npm:real")].name, "real");
        assert_eq!(g.graph.edges().len(), 1);
        assert!(g.resolution_metadata["root"]
            .get("peerDependencies")
            .is_some());
        assert!(parse_with_inputs(&lock, Some(&manifest("{}")), &inputs).is_err());
        assert!(parse(
            &lock,
            Some(&manifest(r#"{"peerDependencies":{"peer":true}}"#))
        )
        .is_err());
    }
    #[test]
    fn classic_record_limit_has_an_exact_boundary() {
        let mut lock = fixture("");
        for i in 0..10_000 {
            lock.push_str(&format!("a{i}@1:\n  version \"1\"\n"));
        }
        assert_eq!(parse(&lock, None).unwrap().packages.len(), 10_001);
        lock.push_str("overflow@1:\n  version \"1\"\n");
        assert!(parse(&lock, None).is_err());
    }
    #[test]
    fn partially_supplied_exact_workspaces_remain_incomplete() {
        let root = manifest(r#"{"workspaces":["packages/a","packages/b"]}"#);
        let inputs = ProjectInputs::from([(
            "packages/a/package.json".into(),
            br#"{"name":"a","version":"1.0.0"}"#.to_vec(),
        )]);
        let g = parse_with_inputs(&fixture(""), Some(&root), &inputs).unwrap();
        assert!(g
            .issues
            .iter()
            .any(|s| s.starts_with("Root attribution incomplete:") && s.contains("packages/b")));
    }
    #[test]
    fn star_excludes_prerelease_workspace_and_uses_the_locked_registry_record() {
        let root = manifest(r#"{"workspaces":["packages/a"],"dependencies":{"a":"*"}}"#);
        let inputs = ProjectInputs::from([(
            "packages/a/package.json".into(),
            br#"{"name":"a","version":"1.0.0-beta.1"}"#.to_vec(),
        )]);
        let g = parse_with_inputs(
            &fixture("a@*:\n  version \"0.9.0\"\n"),
            Some(&root),
            &inputs,
        )
        .unwrap();
        assert!(edge_names(&g).contains(&("root".into(), label("a@*"))));
        assert!(!edge_names(&g).contains(&("root".into(), "yarn:workspace:packages/a".into())));
    }
    #[test]
    fn unsupported_workspace_range_cannot_choose_a_registry_fallback() {
        let root = manifest(r#"{"workspaces":["packages/a"],"dependencies":{"a":">=1"}}"#);
        let inputs = ProjectInputs::from([(
            "packages/a/package.json".into(),
            br#"{"name":"a","version":"2.0.0"}"#.to_vec(),
        )]);
        let g = parse_with_inputs(
            &fixture("\"a@>=1\":\n  version \"1.0.0\"\n"),
            Some(&root),
            &inputs,
        )
        .unwrap();
        assert!(g
            .issues
            .iter()
            .any(|s| s.contains("workspace version selection")));
        assert!(edge_names(&g).is_empty());
    }
}
