//! Exact pnpm v6/v9 lockfile inventory. This is a reader of pnpm's emitted YAML subset,
//! not a YAML implementation or an installed-file / lifecycle-script inspection.
use crate::error::{GateError, Result};
use crate::graph::{DepGraph, PackageInfo, ProjectInputs};
use crate::graph_impl::DiGraph;
use crate::parser::{JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Document {
    version: Option<String>,
    importers: BTreeMap<String, Importer>,
    packages: BTreeMap<String, Package>,
    snapshots: BTreeMap<String, Snapshot>,
    metadata: BTreeMap<String, JsonNode>,
    overrides: BTreeMap<String, String>,
}
#[derive(Default)]
struct Importer {
    dependencies: BTreeMap<String, BTreeMap<String, Requirement>>,
    metadata: BTreeMap<String, JsonNode>,
}
#[derive(Default)]
struct Requirement {
    specifier: String,
    version: String,
}
#[derive(Default)]
struct Package {
    resolution: BTreeMap<String, JsonNode>,
    name: Option<String>,
    version: Option<String>,
    capabilities: BTreeSet<String>,
    execution: bool,
    snapshot: Snapshot,
}
#[derive(Clone, Default)]
struct Snapshot {
    dependencies: BTreeMap<String, BTreeMap<String, String>>,
}
#[derive(Clone, Copy)]
struct Line<'a> {
    number: usize,
    indent: usize,
    text: &'a str,
}

/// Read both the environment document (when present) and the project document.
/// Snapshot labels preserve peer contexts; importer labels preserve workspace paths.
/// Every result is capability-incomplete: pnpm v6/v9 do not record a reliable negative
/// lifecycle capability marker. Positive build markers remain visible when present.
pub fn parse(lock: &str, manifest: Option<&JsonNode>) -> Result<DepGraph> {
    parse_with_inputs(lock, manifest, &ProjectInputs::new())
}

pub fn parse_with_inputs(
    lock: &str,
    manifest: Option<&JsonNode>,
    inputs: &ProjectInputs,
) -> Result<DepGraph> {
    let source_overrides = source_overrides(inputs, manifest)?;
    let documents = MiniParser::parse_pnpm_documents(lock)?;
    let mut result = DepGraph {
        graph: DiGraph::new(),
        execution_packages: BTreeSet::new(),
        suspicious_packages: BTreeSet::new(),
        packages: BTreeMap::new(),
        issues: vec!["Execution capabilities unknown: pnpm v6/v9 packages and workspace importers whose manifests were not inspected; absent build markers do not establish absence of lifecycle execution".into()],
        optional_omissions: Vec::new(),
        edge_kinds: BTreeMap::new(),
        resolution_metadata: BTreeMap::new(),
    };
    let mut indices = BTreeMap::new();
    let last = documents.len() - 1;
    for (doc_index, document) in documents.iter().enumerate() {
        let scope = scope(doc_index, last);
        for (key, value) in &document.metadata {
            result
                .resolution_metadata
                .insert(format!("pnpm:{scope}:{key}"), value.clone());
        }
        for (path, importer) in &document.importers {
            let label = importer_label(scope, path);
            let mut importer_metadata = importer.metadata.clone();
            for (kind, requirements) in &importer.dependencies {
                importer_metadata.insert(
                    kind.clone(),
                    JsonNode::Object(
                        requirements
                            .iter()
                            .map(|(name, req)| {
                                (
                                    name.clone(),
                                    JsonNode::Object(BTreeMap::from([
                                        (
                                            "specifier".into(),
                                            JsonNode::String(req.specifier.clone()),
                                        ),
                                        ("version".into(), JsonNode::String(req.version.clone())),
                                    ])),
                                )
                            })
                            .collect(),
                    ),
                );
            }
            result.resolution_metadata.insert(
                format!("pnpm:{scope}:importer:{path}"),
                JsonNode::Object(importer_metadata),
            );
            let (name, version) = if doc_index == last && path == "." {
                (
                    manifest
                        .and_then(|m| m.get("name"))
                        .and_then(JsonNode::as_str)
                        .unwrap_or("root"),
                    manifest
                        .and_then(|m| m.get("version"))
                        .and_then(JsonNode::as_str)
                        .unwrap_or(""),
                )
            } else {
                (path.as_str(), "")
            };
            indices.insert(label.clone(), result.graph.add_node(label.clone()));
            result.packages.insert(
                label.clone(),
                PackageInfo {
                    path: label,
                    name: name.into(),
                    version: version.into(),
                    source: format!("pnpm:{scope}:importer:{path}"),
                    integrity: String::new(),
                    capabilities: Vec::new(),
                },
            );
            if doc_index == last && path == "." {
                if let Some(m) = manifest {
                    let context = check_manifest(
                        m,
                        importer,
                        &document.overrides,
                        source_overrides.as_ref(),
                        &mut result.issues,
                    )?;
                    if !context.is_empty() {
                        result.resolution_metadata.insert(
                            "pnpm:project:overrideSourceContext".into(),
                            JsonNode::Object(context),
                        );
                    }
                }
            }
        }
        let mut used_metadata = BTreeSet::new();
        for (id, snapshot) in &document.snapshots {
            let label = snapshot_label(scope, id);
            result.resolution_metadata.insert(
                label.clone(),
                JsonNode::Object(
                    snapshot
                        .dependencies
                        .iter()
                        .map(|(kind, deps)| (kind.clone(), string_map(deps.clone())))
                        .collect(),
                ),
            );
            let base = base_id(id);
            let metadata = metadata_id(document, id);
            if let Some(key) = metadata {
                used_metadata.insert(key);
            }
            let record = metadata.and_then(|key| document.packages.get(key));
            let (inferred_name, inferred_version) = identity(base);
            if record.is_none() {
                result
                    .issues
                    .push(format!("missing pnpm package metadata: {scope}:{id}"));
            }
            let mut resolution = record.map(|p| p.resolution.clone()).unwrap_or_default();
            let integrity = resolution
                .remove("integrity")
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            let source = if resolution.is_empty() {
                String::new()
            } else {
                JsonNode::Object(resolution).to_json()
            };
            let capabilities: Vec<_> = record
                .map(|p| p.capabilities.iter().cloned().collect())
                .unwrap_or_default();
            if record.is_some_and(|p| p.execution) {
                result.execution_packages.insert(label.clone());
            }
            indices.insert(label.clone(), result.graph.add_node(label.clone()));
            result.packages.insert(
                label.clone(),
                PackageInfo {
                    path: label,
                    name: record.and_then(|p| p.name.clone()).unwrap_or(inferred_name),
                    version: record
                        .and_then(|p| p.version.clone())
                        .unwrap_or(inferred_version),
                    source,
                    integrity,
                    capabilities,
                },
            );
        }
        // Unreferenced metadata records cannot be interpreted as virtual-store instances.
        for id in document.packages.keys() {
            if !used_metadata.contains(id.as_str()) {
                result.issues.push(format!(
                    "pnpm package metadata has no snapshot: {scope}:{id}"
                ));
            }
        }
    }
    add_local_links(&documents, inputs, &mut result, &mut indices);
    if !indices.contains_key("root") {
        return Err(incomplete("project '.' importer is required"));
    }
    for (doc_index, document) in documents.iter().enumerate() {
        let scope = scope(doc_index, last);
        for (path, importer) in &document.importers {
            let label = importer_label(scope, path);
            let from = indices[&label];
            for (kind, requirements) in &importer.dependencies {
                for (name, requirement) in requirements {
                    match target_label(scope, path, name, &requirement.version, document, &indices)
                    {
                        Some(target) => {
                            add_edge(&mut result, from, indices[&target], kind);
                            if requirement.version.starts_with("link:") {
                                add_edge(&mut result, from, indices[&target], "workspaceLink");
                            }
                        }
                        None => unresolved(&mut result, &label, kind, name, &requirement.version),
                    }
                }
            }
        }
        for (id, snapshot) in &document.snapshots {
            let label = snapshot_label(scope, id);
            let from = indices[&label];
            for (kind, dependencies) in &snapshot.dependencies {
                for (name, version) in dependencies {
                    match target_label(scope, ".", name, version, document, &indices) {
                        Some(target) => {
                            add_edge(&mut result, from, indices[&target], kind);
                            if version.starts_with("link:") {
                                add_edge(&mut result, from, indices[&target], "workspaceLink");
                            }
                        }
                        None => unresolved(&mut result, &label, kind, name, version),
                    }
                }
            }
        }
    }
    for &(from, to) in result.edge_kinds.keys() {
        result.graph.add_edge(from, to);
    }
    Ok(result)
}

fn source_overrides(
    inputs: &ProjectInputs,
    manifest: Option<&JsonNode>,
) -> Result<Option<BTreeMap<String, String>>> {
    if let Some(bytes) = inputs.get("pnpm-workspace.yaml") {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| incomplete("pnpm-workspace.yaml must be UTF-8"))?;
        let mut lines = Vec::new();
        for (number, raw) in text.lines().enumerate() {
            let indent = raw.bytes().take_while(|b| *b == b' ').count();
            let text = strip_comment(raw[indent..].trim_end())?;
            if !text.is_empty() && !matches!(text, "---" | "...") {
                lines.push(Line {
                    number: number + 1,
                    indent,
                    text,
                });
            }
        }
        let mut overrides = BTreeMap::new();
        let mut catalogs = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (at, line) in lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.indent == 0)
        {
            let (key, value) = mapping(line.text)?;
            if !matches!(key.as_str(), "overrides" | "catalog" | "catalogs") {
                continue;
            }
            if !seen.insert(key.clone()) {
                return Err(line_error(
                    line,
                    "duplicate pnpm source configuration field",
                ));
            }
            let body = &lines[at + 1..end_block(&lines, at)];
            match key.as_str() {
                "overrides" => overrides = scalar_map(line, value, body, 2)?,
                "catalog" => {
                    if catalogs
                        .insert("default".into(), scalar_map(line, value, body, 2)?)
                        .is_some()
                    {
                        return Err(line_error(line, "duplicate default source catalog"));
                    }
                }
                _ => {
                    check_map(line, value, body)?;
                    for (line, name, value, body) in fields(body, 2)? {
                        if catalogs
                            .insert(name, scalar_map(line, value, body, 4)?)
                            .is_some()
                        {
                            return Err(line_error(line, "duplicate source catalog"));
                        }
                    }
                }
            }
        }
        for (name, spec) in &mut overrides {
            if let Some(catalog) = spec.strip_prefix("catalog:") {
                if let Some(replacement) = catalogs
                    .get(if catalog.is_empty() {
                        "default"
                    } else {
                        catalog
                    })
                    .and_then(|entries| entries.get(name))
                {
                    *spec = replacement.clone();
                }
            }
        }
        return Ok(Some(overrides));
    }
    let legacy = manifest
        .and_then(|m| m.get("pnpm"))
        .and_then(|p| p.get("overrides"));
    let legacy_supported = manifest
        .and_then(|m| m.get("packageManager"))
        .and_then(JsonNode::as_str)
        .and_then(|p| p.strip_prefix("pnpm@"))
        .and_then(|p| p.split('.').next())
        .and_then(|p| p.parse::<u64>().ok())
        .is_some_and(|major| major <= 10);
    if !legacy_supported {
        return Ok(None);
    }
    legacy
        .map(|overrides| {
            overrides
                .as_object()
                .ok_or_else(|| incomplete("manifest pnpm.overrides must be a string map"))?
                .iter()
                .map(|(name, spec)| {
                    Ok((
                        name.clone(),
                        spec.as_str()
                            .ok_or_else(|| incomplete("manifest override must be a string"))?
                            .into(),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()
        })
        .transpose()
}

fn add_local_links(
    documents: &[Document],
    inputs: &ProjectInputs,
    result: &mut DepGraph,
    indices: &mut BTreeMap<String, usize>,
) {
    for (doc_index, document) in documents.iter().enumerate() {
        let scope = scope(doc_index, documents.len() - 1);
        let references = document
            .importers
            .iter()
            .flat_map(|(path, importer)| {
                importer.dependencies.values().flat_map(move |deps| {
                    deps.values()
                        .map(move |req| (path.as_str(), req.version.as_str()))
                })
            })
            .chain(document.snapshots.values().flat_map(|snapshot| {
                snapshot
                    .dependencies
                    .values()
                    .flat_map(|deps| deps.values().map(|version| (".", version.as_str())))
            }));
        let mut attempted = BTreeSet::new();
        for (importer, version) in references {
            let Some(path) = version
                .strip_prefix("link:")
                .and_then(|relative| relative_workspace(importer, relative))
            else {
                continue;
            };
            let label = format!("pnpm:{scope}:link:{path}");
            if linked_importer(document, &path).is_some() || !attempted.insert(label.clone()) {
                continue;
            }
            let manifest_path = if path == "." {
                "package.json".into()
            } else {
                format!("{path}/package.json")
            };
            let Some(bytes) = inputs.get(&manifest_path) else {
                continue;
            };
            let parsed = (|| -> Result<()> {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| incomplete("linked pnpm manifest must be UTF-8"))?;
                let manifest = MiniParser::parse_json(text)?;
                let fields = manifest
                    .as_object()
                    .ok_or_else(|| incomplete("linked pnpm manifest must be an object"))?;
                let name = fields
                    .get("name")
                    .and_then(JsonNode::as_str)
                    .filter(|n| !n.is_empty())
                    .ok_or_else(|| incomplete("linked pnpm manifest requires a string name"))?;
                let version = match fields.get("version") {
                    Some(value) => value.as_str().ok_or_else(|| {
                        incomplete("linked pnpm manifest version must be a string")
                    })?,
                    None => "",
                };
                for kind in [
                    "dependencies",
                    "optionalDependencies",
                    "devDependencies",
                    "peerDependencies",
                ] {
                    if let Some(deps) = fields.get(kind) {
                        for (name, spec) in deps.as_object().ok_or_else(|| {
                            incomplete("linked pnpm manifest dependencies must be string maps")
                        })? {
                            let spec = spec.as_str().ok_or_else(|| {
                                incomplete("linked pnpm manifest requirement must be a string")
                            })?;
                            result.issues.push(format!("unresolved pnpm linked manifest dependency resolution unknown: {label} {kind} -> {name}@{spec}"));
                        }
                    }
                }
                let mut capabilities = Vec::new();
                if let Some(scripts) = fields.get("scripts") {
                    for (name, body) in scripts.as_object().ok_or_else(|| {
                        incomplete("linked pnpm manifest scripts must be a string map")
                    })? {
                        body.as_str().ok_or_else(|| {
                            incomplete("linked pnpm manifest script must be a string")
                        })?;
                        if matches!(
                            name.as_str(),
                            "preinstall"
                                | "install"
                                | "postinstall"
                                | "prepare"
                                | "prepublish"
                                | "prepublishOnly"
                                | "preprepare"
                                | "postprepare"
                        ) {
                            capabilities.push(format!(
                                "{name}-lifecycle-script (supplied linked manifest)"
                            ));
                        }
                    }
                }
                if !capabilities.is_empty() {
                    result.execution_packages.insert(label.clone());
                }
                result.packages.insert(
                    label.clone(),
                    PackageInfo {
                        path: label.clone(),
                        name: name.into(),
                        version: version.into(),
                        source: format!("pnpm:{scope}:link:{path}"),
                        integrity: String::new(),
                        capabilities,
                    },
                );
                result
                    .resolution_metadata
                    .insert(format!("{label}:manifest"), manifest);
                indices.insert(label.clone(), result.graph.add_node(label.clone()));
                Ok(())
            })();
            if let Err(error) = parsed {
                result.issues.push(format!("Input consistency unknown: invalid supplied linked manifest {manifest_path}: {error}"));
            }
        }
    }
}

fn scope(doc_index: usize, last: usize) -> &'static str {
    if doc_index == last {
        "project"
    } else {
        "environment"
    }
}
fn importer_label(scope: &str, path: &str) -> String {
    if scope == "project" && path == "." {
        "root".into()
    } else {
        format!("pnpm:{scope}:importer:{path}")
    }
}
fn snapshot_label(scope: &str, id: &str) -> String {
    format!("pnpm:{scope}:snapshot:{id}")
}
fn base_id(id: &str) -> &str {
    id.split_once('(').map(|(base, _)| base).unwrap_or(id)
}
fn metadata_id<'a>(document: &'a Document, id: &'a str) -> Option<&'a str> {
    if document.packages.contains_key(id) {
        return Some(id);
    }
    id.char_indices()
        .filter_map(|(i, c)| (c == '(').then_some(&id[..i]))
        .rfind(|prefix| document.packages.contains_key(*prefix))
}
fn identity(id: &str) -> (String, String) {
    let id = id.strip_prefix('/').unwrap_or(id);
    let start = usize::from(id.starts_with('@'));
    match id[start..].split_once('@') {
        Some((name, version)) => (format!("{}{name}", &id[..start]), version.into()),
        None => (id.into(), String::new()),
    }
}
fn target_label(
    scope: &str,
    importer: &str,
    name: &str,
    version: &str,
    document: &Document,
    indices: &BTreeMap<String, usize>,
) -> Option<String> {
    if let Some(relative) = version.strip_prefix("link:") {
        let path = relative_workspace(importer, relative)?;
        return if let Some(importer) = linked_importer(document, &path) {
            Some(importer_label(scope, importer))
        } else {
            let label = format!("pnpm:{scope}:link:{path}");
            indices.contains_key(&label).then_some(label)
        };
    }
    // Aliases carry the real package identity, not the importer alias name.
    let id = if let Some(actual) = version.strip_prefix("npm:") {
        actual.to_string()
    } else if document.snapshots.contains_key(version) {
        version.to_string()
    } else {
        format!("{name}@{version}")
    };
    if document.snapshots.contains_key(&id) {
        Some(snapshot_label(scope, &id))
    } else if document.version.as_deref() == Some("6.0")
        && document.snapshots.contains_key(&format!("/{id}"))
    {
        Some(snapshot_label(scope, &format!("/{id}")))
    } else {
        None
    }
}
fn linked_importer<'a>(document: &'a Document, path: &str) -> Option<&'a str> {
    let mut matches = document.importers.iter().filter_map(|(id, importer)| {
        let published = importer
            .metadata
            .get("publishDirectory")
            .and_then(JsonNode::as_str)
            .filter(|_| {
                importer
                    .metadata
                    .get("linkDirectory")
                    .and_then(JsonNode::as_bool)
                    != Some(false)
            })
            .and_then(|directory| relative_workspace(id, directory));
        (id == path || published.as_deref() == Some(path)).then_some(id.as_str())
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn relative_workspace(importer: &str, relative: &str) -> Option<String> {
    if relative.starts_with('/') || relative.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = if importer == "." {
        Vec::new()
    } else {
        importer.split('/').collect()
    };
    for component in relative.split('/') {
        match component {
            "" | "." => (),
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(component),
        }
    }
    Some(if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    })
}
fn add_edge(graph: &mut DepGraph, from: usize, to: usize, kind: &str) {
    graph
        .edge_kinds
        .entry((from, to))
        .or_default()
        .insert(kind.into());
}
fn unresolved(graph: &mut DepGraph, from: &str, kind: &str, name: &str, version: &str) {
    let detail = format!("unresolved pnpm {kind}: {from} -> {name}@{version}");
    // A v9 lock is platform-independent and should contain optional snapshots too.
    // Record the omission separately, but do not describe extraction as complete.
    if kind == "optionalDependencies" {
        graph.optional_omissions.push(detail.clone());
    }
    graph.issues.push(detail);
}
fn check_manifest(
    manifest: &JsonNode,
    importer: &Importer,
    overrides: &BTreeMap<String, String>,
    source_overrides: Option<&BTreeMap<String, String>>,
    issues: &mut Vec<String>,
) -> Result<BTreeMap<String, JsonNode>> {
    if manifest.as_object().is_none() {
        return Err(incomplete("root manifest must be a JSON object"));
    }
    for key in ["name", "version"] {
        if manifest.get(key).is_some_and(|v| v.as_str().is_none()) {
            return Err(incomplete("root manifest name/version must be strings"));
        }
    }
    let mut context = BTreeMap::new();
    for kind in ["dependencies", "devDependencies", "optionalDependencies"] {
        let mut declared = BTreeMap::new();
        if let Some(value) = manifest.get(kind) {
            for (name, requirement) in value
                .as_object()
                .ok_or_else(|| incomplete("manifest dependencies must be maps"))?
            {
                declared.insert(
                    name.clone(),
                    requirement
                        .as_str()
                        .ok_or_else(|| {
                            incomplete("manifest dependency requirement must be a string")
                        })?
                        .to_string(),
                );
            }
        }
        if let Some(runtime) = manifest
            .get(if kind == "devDependencies" {
                "devEngines"
            } else if kind == "dependencies" {
                "engines"
            } else {
                ""
            })
            .and_then(|v| v.get("runtime"))
        {
            let runtimes: Vec<&JsonNode> = match runtime {
                JsonNode::Array(items) => items.iter().collect(),
                JsonNode::Object(_) => vec![runtime],
                _ => return Err(incomplete("manifest runtime must be an object or sequence")),
            };
            let mut names = BTreeSet::new();
            for runtime in runtimes {
                let name = runtime
                    .get("name")
                    .and_then(JsonNode::as_str)
                    .filter(|name| matches!(*name, "node" | "deno" | "bun"))
                    .ok_or_else(|| incomplete("unsupported manifest runtime name"))?;
                let version = runtime
                    .get("version")
                    .and_then(JsonNode::as_str)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        incomplete("manifest runtime version must be a nonempty string")
                    })?;
                if !names.insert(name) {
                    return Err(incomplete("duplicate manifest runtime name"));
                }
                if runtime.get("onFail").and_then(JsonNode::as_str) == Some("download") {
                    if declared
                        .insert(name.into(), format!("runtime:{version}"))
                        .is_some()
                    {
                        return Err(incomplete(
                            "manifest runtime conflicts with explicit dependency",
                        ));
                    }
                }
            }
        }
        let locked: BTreeMap<_, _> = importer
            .dependencies
            .get(kind)
            .into_iter()
            .flat_map(|d| d.iter())
            .map(|(name, req)| (name.clone(), req.specifier.clone()))
            .collect();
        for (name, declared_spec) in &mut declared {
            if locked.get(name).is_some_and(|spec| spec != declared_spec) {
                if let Some(replacement) = overrides
                    .get(name)
                    .filter(|spec| locked.get(name) == Some(spec))
                {
                    *declared_spec = replacement.clone();
                    let verified =
                        source_overrides.and_then(|source| source.get(name)) == Some(replacement);
                    context.insert(
                        name.clone(),
                        JsonNode::String(
                            if verified {
                                "verified supplied source"
                            } else {
                                "unverified locked override"
                            }
                            .into(),
                        ),
                    );
                    if !verified {
                        issues.push(format!("Input consistency unknown: pnpm override source context unverified: root {kind} {name}; locked override explains applied specifier but supplied source does not verify it"));
                    }
                }
            }
        }
        if declared != locked {
            issues.push(format!("manifest/lock root {kind} disagree"));
        }
    }
    Ok(context)
}

impl MiniParser {
    fn parse_pnpm_documents(content: &str) -> Result<Vec<Document>> {
        if content.len() > 64 * 1024 * 1024 {
            return Err(incomplete("pnpm lockfile exceeds 64 MiB"));
        }
        let mut documents = Vec::new();
        let mut lines = Vec::new();
        for (number, raw) in content.lines().enumerate() {
            if raw.contains('\t') {
                return Err(incomplete(&format!(
                    "tabs in pnpm YAML at line {}",
                    number + 1
                )));
            }
            let indent = raw.bytes().take_while(|b| *b == b' ').count();
            let text = strip_comment(raw[indent..].trim_end())?;
            if text.is_empty() {
                continue;
            }
            if indent == 0 && matches!(text, "---" | "...") {
                if !lines.is_empty() {
                    documents.push(parse_document(&lines)?);
                    lines.clear();
                }
            } else {
                if indent % 2 != 0 {
                    return Err(incomplete(&format!(
                        "unsupported pnpm indentation at line {}",
                        number + 1
                    )));
                }
                lines.push(Line {
                    number: number + 1,
                    indent,
                    text,
                });
            }
        }
        if !lines.is_empty() {
            documents.push(parse_document(&lines)?);
        }
        if documents.is_empty() || documents.len() > 2 {
            return Err(incomplete(
                "expected one project document, optionally preceded by one environment document",
            ));
        }
        for (i, document) in documents.iter().enumerate() {
            if !matches!(document.version.as_deref(), Some("6.0" | "9.0")) {
                return Err(incomplete(
                    "only pnpm lockfileVersion 6.0 and 9.0 are supported",
                ));
            }
            if documents.len() > 1 && document.version.as_deref() != Some("9.0") {
                return Err(incomplete(
                    "multiple pnpm documents require lockfileVersion 9.0",
                ));
            }
            if !document.importers.contains_key(".") {
                return Err(incomplete("each pnpm document must have a '.' importer"));
            }
            if i + 1 != documents.len()
                && document.importers.values().any(|p| {
                    p.dependencies.keys().any(|k| {
                        !matches!(
                            k.as_str(),
                            "configDependencies" | "packageManagerDependencies"
                        )
                    })
                })
            {
                return Err(incomplete(
                    "first pnpm document must be an environment lockfile",
                ));
            }
        }
        Ok(documents)
    }
}

fn parse_document(lines: &[Line<'_>]) -> Result<Document> {
    let mut document = Document::default();
    let mut seen = BTreeSet::new();
    let mut at = 0;
    while at < lines.len() {
        let line = &lines[at];
        if line.indent != 0 {
            return Err(line_error(line, "expected top-level key"));
        }
        let (key, value) = mapping(line.text)?;
        if !seen.insert(key.clone()) {
            return Err(line_error(line, "duplicate top-level key"));
        }
        let end = end_block(lines, at);
        match key.as_str() {
            "lockfileVersion" => {
                document.version = Some(scalar(value)?);
                if end != at + 1 {
                    return Err(line_error(line, "invalid lockfileVersion"));
                }
            }
            "importers" | "packages" | "snapshots" => {
                if !value.is_empty() && value != "{}" {
                    return Err(line_error(line, "unsupported inline top-level map"));
                }
                if value == "{}" && end != at + 1 {
                    return Err(line_error(line, "inline map has nested content"));
                }
                let mut record = at + 1;
                while record < end {
                    let record_end = end_block(lines, record);
                    let l = &lines[record];
                    if l.indent != 2 {
                        return Err(line_error(l, "expected pnpm record at indentation 2"));
                    }
                    let (id, inline) = mapping(l.text)?;
                    if id.is_empty() {
                        return Err(line_error(l, "empty pnpm record ID"));
                    }
                    if !inline.is_empty() && inline != "{}" {
                        return Err(line_error(l, "unsupported inline pnpm record"));
                    }
                    if inline == "{}" && record_end != record + 1 {
                        return Err(line_error(l, "inline record has nested content"));
                    }
                    let body = &lines[record + 1..record_end];
                    let duplicate = match key.as_str() {
                        "importers" => document
                            .importers
                            .insert(id, parse_importer(body)?)
                            .is_some(),
                        "packages" => document.packages.insert(id, parse_package(body)?).is_some(),
                        _ => document
                            .snapshots
                            .insert(id, parse_snapshot(body)?)
                            .is_some(),
                    };
                    if duplicate {
                        return Err(line_error(l, "duplicate pnpm record"));
                    }
                    record = record_end;
                }
            }
            "packageExtensionsChecksum" | "pnpmfileChecksum" => {
                let checksum = scalar(value)?;
                if end != at + 1
                    || checksum.is_empty()
                    || !checksum.starts_with("sha256-")
                    || checksum.len() <= 7
                    || checksum[7..].bytes().any(|c| {
                        !c.is_ascii_alphanumeric() && !matches!(c, b'+' | b'/' | b'=' | b'-' | b'_')
                    })
                {
                    return Err(line_error(line, "invalid pnpm configuration checksum"));
                }
                document.metadata.insert(key, JsonNode::String(checksum));
            }
            "overrides" | "time" | "catalog" => {
                let values = scalar_map(line, value, &lines[at + 1..end], 2)?;
                if key == "overrides" {
                    document.overrides = values.clone();
                }
                document.metadata.insert(key, string_map(values));
            }
            "settings" | "patchedDependencies" | "catalogs" => {
                let metadata = metadata_map(line, value, &lines[at + 1..end], 2)?;
                document.metadata.insert(key, metadata);
            }
            _ => return Err(line_error(line, "unsupported top-level pnpm field")),
        }
        at = end;
    }
    if document.version.as_deref() == Some("6.0") {
        if seen.contains("snapshots") {
            return Err(incomplete(
                "pnpm v6 must keep dependency edges in packages, not snapshots",
            ));
        }
        for (id, package) in &document.packages {
            document
                .snapshots
                .insert(id.clone(), package.snapshot.clone());
        }
    } else if document
        .packages
        .values()
        .any(|p| !p.snapshot.dependencies.is_empty())
    {
        return Err(incomplete(
            "pnpm v9 package metadata cannot contain snapshot dependencies",
        ));
    }
    if !seen.contains("importers") {
        return Err(incomplete("missing pnpm importers map"));
    }
    Ok(document)
}
fn end_block(lines: &[Line<'_>], start: usize) -> usize {
    let indent = lines[start].indent;
    (start + 1..lines.len())
        .find(|&i| lines[i].indent <= indent)
        .unwrap_or(lines.len())
}
type Field<'a> = (&'a Line<'a>, String, &'a str, &'a [Line<'a>]);
fn fields<'a>(lines: &'a [Line<'a>], indent: usize) -> Result<Vec<Field<'a>>> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut seen = BTreeSet::new();
    while at < lines.len() {
        let line = &lines[at];
        if line.indent != indent {
            return Err(line_error(line, "unexpected pnpm field indentation"));
        }
        let (key, value) = mapping(line.text)?;
        if !seen.insert(key.clone()) {
            return Err(line_error(line, "duplicate pnpm field"));
        }
        let end = end_block(lines, at);
        out.push((line, key, value, &lines[at + 1..end]));
        at = end;
    }
    Ok(out)
}
fn parse_importer(lines: &[Line<'_>]) -> Result<Importer> {
    let mut importer = Importer::default();
    for (line, kind, value, body) in fields(lines, 4)? {
        if kind == "dependenciesMeta" {
            check_map(line, value, body)?;
            let mut metadata = BTreeMap::new();
            for (dep, name, value, children) in fields(body, 6)? {
                let flags = scalar_map(dep, value, children, 8)?;
                if flags.iter().any(|(k, v)| {
                    !matches!(k.as_str(), "built" | "injected")
                        || !matches!(v.as_str(), "true" | "false")
                }) {
                    return Err(line_error(dep, "unsupported pnpm dependency metadata flag"));
                }
                metadata.insert(
                    name,
                    JsonNode::Object(
                        flags
                            .into_iter()
                            .map(|(k, v)| (k, JsonNode::Bool(v == "true")))
                            .collect(),
                    ),
                );
            }
            importer.metadata.insert(kind, JsonNode::Object(metadata));
            continue;
        }
        if kind == "linkDirectory" {
            if !body.is_empty() || !matches!(value, "true" | "false") {
                return Err(line_error(line, "pnpm linkDirectory must be boolean"));
            }
            importer
                .metadata
                .insert(kind, JsonNode::Bool(value == "true"));
            continue;
        }
        if kind == "publishDirectory" {
            let path = scalar(value)?;
            if !body.is_empty()
                || path.is_empty()
                || relative_workspace(".", &path).is_none()
                || path.split('/').any(|p| p == "..")
            {
                return Err(line_error(
                    line,
                    "pnpm publishDirectory must be a project-relative directory",
                ));
            }
            importer.metadata.insert(kind, JsonNode::String(path));
            continue;
        }
        if !matches!(
            kind.as_str(),
            "dependencies"
                | "devDependencies"
                | "optionalDependencies"
                | "configDependencies"
                | "packageManagerDependencies"
        ) {
            return Err(line_error(line, "unsupported pnpm importer field"));
        }
        check_map(line, value, body)?;
        let mut dependencies = BTreeMap::new();
        for (dep, name, value, body) in fields(body, 6)? {
            let vals = if value.is_empty() {
                fields(body, 8)?
                    .into_iter()
                    .map(|(_, k, v, b)| {
                        if !b.is_empty() {
                            Err(incomplete("nested pnpm dependency requirement"))
                        } else {
                            Ok((k, scalar(v)?))
                        }
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            } else {
                if !body.is_empty() {
                    return Err(line_error(
                        dep,
                        "inline dependency requirement has nested content",
                    ));
                }
                flow_map(value)?
            };
            if vals
                .keys()
                .any(|k| !matches!(k.as_str(), "specifier" | "version"))
            {
                return Err(line_error(
                    dep,
                    "unsupported pnpm dependency requirement field",
                ));
            }
            let requirement = Requirement {
                specifier: vals
                    .get("specifier")
                    .cloned()
                    .ok_or_else(|| line_error(dep, "missing dependency specifier"))?,
                version: vals
                    .get("version")
                    .cloned()
                    .ok_or_else(|| line_error(dep, "missing dependency version"))?,
            };
            if requirement.version.is_empty() {
                return Err(line_error(dep, "empty dependency version"));
            }
            dependencies.insert(name, requirement);
        }
        importer.dependencies.insert(kind, dependencies);
    }
    Ok(importer)
}
fn parse_package(lines: &[Line<'_>]) -> Result<Package> {
    let mut package = Package::default();
    for (line, key, value, body) in fields(lines, 4)? {
        match key.as_str() {
            "dependencies" | "optionalDependencies" => {
                package
                    .snapshot
                    .dependencies
                    .insert(key, scalar_map(line, value, body, 6)?);
            }
            "transitivePeerDependencies" => (),
            "resolution" => {
                let resolution = emitted_value(line, value, body, 6, 0)?;
                validate_resolution(&resolution, false)?;
                package.resolution = resolution.as_object().unwrap().clone();
            }
            "name" | "version" => {
                if !body.is_empty() {
                    return Err(line_error(line, "nested pnpm identity"));
                }
                if key == "name" {
                    package.name = Some(scalar(value)?);
                } else {
                    package.version = Some(scalar(value)?);
                }
            }
            "requiresBuild" | "hasInstallScript" | "prepare" | "hasBin" => {
                if !body.is_empty() || !matches!(value, "true" | "false") {
                    return Err(line_error(line, "pnpm capability marker must be boolean"));
                }
                if value == "true" {
                    let capability = match key.as_str() {
                        "requiresBuild" => "build-required (script/native build body unknown)",
                        "hasInstallScript" => "install-lifecycle-script (body not inspected)",
                        "prepare" => "prepare-lifecycle-script (body not inspected)",
                        _ => "binary-entrypoint (not automatic installation execution)",
                    };
                    package.capabilities.insert(capability.into());
                    package.execution |= key != "hasBin";
                }
            }
            // Peer declarations are version ranges, not additional exact graph edges.
            "peerDependencies"
            | "peerDependenciesMeta"
            | "engines"
            | "os"
            | "cpu"
            | "libc"
            | "deprecated"
            | "bundledDependencies"
            | "bundleDependencies"
            | "optional"
            | "patched"
            | "dev"
            | "id" => (),
            _ => return Err(line_error(line, "unsupported pnpm package metadata field")),
        }
    }
    Ok(package)
}
fn parse_snapshot(lines: &[Line<'_>]) -> Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    for (line, kind, value, body) in fields(lines, 4)? {
        match kind.as_str() {
            "dependencies" | "optionalDependencies" => {
                check_map(line, value, body)?;
                let dependencies = fields(body, 6)?
                    .into_iter()
                    .map(|(l, name, version, children)| {
                        if !children.is_empty() {
                            return Err(line_error(l, "nested pnpm snapshot reference"));
                        }
                        let version = scalar(version)?;
                        if version.is_empty() {
                            return Err(line_error(l, "empty pnpm snapshot reference"));
                        }
                        Ok((name, version))
                    })
                    .collect::<Result<_>>()?;
                snapshot.dependencies.insert(kind, dependencies);
            }
            "transitivePeerDependencies" => (),
            "optional" | "dev" => {
                if !body.is_empty() || !matches!(value, "true" | "false") {
                    return Err(line_error(line, "pnpm snapshot flag must be boolean"));
                }
            }
            _ => return Err(line_error(line, "unsupported pnpm snapshot field")),
        }
    }
    Ok(snapshot)
}
fn emitted_value(
    line: &Line<'_>,
    value: &str,
    body: &[Line<'_>],
    indent: usize,
    depth: usize,
) -> Result<JsonNode> {
    if depth > 12 {
        return Err(line_error(line, "pnpm resolution nesting exceeds 12"));
    }
    if !value.is_empty() {
        if !body.is_empty() {
            return Err(line_error(
                line,
                "inline pnpm resolution has nested content",
            ));
        }
        return if value.starts_with('{') {
            Ok(string_map(flow_map(value)?))
        } else {
            Ok(JsonNode::String(scalar(value)?))
        };
    }
    if body.first().is_some_and(|l| l.text.starts_with("- ")) {
        let mut values = Vec::new();
        let mut at = 0;
        while at < body.len() {
            let first = &body[at];
            if first.indent != indent || !first.text.starts_with("- ") {
                return Err(line_error(first, "invalid pnpm resolution sequence"));
            }
            let end = end_block(body, at);
            let item = Line {
                number: first.number,
                indent: indent + 2,
                text: &first.text[2..],
            };
            let mut fields = vec![item];
            fields.extend_from_slice(&body[at + 1..end]);
            values.push(emitted_value(first, "", &fields, indent + 2, depth + 1)?);
            at = end;
        }
        return Ok(JsonNode::Array(values));
    }
    let mut values = BTreeMap::new();
    for (line, key, value, children) in fields(body, indent)? {
        values.insert(
            key,
            emitted_value(line, value, children, indent + 2, depth + 1)?,
        );
    }
    Ok(JsonNode::Object(values))
}
fn validate_resolution(value: &JsonNode, in_variant: bool) -> Result<()> {
    let map = value
        .as_object()
        .ok_or_else(|| incomplete("pnpm resolution must be a map"))?;
    let resolution_type = map
        .get("type")
        .map(|v| {
            v.as_str()
                .ok_or_else(|| incomplete("pnpm resolution type must be a scalar"))
        })
        .transpose()?;
    match resolution_type {
        Some("variations") if !in_variant => {
            if map.len() != 2 {
                return Err(incomplete("unsupported pnpm variations resolution field"));
            }
            let variants = map
                .get("variants")
                .and_then(JsonNode::as_array)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    incomplete("pnpm resolution variants must be a nonempty sequence")
                })?;
            for variant in variants {
                let fields = variant
                    .as_object()
                    .filter(|m| m.len() == 2)
                    .ok_or_else(|| {
                        incomplete("pnpm resolution variant requires resolution and targets")
                    })?;
                validate_resolution(
                    fields
                        .get("resolution")
                        .ok_or_else(|| incomplete("pnpm variant missing resolution"))?,
                    true,
                )?;
                let targets = fields
                    .get("targets")
                    .and_then(JsonNode::as_array)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        incomplete("pnpm variant targets must be a nonempty sequence")
                    })?;
                for target in targets {
                    let target = target
                        .as_object()
                        .ok_or_else(|| incomplete("pnpm runtime target must be a map"))?;
                    if !target.contains_key("os")
                        || !target.contains_key("cpu")
                        || target.iter().any(|(k, v)| {
                            !matches!(k.as_str(), "os" | "cpu" | "libc")
                                || v.as_str().is_none_or(str::is_empty)
                        })
                    {
                        return Err(incomplete("unsupported pnpm runtime target"));
                    }
                }
            }
        }
        Some("binary") => {
            if map.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "type" | "archive" | "bin" | "integrity" | "url" | "prefix"
                )
            }) || map
                .get("prefix")
                .is_some_and(|v| v.as_str().is_none_or(str::is_empty))
                || !matches!(
                    map.get("archive").and_then(JsonNode::as_str),
                    Some("zip" | "tarball")
                )
                || ["url", "integrity"].iter().any(|key| {
                    map.get(*key)
                        .and_then(JsonNode::as_str)
                        .is_none_or(str::is_empty)
                })
            {
                return Err(incomplete("unsupported pnpm binary resolution fields"));
            }
            match map.get("bin") {
                Some(JsonNode::String(s)) if !s.is_empty() => (),
                Some(JsonNode::Object(bins))
                    if !bins.is_empty()
                        && bins
                            .values()
                            .all(|v| v.as_str().is_some_and(|s| !s.is_empty())) =>
                {
                    ()
                }
                _ => return Err(incomplete("pnpm binary resolution requires bin paths")),
            }
        }
        Some("variations") => {
            return Err(incomplete("nested pnpm runtime variations are unsupported"))
        }
        Some("git" | "directory") | None => {
            if map.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "integrity"
                        | "tarball"
                        | "type"
                        | "directory"
                        | "repo"
                        | "commit"
                        | "path"
                        | "revision"
                        | "gitHosted"
                )
            }) || map.iter().any(|(k, v)| {
                if k == "gitHosted" {
                    !matches!(v.as_str(), Some("true" | "false"))
                } else {
                    v.as_str().is_none()
                }
            }) {
                return Err(incomplete("unsupported nested pnpm resolution field"));
            }
        }
        _ => return Err(incomplete("unsupported pnpm resolution type")),
    }
    Ok(())
}

fn string_map(values: BTreeMap<String, String>) -> JsonNode {
    JsonNode::Object(
        values
            .into_iter()
            .map(|(k, v)| (k, JsonNode::String(v)))
            .collect(),
    )
}
fn scalar_map(
    line: &Line<'_>,
    value: &str,
    body: &[Line<'_>],
    indent: usize,
) -> Result<BTreeMap<String, String>> {
    if !value.is_empty() {
        if !body.is_empty() {
            return Err(line_error(line, "inline map has nested content"));
        }
        return flow_map(value);
    }
    fields(body, indent)?
        .into_iter()
        .map(|(line, name, value, children)| {
            if !children.is_empty() {
                return Err(line_error(line, "nested pnpm scalar-map entry"));
            }
            let value = scalar(value)?;
            if name.is_empty() || value.is_empty() {
                return Err(line_error(line, "empty pnpm scalar-map entry"));
            }
            Ok((name, value))
        })
        .collect()
}
fn metadata_map(
    line: &Line<'_>,
    value: &str,
    body: &[Line<'_>],
    indent: usize,
) -> Result<JsonNode> {
    check_map(line, value, body)?;
    let mut result = BTreeMap::new();
    let (section, _) = mapping(line.text)?;
    for (entry, key, value, children) in fields(body, indent)? {
        let parsed = match section.as_str() {
            "settings" => {
                if !children.is_empty() {
                    return Err(line_error(entry, "nested pnpm setting"));
                }
                if matches!(
                    key.as_str(),
                    "autoInstallPeers"
                        | "excludeLinksFromLockfile"
                        | "dedupePeers"
                        | "autoDedupe"
                        | "dedupeInjectedDeps"
                        | "dedupePeerDependents"
                        | "linkWorkspacePackages"
                ) && matches!(value, "true" | "false")
                {
                    JsonNode::Bool(value == "true")
                } else if key == "peersSuffixMaxLength"
                    && value.bytes().all(|c| c.is_ascii_digit())
                    && !value.is_empty()
                {
                    JsonNode::String(value.into())
                } else {
                    return Err(line_error(
                        entry,
                        "unsupported pnpm setting or setting value",
                    ));
                }
            }
            "patchedDependencies" => {
                if !value.is_empty() && !value.starts_with('{') {
                    if !children.is_empty() {
                        return Err(line_error(entry, "patch hash has nested content"));
                    }
                    JsonNode::String(scalar(value)?)
                } else {
                    let values = scalar_map(entry, value, children, indent + 2)?;
                    if values
                        .keys()
                        .any(|k| !matches!(k.as_str(), "hash" | "path"))
                        || !values.contains_key("hash")
                    {
                        return Err(line_error(entry, "unsupported pnpm patch record"));
                    }
                    string_map(values)
                }
            }
            "catalogs" => {
                check_map(entry, value, children)?;
                let mut catalog = BTreeMap::new();
                for (dep, name, value, body) in fields(children, indent + 2)? {
                    let values = scalar_map(dep, value, body, indent + 4)?;
                    if values.len() != 2
                        || !values.contains_key("specifier")
                        || !values.contains_key("version")
                    {
                        return Err(line_error(
                            dep,
                            "pnpm catalog entry requires specifier and version",
                        ));
                    }
                    catalog.insert(name, string_map(values));
                }
                JsonNode::Object(catalog)
            }
            _ => return Err(line_error(entry, "unsupported pnpm metadata section")),
        };
        result.insert(key, parsed);
    }
    Ok(JsonNode::Object(result))
}

fn check_map(line: &Line<'_>, value: &str, body: &[Line<'_>]) -> Result<()> {
    if !value.is_empty() && value != "{}" {
        return Err(line_error(line, "expected emitted block map or empty map"));
    }
    if value == "{}" && !body.is_empty() {
        return Err(line_error(line, "inline map has nested content"));
    }
    Ok(())
}
fn mapping(text: &str) -> Result<(String, &str)> {
    let mut quote = None;
    let mut escape = false;
    for (i, c) in text.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quote == Some('"') {
            escape = true;
            continue;
        }
        if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote.is_none()
            && c == ':'
            && text[i + 1..]
                .chars()
                .next()
                .is_none_or(|n| n.is_whitespace())
        {
            return Ok((scalar(text[..i].trim())?, text[i + 1..].trim()));
        }
    }
    Err(incomplete("unsupported or malformed pnpm mapping"))
}
fn scalar(text: &str) -> Result<String> {
    let text = text.trim();
    if text.starts_with('"') {
        return match MiniParser::parse_json(text)? {
            JsonNode::String(s) => Ok(s),
            _ => Err(incomplete("expected pnpm string")),
        };
    }
    if text.starts_with('\'') {
        if !text.ends_with('\'') || text.len() < 2 {
            return Err(incomplete("unterminated pnpm quoted scalar"));
        }
        let inner = &text[1..text.len() - 1];
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\'' && chars.next() != Some('\'') {
                return Err(incomplete("invalid pnpm single-quoted scalar"));
            }
            out.push(c);
        }
        return Ok(out);
    }
    if text.starts_with(['&', '*', '!', '{', '[', '|', '>']) || text == "null" || text == "~" {
        return Err(incomplete("unsupported pnpm YAML scalar structure"));
    }
    Ok(text.into())
}
fn flow_map(text: &str) -> Result<BTreeMap<String, String>> {
    if !text.starts_with('{') || !text.ends_with('}') {
        return Err(incomplete("expected pnpm emitted flow map"));
    }
    let inner = &text[1..text.len() - 1];
    let mut quote = None;
    let mut escape = false;
    let mut start = 0;
    let mut entries = Vec::new();
    for (i, c) in inner.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quote == Some('"') {
            escape = true;
            continue;
        }
        if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote.is_none() && c == ',' {
            entries.push(&inner[start..i]);
            start = i + 1;
        }
    }
    if quote.is_some() {
        return Err(incomplete("unterminated pnpm flow-map quote"));
    }
    entries.push(&inner[start..]);
    let mut result = BTreeMap::new();
    for entry in entries {
        if entry.trim().is_empty() {
            continue;
        }
        let (key, value) = mapping(entry.trim())?;
        if result.insert(key, scalar(value)?).is_some() {
            return Err(incomplete("duplicate pnpm flow-map key"));
        }
    }
    Ok(result)
}
fn strip_comment(text: &str) -> Result<&str> {
    let mut quote = None;
    let mut escape = false;
    for (i, c) in text.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quote == Some('"') {
            escape = true;
            continue;
        }
        if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote.is_none()
            && c == '#'
            && (i == 0
                || text[..i]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace))
        {
            return Ok(text[..i].trim_end());
        }
    }
    // Folded irrelevant metadata may span quoted lines; a relevant scalar parser
    // rejects these. Do not let irrelevant human descriptions truncate graph reads.
    Ok(text)
}
fn incomplete(message: &str) -> GateError {
    GateError::Graph(format!("INCOMPLETE: {message}"))
}
fn line_error(line: &Line<'_>, message: &str) -> GateError {
    incomplete(&format!("{message} at pnpm line {}", line.number))
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOCK:&str="lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alias:\n        specifier: npm:a@^1\n        version: a@1.0.0(p@2.0.0)\n      child:\n        specifier: workspace:*\n        version: link:packages/child\n  packages/child:\n    devDependencies:\n      p:\n        specifier: ^2\n        version: 2.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-example, gitHosted: true}\n    requiresBuild: true\n  p@2.0.0:\n    resolution:\n      tarball: 'https://registry.example/p.tgz'\n      integrity: sha512-peer\n      revision: 1\nsnapshots:\n  a@1.0.0(p@2.0.0):\n    dependencies:\n      p: 2.0.0\n  p@2.0.0: {}\n";
    fn edges(g: &DepGraph) -> BTreeSet<(String, String, String)> {
        g.edge_kinds
            .iter()
            .flat_map(|(&(u, v), kinds)| {
                kinds.iter().map(move |kind| {
                    (
                        g.graph.node_weight(u).unwrap().clone(),
                        g.graph.node_weight(v).unwrap().clone(),
                        kind.clone(),
                    )
                })
            })
            .collect()
    }
    #[test]
    fn exact_peer_alias_workspace_and_metadata() {
        let g = parse(LOCK, None).unwrap();
        assert_eq!(g.graph.node_count(), 4);
        assert_eq!(g.graph._edge_count(), 4);
        assert!(edges(&g).contains(&(
            "root".into(),
            "pnpm:project:snapshot:a@1.0.0(p@2.0.0)".into(),
            "dependencies".into()
        )));
        let p = &g.packages["pnpm:project:snapshot:p@2.0.0"];
        assert_eq!(p.name, "p");
        assert_eq!(p.version, "2.0.0");
        assert_eq!(p.integrity, "sha512-peer");
        assert!(p.source.contains("revision"));
        assert!(g
            .execution_packages
            .contains("pnpm:project:snapshot:a@1.0.0(p@2.0.0)"));
        assert_eq!(g.issues.len(), 1);
    }
    #[test]
    fn two_documents_preserve_both_root_scopes() {
        let env="---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    packageManagerDependencies:\n      p:\n        specifier: 2\n        version: 2.0.0\npackages:\n  p@2.0.0:\n    resolution: {integrity: sha512-env}\nsnapshots:\n  p@2.0.0: {}\n---\n";
        let g = parse(&format!("{env}{LOCK}"), None).unwrap();
        assert_eq!(g.graph.node_count(), 6);
        assert_eq!(
            g.packages["pnpm:environment:snapshot:p@2.0.0"].integrity,
            "sha512-env"
        );
        assert_eq!(
            g.packages["pnpm:project:snapshot:p@2.0.0"].integrity,
            "sha512-peer"
        );
        assert!(!edges(&g)
            .iter()
            .any(|(u, v, _)| u == "root" && v == "pnpm:environment:importer:."));
    }
    #[test]
    fn missing_optional_and_required_refs_are_incomplete() {
        let g = parse(&LOCK.replace("p: 2.0.0", "p: 3.0.0"), None).unwrap();
        assert!(g.issues.iter().any(|i| i.contains("unresolved")));
        let g = parse(
            &LOCK.replace(
                "    dependencies:\n      p: 2.0.0",
                "    optionalDependencies:\n      p: 3.0.0",
            ),
            None,
        )
        .unwrap();
        assert_eq!(g.optional_omissions.len(), 1);
        assert!(g.issues.iter().any(|i| i.contains("optionalDependencies")));
    }
    #[test]
    fn root_manifest_specs_are_checked() {
        let m = MiniParser::parse_json(
            r#"{"dependencies":{"alias":"npm:a@^1","child":"workspace:*"}}"#,
        )
        .unwrap();
        assert_eq!(parse(LOCK, Some(&m)).unwrap().issues.len(), 1);
        let m = MiniParser::parse_json(r#"{"dependencies":{"alias":"npm:a@^2"}}"#).unwrap();
        assert!(parse(LOCK, Some(&m))
            .unwrap()
            .issues
            .iter()
            .any(|i| i.contains("disagree")));
    }
    #[test]
    fn rejects_unsupported_version_structure_and_duplicates() {
        for bad in [
            LOCK.replace("'9.0'", "'8.0'"),
            LOCK.replace("requiresBuild: true", "requiresBuild: yes"),
            LOCK.replace("gitHosted: true", "gitHosted: maybe"),
            LOCK.replace("gitHosted: true", "unknownResolution: true"),
            LOCK.replace("  p@2.0.0: {}", "  p@2.0.0: {}\n  p@2.0.0: {}"),
            LOCK.replace("version: 2.0.0", "version: &anchor 2.0.0"),
            LOCK.replace(
                "dependencies:\n      alias:",
                "dependencies: {alias: 1}\n      alias:",
            ),
        ] {
            assert!(parse(&bad, None).is_err(), "{bad}");
        }
    }
    #[test]
    fn v6_combines_metadata_and_edges_without_merging_peer_contexts() {
        let lock = "lockfileVersion: '6.0'\nimporters:\n  .:\n    dependencies:\n      alias:\n        specifier: npm:a@1\n        version: /a@1.0.0(p@2.0.0)\npackages:\n  /a@1.0.0(p@2.0.0):\n    resolution: {integrity: sha512-a}\n    dependencies:\n      p: 2.0.0\n  /a@1.0.0(p@3.0.0):\n    resolution: {integrity: sha512-b}\n    optionalDependencies:\n      p: 3.0.0\n  /p@2.0.0: {}\n  /p@3.0.0: {}\n";
        let g = parse(lock, None).unwrap();
        assert_eq!(g.packages.len(), 5);
        assert_eq!(
            g.packages["pnpm:project:snapshot:/a@1.0.0(p@2.0.0)"].name,
            "a"
        );
        assert!(edges(&g).contains(&(
            "root".into(),
            "pnpm:project:snapshot:/a@1.0.0(p@2.0.0)".into(),
            "dependencies".into()
        )));
        assert!(edges(&g).contains(&(
            "pnpm:project:snapshot:/a@1.0.0(p@3.0.0)".into(),
            "pnpm:project:snapshot:/p@3.0.0".into(),
            "optionalDependencies".into()
        )));
        assert_eq!(g.issues.len(), 1);
        let mixed = format!("{lock}snapshots:\n  a@1.0.0: {{}}\n");
        assert!(parse(&mixed, None).is_err());
        assert!(parse(&lock.replace("'6.0'", "'8.0'"), None).is_err());
    }
    #[test]
    fn retains_and_validates_resolution_checksums_and_importer_directories() {
        let lock = LOCK
            .replace(
                "importers:",
                "packageExtensionsChecksum: sha256-abc\npnpmfileChecksum: sha256-def\nimporters:",
            )
            .replace(
                "  packages/child:\n",
                "  packages/child:\n    linkDirectory: false\n    publishDirectory: dist\n",
            );
        let g = parse(&lock, None).unwrap();
        assert_eq!(
            g.resolution_metadata["pnpm:project:packageExtensionsChecksum"].as_str(),
            Some("sha256-abc")
        );
        assert_eq!(
            g.resolution_metadata["pnpm:project:pnpmfileChecksum"].as_str(),
            Some("sha256-def")
        );
        assert_eq!(
            g.resolution_metadata["pnpm:project:importer:packages/child"]
                .get("publishDirectory")
                .and_then(JsonNode::as_str),
            Some("dist")
        );
        for bad in [
            lock.replace("linkDirectory: false", "linkDirectory: no"),
            lock.replace("publishDirectory: dist", "publishDirectory: ../escape"),
            lock.replace("pnpmfileChecksum: sha256-def", "pnpmfileChecksum: {}"),
            lock.replace(
                "pnpmfileChecksum: sha256-def",
                "unknownChecksum: sha256-def",
            ),
        ] {
            assert!(parse(&bad, None).is_err(), "{bad}");
        }
    }
    #[test]
    fn unconditional_overrides_explain_manifest_specs_without_approving_source_policy() {
        let lock = "lockfileVersion: '9.0'\noverrides:\n  a: 2.0.0\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 2.0.0\n        version: 2.0.0\npackages:\n  a@2.0.0: {}\nsnapshots:\n  a@2.0.0: {}\n";
        let manifest = MiniParser::parse_json(r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        let g = parse(lock, Some(&manifest)).unwrap();
        assert!(!g.issues.iter().any(|i| i.contains("disagree")));
        assert!(g
            .issues
            .iter()
            .any(|i| i.contains("override source context unverified")));
        let mut inputs = crate::graph::ProjectInputs::new();
        inputs.insert(
            "pnpm-workspace.yaml".into(),
            b"packages:\n  - packages/*\noverrides:\n  a: 2.0.0\n".to_vec(),
        );
        let g = parse_with_inputs(lock, Some(&manifest), &inputs).unwrap();
        assert_eq!(g.issues.len(), 1);
        inputs.insert(
            "pnpm-workspace.yaml".into(),
            b"overrides:\n  a: 'catalog:'\ncatalog:\n  a: 2.0.0\n".to_vec(),
        );
        assert_eq!(
            parse_with_inputs(lock, Some(&manifest), &inputs)
                .unwrap()
                .issues
                .len(),
            1
        );
        inputs.insert(
            "pnpm-workspace.yaml".into(),
            b"overrides:\n  a: catalog:named\ncatalogs:\n  named:\n    a: 2.0.0\n".to_vec(),
        );
        assert_eq!(
            parse_with_inputs(lock, Some(&manifest), &inputs)
                .unwrap()
                .issues
                .len(),
            1
        );
        inputs.insert(
            "pnpm-workspace.yaml".into(),
            b"overrides:\n  a: 3.0.0\n".to_vec(),
        );
        assert!(parse_with_inputs(lock, Some(&manifest), &inputs)
            .unwrap()
            .issues
            .iter()
            .any(|i| i.contains("override source context")));
        assert!(parse(
            &lock.replace("  a: 2.0.0", "  a@^1: 2.0.0"),
            Some(&manifest)
        )
        .unwrap()
        .issues
        .iter()
        .any(|i| i.contains("disagree")));
    }
    #[test]
    fn supplied_local_link_manifest_keeps_a_source_identity_without_guessing_dependencies() {
        let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      alias:\n        specifier: link:fixtures/local\n        version: link:fixtures/local\n";
        let mut inputs = crate::graph::ProjectInputs::new();
        inputs.insert(
            "fixtures/local/package.json".into(),
            br#"{"name":"local","version":"1.0.0","dependencies":{"missing":"^1"}}"#.to_vec(),
        );
        let g = parse_with_inputs(lock, None, &inputs).unwrap();
        assert_eq!(g.packages["pnpm:project:link:fixtures/local"].name, "local");
        assert!(edges(&g).contains(&(
            "root".into(),
            "pnpm:project:link:fixtures/local".into(),
            "workspaceLink".into()
        )));
        assert!(g
            .issues
            .iter()
            .any(|i| i.contains("linked manifest dependency resolution unknown")));
        assert!(parse(lock, None)
            .unwrap()
            .issues
            .iter()
            .any(|i| i.contains("unresolved")));
        inputs.insert(
            "fixtures/local/package.json".into(),
            br#"{"name":5}"#.to_vec(),
        );
        let invalid = parse_with_inputs(lock, None, &inputs).unwrap();
        assert!(invalid
            .issues
            .iter()
            .any(|i| i.contains("invalid supplied linked manifest")));
        assert!(invalid.issues.iter().any(|i| i.contains("unresolved")));
        assert!(!invalid
            .packages
            .contains_key("pnpm:project:link:fixtures/local"));
        assert!(
            parse_with_inputs(&lock.replace("fixtures/local", "../escape"), None, &inputs)
                .unwrap()
                .issues
                .iter()
                .any(|i| i.contains("unresolved"))
        );
    }
    #[test]
    fn importer_build_metadata_and_publish_links_are_exact_and_retained() {
        let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependenciesMeta:\n      a:\n        built: true\n    dependencies:\n      a:\n        specifier: workspace:*\n        version: link:packages/a/dist\n  packages/a:\n    publishDirectory: dist\n";
        let g = parse(lock, None).unwrap();
        assert_eq!(g.issues.len(), 1);
        assert!(edges(&g).contains(&(
            "root".into(),
            "pnpm:project:importer:packages/a".into(),
            "workspaceLink".into()
        )));
        assert!(g.resolution_metadata["pnpm:project:importer:."]
            .get("dependenciesMeta")
            .is_some());
        assert!(parse(&lock.replace("built: true", "built: yes"), None).is_err());
        assert!(parse(&lock.replace("built: true", "unknown: true"), None).is_err());
        let disabled = lock.replace(
            "    publishDirectory: dist",
            "    publishDirectory: dist\n    linkDirectory: false",
        );
        assert!(parse(&disabled, None)
            .unwrap()
            .issues
            .iter()
            .any(|i| i.contains("unresolved")));
    }
    #[test]
    fn platform_runtime_variants_are_retained_without_selecting_a_host() {
        let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      node:\n        specifier: runtime:^26\n        version: runtime:26.0.0\npackages:\n  node@runtime:26.0.0:\n    resolution:\n      type: variations\n      variants:\n        - resolution:\n            archive: tarball\n            bin:\n              node: bin/node\n            integrity: sha256-a\n            type: binary\n            url: https://nodejs.org/node.tar.gz\n          targets:\n            - cpu: arm64\n              os: darwin\n        - resolution:\n            archive: zip\n            prefix: node-win\n            bin: node.exe\n            integrity: sha256-b\n            type: binary\n            url: https://nodejs.org/node.zip\n          targets:\n            - cpu: x64\n              os: win32\nsnapshots:\n  node@runtime:26.0.0: {}\n";
        let g = parse(lock, None).unwrap();
        let package = &g.packages["pnpm:project:snapshot:node@runtime:26.0.0"];
        assert!(package.source.contains("variants"));
        assert!(package.source.contains("sha256-a"));
        assert!(package.source.contains("sha256-b"));
        assert_eq!(g.issues.len(), 1);
        for bad in [
            lock.replace("archive: zip", "archive: rar"),
            lock.replace("prefix: node-win", "unknown: node-win"),
            lock.replace("              os: win32", "              unknown: win32"),
            lock.replace("      variants:", "      variants: {}"),
            lock.replace(
                "            bin: node.exe",
                "            bin: &anchor node.exe",
            ),
        ] {
            assert!(parse(&bad, None).is_err(), "{bad}");
        }
    }
    #[test]
    fn managed_runtime_manifest_projects_to_the_recorded_dependency_kind() {
        let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      node:\n        specifier: runtime:^26\n        version: runtime:26.0.0\npackages:\n  node@runtime:26.0.0: {}\nsnapshots:\n  node@runtime:26.0.0: {}\n";
        let manifest = MiniParser::parse_json(
            r#"{"devEngines":{"runtime":{"name":"node","version":"^26","onFail":"download"}}}"#,
        )
        .unwrap();
        assert_eq!(parse(lock, Some(&manifest)).unwrap().issues.len(), 1);
        let wrong_kind = lock.replace("    devDependencies:", "    dependencies:");
        assert!(parse(&wrong_kind, Some(&manifest))
            .unwrap()
            .issues
            .iter()
            .any(|i| i.contains("disagree")));
        let ambiguous = MiniParser::parse_json(r#"{"devEngines":{"runtime":[{"name":"node","version":"^26","onFail":"download"},{"name":"node","version":"^25","onFail":"download"}]}}"#).unwrap();
        assert!(parse(lock, Some(&ambiguous)).is_err());
        let ignored = MiniParser::parse_json(
            r#"{"devEngines":{"runtime":{"name":"node","version":"^26","onFail":"ignore"}}}"#,
        )
        .unwrap();
        assert!(parse(lock, Some(&ignored))
            .unwrap()
            .issues
            .iter()
            .any(|i| i.contains("disagree")));
    }
    #[test]
    fn alias_names_specifiers_and_patch_contexts_survive_graph_edge_deduplication() {
        let g = parse(LOCK, None).unwrap();
        let changed = parse(&LOCK.replace("      alias:", "      renamed:"), None).unwrap();
        assert_eq!(edges(&g), edges(&changed));
        assert_ne!(g.resolution_metadata, changed.resolution_metadata);
        let changed_snapshot = parse(
            &LOCK.replace("      p: 2.0.0", "      other: p@2.0.0"),
            None,
        )
        .unwrap();
        assert_ne!(g.resolution_metadata, changed_snapshot.resolution_metadata);
        let patched = LOCK.replace("a@1.0.0(p@2.0.0)", "a@1.0.0(patch_hash=abc)(p@2.0.0)");
        let g = parse(&patched, None).unwrap();
        assert!(g
            .packages
            .contains_key("pnpm:project:snapshot:a@1.0.0(patch_hash=abc)(p@2.0.0)"));
        assert_eq!(
            g.packages["pnpm:project:snapshot:a@1.0.0(patch_hash=abc)(p@2.0.0)"].integrity,
            "sha512-example"
        );
        assert_eq!(g.issues.len(), 1);
    }
    #[test]
    fn exact_multiple_versions_never_match_by_name_only() {
        let lock="lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 1\n        version: 1.0.0\npackages:\n  a@1.0.0: {}\n  a@2.0.0: {}\nsnapshots:\n  a@1.0.0:\n    dependencies:\n      a: 2.0.0\n  a@2.0.0: {}\n";
        let g = parse(lock, None).unwrap();
        assert!(edges(&g).contains(&(
            "root".into(),
            "pnpm:project:snapshot:a@1.0.0".into(),
            "dependencies".into()
        )));
        assert!(edges(&g).contains(&(
            "pnpm:project:snapshot:a@1.0.0".into(),
            "pnpm:project:snapshot:a@2.0.0".into(),
            "dependencies".into()
        )));
    }
}
