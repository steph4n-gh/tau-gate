//! Exact pnpm v9 lockfile inventory. This is a reader of pnpm's emitted YAML subset,
//! not a YAML implementation or an installed-file / lifecycle-script inspection.
use crate::error::{GateError, Result};
use crate::graph::{DepGraph, PackageInfo};
use crate::graph_impl::DiGraph;
use crate::parser::{JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Document {
    version: Option<String>,
    importers: BTreeMap<String, Importer>,
    packages: BTreeMap<String, Package>,
    snapshots: BTreeMap<String, Snapshot>,
}
#[derive(Default)]
struct Importer {
    dependencies: BTreeMap<String, BTreeMap<String, Requirement>>,
}
#[derive(Default)]
struct Requirement {
    specifier: String,
    version: String,
}
#[derive(Default)]
struct Package {
    resolution: BTreeMap<String, String>,
    name: Option<String>,
    version: Option<String>,
    capabilities: BTreeSet<String>,
    execution: bool,
}
#[derive(Default)]
struct Snapshot {
    dependencies: BTreeMap<String, BTreeMap<String, String>>,
}
struct Line<'a> {
    number: usize,
    indent: usize,
    text: &'a str,
}

/// Read both the environment document (when present) and the project document.
/// Snapshot labels preserve peer contexts; importer labels preserve workspace paths.
/// Every result is capability-incomplete: pnpm v9 does not record a reliable negative
/// lifecycle capability marker. Positive build markers remain visible when present.
pub fn parse(lock: &str, manifest: Option<&JsonNode>) -> Result<DepGraph> {
    let documents = MiniParser::parse_pnpm_v9(lock)?;
    let mut result = DepGraph {
        graph: DiGraph::new(),
        execution_packages: BTreeSet::new(),
        suspicious_packages: BTreeSet::new(),
        packages: BTreeMap::new(),
        issues: vec!["Execution capabilities unknown: pnpm v9 packages and workspace importers whose manifests were not inspected; absent build markers do not establish absence of lifecycle execution".into()],
        optional_omissions: Vec::new(),
        edge_kinds: BTreeMap::new(),
    };
    let mut indices = BTreeMap::new();
    let last = documents.len() - 1;
    for (doc_index, document) in documents.iter().enumerate() {
        let scope = scope(doc_index, last);
        for (path, importer) in &document.importers {
            let label = importer_label(scope, path);
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
                    check_manifest(m, importer, &mut result.issues)?;
                }
            }
        }
        let mut used_metadata = BTreeSet::new();
        for id in document.snapshots.keys() {
            let label = snapshot_label(scope, id);
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
            let integrity = resolution.remove("integrity").unwrap_or_default();
            let source = if resolution.is_empty() {
                String::new()
            } else {
                JsonNode::Object(
                    resolution
                        .into_iter()
                        .map(|(k, v)| (k, JsonNode::String(v)))
                        .collect(),
                )
                .to_json()
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
                    match target_label(scope, path, name, &requirement.version, document) {
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
                    match target_label(scope, ".", name, version, document) {
                        Some(target) => add_edge(&mut result, from, indices[&target], kind),
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
) -> Option<String> {
    if let Some(relative) = version.strip_prefix("link:") {
        let path = relative_workspace(importer, relative)?;
        return document
            .importers
            .contains_key(&path)
            .then(|| importer_label(scope, &path));
    }
    // Aliases carry the real package identity, not the importer alias name.
    let id = if let Some(actual) = version.strip_prefix("npm:") {
        actual.to_string()
    } else if document.snapshots.contains_key(version) {
        version.to_string()
    } else {
        format!("{name}@{version}")
    };
    document
        .snapshots
        .contains_key(&id)
        .then(|| snapshot_label(scope, &id))
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
    issues: &mut Vec<String>,
) -> Result<()> {
    if manifest.as_object().is_none() {
        return Err(incomplete("root manifest must be a JSON object"));
    }
    for key in ["name", "version"] {
        if manifest.get(key).is_some_and(|v| v.as_str().is_none()) {
            return Err(incomplete("root manifest name/version must be strings"));
        }
    }
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
        let locked: BTreeMap<_, _> = importer
            .dependencies
            .get(kind)
            .into_iter()
            .flat_map(|d| d.iter())
            .map(|(name, req)| (name.clone(), req.specifier.clone()))
            .collect();
        if declared != locked {
            issues.push(format!("manifest/lock root {kind} disagree"));
        }
    }
    Ok(())
}

impl MiniParser {
    fn parse_pnpm_v9(content: &str) -> Result<Vec<Document>> {
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
            if document.version.as_deref() != Some("9.0") {
                return Err(incomplete("only pnpm lockfileVersion 9.0 is supported"));
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
            // These are policy / selection metadata, not resolved graph references.
            "settings" | "overrides" | "patchedDependencies" | "catalogs" | "catalog" | "time" => {}
            _ => return Err(line_error(line, "unsupported top-level pnpm field")),
        }
        at = end;
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
            "resolution" => {
                package.resolution = if value.is_empty() {
                    fields(body, 6)?
                        .into_iter()
                        .map(|(l, k, v, b)| {
                            if !b.is_empty() {
                                Err(line_error(l, "nested pnpm resolution"))
                            } else {
                                Ok((k, scalar(v)?))
                            }
                        })
                        .collect::<Result<_>>()?
                } else {
                    if !body.is_empty() {
                        return Err(line_error(line, "inline resolution has nested content"));
                    }
                    flow_map(value)?
                };
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
    const LOCK:&str="lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      alias:\n        specifier: npm:a@^1\n        version: a@1.0.0(p@2.0.0)\n      child:\n        specifier: workspace:*\n        version: link:packages/child\n  packages/child:\n    devDependencies:\n      p:\n        specifier: ^2\n        version: 2.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-example}\n    requiresBuild: true\n  p@2.0.0:\n    resolution:\n      tarball: 'https://registry.example/p.tgz'\n      integrity: sha512-peer\n      revision: 1\nsnapshots:\n  a@1.0.0(p@2.0.0):\n    dependencies:\n      p: 2.0.0\n  p@2.0.0: {}\n";
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
            LOCK.replace("'9.0'", "'6.0'"),
            LOCK.replace("requiresBuild: true", "requiresBuild: yes"),
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
