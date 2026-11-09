//! Yarn Berry descriptor snapshots. Peer constraints are not installed peer edges.
use crate::error::{GateError, Result};
use crate::graph::{DepGraph, PackageInfo, ProjectInputs};
use crate::graph_impl::DiGraph;
use crate::parser::{JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};

fn incomplete(message: impl Into<String>) -> GateError {
    GateError::Graph(format!("INCOMPLETE: Yarn Berry: {}", message.into()))
}

/// Read generated Berry lockfiles without invoking Yarn or materializing peer contexts.
pub fn parse(lock: &str, manifest: Option<&JsonNode>, inputs: &ProjectInputs) -> Result<DepGraph> {
    let source_root = inputs
        .get("package.json")
        .map(|b| super::source_manifest(b, "package.json"))
        .transpose()?;
    let manifest = manifest.or(source_root.as_ref());
    if let Some(manifest) = manifest {
        object(Some(manifest), "root manifest must be an object")?;
    }

    let document = read_mapping(lock)?;
    let metadata = object(document.get("__metadata"), "missing __metadata")?;
    for key in metadata.keys() {
        if !matches!(key.as_str(), "version" | "cacheKey") {
            return Err(incomplete(format!("unsupported metadata field {key}")));
        }
        scalar(metadata.get(key), key)?;
    }
    let version = scalar(metadata.get("version"), "metadata version")?;
    if !matches!(version, "6" | "8" | "10") {
        return Err(incomplete(format!(
            "unsupported lockfile version {version}"
        )));
    }
    if document.len() > 10_001 {
        return Err(incomplete("more than 10000 resolution records"));
    }
    let mut config = read_configuration(inputs)?;
    config.resolution_order = resolution_order(manifest, inputs)?;
    let mut result = DepGraph {
        graph: DiGraph::new(),
        execution_packages: BTreeSet::new(),
        suspicious_packages: BTreeSet::new(),
        packages: BTreeMap::new(),
        issues: vec!["Execution capabilities unknown: Yarn Berry lockfiles do not encode dependency lifecycle bodies; descriptor topology does not establish installed peer contexts or plugin execution behavior".into()],
        optional_omissions: Vec::new(),
        edge_kinds: BTreeMap::new(),
        resolution_metadata: BTreeMap::new(),
    };
    let mut selectors = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut indices = BTreeMap::new();
    let mut references = 0;
    let mut source_bytes = 0;
    for (group, value) in &document {
        if group == "__metadata" {
            continue;
        }
        let record = object(Some(value), "resolution record must be a mapping")?;
        validate_record(record, &mut references)?;
        let resolution = scalar(record.get("resolution"), "resolution")?;
        let (name, range) = super::descriptor(resolution)?;
        let path = range
            .strip_prefix("workspace:")
            .map(super::project_path)
            .transpose()?;
        let label = if path.as_deref() == Some(".") {
            "root".into()
        } else {
            format!("yarn:berry:{resolution}")
        };
        if records.insert(label.clone(), record).is_some() {
            return Err(incomplete(format!("duplicate resolution {resolution}")));
        }
        let idx = result.graph.add_node(label.clone());
        indices.insert(label.clone(), idx);
        let mut descriptors = Vec::new();
        for selector in group.split(',').map(str::trim) {
            super::descriptor(selector)?;
            if selectors.insert(selector.to_owned(), idx).is_some() {
                return Err(incomplete(format!("duplicate descriptor {selector}")));
            }
            if version == "6" {
                let (n, r) = super::descriptor(selector)?;
                let normalized = format!("{n}@{}", normalize(r, &config.protocol));
                if let Some(previous) = selectors.insert(normalized, idx) {
                    if previous != idx {
                        return Err(incomplete("conflicting normalized descriptors"));
                    }
                }
            }
            descriptors.push(JsonNode::String(selector.into()));
        }
        let mut retained = record.clone();
        retained.insert("descriptorGroup".into(), JsonNode::String(group.clone()));
        retained.insert("descriptors".into(), JsonNode::Array(descriptors));
        if record.contains_key("checksum") {
            retained.insert(
                "checksumKind".into(),
                JsonNode::String("yarn-cache-checksum".into()),
            );
            if let Some(cache_key) = metadata.get("cacheKey") {
                retained.insert("cacheKey".into(), cache_key.clone());
            }
        }
        if record.contains_key("peerDependencies") || record.contains_key("peerDependenciesMeta") {
            retained.insert(
                "peerTopology".into(),
                JsonNode::String(
                    "constraints only; installed peer contexts are not encoded".into(),
                ),
            );
        }
        if let Some(path) = &path {
            retained.insert("sourcePath".into(), JsonNode::String(path.clone()));
            let key = super::manifest_path(path);
            if let Some(bytes) = inputs.get(&key) {
                source_bytes += bytes.len();
                if source_bytes > 64 * 1024 * 1024 {
                    return Err(incomplete("source manifests exceed 64 MiB"));
                }
                let source = super::source_manifest(bytes, &key)?;
                let source_name = source.get("name").and_then(JsonNode::as_str);
                if source_name.is_some_and(|n| n != name) {
                    return Err(incomplete(format!("workspace name differs at {path}")));
                }
                retained.insert("sourceManifest".into(), source);
            } else if path == "." {
                if let Some(m) = manifest {
                    retained.insert("sourceManifest".into(), m.clone());
                }
            }
        }
        if path.is_some()
            && record
                .get("dependencies")
                .and_then(JsonNode::as_object)
                .is_some_and(|deps| !deps.is_empty())
        {
            if retained.contains_key("sourceManifest") {
                retained.insert(
                    "dependencyKinds".into(),
                    JsonNode::String("source-manifest declarations".into()),
                );
            } else {
                retained.insert(
                    "dependencyKinds".into(),
                    JsonNode::String(
                        "unknown; only merged lockfile dependencies are encoded".into(),
                    ),
                );
                result.issues.push(format!("Dependency kinds unknown: Yarn Berry workspace source manifest not supplied: {label}"));
            }
        }
        let mut capabilities = vec!["unknown (dependency lifecycle bodies are not encoded)".into()];
        if record
            .get("bin")
            .and_then(JsonNode::as_object)
            .is_some_and(|b| !b.is_empty())
        {
            capabilities.push("binary-entrypoint (not automatic installation execution)".into());
        }
        result.packages.insert(
            label.clone(),
            PackageInfo {
                path: label.clone(),
                name: name.into(),
                version: scalar(record.get("version"), "version")?.into(),
                source: resolution.into(),
                integrity: String::new(),
                capabilities,
            },
        );
        result
            .resolution_metadata
            .insert(label, JsonNode::Object(retained));
    }
    if !indices.contains_key("root") {
        indices.insert("root".into(), result.graph.add_node("root".into()));
        result.packages.insert(
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
        result
            .issues
            .push("Root attribution incomplete: Berry root workspace resolution is absent".into());
    }
    for (label, record) in &records {
        let from = indices[label];
        let parent = scalar(record.get("resolution"), "resolution")?;
        let (parent_name, parent_range) = super::descriptor(parent)?;
        let source_manifest = if parent_range.starts_with("workspace:") {
            result.resolution_metadata[label].get("sourceManifest")
        } else {
            None
        };
        let declared = source_manifest
            .map(declared_requirements)
            .transpose()?
            .unwrap_or_default();
        if source_manifest.is_some() {
            for name in declared.keys() {
                if !record
                    .get("dependencies")
                    .and_then(JsonNode::as_object)
                    .is_some_and(|deps| deps.contains_key(name))
                {
                    result.issues.push(format!("Manifest attribution incomplete: source requirement absent from Berry workspace lock dependencies: {label} -> {name}"));
                }
            }
        }
        if let Some(deps) = record.get("dependencies").and_then(JsonNode::as_object) {
            for (name, range) in deps {
                let range = range
                    .as_str()
                    .ok_or_else(|| incomplete("invalid dependency range"))?;
                let reduced =
                    reduce_requirement(name, range, parent_name, parent_range, manifest, &config)?;
                let root_locator = records
                    .get("root")
                    .and_then(|r| r.get("resolution"))
                    .and_then(JsonNode::as_str)
                    .unwrap_or(parent);
                let binding = if reduced.1 { root_locator } else { parent };
                let mut selector = bind_descriptor(name, &reduced.0, binding, &config.protocol);
                if matches!(name.as_str(), "typescript" | "resolve" | "fsevents")
                    && !reduced.0.starts_with("patch:")
                {
                    let patched = format!(
                        "{name}@patch:{}#optional!builtin<compat/{name}>",
                        selector
                            .replace('%', "%25")
                            .replace(':', "%3A")
                            .replace('#', "%23")
                    );
                    if selectors.contains_key(&patched) {
                        selector = patched;
                    }
                }
                let optional = record
                    .get("dependenciesMeta")
                    .and_then(|m| m.get(name))
                    .and_then(|m| m.get("optional"))
                    .and_then(JsonNode::as_str)
                    == Some("true");
                let kind = if optional {
                    "optionalDependencies"
                } else {
                    "dependencies"
                };
                let mut kinds = BTreeSet::from([kind.to_owned()]);
                if source_manifest.is_some() {
                    if let Some(requirements) = declared.get(name) {
                        let matches = requirements.iter().any(|(_, requirement)| {
                            normalize(requirement, &config.protocol)
                                == normalize(range, &config.protocol)
                        });
                        if !matches {
                            result.issues.push(format!("Manifest attribution incomplete: Berry workspace requirement differs from source manifest: {label} -> {name}@{range}"));
                        }
                        kinds = requirements.iter().map(|(kind, _)| kind.clone()).collect();
                        if optional {
                            kinds.remove("dependencies");
                            kinds.insert("optionalDependencies".into());
                        }
                    } else {
                        result.issues.push(format!("Manifest attribution incomplete: Berry workspace dependency absent from source manifest: {label} -> {name}"));
                    }
                }
                if let Some(&to) = selectors.get(&selector) {
                    result
                        .edge_kinds
                        .entry((from, to))
                        .or_default()
                        .extend(kinds);
                } else {
                    let issue = format!("unresolved {kind}: {label} -> {selector}");
                    if optional {
                        result.optional_omissions.push(issue);
                    } else {
                        result.issues.push(issue);
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

fn declared_requirements(manifest: &JsonNode) -> Result<BTreeMap<String, Vec<(String, String)>>> {
    let mut result = BTreeMap::<String, Vec<(String, String)>>::new();
    for kind in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(value) = manifest.get(kind) {
            for (name, range) in object(Some(value), "invalid source dependency mapping")? {
                let range = scalar(Some(range), "source dependency range")?;
                super::descriptor(&format!("{name}@{range}"))?;
                if kind == "dependencies"
                    && manifest
                        .get("optionalDependencies")
                        .and_then(JsonNode::as_object)
                        .is_some_and(|d| d.contains_key(name))
                {
                    continue;
                }
                result
                    .entry(name.clone())
                    .or_default()
                    .push((kind.into(), range.into()));
            }
        }
    }
    Ok(result)
}

fn object<'a>(node: Option<&'a JsonNode>, message: &str) -> Result<&'a BTreeMap<String, JsonNode>> {
    node.and_then(JsonNode::as_object)
        .ok_or_else(|| incomplete(message))
}
fn scalar<'a>(node: Option<&'a JsonNode>, message: &str) -> Result<&'a str> {
    node.and_then(JsonNode::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| incomplete(format!("invalid or missing {message}")))
}
fn validate_record(record: &BTreeMap<String, JsonNode>, references: &mut usize) -> Result<()> {
    for (key, value) in record {
        match key.as_str() {
            "version" | "resolution" | "checksum" | "languageName" | "conditions" => {
                scalar(Some(value), key)?;
            }
            "linkType" => {
                if !matches!(value.as_str(), Some("hard" | "soft")) {
                    return Err(incomplete("invalid linkType"));
                }
            }
            "dependencies" | "peerDependencies" | "bin" => {
                for (name, range) in object(Some(value), "invalid dependency or bin mapping")? {
                    let range = scalar(Some(range), "dependency or bin value")?;
                    if key != "bin" {
                        super::descriptor(&format!("{name}@{range}"))?;
                        *references += 1;
                    }
                }
            }
            "dependenciesMeta" | "peerDependenciesMeta" => {
                for (name, meta) in object(Some(value), "invalid dependency metadata")? {
                    super::descriptor(&format!("{name}@*"))?;
                    for (flag, value) in object(Some(meta), "invalid dependency metadata flags")? {
                        if !(flag == "optional"
                            || (key == "dependenciesMeta"
                                && matches!(flag.as_str(), "built" | "unplugged")))
                            || !matches!(value.as_str(), Some("true" | "false"))
                        {
                            return Err(incomplete("unsupported dependency metadata flag"));
                        }
                    }
                }
            }
            _ => return Err(incomplete(format!("unsupported resolution field {key}"))),
        }
    }
    for key in ["version", "resolution", "languageName", "linkType"] {
        scalar(record.get(key), key)?;
    }
    if *references > 50_000 {
        return Err(incomplete("more than 50000 dependency references"));
    }
    Ok(())
}

struct Configuration {
    protocol: String,
    catalogs: BTreeMap<String, JsonNode>,
    resolution_order: Option<Vec<String>>,
}
fn read_configuration(inputs: &ProjectInputs) -> Result<Configuration> {
    let mut config = Configuration {
        protocol: "npm:".into(),
        catalogs: BTreeMap::new(),
        resolution_order: None,
    };
    let Some(bytes) = inputs.get(".yarnrc.yml") else {
        return Ok(config);
    };
    if bytes.len() > 1024 * 1024 {
        return Err(incomplete(".yarnrc.yml exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| incomplete("non-UTF-8 .yarnrc.yml"))?;
    let mut relevant = String::new();
    let mut selected = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
            selected = ["catalog:", "catalogs:", "defaultProtocol:"]
                .iter()
                .any(|prefix| line.starts_with(prefix));
        }
        if selected {
            relevant.push_str(line);
            relevant.push('\n');
        }
    }
    let values = read_mapping(&relevant)?;
    if let Some(value) = values.get("defaultProtocol") {
        config.protocol = scalar(Some(value), "defaultProtocol")?.into();
        if config.protocol != "npm:" {
            return Err(incomplete("non-npm defaultProtocol is unsupported"));
        }
    }
    for key in ["catalog", "catalogs"] {
        if let Some(value) = values.get(key) {
            config.catalogs.insert(key.into(), value.clone());
        }
    }
    Ok(config)
}
fn normalize(range: &str, protocol: &str) -> String {
    if range.contains(':')
        || range.contains('/')
        || range.starts_with("../")
        || range.starts_with("./")
        || range.starts_with('/')
    {
        range.into()
    } else {
        format!("{protocol}{range}")
    }
}
fn bind_descriptor(name: &str, range: &str, parent: &str, protocol: &str) -> String {
    let range = normalize(range, protocol);
    let relative_patch = range
        .strip_prefix("patch:")
        .and_then(|r| r.split_once('#'))
        .is_some_and(|(_, paths)| {
            paths.split('&').any(|p| {
                let p = p.rsplit('!').next().unwrap_or(p);
                !p.starts_with("builtin<") && !p.starts_with("~/") && !p.starts_with('/')
            })
        });
    if (range.starts_with("link:")
        || range.starts_with("portal:")
        || range.starts_with("file:")
        || relative_patch)
        && !range.contains("::")
    {
        format!("{name}@{range}::locator={}", percent_encode(parent))
    } else {
        format!("{name}@{range}")
    }
}
fn percent_encode(value: &str) -> String {
    let mut result = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            result.push(b as char);
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}
type Specifier<'a> = (&'a str, Option<&'a str>);
fn specifier(value: &str) -> Result<Specifier<'_>> {
    if let Ok((name, range)) = super::descriptor(value) {
        if range.contains('/') {
            return Err(incomplete("slash in resolution pattern description"));
        }
        Ok((name, Some(range)))
    } else {
        super::descriptor(&format!("{value}@*"))?;
        Ok((value, None))
    }
}
fn resolution_pattern(pattern: &str) -> Result<(Option<Specifier<'_>>, Specifier<'_>)> {
    let mut splits = Vec::new();
    for (i, _) in pattern.match_indices('/') {
        if let (Ok(parent), Ok(dep)) = (specifier(&pattern[..i]), specifier(&pattern[i + 1..])) {
            splits.push((Some(parent), dep));
        }
    }
    if let Ok(dep) = specifier(pattern) {
        splits.push((None, dep));
    }
    if splits.len() != 1 {
        return Err(incomplete(format!(
            "unsupported resolution pattern {pattern}"
        )));
    }
    Ok(splits[0])
}
fn reduce_requirement(
    name: &str,
    range: &str,
    parent_name: &str,
    parent_range: &str,
    manifest: Option<&JsonNode>,
    config: &Configuration,
) -> Result<(String, bool)> {
    let mut targets = BTreeSet::new();
    if let Some(value) = manifest.and_then(|m| m.get("resolutions")) {
        let rules = object(Some(value), "invalid manifest resolutions")?;
        let keys = config
            .resolution_order
            .as_ref()
            .cloned()
            .unwrap_or_else(|| rules.keys().cloned().collect());
        for pattern in &keys {
            let target = &rules[pattern];
            let (parent, dep) = resolution_pattern(pattern)?;
            if dep.0 != name
                || dep.1.is_some_and(|r| {
                    normalize(r, &config.protocol) != normalize(range, &config.protocol)
                })
            {
                continue;
            }
            if let Some((p, r)) = parent {
                if p != parent_name
                    || r.is_some_and(|r| {
                        normalize(r, &config.protocol) != normalize(parent_range, &config.protocol)
                    })
                {
                    continue;
                }
            }
            targets.insert(scalar(Some(target), "resolution target")?.to_owned());
            if config.resolution_order.is_some() {
                break;
            }
        }
    }
    if targets.len() > 1 {
        return Err(incomplete(format!(
            "overlapping resolution rules for {name}@{range}"
        )));
    }
    let mut root_bound = !targets.is_empty();
    let mut reduced = targets.into_iter().next().unwrap_or_else(|| range.into());
    if let Some(catalog) = reduced.strip_prefix("catalog:") {
        root_bound = true;
        let entry = if catalog.is_empty() {
            config.catalogs.get("catalog").and_then(|c| c.get(name))
        } else {
            config
                .catalogs
                .get("catalogs")
                .and_then(|c| c.get(catalog))
                .and_then(|c| c.get(name))
        };
        reduced = scalar(entry, &format!("catalog entry {catalog}/{name}"))?.into();
        if reduced.starts_with("catalog:") {
            return Err(incomplete("recursive catalog entry"));
        }
    }
    Ok((reduced, root_bound))
}

fn resolution_order(
    manifest: Option<&JsonNode>,
    inputs: &ProjectInputs,
) -> Result<Option<Vec<String>>> {
    let Some(bytes) = inputs.get("package.json") else {
        return Ok(None);
    };
    let source = super::source_manifest(bytes, "package.json")?;
    if manifest.is_some_and(|m| m != &source) {
        return Err(incomplete(
            "root manifest differs from supplied package.json",
        ));
    }
    if let Some(value) = source.get("resolutions") {
        object(Some(value), "invalid root resolutions")?;
    }
    let text = std::str::from_utf8(bytes).map_err(|_| incomplete("non-UTF-8 root manifest"))?;
    let Some((_, start)) = ordered_keys(text)?
        .into_iter()
        .find(|(key, _)| key == "resolutions")
    else {
        return Ok(None);
    };
    let keys = ordered_keys(&text[start..])?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    Ok(Some(keys))
}
fn ordered_keys(text: &str) -> Result<Vec<(String, usize)>> {
    if !text.trim_start().starts_with('{') {
        return Err(incomplete("expected JSON object for ordered resolutions"));
    }
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut expect_key = false;
    let mut position = 0;
    let bytes = text.as_bytes();
    while position < bytes.len() {
        match bytes[position] {
            b'"' => {
                let start = position;
                position += 1;
                while position < bytes.len() {
                    match bytes[position] {
                        b'\\' => position += 2,
                        b'"' => {
                            position += 1;
                            break;
                        }
                        _ => position += 1,
                    }
                }
                if expect_key && depth == 1 {
                    let key = MiniParser::parse_json(&text[start..position])?
                        .as_str()
                        .ok_or_else(|| incomplete("invalid resolution key"))?
                        .to_owned();
                    while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
                        position += 1;
                    }
                    if bytes.get(position) != Some(&b':') {
                        return Err(incomplete("invalid root manifest key"));
                    }
                    position += 1;
                    while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
                        position += 1;
                    }
                    result.push((key, position));
                    expect_key = false;
                }
                continue;
            }
            b'{' | b'[' => {
                depth += 1;
                if depth == 1 {
                    expect_key = true;
                }
            }
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            b',' if depth == 1 => expect_key = true,
            _ => {}
        }
        position += 1;
    }
    Ok(result)
}

struct Line {
    indent: usize,
    key: String,
    value: Option<String>,
}
fn read_mapping(text: &str) -> Result<BTreeMap<String, JsonNode>> {
    if text.len() > 64 * 1024 * 1024 {
        return Err(incomplete("input exceeds 64 MiB"));
    }
    let mut lines = Vec::new();
    for original in text.trim_start_matches('\u{feff}').lines() {
        let line = original.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line.contains('\t') || line.chars().any(|c| c.is_control()) {
            return Err(incomplete("tabs and control characters are unsupported"));
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if indent % 2 != 0 || indent > 6 {
            return Err(incomplete("unsupported YAML indentation"));
        }
        let (key, rest) = mapping_entry(&line[indent..])?;
        let rest = rest.trim_start_matches(' ');
        let value = if rest.is_empty() || rest.starts_with('#') {
            None
        } else {
            Some(read_scalar(rest)?.0)
        };
        lines.push(Line { indent, key, value });
        if lines.len() > 200_000 {
            return Err(incomplete("more than 200000 YAML entries"));
        }
    }
    fn mapping(
        lines: &[Line],
        pos: &mut usize,
        indent: usize,
    ) -> Result<BTreeMap<String, JsonNode>> {
        let mut result = BTreeMap::new();
        while let Some(line) = lines.get(*pos) {
            if line.indent < indent {
                break;
            }
            if line.indent != indent {
                return Err(incomplete("unexpected YAML indentation"));
            }
            *pos += 1;
            let value = match &line.value {
                Some(value) => JsonNode::String(value.clone()),
                None => {
                    if lines.get(*pos).is_none_or(|next| next.indent != indent + 2) {
                        return Err(incomplete("empty or unindented mapping"));
                    }
                    JsonNode::Object(mapping(lines, pos, indent + 2)?)
                }
            };
            if result.insert(line.key.clone(), value).is_some() {
                return Err(incomplete(format!("duplicate YAML key {}", line.key)));
            }
        }
        Ok(result)
    }
    mapping(&lines, &mut 0, 0)
}
fn mapping_entry(text: &str) -> Result<(String, &str)> {
    if text.starts_with('"') {
        let (key, rest) = quoted(text)?;
        let rest = rest
            .strip_prefix(':')
            .ok_or_else(|| incomplete("mapping key requires colon"))?;
        if !rest.is_empty() && !rest.starts_with(' ') {
            return Err(incomplete("mapping value requires space"));
        }
        Ok((key, rest))
    } else {
        let index = text
            .char_indices()
            .find(|(i, c)| {
                *c == ':'
                    && text
                        .get(i + 1..)
                        .is_some_and(|s| s.is_empty() || s.starts_with(' '))
            })
            .map(|(i, _)| i)
            .ok_or_else(|| incomplete("mapping key requires colon"))?;
        let (key, rest) = text.split_at(index);
        if key.contains(" #") || key.ends_with(' ') {
            return Err(incomplete("unsupported mapping key syntax"));
        }
        let key = read_scalar(key)?.0;
        Ok((key, &rest[1..]))
    }
}
fn quoted(text: &str) -> Result<(String, &str)> {
    let mut escaped = false;
    for (i, c) in text.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            let value = MiniParser::parse_json(&text[..i + 1])?;
            return Ok((
                value
                    .as_str()
                    .ok_or_else(|| incomplete("invalid quoted scalar"))?
                    .into(),
                &text[i + 1..],
            ));
        }
    }
    Err(incomplete("unterminated quoted scalar"))
}
fn read_scalar(text: &str) -> Result<(String, &str)> {
    if text.starts_with('"') {
        let (value, rest) = quoted(text)?;
        if !(rest.trim().is_empty() || rest.starts_with(' ') && rest.trim_start().starts_with('#'))
        {
            return Err(incomplete("trailing scalar content"));
        }
        return Ok((value, rest));
    }
    let text = text
        .split(" #")
        .next()
        .unwrap_or(text)
        .trim_end_matches(' ');
    if text.is_empty()
        || text.starts_with(|c: char| "-?:,][{}#&*!|>'\"%@`".contains(c))
        || text.chars().any(|c| "[],{}\"'\\".contains(c))
        || text.contains(": ")
        || text.ends_with(':')
    {
        return Err(incomplete("unsupported YAML scalar syntax"));
    }
    Ok((text.into(), ""))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::MiniParser;

    #[test]
    fn descriptors_aliases_optional_peers_and_cache_checksums_are_preserved() {
        let lock = "__metadata:\n  version: 8\n  cacheKey: 10\n\n\"root@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"root@workspace:.\"\n  dependencies:\n    alias: \"npm:real@^1\"\n  peerDependencies:\n    peer: ^2\n  peerDependenciesMeta:\n    peer:\n      optional: true\n  languageName: unknown\n  linkType: soft\n\n\"alias@npm:real@^1, real@npm:^1\":\n  version: 1.2.0\n  resolution: \"real@npm:1.2.0\"\n  dependencies:\n    absent: \"npm:^1\"\n  dependenciesMeta:\n    absent:\n      optional: true\n  checksum: 10/cache-digest\n  languageName: node\n  linkType: hard\n";
        let root = MiniParser::parse_json(r#"{"name":"root","dependencies":{"alias":"npm:real@^1"},"peerDependencies":{"peer":"^2"}}"#).unwrap();
        let g = parse(lock, Some(&root), &ProjectInputs::new()).unwrap();
        assert_eq!(g.packages.len(), 2);
        let label = "yarn:berry:real@npm:1.2.0";
        assert_eq!(g.packages[label].name, "real");
        assert!(g.packages[label].integrity.is_empty());
        assert_eq!(
            g.resolution_metadata[label]
                .get("checksum")
                .and_then(JsonNode::as_str),
            Some("10/cache-digest")
        );
        assert_eq!(g.graph.edges().len(), 1);
        assert_eq!(g.optional_omissions.len(), 1);
        assert!(g.resolution_metadata["root"]
            .get("peerDependencies")
            .is_some());
        for invalid in [
            lock.replace("  version: 8", "  version: 99"),
            lock.replace(
                "  checksum: 10/cache-digest",
                "  checksum: 10/cache-digest\n  checksum: other",
            ),
            lock.replace("    absent: \"npm:^1\"", "    absent: *alias"),
        ] {
            assert!(parse(&invalid, Some(&root), &ProjectInputs::new()).is_err());
        }
    }
    fn record(group: &str, resolution: &str, body: &str) -> String {
        format!("\n{}:\n  version: 1.0.0\n  resolution: {}\n{body}  languageName: node\n  linkType: hard\n", crate::parser::json_string(group), crate::parser::json_string(resolution))
    }
    fn lock(records: &str) -> String {
        format!("__metadata:\n  version: 10\n  cacheKey: 10\n{records}")
    }
    #[test]
    fn resolutions_use_source_order_and_reject_unknown_precedence() {
        let records = record(
            "app@workspace:.",
            "app@workspace:.",
            "  dependencies:\n    parent: \"npm:1\"\n",
        ) + &record(
            "parent@npm:1",
            "parent@npm:1.0.0",
            "  dependencies:\n    target: \"npm:^1\"\n",
        ) + &record("target@npm:2", "target@npm:2.0.0", "")
            + &record("target@npm:3", "target@npm:3.0.0", "");
        let text = r#"{"name":"app","dependencies":{"parent":"1"},"resolutions":{"target":"3","parent/target":"2"}}"#;
        let root = MiniParser::parse_json(text).unwrap();
        let inputs = ProjectInputs::from([("package.json".into(), text.as_bytes().to_vec())]);
        let g = parse(&lock(&records), Some(&root), &inputs).unwrap();
        assert!(g
            .issues
            .iter()
            .all(|s| s.starts_with("Execution capabilities unknown:")));
        let parent = g
            .graph
            ._node_weights()
            .position(|n| n == "yarn:berry:parent@npm:1.0.0")
            .unwrap();
        let target = g
            .graph
            ._node_weights()
            .position(|n| n == "yarn:berry:target@npm:3.0.0")
            .unwrap();
        assert!(g.graph.edges().contains(&(parent, target)));
        assert!(parse(&lock(&records), Some(&root), &ProjectInputs::new()).is_err());
        let mismatch = MiniParser::parse_json("{}").unwrap();
        assert!(parse(&lock(&records), Some(&mismatch), &inputs).is_err());
    }
    #[test]
    fn catalogs_bound_links_and_relative_patch_resolutions_remain_exact() {
        let records = record("app@workspace:.", "app@workspace:.", "  dependencies:\n    leaf: \"catalog:dev\"\n    local: \"link:./local\"\n    patched: \"npm:^1\"\n")
            + &record("leaf@npm:^1", "leaf@npm:1.0.0", "  peerDependencies:\n    unrelated: \"*\"\n  bin:\n    leaf: ./run.js\n  conditions: os=linux\n")
            + &record("local@link:./local::locator=app%40workspace%3A.", "local@link:./local::locator=app%40workspace%3A.", "")
            + &record("patched@patch:patched@npm%3A1#./fix.patch::locator=app%40workspace%3A.", "patched@patch:patched@npm%3A1#./fix.patch::hash=abc&locator=app%40workspace%3A.", "");
        let root = MiniParser::parse_json(
            r#"{"name":"app","dependencies":{"leaf":"catalog:dev","local":"link:./local","patched":"^1"},"resolutions":{"patched":"patch:patched@npm%3A1#./fix.patch"}}"#,
        )
        .unwrap();
        let inputs = ProjectInputs::from([(
            ".yarnrc.yml".into(),
            b"catalogs:\n  dev:\n    leaf: ^1\nplugins:\n  - path: ignored.js\n".to_vec(),
        )]);
        let g = parse(&lock(&records), Some(&root), &inputs).unwrap();
        assert_eq!(g.graph.edges().len(), 3);
        assert_eq!(g.issues.len(), 1);
        assert_eq!(
            g.resolution_metadata["yarn:berry:leaf@npm:1.0.0"]
                .get("conditions")
                .and_then(JsonNode::as_str),
            Some("os=linux")
        );
        assert!(g.packages["yarn:berry:leaf@npm:1.0.0"]
            .capabilities
            .iter()
            .any(|s| s.starts_with("binary-entrypoint")));
        assert!(parse(&lock(&records), Some(&root), &ProjectInputs::new()).is_err());
        let invalid = ProjectInputs::from([(
            ".yarnrc.yml".into(),
            b"catalogs:\n  dev:\n    leaf: *anchor\n".to_vec(),
        )]);
        assert!(parse(&lock(&records), Some(&root), &invalid).is_err());
    }
    #[test]
    fn legacy_npm_descriptors_and_exact_builtin_patch_keys_are_retained() {
        let records = record("app@workspace:.", "app@workspace:.", "  dependencies:\n    leaf: ^1\n    typescript: ^5\n")
            + &record("leaf@^1", "leaf@npm:1.0.0", "  checksum: raw-cache-digest\n")
            + &record("typescript@npm:^5", "typescript@npm:5.0.0", "")
            + &record("typescript@patch:typescript@npm%3A^5#optional!builtin<compat/typescript>", "typescript@patch:typescript@npm%3A5.0.0#optional!builtin<compat/typescript>::version=5.0.0&hash=123", "");
        let g = parse(
            &lock(&records).replace("version: 10", "version: 6"),
            None,
            &ProjectInputs::new(),
        )
        .unwrap();
        assert_eq!(g.graph.edges().len(), 2);
        let destinations = g
            .graph
            .edges()
            .iter()
            .map(|(_, to)| g.graph.node_weight(*to).unwrap())
            .collect::<Vec<_>>();
        assert!(destinations.iter().any(|s| s.contains("typescript@patch:")));
        let leaf = "yarn:berry:leaf@npm:1.0.0";
        assert!(g.packages[leaf].integrity.is_empty());
        assert_eq!(
            g.resolution_metadata[leaf]
                .get("checksum")
                .and_then(JsonNode::as_str),
            Some("raw-cache-digest")
        );
        assert_eq!(
            g.resolution_metadata[leaf]
                .get("descriptorGroup")
                .and_then(JsonNode::as_str),
            Some("leaf@^1")
        );
    }
    #[test]
    fn duplicate_or_non_generated_yaml_is_rejected() {
        let valid = lock(
            &(record("app@workspace:.", "app@workspace:.", "")
                + &record("leaf@npm:1", "leaf@npm:1.0.0", "")),
        );
        for invalid in [
            valid.replace("  version: 1.0.0", "  version: &anchor 1.0.0"),
            valid.replace("  version: 1.0.0", "  version: '1.0.0'"),
            valid.replace("  version: 1.0.0", "   version: 1.0.0"),
            valid.replace("  version: 1.0.0", "  version: 1.0.0\n  unknown: value"),
            valid.replace(
                "  version: 1.0.0",
                "  version: 1.0.0\n  dependencies: {leaf: 1}",
            ),
            valid.replace(
                "  languageName: node",
                "  languageName: node\n  peerDependencies:\n    peer: \"*\"\n    peer: ^1",
            ),
            valid.clone() + &record("leaf@npm:1", "leaf@npm:2.0.0", ""),
            valid.clone() + &record("other@npm:1", "leaf@npm:1.0.0", ""),
            valid.replace("  version: 10", "  version # comment: 10"),
        ] {
            assert!(
                parse(&invalid, None, &ProjectInputs::new()).is_err(),
                "{invalid}"
            );
        }
        for source in [
            r#"{"resolutions":3}"#,
            r#"{"resolutions":[]}"#,
            r#"{"resolutions":"invalid"}"#,
        ] {
            let root = MiniParser::parse_json(source).unwrap();
            let inputs = ProjectInputs::from([("package.json".into(), source.as_bytes().to_vec())]);
            assert!(parse(&valid, Some(&root), &inputs).is_err());
        }
    }
    #[test]
    fn workspace_source_manifests_preserve_dev_and_optional_dependency_kinds() {
        let records = record("app@workspace:.", "app@workspace:.", "  dependencies:\n    leaf: \"npm:^1\"\n  dependenciesMeta:\n    leaf:\n      optional: true\n")
            + &record("leaf@npm:^1", "leaf@npm:1.0.0", "");
        let root = MiniParser::parse_json(r#"{"name":"app","devDependencies":{"leaf":"^1"},"dependenciesMeta":{"leaf":{"optional":true}}}"#).unwrap();
        let g = parse(&lock(&records), Some(&root), &ProjectInputs::new()).unwrap();
        let kinds = g.edge_kinds.values().next().unwrap();
        assert!(kinds.contains("devDependencies"));
        assert!(kinds.contains("optionalDependencies"));
        let missing = parse(&lock(&records), None, &ProjectInputs::new()).unwrap();
        assert!(missing
            .issues
            .iter()
            .any(|s| s.starts_with("Dependency kinds unknown:")));
        let stale =
            MiniParser::parse_json(r#"{"name":"app","devDependencies":{"leaf":"^2"}}"#).unwrap();
        let stale = parse(&lock(&records), Some(&stale), &ProjectInputs::new()).unwrap();
        assert!(stale
            .issues
            .iter()
            .any(|s| s.starts_with("Manifest attribution incomplete:")));
    }
}
