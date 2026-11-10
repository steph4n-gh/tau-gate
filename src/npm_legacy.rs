//! npm v1 installed locations and requires edges. Dependency kinds and lifecycle
//! capabilities cannot be recovered from the legacy lockfile.
use super::{
    npm_target, DepGraph, PackageInfo, DEPENDENCY_KINDS, MAX_NPM_RECORDS, MAX_NPM_REFERENCES,
};
use crate::error::{GateContext, GateError, Result};
use crate::graph_impl::DiGraph;
use crate::parser::{JsonNode, MiniParser};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn parse(root: &JsonNode, manifest: Option<&JsonNode>) -> Result<DepGraph> {
    if root.get("packages").is_some() {
        return Err(GateError::Graph(
            "INCOMPLETE: npm v1 has a competing packages map".into(),
        ));
    }
    if manifest.is_some_and(|m| m.as_object().is_none()) {
        return Err(GateError::Graph("Manifest must be an object".into()));
    }
    let empty = BTreeMap::new();
    let dependencies = match root.get("dependencies") {
        Some(dependencies) => dependencies
            .as_object()
            .context("Invalid npm v1 dependencies map")?,
        None => &empty,
    };
    let mut records = BTreeMap::new();
    let mut references = 0;
    collect("", dependencies, &mut records, &mut references)?;
    let mut result = DepGraph {
        graph: DiGraph::new(),
        execution_packages: BTreeSet::new(),
        suspicious_packages: BTreeSet::new(),
        packages: BTreeMap::new(),
        issues: vec![
            "Execution capabilities unknown: npm v1 does not encode dependency lifecycle scripts or binaries; an empty execution inventory is not proof of absence".into(),
            "Dependency kinds unknown: npm v1 requires records do not distinguish runtime, optional or peer dependency edges".into(),
        ],
        optional_omissions: Vec::new(),
        edge_kinds: BTreeMap::new(),
        resolution_metadata: BTreeMap::new(),
    };
    if root
        .get("preserveSymlinks")
        .is_some_and(|v| v.as_bool() != Some(false))
    {
        result
            .issues
            .push("INCOMPLETE: npm v1 preserveSymlinks resolution is unqualified".into());
    }
    let mut indices = BTreeMap::new();
    indices.insert(String::new(), result.graph.add_node("root".into()));
    let root_record = manifest.unwrap_or(root);
    result.packages.insert(
        "root".into(),
        PackageInfo {
            path: String::new(),
            name: field(root_record, "name", "root")?.to_owned(),
            version: field(root_record, "version", "root")?.to_owned(),
            source: String::new(),
            integrity: String::new(),
            capabilities: Vec::new(),
        },
    );
    for (path, (installed_name, details)) in &records {
        indices.insert(path.clone(), result.graph.add_node(path.clone()));
        let raw_version = field(details, "version", path)?;
        let (name, version) = if let Some(alias) = raw_version.strip_prefix("npm:") {
            let (name, version) = alias
                .rsplit_once('@')
                .context("INCOMPLETE: invalid npm v1 alias")?;
            if !valid_name(name) || version.is_empty() {
                return Err(GateError::Graph("INCOMPLETE: invalid npm v1 alias".into()));
            }
            (name, version)
        } else {
            (*installed_name, raw_version)
        };
        if raw_version.is_empty() {
            result.issues.push(format!("missing version: {path}"));
        }
        let resolved = field(details, "resolved", path)?;
        let source = if resolved.is_empty() && non_registry_spec(raw_version) {
            raw_version
        } else {
            resolved
        };
        if MiniParser::detect_obfuscation(path) {
            result.suspicious_packages.insert(path.clone());
        }
        result.packages.insert(
            path.clone(),
            PackageInfo {
                path: path.clone(),
                name: name.into(),
                version: version.into(),
                source: source.into(),
                integrity: field(details, "integrity", path)?.into(),
                capabilities: Vec::new(),
            },
        );
        let metadata = details
            .as_object()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.as_str() != "dependencies")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        result
            .resolution_metadata
            .insert(path.clone(), JsonNode::Object(metadata));
    }
    for (path, (_, record)) in &records {
        if let Some(requires) = record.get("requires") {
            for (name, requirement) in requires
                .as_object()
                .context("Invalid npm v1 requires map")?
            {
                requirement.as_str().context("Invalid npm v1 requirement")?;
                if !valid_name(name) {
                    return Err(GateError::Graph(
                        "INCOMPLETE: invalid npm v1 dependency name".into(),
                    ));
                }
                if let Some(target) = npm_target(path, name, &indices) {
                    result
                        .edge_kinds
                        .entry((indices[path], target))
                        .or_default()
                        .insert("requires".into());
                } else {
                    result
                        .issues
                        .push(format!("unresolved requires: {path} -> {name}"));
                }
            }
        }
    }
    if let Some(manifest) = manifest {
        for kind in DEPENDENCY_KINDS {
            if let Some(dependencies) = manifest.get(kind) {
                let dependencies = dependencies.as_object().context("Invalid dependency map")?;
                references += dependencies.len();
                reference_limit(references)?;
                for (name, requirement) in dependencies {
                    requirement
                        .as_str()
                        .context("Invalid dependency requirement")?;
                    if !valid_name(name) {
                        return Err(GateError::Graph(
                            "INCOMPLETE: invalid npm v1 dependency name".into(),
                        ));
                    }
                    if kind == "dependencies"
                        && manifest
                            .get("optionalDependencies")
                            .and_then(JsonNode::as_object)
                            .is_some_and(|m| m.contains_key(name))
                    {
                        continue;
                    }
                    if let Some(target) = npm_target("", name, &indices) {
                        result
                            .edge_kinds
                            .entry((indices[""], target))
                            .or_default()
                            .insert(kind.into());
                    } else if kind == "optionalDependencies"
                        || (kind == "peerDependencies"
                            && manifest
                                .get("peerDependenciesMeta")
                                .and_then(|m| m.get(name))
                                .and_then(|m| m.get("optional"))
                                .and_then(JsonNode::as_bool)
                                == Some(true))
                    {
                        result
                            .optional_omissions
                            .push(format!("absent {kind}: root -> {name}"));
                    } else {
                        result
                            .issues
                            .push(format!("unresolved {kind}: root -> {name}"));
                    }
                }
            }
        }
    } else {
        result.issues.push("Root attribution incomplete: npm v1 requires a supplied package.json; hoisted records are not assumed direct dependencies".into());
    }
    for &(from, to) in result.edge_kinds.keys() {
        result.graph.add_edge(from, to);
    }
    Ok(result)
}

fn collect<'a>(
    parent: &str,
    dependencies: &'a BTreeMap<String, JsonNode>,
    records: &mut BTreeMap<String, (&'a str, &'a JsonNode)>,
    references: &mut usize,
) -> Result<()> {
    for (name, record) in dependencies {
        if !valid_name(name) {
            return Err(GateError::Graph(
                "INCOMPLETE: invalid npm v1 dependency name".into(),
            ));
        }
        let path = if parent.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{parent}/node_modules/{name}")
        };
        let object = record
            .as_object()
            .context("Invalid npm v1 package record")?;
        for key in ["version", "resolved", "integrity"] {
            field(record, key, &path)?;
        }
        for key in ["dev", "optional", "bundled"] {
            if record.get(key).is_some_and(|v| v.as_bool().is_none()) {
                return Err(GateError::Graph(format!("Invalid {key} in {path}")));
            }
        }
        if let Some(requires) = object.get("requires") {
            *references += requires
                .as_object()
                .context("Invalid npm v1 requires map")?
                .len();
            reference_limit(*references)?;
        }
        records.insert(path.clone(), (name, record));
        if records.len() >= MAX_NPM_RECORDS {
            return Err(GateError::Graph(
                "INCOMPLETE: npm snapshot exceeds 10000 package records".into(),
            ));
        }
        if let Some(nested) = object.get("dependencies") {
            collect(
                &path,
                nested
                    .as_object()
                    .context("Invalid npm v1 dependencies map")?,
                records,
                references,
            )?;
        }
    }
    Ok(())
}

fn field<'a>(record: &'a JsonNode, key: &str, path: &str) -> Result<&'a str> {
    match record.get(key) {
        None => Ok(""),
        Some(value) => value
            .as_str()
            .ok_or_else(|| GateError::Graph(format!("Invalid {key} in {path}"))),
    }
}

fn valid_name(name: &str) -> bool {
    let parts: Vec<_> = name.split('/').collect();
    let valid_part = |part: &str| {
        !part.is_empty()
            && !matches!(part, "." | ".." | "node_modules")
            && !part
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\\' | ':' | '@'))
    };
    if let Some(scope) = parts.first().and_then(|s| s.strip_prefix('@')) {
        parts.len() == 2 && valid_part(scope) && valid_part(parts[1])
    } else {
        parts.len() == 1 && valid_part(name)
    }
}

fn non_registry_spec(spec: &str) -> bool {
    spec.starts_with("file:")
        || spec.starts_with("git")
        || spec.starts_with("http:")
        || spec.starts_with("https:")
}

fn reference_limit(references: usize) -> Result<()> {
    if references > MAX_NPM_REFERENCES {
        Err(GateError::Graph(
            "INCOMPLETE: npm snapshot exceeds 50000 dependency references".into(),
        ))
    } else {
        Ok(())
    }
}
