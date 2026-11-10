use crate::{
    artifact,
    digest::sha256,
    graph::DepGraph,
    parser::{JsonNode as J, MiniParser},
    review::{object, string},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST: u64 = 1024 * 1024;
const DEPENDENCY_EVENTS: &[&str] = &["preinstall", "install", "postinstall"];
const ROOT_EVENTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Qualified,
    Missing,
    Unsupported,
    Conflict,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Artifact,
    BundledArtifact {
        parent: String,
        source: String,
        integrity: String,
    },
    SourceProject,
    WorkspaceLink(String),
}
#[derive(Clone, Debug, PartialEq)]
struct Facts {
    name: Option<String>,
    version: Option<String>,
    kind: Kind,
    artifact_sha512: Option<String>,
    manifest_sha256: String,
    lifecycle: BTreeMap<String, String>,
    binding_gyp_sha256: Option<String>,
    gypfile_false: bool,
    implicit_node_gyp: bool,
    binary_entrypoints: J,
    active_lifecycle: bool,
    install_candidate: bool,
}
impl Facts {
    fn candidate(&self) -> bool {
        self.implicit_node_gyp || self.active_lifecycle
    }
    fn kind(&self) -> &'static str {
        match self.kind {
            Kind::Artifact => "artifact",
            Kind::BundledArtifact { .. } => "bundled_artifact",
            Kind::SourceProject => "source_project",
            Kind::WorkspaceLink(_) => "workspace_link",
        }
    }
    fn json(&self) -> J {
        let mut value = object([
            ("kind", string(self.kind())),
            ("name", optional(&self.name)),
            ("version", optional(&self.version)),
            (
                "workspace_target",
                match &self.kind {
                    Kind::WorkspaceLink(t) => string(t),
                    _ => J::Null,
                },
            ),
            ("artifact_sha512", optional(&self.artifact_sha512)),
            ("manifest_sha256", string(&self.manifest_sha256)),
            (
                "lifecycle",
                J::Object(
                    self.lifecycle
                        .iter()
                        .map(|(k, v)| (k.clone(), string(v)))
                        .collect(),
                ),
            ),
            ("binding_gyp", J::Bool(self.binding_gyp_sha256.is_some())),
            ("binding_gyp_sha256", optional(&self.binding_gyp_sha256)),
            ("gypfile_false", J::Bool(self.gypfile_false)),
            ("implicit_node_gyp", J::Bool(self.implicit_node_gyp)),
            ("binary_entrypoints", self.binary_entrypoints.clone()),
        ]);
        if let Kind::BundledArtifact {
            parent,
            source,
            integrity,
        } = &self.kind
        {
            if let J::Object(fields) = &mut value {
                fields.insert("bundle_parent".into(), string(parent));
                fields.insert("bundle_parent_source".into(), string(source));
                fields.insert("bundle_parent_integrity".into(), string(integrity));
            }
        }
        value
    }
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExecutionEvidence {
    state: State,
    facts: Option<Facts>,
    verified_artifact_sha512: Option<String>,
    marker: Option<bool>,
    reason: Option<String>,
    fingerprint: Option<String>,
}
impl ExecutionEvidence {
    fn unknown(state: State, marker: Option<bool>, reason: impl Into<String>) -> Self {
        Self {
            state,
            facts: None,
            verified_artifact_sha512: None,
            marker,
            reason: Some(reason.into()),
            fingerprint: None,
        }
    }
    pub(crate) fn qualified(&self) -> bool {
        self.state == State::Qualified
    }
    pub(crate) fn manifest_hash(&self) -> Option<&str> {
        self.facts
            .as_ref()
            .map(|facts| facts.manifest_sha256.as_str())
    }
    pub(crate) fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
    pub(crate) fn candidate(&self) -> bool {
        if self
            .facts
            .as_ref()
            .is_some_and(|f| matches!(f.kind, Kind::WorkspaceLink(_)))
        {
            return false;
        }
        self.facts
            .as_ref()
            .map_or(self.marker == Some(true), Facts::candidate)
    }
    pub(crate) fn capabilities(&self) -> Vec<String> {
        let Some(f) = &self.facts else {
            return Vec::new();
        };
        let mut caps: Vec<_> = f
            .lifecycle
            .iter()
            .map(|(event, hash)| format!("lifecycle:{event}:sha256:{hash}"))
            .collect();
        if f.implicit_node_gyp {
            caps.push("implicit-node-gyp-rebuild".into());
        }
        if f.binary_entrypoints != J::Null {
            caps.push("binary-entrypoint (not automatic installation execution)".into());
        }
        caps
    }
    pub(crate) fn json(&self, path: &str) -> J {
        object([
            ("path", string(path)),
            (
                "state",
                string(match self.state {
                    State::Qualified => "qualified",
                    State::Missing => "missing",
                    State::Unsupported => "unsupported",
                    State::Conflict => "conflict",
                }),
            ),
            (
                "locked_install_marker",
                self.marker.map(J::Bool).unwrap_or(J::Null),
            ),
            ("candidate", J::Bool(self.candidate())),
            (
                "facts",
                self.facts.as_ref().map(Facts::json).unwrap_or(J::Null),
            ),
            (
                "verified_artifact_sha512",
                optional(&self.verified_artifact_sha512),
            ),
            ("reason", optional(&self.reason)),
            ("approval_fingerprint", optional(&self.fingerprint)),
        ])
    }
}
pub(crate) type Evidence = BTreeMap<String, ExecutionEvidence>;
fn optional(value: &Option<String>) -> J {
    value.as_ref().map(string).unwrap_or(J::Null)
}
fn parse(bytes: &[u8]) -> Result<J, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "evidence JSON must be UTF-8".to_owned())?;
    MiniParser::parse_json(text).map_err(|e| e.to_string())
}
pub(crate) fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    read_regular_into(path, limit, &mut bytes, None)?;
    Ok(bytes)
}
fn read_regular_into(
    path: &Path,
    limit: u64,
    bytes: &mut Vec<u8>,
    mut budget: Option<&mut artifact::Budget>,
) -> Result<(), String> {
    bytes.clear();
    if let Some(budget) = &budget {
        budget.check()?;
    }
    let limit = budget
        .as_ref()
        .map_or(limit, |budget| limit.min(budget.read_remaining));
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("input is not a regular file".into());
    }
    let read = (&mut file).take(limit + 1).read_to_end(bytes);
    if let Some(budget) = &mut budget {
        budget.read(bytes.len())?;
    }
    read.map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!("input exceeds {limit} bytes"));
    }
    Ok(())
}
pub(crate) fn safe_relative(value: &str, empty: bool) -> Result<(), String> {
    if value.is_empty() && empty {
        return Ok(());
    }
    if value.is_empty()
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || Path::new(value)
            .components()
            .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err(format!("unsafe relative path {value:?}"));
    }
    Ok(())
}
pub(crate) fn confined(root: &Path, value: &str) -> Result<PathBuf, String> {
    safe_relative(value, false)?;
    let mut path = root.to_path_buf();
    for component in value.split('/') {
        path.push(component);
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("symlink in evidence path {}", path.display()));
        }
    }
    Ok(path)
}
fn keys(value: &J, expected: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.len() == expected.len() && expected.iter().all(|k| m.contains_key(*k)))
}
fn registry(path: &str) -> bool {
    path.starts_with("node_modules/") || path.contains("/node_modules/")
}
fn direct_bundle_name(relative: &str) -> Option<&str> {
    let name = relative.strip_prefix("node_modules/")?;
    if name.is_empty() || name.contains("/node_modules/") {
        return None;
    }
    if name.starts_with('@') {
        let (scope, package) = name.split_once('/')?;
        (scope.len() > 1 && !package.is_empty() && !package.contains('/')).then_some(name)
    } else {
        (!name.contains('/')).then_some(name)
    }
}
fn declared_bundles(manifest: &J) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let dependencies: BTreeSet<String> = ["dependencies", "optionalDependencies"]
        .into_iter()
        .filter_map(|field| manifest.get(field).and_then(J::as_object))
        .flat_map(|values| values.keys().cloned())
        .collect();
    if manifest.get("bundleDependencies").is_some() && manifest.get("bundledDependencies").is_some()
    {
        return names;
    }
    match manifest
        .get("bundleDependencies")
        .or_else(|| manifest.get("bundledDependencies"))
    {
        Some(J::Array(values)) => {
            for value in values {
                if let Some(name) = value.as_str() {
                    if dependencies.contains(name) {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
        Some(J::Bool(true)) => {
            names = dependencies;
        }
        _ => {}
    }
    names
}
fn direct_archive_source(source: &str) -> bool {
    let Some(url) = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("http://"))
    else {
        return false;
    };
    let Some((authority, path)) = url.split_once('/') else {
        return false;
    };
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || host.split('.').any(|label| {
            label.is_empty()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
        || port.is_some_and(|p| {
            p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || p.parse::<u16>().ok().is_none_or(|n| n == 0)
        })
    {
        return false;
    }
    let host = host.to_ascii_lowercase();
    if [
        "github.com",
        "gist.github.com",
        "gitlab.com",
        "bitbucket.org",
        "git.sr.ht",
    ]
    .iter()
    .any(|forge| {
        host == *forge
            || host
                .strip_suffix(forge)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }) {
        return false;
    }
    (path.ends_with(".tgz") || path.ends_with(".tar.gz"))
        && path.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'@' | b'+')
        })
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

struct Work {
    compressed: Vec<u8>,
    budget: artifact::Budget,
}

struct ReadFacts {
    facts: Result<Facts, String>,
    verified_artifact_sha512: Option<String>,
    nested: BTreeMap<String, artifact::NestedArtifact>,
    declared_bundles: BTreeSet<String>,
}

struct BundleInput<'a> {
    nested: &'a artifact::NestedArtifact,
    parent: &'a str,
    source: &'a str,
    integrity: &'a str,
    sha512: &'a str,
}

enum FactSource<'a> {
    Direct(&'a BTreeSet<String>),
    Bundle(BundleInput<'a>),
}

pub(crate) fn load(
    lock: &J,
    lock_hash: &str,
    index_path: &Path,
    root_hash: Option<&str>,
) -> Result<(Evidence, String), String> {
    let index_bytes = read_regular(index_path, MAX_FILE)?;
    let index_hash = sha256(&index_bytes);
    let index = parse(&index_bytes)?;
    if !keys(&index, &["schema_version", "lock_sha256", "packages"])
        || index.get("schema_version") != Some(&J::Number(1.0))
    {
        return Err("unsupported locator index schema".into());
    }
    if index.get("lock_sha256").and_then(J::as_str) != Some(lock_hash) {
        return Err("index lock hash mismatch".into());
    }
    let records = lock
        .get("packages")
        .and_then(J::as_object)
        .ok_or("missing lock packages")?;
    crate::graph::npm_limits(records).map_err(|e| e.to_string())?;
    for path in records.keys() {
        safe_relative(path, true)?;
    }
    let entries = index
        .get("packages")
        .and_then(J::as_array)
        .ok_or("packages index must be an array")?;
    let mut locators = BTreeMap::new();
    for entry in entries {
        if !keys(entry, &["path", "artifact"]) && !keys(entry, &["path", "project_manifest"]) {
            return Err("locator entry requires path and one supported evidence source".into());
        }
        let path = entry
            .get("path")
            .and_then(J::as_str)
            .ok_or("invalid locator instance")?;
        if !records.contains_key(path)
            || records[path].get("link").and_then(J::as_bool) == Some(true)
            || locators.insert(path, entry).is_some()
        {
            return Err("duplicate or unknown index instance".into());
        }
    }
    let mut capture_by_parent: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut bundle_children = BTreeMap::new();
    for (path, record) in records {
        if record.get("inBundle") != Some(&J::Bool(true))
            || record.get("resolved").is_some()
            || record.get("integrity").is_some()
            || locators.contains_key(path.as_str())
        {
            continue;
        }
        let mut ancestor = path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once("/node_modules/") {
            if locators
                .get(parent)
                .is_some_and(|entry| entry.get("artifact").is_some())
            {
                let relative = path[parent.len() + 1..].to_owned();
                capture_by_parent
                    .entry(parent.to_owned())
                    .or_default()
                    .insert(relative.clone());
                bundle_children.insert(path.clone(), (parent.to_owned(), relative));
                break;
            }
            ancestor = parent;
        }
    }
    let mut result = BTreeMap::new();
    let mut observed_bundles = BTreeMap::new();
    let root = index_path.parent().unwrap_or(Path::new("."));
    let mut work = Work {
        compressed: Vec::new(),
        budget: artifact::Budget::new(),
    };
    for (path, record) in records {
        let marker = record.get("hasInstallScript").and_then(J::as_bool);
        if record.get("link").and_then(J::as_bool) == Some(true) {
            continue;
        }
        let evidence = if let Some(entry) = locators.get(path.as_str()) {
            let capture = capture_by_parent.get(path).cloned().unwrap_or_default();
            let read = if capture.is_empty() {
                read_facts(root, path, record, entry, root_hash, &mut work)
            } else {
                read_facts_with_bundle(
                    root,
                    path,
                    record,
                    entry,
                    root_hash,
                    &mut work,
                    FactSource::Direct(&capture),
                )
            };
            let mut evidence = match read.facts {
                Ok(facts) => qualify(path, record, marker, facts),
                Err(reason) => ExecutionEvidence::unknown(State::Unsupported, marker, reason),
            };
            evidence.verified_artifact_sha512 = read.verified_artifact_sha512;
            if evidence.qualified() {
                observed_bundles.insert(path.clone(), (read.nested, read.declared_bundles));
            }
            evidence
        } else {
            ExecutionEvidence::unknown(
                State::Missing,
                marker,
                "missing locator for locked instance",
            )
        };
        result.insert(path.clone(), evidence);
    }
    for (path, (parent, relative)) in bundle_children {
        let record = &records[&path];
        let marker = record.get("hasInstallScript").and_then(J::as_bool);
        let declared = observed_bundles
            .get(&parent)
            .and_then(|(_, names)| direct_bundle_name(&relative).map(|name| names.contains(name)))
            == Some(true);
        let evidence = match (
            result.get(&parent),
            observed_bundles
                .get(&parent)
                .and_then(|(nested, _)| nested.get(&relative)),
        ) {
            (Some(parent_evidence), _) if parent_evidence.qualified() && !declared => {
                ExecutionEvidence::unknown(
                    State::Missing,
                    marker,
                    "child is not a direct declared bundled dependency of its parent archive",
                )
            }
            (Some(parent_evidence), Some(nested)) if parent_evidence.qualified() => {
                let parent_record = &records[&parent];
                let bundle = BundleInput {
                    nested,
                    parent: &parent,
                    source: parent_record.get("resolved").and_then(J::as_str).unwrap(),
                    integrity: parent_record.get("integrity").and_then(J::as_str).unwrap(),
                    sha512: parent_evidence
                        .facts
                        .as_ref()
                        .unwrap()
                        .artifact_sha512
                        .as_deref()
                        .unwrap(),
                };
                let read = read_facts_with_bundle(
                    root,
                    &path,
                    record,
                    &J::Null,
                    None,
                    &mut work,
                    FactSource::Bundle(bundle),
                );
                match read.facts {
                    Ok(facts) => qualify(&path, record, marker, facts),
                    Err(reason) => ExecutionEvidence::unknown(State::Unsupported, marker, reason),
                }
            }
            (Some(parent_evidence), _) if parent_evidence.qualified() => {
                ExecutionEvidence::unknown(
                    State::Missing,
                    marker,
                    "bundled package manifest absent from verified parent archive",
                )
            }
            _ => ExecutionEvidence::unknown(
                State::Missing,
                marker,
                "bundle parent lacks qualified archive evidence",
            ),
        };
        result.insert(path, evidence);
    }
    for (path, record) in records {
        if record.get("link").and_then(J::as_bool) != Some(true) {
            continue;
        }
        let marker = record.get("hasInstallScript").and_then(J::as_bool);
        let target = record.get("resolved").and_then(J::as_str).unwrap_or("");
        let evidence = match result.get(target) {
            Some(e) if e.qualified() && !registry(target) && !target.is_empty() => {
                let mut facts = e.facts.clone().unwrap();
                facts.kind = Kind::WorkspaceLink(target.into());
                qualify(path, record, marker, facts)
            }
            _ => ExecutionEvidence::unknown(
                State::Missing,
                marker,
                "workspace link requires qualified exact source target evidence",
            ),
        };
        result.insert(path.clone(), evidence);
    }
    Ok((result, index_hash))
}
fn qualify(path: &str, record: &J, marker: Option<bool>, facts: Facts) -> ExecutionEvidence {
    let conflict = marker == Some(false) && facts.install_candidate;
    let reason = if conflict {
        Some("locked hasInstallScript contradicts inspected install lifecycle/native facts".into())
    } else {
        match (
            record.get("version").and_then(J::as_str),
            facts.version.as_deref(),
        ) {
            (Some(locked), Some(source))
                if path.is_empty() && matches!(facts.kind, Kind::SourceProject) && source != locked =>
            {
                Some(format!("root source version {source:?} differs from locked version {locked:?}; exact source and locked metadata remain approval-bound"))
            }
            _ => None,
        }
    };
    let fingerprint = if conflict {
        None
    } else {
        Some(sha256(
            J::Array(vec![
                string("tau-gate.execution-approval"),
                J::Number(1.0),
                string("npm_v3"),
                string(path),
                record.get("name").cloned().unwrap_or(J::Null),
                record.get("version").cloned().unwrap_or(J::Null),
                record.get("resolved").cloned().unwrap_or(J::Null),
                record.get("integrity").cloned().unwrap_or(J::Null),
                facts.json(),
            ])
            .to_json()
            .as_bytes(),
        ))
    };
    ExecutionEvidence {
        state: if conflict {
            State::Conflict
        } else {
            State::Qualified
        },
        facts: Some(facts),
        verified_artifact_sha512: None,
        marker,
        reason,
        fingerprint,
    }
}
fn read_facts(
    root: &Path,
    path: &str,
    record: &J,
    entry: &J,
    root_hash: Option<&str>,
    work: &mut Work,
) -> ReadFacts {
    read_facts_with_bundle(
        root,
        path,
        record,
        entry,
        root_hash,
        work,
        FactSource::Direct(&BTreeSet::new()),
    )
}

fn read_facts_with_bundle(
    root: &Path,
    path: &str,
    record: &J,
    entry: &J,
    root_hash: Option<&str>,
    work: &mut Work,
    selection: FactSource<'_>,
) -> ReadFacts {
    let mut verified_artifact_sha512 = None;
    let mut nested = BTreeMap::new();
    let mut bundle_names = BTreeSet::new();
    let empty_capture = BTreeSet::new();
    let capture = match &selection {
        FactSource::Direct(capture) => *capture,
        FactSource::Bundle(_) => &empty_capture,
    };
    let bundle = match &selection {
        FactSource::Bundle(bundle) => Some(bundle),
        FactSource::Direct(_) => None,
    };
    let facts = (|| {
        work.budget.check()?;
        let (bytes, binding, kind, artifact_sha512) = if let Some(bundle) = bundle {
            (
                bundle
                    .nested
                    .manifest
                    .clone()
                    .ok_or("bundled package manifest is absent")?,
                bundle.nested.binding_gyp_sha256.clone(),
                Kind::BundledArtifact {
                    parent: bundle.parent.to_owned(),
                    source: bundle.source.to_owned(),
                    integrity: bundle.integrity.to_owned(),
                },
                Some(bundle.sha512.to_owned()),
            )
        } else if let Some(value) = entry.get("artifact") {
            if !registry(path) {
                return Err("project instance cannot use artifact evidence".into());
            }
            if !record
                .get("resolved")
                .and_then(J::as_str)
                .is_some_and(direct_archive_source)
            {
                return Err(
                    "artifact source requires a supported direct HTTP(S) archive URL".into(),
                );
            }
            let file = confined(
                root,
                value.as_str().ok_or("artifact locator must be a string")?,
            )?;
            read_regular_into(
                &file,
                MAX_FILE,
                &mut work.compressed,
                Some(&mut work.budget),
            )?;
            let verified = artifact::verify(
                &work.compressed,
                record.get("integrity").and_then(J::as_str).unwrap_or(""),
            )?;
            verified_artifact_sha512 = Some(verified.sha512().to_owned());
            let archive = artifact::inspect_verified_nested(verified, &mut work.budget, capture)?;
            nested = archive.nested;
            (
                archive.manifest,
                archive.binding_gyp_sha256,
                Kind::Artifact,
                Some(archive.sha512),
            )
        } else {
            if registry(path) {
                return Err("supplied manifest cannot establish registry artifact binding".into());
            }
            let file = confined(
                root,
                entry
                    .get("project_manifest")
                    .and_then(J::as_str)
                    .ok_or("project manifest locator must be a string")?,
            )?;
            read_regular_into(
                &file,
                MAX_MANIFEST,
                &mut work.compressed,
                Some(&mut work.budget),
            )?;
            let bytes = work.compressed.clone();
            if path.is_empty() && root_hash.is_some_and(|h| h != sha256(&bytes)) {
                return Err("index root manifest differs from supplied root input".into());
            }
            let binding_file = file.parent().unwrap().join("binding.gyp");
            let binding = match fs::symlink_metadata(&binding_file) {
                Ok(_) => {
                    read_regular_into(
                        &binding_file,
                        MAX_FILE,
                        &mut work.compressed,
                        Some(&mut work.budget),
                    )?;
                    Some(sha256(&work.compressed))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("cannot inspect source binding.gyp: {e}")),
            };
            (bytes, binding, Kind::SourceProject, None)
        };
        let manifest = parse(&bytes)?;
        if !capture.is_empty() {
            bundle_names = declared_bundles(&manifest);
        }
        let m = manifest.as_object().ok_or("manifest must be an object")?;
        let name = record
            .get("name")
            .and_then(J::as_str)
            .map(str::to_owned)
            .or_else(|| {
                registry(path).then(|| path.rsplit("node_modules/").next().unwrap().to_owned())
            });
        if name
            .as_deref()
            .is_some_and(|name| manifest.get("name").and_then(J::as_str) != Some(name))
        {
            return Err(format!(
                "manifest name does not match lock instance {path:?}"
            ));
        }
        let root_version_metadata = path.is_empty()
            && matches!(kind, Kind::SourceProject)
            && manifest
                .get("version")
                .and_then(J::as_str)
                .is_some_and(|v| !v.is_empty())
            && record
                .get("version")
                .and_then(J::as_str)
                .is_some_and(|v| !v.is_empty());
        if manifest.get("version") != record.get("version") && !root_version_metadata {
            return Err(format!(
                "manifest version does not match lock instance {path:?}"
            ));
        }
        if !registry(path) {
            for field in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                let empty = J::Object(BTreeMap::new());
                if manifest.get(field).unwrap_or(&empty) != record.get(field).unwrap_or(&empty) {
                    return Err(format!(
                        "source manifest {field} does not match lock instance {path:?}"
                    ));
                }
            }
        }
        let empty = BTreeMap::new();
        let scripts = match m.get("scripts") {
            Some(s) => s.as_object().ok_or("invalid scripts map")?,
            None => &empty,
        };
        if scripts.values().any(|v| v.as_str().is_none()) {
            return Err("invalid script body".into());
        }
        let mut events = if path.is_empty() {
            ROOT_EVENTS.to_vec()
        } else {
            DEPENDENCY_EVENTS.to_vec()
        };
        if !path.is_empty() && !registry(path) {
            events.push("prepare");
        }
        let lifecycle: BTreeMap<String, String> = events
            .into_iter()
            .filter_map(|event| {
                scripts
                    .get(event)
                    .and_then(J::as_str)
                    .map(|s| (event.into(), sha256(s.as_bytes())))
            })
            .collect();
        let gypfile_false = m.get("gypfile") == Some(&J::Bool(false));
        let implicit_node_gyp = binding.is_some()
            && !gypfile_false
            && !["preinstall", "install"].iter().any(|event| {
                scripts
                    .get(*event)
                    .and_then(J::as_str)
                    .is_some_and(|s| !s.is_empty())
            });
        let install_candidate = implicit_node_gyp
            || DEPENDENCY_EVENTS.iter().any(|event| {
                scripts
                    .get(*event)
                    .and_then(J::as_str)
                    .is_some_and(|s| !s.is_empty())
            });
        let active_lifecycle = scripts.iter().any(|(event, body)| {
            lifecycle.contains_key(event) && body.as_str().is_some_and(|s| !s.is_empty())
        });
        Ok(Facts {
            name: manifest.get("name").and_then(J::as_str).map(str::to_owned),
            version: manifest
                .get("version")
                .and_then(J::as_str)
                .map(str::to_owned),
            kind,
            artifact_sha512,
            manifest_sha256: sha256(&bytes),
            lifecycle,
            binding_gyp_sha256: binding,
            gypfile_false,
            implicit_node_gyp,
            binary_entrypoints: m.get("bin").cloned().unwrap_or(J::Null),
            active_lifecycle,
            install_candidate,
        })
    })();
    ReadFacts {
        facts,
        verified_artifact_sha512,
        nested,
        declared_bundles: bundle_names,
    }
}

pub(crate) fn apply(evidence: &Evidence, graph: &mut DepGraph) {
    for (path, e) in evidence {
        let label = if path.is_empty() { "root" } else { path };
        if e.facts.is_some() {
            graph.execution_packages.remove(label);
        }
        if e.candidate() {
            graph.execution_packages.insert(label.into());
        }
        if let Some(p) = graph.packages.get_mut(label) {
            if e.facts.is_some() {
                p.capabilities.retain(|c| {
                    !c.starts_with("root-lifecycle:")
                        && c != "install-lifecycle-script (body not inspected)"
                });
            }
            p.capabilities.extend(e.capabilities());
            p.capabilities.sort();
            p.capabilities.dedup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_bytes_survive_current_content_budget_failure_but_not_subsequent_reads() {
        let root =
            std::env::temp_dir().join(format!("tau-current-byte-budget-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let bytes = include_bytes!("../tests/fixtures/archive/large-nonlifecycle.tgz");
        fs::write(root.join("pkg.tgz"), bytes).unwrap();
        let record = parse(br#"{"version":"1","resolved":"https://registry.npmjs.org/large/-/large-1.tgz","integrity":"sha512-2YOZUZnWe3iTo0e7YE4YDKgpjH5xdeCUAegxELEtteXQF+AxiUhr6Aht/0j53bledir/8AYdOuLAeCiUj6Pegg=="}"#).unwrap();
        let entry = parse(br#"{"artifact":"pkg.tgz"}"#).unwrap();
        for (expanded, headers, reason) in [
            (1, 250_000, "expanded evidence"),
            (128 * 1024 * 1024, 1, "tar processing"),
        ] {
            let mut work = Work {
                compressed: Vec::new(),
                budget: artifact::Budget::with_work_limits(expanded, headers),
            };
            let current = read_facts(
                &root,
                "node_modules/large",
                &record,
                &entry,
                None,
                &mut work,
            );
            assert!(current.facts.unwrap_err().contains(reason));
            assert_eq!(
                current.verified_artifact_sha512,
                Some(crate::digest::sha512(bytes))
            );
            let subsequent = read_facts(
                &root,
                "node_modules/large",
                &record,
                &entry,
                None,
                &mut work,
            );
            assert!(subsequent.facts.unwrap_err().contains(reason));
            assert!(subsequent.verified_artifact_sha512.is_none());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repeated_regular_reads_recover_after_size_and_file_errors() {
        let root = std::env::temp_dir().join(format!(
            "tau-gate-regular-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let large = root.join("large");
        let small = root.join("small");
        fs::write(&large, vec![42; 8192]).unwrap();
        fs::write(&small, b"small").unwrap();
        let mut bytes = Vec::new();
        for (invalid, limit) in [(&large, 8191), (&root, 8192), (&root.join("missing"), 8192)] {
            read_regular_into(&large, 8192, &mut bytes, None).unwrap();
            assert_eq!(bytes, vec![42; 8192]);
            assert!(read_regular_into(invalid, limit, &mut bytes, None).is_err());
            read_regular_into(&small, 8192, &mut bytes, None).unwrap();
            assert_eq!(bytes, b"small");
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn actual_reads_count_repeated_files_and_failed_file_limits() {
        let root = std::env::temp_dir().join(format!("tau-evidence-budget-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("input");
        fs::write(&path, b"12345").unwrap();
        let mut bytes = Vec::new();
        let mut budget = artifact::Budget::new();
        budget.read_remaining = 10;
        read_regular_into(&path, 5, &mut bytes, Some(&mut budget)).unwrap();
        assert!(read_regular_into(&path, 4, &mut bytes, Some(&mut budget)).is_err());
        assert_eq!(bytes, b"12345");
        assert_eq!(budget.read_remaining, 0);
        let error = read_regular_into(&path, 5, &mut bytes, Some(&mut budget)).unwrap_err();
        assert_eq!(bytes.len(), 1);
        fs::remove_file(&path).unwrap();
        assert_eq!(
            read_regular_into(&path, 5, &mut bytes, Some(&mut budget)).unwrap_err(),
            error
        );
        assert!(bytes.is_empty());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn source_reads_recover_after_failure_and_exhaustion_has_no_facts() {
        let root = std::env::temp_dir().join(format!("tau-facts-budget-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let bytes = br#"{"name":"root","version":"1"}"#;
        fs::write(root.join("package.json"), bytes).unwrap();
        let record = parse(bytes).unwrap();
        let entry = parse(br#"{"project_manifest":"package.json"}"#).unwrap();
        let mut work = Work {
            compressed: Vec::new(),
            budget: artifact::Budget::new(),
        };
        work.budget.read_remaining = 2 * bytes.len() as u64;
        let invalid_entry = parse(br#"{"project_manifest":"missing.json"}"#).unwrap();
        assert!(
            read_facts(&root, "", &record, &invalid_entry, None, &mut work)
                .facts
                .is_err()
        );
        let facts = read_facts(&root, "", &record, &entry, None, &mut work)
            .facts
            .unwrap();
        assert_eq!(facts.manifest_sha256, sha256(bytes));
        read_facts(&root, "", &record, &entry, None, &mut work)
            .facts
            .unwrap();
        let reason = read_facts(&root, "", &record, &entry, None, &mut work)
            .facts
            .unwrap_err();
        let evidence = ExecutionEvidence::unknown(State::Unsupported, None, &reason);
        assert!(!evidence.qualified());
        assert!(evidence.facts.is_none());
        assert_eq!(
            read_facts(&root, "", &record, &invalid_entry, None, &mut work)
                .facts
                .unwrap_err(),
            reason
        );
        assert_eq!(facts.manifest_sha256, sha256(bytes));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verified_byte_observations_do_not_leak_after_failed_or_exhausted_reads() {
        let root =
            std::env::temp_dir().join(format!("tau-byte-observation-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("pkg.tgz"), b"first").unwrap();
        let record = parse(br#"{"version":"1","resolved":"https://registry.npmjs.org/pkg/-/pkg-1.tgz","integrity":"sha512-f92A293tFWMj02xFnl/RM6TYiMInMgz7cEK+n+s11/ByAeU1aXr5FOadb0ayqIZVyGwjcSiAUszU+pIFiwHT/Q=="}"#).unwrap();
        let entry = parse(br#"{"artifact":"pkg.tgz"}"#).unwrap();
        let mut work = Work {
            compressed: Vec::new(),
            budget: artifact::Budget::new(),
        };
        let read = read_facts(&root, "node_modules/pkg", &record, &entry, None, &mut work);
        assert!(read.facts.is_err());
        assert_eq!(
            read.verified_artifact_sha512,
            Some(crate::digest::sha512(b"first"))
        );
        let wrong_integrity = parse(br#"{"version":"1","resolved":"https://registry.npmjs.org/pkg/-/pkg-1.tgz","integrity":"sha512-invalid"}"#).unwrap();
        let read = read_facts(
            &root,
            "node_modules/pkg",
            &wrong_integrity,
            &entry,
            None,
            &mut work,
        );
        assert!(read.facts.is_err());
        assert!(read.verified_artifact_sha512.is_none());
        for entry in [
            br#"{"artifact":"missing.tgz"}"#.as_slice(),
            br#"{"artifact":"../pkg.tgz"}"#,
        ] {
            let read = read_facts(
                &root,
                "node_modules/pkg",
                &record,
                &parse(entry).unwrap(),
                None,
                &mut work,
            );
            assert!(read.facts.is_err());
            assert!(read.verified_artifact_sha512.is_none());
        }
        work.budget.read_remaining = 4;
        for _ in 0..2 {
            let read = read_facts(&root, "node_modules/pkg", &record, &entry, None, &mut work);
            assert!(read.facts.is_err());
            assert!(read.verified_artifact_sha512.is_none());
        }
        fs::remove_dir_all(root).unwrap();
    }
}
