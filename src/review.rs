//! Read-only dependency snapshot reports. Execution markers are review evidence, not malware labels.
use crate::{
    digest::sha256,
    error::{GateError, Result},
    graph::{DepGraph, PackageInfo},
    parser::{JsonNode as J, MiniParser},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::Read,
    path::Path,
};
pub fn string(s: impl Into<String>) -> J {
    J::String(s.into())
}
pub fn object<const N: usize>(items: [(&str, J); N]) -> J {
    J::Object(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn strings(items: impl IntoIterator<Item = String>) -> J {
    J::Array(items.into_iter().map(string).collect())
}
fn package(p: &PackageInfo, format: SnapshotFormat) -> J {
    object([
        ("path", string(&p.path)),
        ("identity_kind", string(format.identity_kind())),
        (
            "installed_path",
            if format.installed_instances() {
                string(&p.path)
            } else {
                J::Null
            },
        ),
        ("name", string(&p.name)),
        ("version", string(&p.version)),
        ("source", string(&p.source)),
        ("integrity", string(&p.integrity)),
        ("capabilities", strings(p.capabilities.clone())),
    ])
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotFormat {
    Npm,
    NpmV1,
    NpmV2,
    Pnpm,
    PnpmV6,
    Yarn,
    YarnBerry,
}
impl SnapshotFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm_v3",
            Self::NpmV1 => "npm_v1",
            Self::NpmV2 => "npm_v2",
            Self::Pnpm => "pnpm_v9",
            Self::PnpmV6 => "pnpm_v6",
            Self::Yarn => "yarn_classic_v1",
            Self::YarnBerry => "yarn_berry",
        }
    }
    fn identity_kind(self) -> &'static str {
        match self {
            Self::Npm | Self::NpmV1 | Self::NpmV2 => "installed_package_instance",
            Self::Pnpm | Self::PnpmV6 => "pnpm_contextual_resolution_snapshot",
            Self::Yarn | Self::YarnBerry => "yarn_descriptor_record",
        }
    }
    fn installed_instances(self) -> bool {
        matches!(self, Self::Npm | Self::NpmV1 | Self::NpmV2)
    }
    fn pnpm(self) -> bool {
        matches!(self, Self::Pnpm | Self::PnpmV6)
    }
    fn detect(text: &str) -> Result<Self> {
        let t = text.trim_start();
        if t.starts_with('{') {
            return match MiniParser::parse_json(text)?.get("lockfileVersion") {
                Some(J::Number(1.0)) => Ok(Self::NpmV1),
                Some(J::Number(2.0)) => Ok(Self::NpmV2),
                Some(J::Number(3.0)) => Ok(Self::Npm),
                _ => Err(GateError::Graph(
                    "INCOMPLETE: supported npm lockfileVersion values are 1, 2 and 3".into(),
                )),
            };
        }
        if text.lines().any(|l| l.trim() == "# yarn lockfile v1") {
            return Ok(Self::Yarn);
        }
        if text
            .lines()
            .any(|l| l.trim_start().starts_with("lockfileVersion:"))
        {
            return Ok(Self::Pnpm);
        }
        if text
            .lines()
            .any(|l| l.trim_start().starts_with("__metadata:"))
        {
            return Ok(Self::YarnBerry);
        }
        Err(GateError::Graph(
            "INCOMPLETE: unsupported lockfile format; provide npm v1/v2/v3, pnpm v6/v9 or Yarn Classic/Berry"
                .into(),
        ))
    }
}
pub struct Snapshot {
    pub graph: DepGraph,
    pub format: SnapshotFormat,
    pub hash: String,
    pub manifest_hash: Option<String>,
    pub(crate) evidence: Option<crate::evidence::Evidence>,
    evidence_hash: Option<String>,
    project_input_hashes: BTreeMap<String, J>,
    project_inputs_index_hash: Option<String>,
}
impl Snapshot {
    pub fn load(lock: &Path, manifest: Option<&Path>) -> Result<Self> {
        Self::load_context(lock, manifest, None, None)
    }
    pub fn load_context(
        lock: &Path,
        manifest: Option<&Path>,
        project_inputs: Option<&Path>,
        evidence: Option<&Path>,
    ) -> Result<Self> {
        let mut snapshot = Self::load_inputs(lock, manifest, project_inputs)?;
        if let Some(index) = evidence {
            snapshot.attach_evidence(lock, index)?;
        }
        Ok(snapshot)
    }
    fn load_inputs(
        lock: &Path,
        manifest: Option<&Path>,
        project_inputs: Option<&Path>,
    ) -> Result<Self> {
        let supplied = project_inputs
            .map(crate::project_inputs::load)
            .transpose()
            .map_err(|e| GateError::Graph(format!("Invalid project inputs: {e}")))?;
        let mut inputs = supplied
            .as_ref()
            .map(|s| s.files.clone())
            .unwrap_or_default();
        let bytes = read_input(lock)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| GateError::Graph("Lockfile must be UTF-8".into()))?;
        let mut format = SnapshotFormat::detect(text)?;
        let mut manifest_hash = None;
        let manifest_bytes = manifest.map(read_input).transpose()?;
        if let (Some(explicit), Some(bundled)) =
            (manifest_bytes.as_ref(), inputs.get("package.json"))
        {
            if explicit != bundled {
                return Err(GateError::Graph(
                    "Explicit manifest and project input package.json disagree".into(),
                ));
            }
        }
        if let Some(bytes) = manifest_bytes {
            inputs.insert("package.json".into(), bytes);
        }
        let m = if let Some(b) = inputs.get("package.json") {
            manifest_hash = Some(sha256(b));
            let m = MiniParser::parse_json(
                std::str::from_utf8(b)
                    .map_err(|_| GateError::Graph("Manifest must be UTF-8".into()))?,
            )?;
            if m.as_object().is_none() {
                return Err(GateError::Graph("Manifest must be an object".into()));
            }
            Some(m)
        } else {
            None
        };
        let mut graph = match format {
            SnapshotFormat::Npm | SnapshotFormat::NpmV1 | SnapshotFormat::NpmV2 => {
                DepGraph::parse_npm_lockfile_with_manifest(text, m.as_ref())?
            }
            SnapshotFormat::Pnpm | SnapshotFormat::PnpmV6 => {
                crate::pnpm::parse_with_inputs(text, m.as_ref(), &inputs)?
            }
            SnapshotFormat::Yarn => crate::yarn::parse_with_inputs(text, m.as_ref(), &inputs)?,
            SnapshotFormat::YarnBerry => crate::yarn::berry::parse(text, m.as_ref(), &inputs)?,
        };
        if format.pnpm()
            && graph
                .resolution_metadata
                .get("pnpm:project:lockfileVersion")
                .and_then(J::as_str)
                == Some("6.0")
        {
            format = SnapshotFormat::PnpmV6;
        }
        if let Some(m) = m.as_ref() {
            if matches!(format, SnapshotFormat::Npm | SnapshotFormat::NpmV2) {
                let root = MiniParser::parse_json(text)?;
                let locked = root.get("packages").and_then(|p| p.get("")).unwrap();
                for kind in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ] {
                    let empty = J::Object(Default::default());
                    if m.get(kind).unwrap_or(&empty) != locked.get(kind).unwrap_or(&empty) {
                        graph
                            .issues
                            .push(format!("manifest/lock root {kind} disagree"));
                    }
                }
            }
            if m.get("scripts").is_some_and(|s| s.as_object().is_none()) {
                return Err(GateError::Graph("Invalid scripts map".into()));
            }
            if let Some(scripts) = m.get("scripts").and_then(J::as_object) {
                for (name, body) in scripts {
                    if matches!(
                        name.as_str(),
                        "preinstall"
                            | "install"
                            | "postinstall"
                            | "prepublish"
                            | "preprepare"
                            | "prepare"
                            | "postprepare"
                    ) {
                        let body = body
                            .as_str()
                            .ok_or_else(|| GateError::Graph("Invalid script body".into()))?;
                        graph.execution_packages.insert("root".into());
                        if let Some(p) = graph.packages.get_mut("root") {
                            p.capabilities.push(format!(
                                "root-lifecycle:{name}:sha256:{}",
                                sha256(body.as_bytes())
                            ));
                        }
                    }
                }
            }
        }
        Ok(Self {
            format,
            graph,
            hash: sha256(&bytes),
            manifest_hash,
            evidence: None,
            evidence_hash: None,
            project_input_hashes: supplied
                .as_ref()
                .map(|s| s.hashes.clone())
                .unwrap_or_default(),
            project_inputs_index_hash: supplied.map(|s| s.index_hash),
        })
    }
    /// Verify a locator bundle without extraction, installation, network access or writes.
    pub fn load_with_evidence(lock: &Path, manifest: Option<&Path>, index: &Path) -> Result<Self> {
        Self::load_context(lock, manifest, None, Some(index))
    }
    fn attach_evidence(&mut self, lock: &Path, index: &Path) -> Result<()> {
        let snapshot = self;
        if snapshot.format != SnapshotFormat::Npm {
            return Err(GateError::Graph(
                "Execution evidence is qualified only for npm v3".into(),
            ));
        }
        let bytes = read_input(lock)?;
        if sha256(&bytes) != snapshot.hash {
            return Err(GateError::Graph(
                "Lockfile changed while loading evidence".into(),
            ));
        }
        let root = MiniParser::parse_json(
            std::str::from_utf8(&bytes)
                .map_err(|_| GateError::Graph("Lockfile must be UTF-8".into()))?,
        )?;
        let (evidence, index_hash) = crate::evidence::load(
            &root,
            &snapshot.hash,
            index,
            snapshot.manifest_hash.as_deref(),
        )
        .map_err(GateError::Graph)?;
        crate::evidence::apply(&evidence, &mut snapshot.graph);
        if snapshot.manifest_hash.is_none() {
            snapshot.manifest_hash = evidence
                .get("")
                .and_then(crate::evidence::ExecutionEvidence::manifest_hash)
                .map(str::to_owned);
        }
        snapshot.evidence_hash = Some(index_hash);
        snapshot.evidence = Some(evidence);
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        self.graph.issues.is_empty()
            && self.evidence.as_ref().is_none_or(|items| {
                items
                    .values()
                    .all(crate::evidence::ExecutionEvidence::qualified)
            })
    }
    /// Evaluate explicit bound approvals. Legacy coordinate whitelists cannot authorize execution.
    pub fn policy(&self, approvals: Option<&Path>, enforce: bool) -> Result<J> {
        crate::policy::evaluate(self, approvals, enforce).map_err(GateError::Graph)
    }
    pub fn report(&self) -> J {
        let d = &self.graph;
        let n = d.graph.node_count();
        let root = (0..n).find(|&i| d.graph.node_weight(i).map(String::as_str) == Some("root"));
        let mut parents = vec![None; n];
        let mut reached = vec![false; n];
        let mut queue = VecDeque::new();
        for r in known_roots(self) {
            reached[r] = true;
            queue.push_back(r);
        }
        let mut adj = vec![BTreeSet::new(); n];
        let mut degree = vec![0; n];
        for &(u, v) in d.graph.edges() {
            adj[u].insert(v);
            if u != v {
                degree[u] += 1;
                degree[v] += 1
            }
        }
        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                if !reached[v] {
                    reached[v] = true;
                    parents[v] = Some(u);
                    queue.push_back(v)
                }
            }
        }
        let candidates = d
            .execution_packages
            .iter()
            .map(|label| {
                let i = (0..n).find(|&i| d.graph.node_weight(i) == Some(label));
                let path = i
                    .filter(|&i| reached[i])
                    .map(|mut i| {
                        let mut p = Vec::new();
                        loop {
                            p.push(d.graph.node_weight(i).unwrap().clone());
                            if let Some(parent) = parents[i] {
                                i = parent
                            } else {
                                break;
                            }
                        }
                        p.reverse();
                        strings(p)
                    })
                    .unwrap_or(J::Null);
                object([
                    (
                        "package",
                        d.packages
                            .get(label)
                            .map(|p| package(p, self.format))
                            .unwrap_or_else(|| object([("name", string(label))])),
                    ),
                    ("introducer_path", path),
                    (
                        "introducer_edges",
                        i.filter(|&i| reached[i])
                            .map(|mut i| {
                                let mut edges = Vec::new();
                                while let Some(parent) = parents[i] {
                                    edges.push(edge(self, parent, i));
                                    i = parent;
                                }
                                edges.reverse();
                                J::Array(edges)
                            })
                            .unwrap_or(J::Null),
                    ),
                    (
                        "approval_fingerprint",
                        self.evidence
                            .as_ref()
                            .and_then(|items| items.get(if label == "root" { "" } else { label }))
                            .and_then(crate::evidence::ExecutionEvidence::fingerprint)
                            .map(string)
                            .unwrap_or(J::Null),
                    ),
                    (
                        "undirected_degree",
                        J::Number(i.map(|i| degree[i]).unwrap_or(0) as f64),
                    ),
                ])
            })
            .collect();
        let math = match crate::math::analyze_graph(&d.graph) {
            Ok(m) => object([
                (
                    "kind",
                    string("connectivity_estimate_not_security_certificate"),
                ),
                ("score", J::Number(m.connectivity_score)),
                ("residual_converged", J::Bool(m.converged)),
                ("residual", J::Number(m.residual)),
                ("iterations", J::Number(m.iterations as f64)),
                (
                    "cut_diagnostics",
                    m.cut_diagnostics
                        .map(|cut| {
                            object([
                                ("method", string("four_fixed_ritz_projections_ratio_cut")),
                                ("projection", string(cut.projection)),
                                ("ratio_cut", J::Number(cut.ratio_cut)),
                                ("conductance", J::Number(cut.conductance)),
                                (
                                    "secondary_direction_residual",
                                    cut.secondary_direction_residual
                                        .map(J::Number)
                                        .unwrap_or(J::Null),
                                ),
                                (
                                    "conductance_alternative",
                                    cut.conductance_alternative
                                        .map(|alternative| {
                                            object([
                                                ("partition", strings(alternative.partition_b)),
                                                ("tau", J::Number(alternative.tau)),
                                                ("projection", string(alternative.projection)),
                                                ("ratio_cut", J::Number(alternative.ratio_cut)),
                                                ("conductance", J::Number(alternative.conductance)),
                                            ])
                                        })
                                        .unwrap_or(J::Null),
                                ),
                            ])
                        })
                        .unwrap_or(J::Null),
                ),
                ("partition", strings(m.partition_b)),
            ]),
            Err(e) => object([("error", string(e.to_string()))]),
        };
        let edges = d
            .graph
            .edges()
            .iter()
            .map(|&(u, v)| edge(self, u, v))
            .collect();
        object([
            ("schema_version", J::Number(1.0)),
            ("format", string(self.format.label())),
            ("parsing_status", string("complete")),
            (
                "dependency_kind_status",
                string(
                    if d.issues
                        .iter()
                        .any(|s| s.starts_with("Dependency kinds unknown:"))
                    {
                        "unknown_transitive_kinds"
                    } else {
                        "declared_kinds"
                    },
                ),
            ),
            (
                "resolution_metadata",
                J::Object(d.resolution_metadata.clone()),
            ),
            (
                "project_input_hashes",
                J::Object(self.project_input_hashes.clone()),
            ),
            (
                "project_inputs_index_sha256",
                self.project_inputs_index_hash
                    .as_ref()
                    .map(string)
                    .unwrap_or(J::Null),
            ),
            ("identity_kind", string(self.format.identity_kind())),
            (
                "introducer_roots",
                strings(
                    known_roots(self)
                        .into_iter()
                        .map(|i| d.graph.node_weight(i).unwrap().clone()),
                ),
            ),
            (
                "introducer_path_scope",
                string(if self.format.pnpm() {
                    "all_known_importers"
                } else if matches!(
                    self.format,
                    SnapshotFormat::Yarn | SnapshotFormat::YarnBerry
                ) {
                    "all_known_workspaces"
                } else {
                    "project_root"
                }),
            ),
            (
                "topology_status",
                string(
                    if d.issues.iter().any(|s| {
                        !s.starts_with("Execution capabilities unknown:")
                            && !s.starts_with("Root attribution incomplete:")
                            && !s.starts_with("Peer placement unknown:")
                            && !s.starts_with("Input consistency unknown:")
                            && !s.starts_with("Dependency kinds unknown:")
                    }) {
                        "incomplete"
                    } else {
                        "complete"
                    },
                ),
            ),
            (
                "root_attribution_status",
                string(
                    if root.is_some()
                        && !d
                            .issues
                            .iter()
                            .any(|s| s.starts_with("Root attribution incomplete:"))
                    {
                        "available"
                    } else {
                        "incomplete"
                    },
                ),
            ),
            (
                "execution_evidence",
                self.evidence
                    .as_ref()
                    .map(|items| J::Array(items.iter().map(|(path, e)| e.json(path)).collect()))
                    .unwrap_or(J::Null),
            ),
            (
                "execution_metadata_status",
                string(if self.evidence.is_some() {
                    "inspected_npm_artifacts_and_source_snapshots"
                } else if self.format == SnapshotFormat::Npm {
                    if self.manifest_hash.is_some() {
                        "declared_lock_markers_and_root_lifecycle_bodies"
                    } else {
                        "declared_lock_markers_only"
                    }
                } else {
                    "unknown_transitive_scripts"
                }),
            ),
            (
                "status",
                string(if self.is_complete() {
                    "complete"
                } else {
                    "incomplete"
                }),
            ),
            (
                "scope",
                string(if self.evidence.is_some() {
                    "npm_v3_artifacts_and_source_snapshots".to_owned()
                } else {
                    format!(
                        "{}_{}",
                        self.format.label(),
                        if self.manifest_hash.is_some() {
                            "lock_and_root_manifest"
                        } else {
                            "lock_snapshot_only"
                        }
                    )
                }),
            ),
            ("lock_sha256", string(&self.hash)),
            (
                "evidence_index_sha256",
                self.evidence_hash.as_ref().map(string).unwrap_or(J::Null),
            ),
            (
                "manifest_sha256",
                self.manifest_hash.as_ref().map(string).unwrap_or(J::Null),
            ),
            (
                "limitations",
                if self.evidence.is_some() {
                    strings(["Archive integrity binds bytes to the supplied lock, not publisher authenticity or code safety".into(),"Source project manifests and sibling binding.gyp presence or absence are caller-trusted supplied scope".into(),"All lock records remain in policy scope, including disconnected and platform-omitted optionals; host execution selection is not predicted".into(),"Lifecycle inventory follows npm 11.19.1 ci rules; binary entrypoints are separate from automatic lifecycle execution".into()])
                } else {
                    strings(["Dependency script bodies and runtime behavior are not inspected; markers describe execution potential".into(),"Topology cannot distinguish same-shape benign and malicious code".into(),"All lockfile records are included; host platform, dev, optional and lifecycle selection are not evaluated".into(),"Resolution lock records are not an installed node_modules tree; installed_path is unknown for pnpm/Yarn".into(),"Integrity/source fields are recorded, not verified against downloaded artifacts; missing install markers are not proof of no execution".into()])
                },
            ),
            ("issues", strings(d.issues.clone())),
            ("optional_omissions", strings(d.optional_omissions.clone())),
            (
                "packages",
                J::Array(
                    d.packages
                        .values()
                        .map(|p| package(p, self.format))
                        .collect(),
                ),
            ),
            ("edges", J::Array(edges)),
            ("execution_candidates", J::Array(candidates)),
            ("topology", math),
        ])
    }
}
pub fn compare(base: &Snapshot, head: &Snapshot) -> J {
    if base.format != head.format {
        return object([("schema_version",J::Number(1.0)),
            ("status",string("incomplete")),
            ("error",string("Cross-format identities are not comparable; review two snapshots in the same supported format")),
            ("base",base.report()),
            ("head",head.report())]);
    }
    let ap = ancestry(base);
    let bp = ancestry(head);
    let a = &base.graph.packages;
    let b = &head.graph.packages;
    let keys: BTreeSet<_> = a.keys().chain(b.keys()).collect();
    let changes = keys
        .into_iter()
        .filter_map(|k| {
            let before = a.get(k);
            let after = b.get(k);
            if before == after {
                return None;
            }
            let kind = if before.is_none() {
                "added"
            } else if after.is_none() {
                "removed"
            } else {
                "changed"
            };
            let mut fields = Vec::new();
            if let (Some(a), Some(b)) = (before, after) {
                if a.version != b.version {
                    fields.push("version".into())
                }
                if a.name != b.name {
                    fields.push("name".into())
                }
                if a.source != b.source {
                    fields.push("source".into())
                }
                if a.integrity != b.integrity {
                    fields.push("integrity".into())
                }
                if a.capabilities != b.capabilities {
                    fields.push("capabilities".into())
                }
            }
            Some(object([
                ("path", string(before.or(after).unwrap().path.clone())),
                ("change", string(kind)),
                ("changed_fields", strings(fields)),
                (
                    "before",
                    before.map(|p| package(p, base.format)).unwrap_or(J::Null),
                ),
                (
                    "after",
                    after.map(|p| package(p, head.format)).unwrap_or(J::Null),
                ),
                ("before_introducer_path", path_for(base, &ap, k)),
                ("after_introducer_path", path_for(head, &bp, k)),
            ]))
        })
        .collect();
    let edge_set = |s: &Snapshot| {
        s.graph
            .graph
            .edges()
            .iter()
            .map(|&(u, v)| {
                (
                    s.graph.graph.node_weight(u).unwrap().clone(),
                    s.graph.graph.node_weight(v).unwrap().clone(),
                    s.graph.edge_kinds.get(&(u, v)).cloned().unwrap_or_default(),
                )
            })
            .collect::<BTreeSet<_>>()
    };
    let ea = edge_set(base);
    let eb = edge_set(head);
    let edge_json = |e: &BTreeSet<(String, String, BTreeSet<String>)>| {
        J::Array(
            e.iter()
                .map(|(u, v, k)| {
                    object([
                        ("from", string(u)),
                        ("to", string(v)),
                        ("kinds", strings(k.iter().cloned())),
                    ])
                })
                .collect(),
        )
    };
    object([
        ("schema_version", J::Number(1.0)),
        (
            "status",
            string(if base.is_complete() && head.is_complete() {
                "complete"
            } else {
                "incomplete"
            }),
        ),
        ("base", base.report()),
        ("head", head.report()),
        ("package_changes", J::Array(changes)),
        (
            "resolution_metadata_changed",
            J::Bool(base.graph.resolution_metadata != head.graph.resolution_metadata),
        ),
        (
            "execution_evidence_changes",
            evidence_changes(base, head, &ap, &bp),
        ),
        (
            "added_edges",
            edge_json(&eb.difference(&ea).cloned().collect()),
        ),
        (
            "removed_edges",
            edge_json(&ea.difference(&eb).cloned().collect()),
        ),
    ])
}

fn evidence_changes(base: &Snapshot, head: &Snapshot, ap: &Ancestry, bp: &Ancestry) -> J {
    let empty = BTreeMap::new();
    let a = base.evidence.as_ref().unwrap_or(&empty);
    let b = head.evidence.as_ref().unwrap_or(&empty);
    let keys = a.keys().chain(b.keys()).collect::<BTreeSet<_>>();
    J::Array(
        keys.into_iter()
            .filter_map(|path| {
                let before = a.get(path);
                let after = b.get(path);
                if before == after {
                    return None;
                }
                let label = if path.is_empty() { "root" } else { path };
                Some(object([
                    ("path", string(path)),
                    ("before", before.map(|e| e.json(path)).unwrap_or(J::Null)),
                    ("after", after.map(|e| e.json(path)).unwrap_or(J::Null)),
                    ("before_introducer_path", path_for(base, ap, label)),
                    ("after_introducer_path", path_for(head, bp, label)),
                ]))
            })
            .collect(),
    )
}

fn edge(s: &Snapshot, u: usize, v: usize) -> J {
    object([
        ("from", string(s.graph.graph.node_weight(u).unwrap())),
        ("to", string(s.graph.graph.node_weight(v).unwrap())),
        (
            "kinds",
            strings(
                s.graph
                    .edge_kinds
                    .get(&(u, v))
                    .into_iter()
                    .flatten()
                    .cloned(),
            ),
        ),
    ])
}

fn read_input(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(GateError::Graph(format!(
            "Input must be a regular file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(GateError::Graph("Input exceeds 64 MiB".into()));
    }
    Ok(bytes)
}

struct Ancestry {
    parents: Vec<Option<usize>>,
    reached: Vec<bool>,
    indices: BTreeMap<String, usize>,
}
fn ancestry(s: &Snapshot) -> Ancestry {
    let g = &s.graph.graph;
    let n = g.node_count();
    let indices = (0..n)
        .map(|i| (g.node_weight(i).unwrap().clone(), i))
        .collect::<BTreeMap<_, _>>();
    let mut a = Ancestry {
        parents: vec![None; n],
        reached: vec![false; n],
        indices,
    };
    let mut adj = vec![BTreeSet::new(); n];
    for &(u, v) in g.edges() {
        adj[u].insert(v);
    }
    let mut q = VecDeque::new();
    for root in known_roots(s) {
        a.reached[root] = true;
        q.push_back(root);
    }
    while let Some(u) = q.pop_front() {
        for &v in &adj[u] {
            if !a.reached[v] {
                a.reached[v] = true;
                a.parents[v] = Some(u);
                q.push_back(v);
            }
        }
    }
    a
}
fn path_for(s: &Snapshot, a: &Ancestry, label: &str) -> J {
    let Some(mut i) = a.indices.get(label).copied().filter(|&i| a.reached[i]) else {
        return J::Null;
    };
    let mut path = Vec::new();
    loop {
        path.push(s.graph.graph.node_weight(i).unwrap().clone());
        if let Some(p) = a.parents[i] {
            i = p
        } else {
            break;
        }
    }
    path.reverse();
    strings(path)
}

// Real importers are independent graph roots. No membership edges are invented.
fn known_roots(s: &Snapshot) -> Vec<usize> {
    let g = &s.graph.graph;
    let mut roots = (0..g.node_count())
        .filter(|&i| {
            let name = g.node_weight(i).unwrap();
            name == "root"
                || (s.format.pnpm()
                    && (name.starts_with("pnpm:project:importer:")
                        || name.starts_with("pnpm:environment:importer:")))
                || (s.format == SnapshotFormat::Yarn && name.starts_with("yarn:workspace:"))
                || (s.format == SnapshotFormat::YarnBerry
                    && s.graph
                        .resolution_metadata
                        .get(name)
                        .and_then(|m| m.get("sourcePath"))
                        .is_some())
        })
        .collect::<Vec<_>>();
    roots.sort_by(|&a, &b| {
        let a = g.node_weight(a).unwrap();
        let b = g.node_weight(b).unwrap();
        (a != "root", a).cmp(&(b != "root", b))
    });
    roots
}
