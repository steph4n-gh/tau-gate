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
            if format == SnapshotFormat::Npm {
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
    Pnpm,
    Yarn,
}
impl SnapshotFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm_v3",
            Self::Pnpm => "pnpm_v9",
            Self::Yarn => "yarn_classic_v1",
        }
    }
    fn identity_kind(self) -> &'static str {
        match self {
            Self::Npm => "installed_package_instance",
            Self::Pnpm => "pnpm_contextual_resolution_snapshot",
            Self::Yarn => "yarn_descriptor_record",
        }
    }
    fn detect(text: &str) -> Result<Self> {
        let t = text.trim_start();
        if t.starts_with('{') {
            return Ok(Self::Npm);
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
            return Err(GateError::Graph("INCOMPLETE: Yarn Berry lockfiles are unsupported; supported Yarn format is Classic v1".into()));
        }
        Err(GateError::Graph(
            "INCOMPLETE: unsupported lockfile format; provide npm v3, pnpm v9 or Yarn Classic v1"
                .into(),
        ))
    }
}
pub struct Snapshot {
    pub graph: DepGraph,
    pub format: SnapshotFormat,
    pub hash: String,
    pub manifest_hash: Option<String>,
}
impl Snapshot {
    pub fn load(lock: &Path, manifest: Option<&Path>) -> Result<Self> {
        let bytes = read_input(lock)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| GateError::Graph("Lockfile must be UTF-8".into()))?;
        let format = SnapshotFormat::detect(text)?;
        let mut manifest_hash = None;
        let m = if let Some(path) = manifest {
            let b = read_input(path)?;
            manifest_hash = Some(sha256(&b));
            let m = MiniParser::parse_json(
                std::str::from_utf8(&b)
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
            SnapshotFormat::Npm => DepGraph::parse_npm_lockfile(text)?,
            SnapshotFormat::Pnpm => crate::pnpm::parse(text, m.as_ref())?,
            SnapshotFormat::Yarn => crate::yarn::parse(text, m.as_ref())?,
        };
        if let Some(m) = m.as_ref() {
            if format == SnapshotFormat::Npm {
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
                        "preinstall" | "install" | "postinstall" | "prepare"
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
        })
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
        object([("schema_version",J::Number(1.0)),
            ("format",string(self.format.label())),
            ("identity_kind",string(self.format.identity_kind())),("introducer_roots",strings(known_roots(self).into_iter().map(|i|d.graph.node_weight(i).unwrap().clone()))),("introducer_path_scope",string(if self.format==SnapshotFormat::Pnpm{"all_known_importers"}else{"project_root"})),
            ("topology_status",string(if d.issues.iter().any(|s|!s.starts_with("Execution capabilities unknown:")&&!s.starts_with("Root attribution incomplete:")){"incomplete"}else{"complete"})),
            ("root_attribution_status",string(if root.is_some()&&!d.issues.iter().any(|s|s.starts_with("Root attribution incomplete:")){"available"}else{"incomplete"})),
            ("execution_metadata_status",string(if self.format==SnapshotFormat::Npm{if self.manifest_hash.is_some(){"declared_lock_markers_and_root_lifecycle_bodies"}else{"declared_lock_markers_only"}}else{"unknown_transitive_scripts"})),
            ("status",string(if d.issues.is_empty(){"complete"}else{"incomplete"})),
            ("scope",string(format!("{}_{}",self.format.label(),if self.manifest_hash.is_some(){"lock_and_root_manifest"}else{"lock_snapshot_only"}))),
            ("lock_sha256",string(&self.hash)),
            ("manifest_sha256",self.manifest_hash.as_ref().map(string).unwrap_or(J::Null)),
            ("limitations",strings(["Dependency script bodies and runtime behavior are not inspected; markers describe execution potential".into(),"Topology cannot distinguish same-shape benign and malicious code".into(),"All lockfile records are included; host platform, dev, optional and lifecycle selection are not evaluated".into(),"Resolution lock records are not an installed node_modules tree; installed_path is unknown for pnpm/Yarn".into(),"Integrity/source fields are recorded, not verified against downloaded artifacts; missing install markers are not proof of no execution".into()])),
            ("issues",strings(d.issues.clone())),
            ("optional_omissions",strings(d.optional_omissions.clone())),
            ("packages",J::Array(d.packages.values().map(|p|package(p,self.format)).collect())),
            ("edges",J::Array(edges)),
            ("execution_candidates",J::Array(candidates)),
            ("topology",math)])
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
            string(
                if base.graph.issues.is_empty() && head.graph.issues.is_empty() {
                    "complete"
                } else {
                    "incomplete"
                },
            ),
        ),
        ("base", base.report()),
        ("head", head.report()),
        ("package_changes", J::Array(changes)),
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
                || (s.format == SnapshotFormat::Pnpm
                    && (name.starts_with("pnpm:project:importer:")
                        || name.starts_with("pnpm:environment:importer:")))
        })
        .collect::<Vec<_>>();
    roots.sort_by(|&a, &b| {
        let a = g.node_weight(a).unwrap();
        let b = g.node_weight(b).unwrap();
        (a != "root", a).cmp(&(b != "root", b))
    });
    roots
}
