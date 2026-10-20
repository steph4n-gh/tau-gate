use std::ffi::{CStr, CString};
use std::io::{Read, Write};

use base64::Engine;
use flate2::{read::DeflateDecoder, read::GzDecoder, write::GzEncoder, Compression};
use sha2::{Digest, Sha256, Sha512};
use tau_gate::{
    graph::DepGraph,
    parser::{JsonNode, MiniParser},
    review::Snapshot,
};

pub use tau_gate::digest;

#[allow(dead_code)]
mod archive {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/artifact.rs"));

    pub(super) fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        gunzip(bytes, &mut out, &mut Budget::new())?;
        Ok(out)
    }
    pub(super) fn deflate(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        inflate(bytes, &mut out, &mut Budget::new())?;
        Ok(out)
    }
    pub(super) fn tar(bytes: &[u8]) -> Result<(Vec<u8>, Option<String>), String> {
        inspect_tar(bytes, &mut Budget::new())
    }
    pub(super) fn artifact(bytes: &[u8], sri: &str) -> Result<Artifact, String> {
        inspect(bytes, sri, &mut Vec::new(), &mut Budget::new())
    }
}

const INPUT: usize = 64 * 1024;
const OUTPUT: usize = 64 * 1024 * 1024;

fn external_read(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take((OUTPUT + 1) as u64)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= OUTPUT).then_some(out)
}

fn same_json(actual: &JsonNode, expected: &serde_json::Value) -> bool {
    match (actual, expected) {
        (JsonNode::Null, serde_json::Value::Null) => true,
        (JsonNode::Bool(a), serde_json::Value::Bool(b)) => a == b,
        (JsonNode::String(a), serde_json::Value::String(b)) => a == b,
        (JsonNode::Number(a), serde_json::Value::Number(b)) => b.as_f64() == Some(*a),
        (JsonNode::Array(a), serde_json::Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same_json(x, y))
        }
        (JsonNode::Object(a), serde_json::Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| same_json(v, w)))
        }
        _ => false,
    }
}

pub fn json(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let actual = MiniParser::parse_json(input);
    if let Ok(value) = actual {
        let external: serde_json::Value =
            serde_json::from_str(input).expect("accepted invalid JSON");
        assert!(same_json(&value, &external), "JSON value mismatch");
        let roundtrip = MiniParser::parse_json(&value.to_json()).expect("invalid own JSON output");
        assert_eq!(roundtrip, value);
    }
    let quoted = serde_json::to_string(input).unwrap();
    assert_eq!(
        MiniParser::parse_json(&quoted).unwrap(),
        JsonNode::String(input.into())
    );
    assert_eq!(digest::sha256(data), format!("{:x}", Sha256::digest(data)));
    assert_eq!(digest::sha512(data), format!("{:x}", Sha512::digest(data)));
}

pub fn gzip(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    let generated = encoder.finish().unwrap();
    assert_eq!(archive::gzip(&generated).unwrap(), data);
    if let Ok(actual) = archive::gzip(data) {
        assert_eq!(Some(actual), external_read(GzDecoder::new(data)));
    }
}

pub fn deflate(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    let generated = encoder.finish().unwrap();
    assert_eq!(archive::deflate(&generated).unwrap(), data);
    if let Ok(actual) = archive::deflate(data) {
        assert_eq!(Some(actual), external_read(DeflateDecoder::new(data)));
    }
}

fn external_tar(data: &[u8]) -> Option<(Vec<u8>, Option<String>)> {
    let mut reader = tar::Archive::new(data);
    let mut manifest = None;
    let mut binding = None;
    for entry in reader.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_string_lossy().to_string();
        let relative = path.split_once('/').map(|(_, relative)| relative);
        if relative == Some("package.json") {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).ok()?;
            manifest = Some(bytes);
        } else if relative == Some("binding.gyp") {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).ok()?;
            binding = Some(format!("{:x}", Sha256::digest(&bytes)));
        }
    }
    Some((manifest?, binding))
}

fn repaired_tar(data: &[u8]) -> Vec<u8> {
    let mut bytes = data.to_vec();
    for header in bytes.chunks_exact_mut(512) {
        if &header[257..265] == b"ustar\0\0" {
            header[148..156].fill(b' ');
            let checksum: usize = header.iter().map(|b| *b as usize).sum();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        }
    }
    bytes
}

pub fn tar(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let bytes = if data.first() == Some(&1) {
        repaired_tar(&data[1..])
    } else {
        data.to_vec()
    };
    if let Ok(actual) = archive::tar(&bytes) {
        assert_eq!(Some(actual), external_tar(&bytes));
    }
}

pub fn artifact(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let bytes = if data.first() == Some(&1) {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&repaired_tar(&data[1..])).unwrap();
        encoder.finish().unwrap()
    } else {
        data.to_vec()
    };
    let sri = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
    );
    if let Ok(actual) = archive::artifact(&bytes, &sri) {
        assert_eq!(actual.sha512, format!("{:x}", Sha512::digest(&bytes)));
        assert_eq!(
            Some((actual.manifest, actual.binding_gyp_sha256)),
            external_read(GzDecoder::new(&bytes[..])).and_then(|bytes| external_tar(&bytes))
        );
    }
    let mut wrong = sri.into_bytes();
    wrong[7] = if wrong[7] == b'A' { b'B' } else { b'A' };
    assert!(archive::artifact(&bytes, std::str::from_utf8(&wrong).unwrap()).is_err());
}

pub fn lockfiles(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(graph) = DepGraph::parse_npm_lockfile(text) {
        assert!(graph.packages.len() <= 10_000);
        assert!(graph.graph.node_count() <= 10_000);
    }
    let _ = tau_gate::pnpm::parse(text, None);
    let _ = tau_gate::yarn::parse(text, None);
    let _ = MiniParser::parse_config(text);
}

pub fn ffi(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let n = (data.first().copied().unwrap_or(0) as usize % 32) + 1;
    let names: Vec<CString> = (0..n)
        .map(|i| CString::new(format!("node-{i}")).unwrap())
        .collect();
    let pointers: Vec<_> = names.iter().map(|s| s.as_ptr()).collect();
    let edges: Vec<i32> = data
        .get(1..)
        .unwrap_or_default()
        .chunks_exact(2)
        .take(128)
        .flat_map(|pair| [pair[0] as i32 % n as i32, pair[1] as i32 % n as i32])
        .collect();
    unsafe {
        let result =
            tau_gate::tau_gate_analyze(edges.as_ptr(), edges.len() / 2, pointers.as_ptr(), n);
        if !result.is_null() {
            assert!((*result).nodes_count <= n);
            assert!((*result).tau.is_finite());
            assert!((*result).connectivity_score.is_finite());
            assert!((*result).residual.is_finite());
            for i in 0..(*result).nodes_count {
                let name = CStr::from_ptr(*(*result).nodes.add(i)).to_str().unwrap();
                assert!(names
                    .iter()
                    .any(|candidate| candidate.to_str().unwrap() == name));
            }
            tau_gate::tau_gate_free_result(result);
        }
        assert!(tau_gate::tau_gate_analyze(std::ptr::null(), 1, pointers.as_ptr(), n).is_null());
        tau_gate::tau_gate_free_result(std::ptr::null_mut());
    }
}

pub fn review(data: &[u8]) {
    if data.len() > INPUT {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let lock = root.path().join("package-lock.json");
    let manifest = root.path().join("package.json");
    let index = root.path().join("index.json");
    let approvals = root.path().join("approvals.json");
    let fixture = br#"{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1"}}}"#;
    let manifest_fixture =
        br#"{"name":"root","version":"1","scripts":{"preinstall":"echo fixture"}}"#;
    std::fs::write(
        &lock,
        if data.first() == Some(&0) {
            &data[1..]
        } else {
            fixture
        },
    )
    .unwrap();
    std::fs::write(
        &manifest,
        if data.first() == Some(&1) {
            &data[1..]
        } else {
            manifest_fixture
        },
    )
    .unwrap();
    let index_fixture = format!(
        r#"{{"schema_version":1,"lock_sha256":"{}","packages":[{{"path":"","project_manifest":"package.json"}}]}}"#,
        digest::sha256(&std::fs::read(&lock).unwrap())
    );
    std::fs::write(
        &index,
        if data.first() == Some(&2) {
            &data[1..]
        } else {
            index_fixture.as_bytes()
        },
    )
    .unwrap();
    let approvals_fixture = br#"{"schema_version":1,"approvals":[]}"#;
    std::fs::write(
        &approvals,
        if data.first() == Some(&3) {
            &data[1..]
        } else {
            approvals_fixture
        },
    )
    .unwrap();
    if let Ok(snapshot) = Snapshot::load_with_evidence(&lock, Some(&manifest), &index) {
        let _ = snapshot.report();
        if data.first() != Some(&3) {
            let policy = snapshot.policy(Some(&approvals), true).unwrap();
            if policy.get("outcome").and_then(JsonNode::as_str) == Some("allowed") {
                assert!(snapshot.graph.execution_packages.is_empty());
            }
        }
        let no_approval = snapshot.policy(None, true).unwrap();
        assert_ne!(
            no_approval.get("outcome").and_then(JsonNode::as_str),
            Some("allowed")
        );
        let _ = snapshot.policy(Some(&approvals), true);
    }
}

#[cfg(test)]
mod seed_checks {
    use super::*;

    #[test]
    fn independently_generated_archive_seeds_reach_success_paths() {
        let raw = std::fs::read("corpus/tar/ordinary").unwrap();
        let tar_facts = archive::tar(&raw).unwrap();
        assert!(tar_facts.0.starts_with(b"{\"name\":\"seed\""));
        assert!(tar_facts.1.is_some());
        let named = std::fs::read("corpus/tar/named-root").unwrap();
        assert_eq!(archive::tar(&named).unwrap(), tar_facts);
        assert_eq!(external_tar(&named), Some(tar_facts.clone()));
        let alias = std::fs::read("corpus/tar/identical-dot-alias").unwrap();
        assert_eq!(archive::tar(&alias).unwrap().0, tar_facts.0);
        assert_eq!(external_tar(&alias).unwrap().0, tar_facts.0);
        let gz = std::fs::read("corpus/artifact/ordinary").unwrap();
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&gz))
        );
        let facts = archive::artifact(&gz, &sri).unwrap();
        assert_eq!(facts.manifest, tar_facts.0);
        assert_eq!(facts.binding_gyp_sha256, tar_facts.1);
    }

    #[test]
    fn root_evidence_seed_reaches_enforcement_and_blocks_missing_approval() {
        let root = tempfile::tempdir().unwrap();
        let lock = root.path().join("package-lock.json");
        let manifest = root.path().join("package.json");
        let index = root.path().join("index.json");
        let approvals = root.path().join("approvals.json");
        let lock_bytes = br#"{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1"}}}"#;
        std::fs::write(&lock, lock_bytes).unwrap();
        std::fs::write(
            &manifest,
            br#"{"name":"root","version":"1","scripts":{"preinstall":"echo fixture"}}"#,
        )
        .unwrap();
        std::fs::write(&index, format!(r#"{{"schema_version":1,"lock_sha256":"{}","packages":[{{"path":"","project_manifest":"package.json"}}]}}"#, digest::sha256(lock_bytes))).unwrap();
        std::fs::write(&approvals, br#"{"schema_version":1,"approvals":[]}"#).unwrap();
        let snapshot = Snapshot::load_with_evidence(&lock, Some(&manifest), &index).unwrap();
        assert!(snapshot.is_complete());
        assert_eq!(
            snapshot
                .policy(Some(&approvals), true)
                .unwrap()
                .get("outcome")
                .and_then(JsonNode::as_str),
            Some("blocked")
        );
    }
}
