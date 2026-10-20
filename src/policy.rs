use crate::{
    evidence::read_regular,
    parser::{JsonNode as J, MiniParser},
    review::{object, string, Snapshot, SnapshotFormat},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn valid_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn approvals(path: &Path) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let bytes = read_regular(path, 64 * 1024 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "approval JSON must be UTF-8")?;
    let value = MiniParser::parse_json(text).map_err(|e| e.to_string())?;
    let fields = value.as_object().ok_or("approval file must be an object")?;
    if fields.len() != 2 {
        return Err("unsupported approval schema".into());
    }
    let version = match value.get("schema_version") {
        Some(J::Number(1.0)) => 1,
        Some(J::Number(2.0)) => 2,
        _ => return Err("unsupported approval schema".into()),
    };
    let items = value
        .get("approvals")
        .and_then(J::as_array)
        .ok_or("approvals must be an array")?;
    let mut result = BTreeMap::new();
    for item in items {
        let fields = item.as_object().ok_or("invalid approval entry")?;
        let path = item
            .get("path")
            .and_then(J::as_str)
            .ok_or("approval requires exact instance path")?;
        let mut fingerprints = BTreeSet::new();
        if version == 1 {
            if fields.len() != 2 {
                return Err("approval entry requires path and fingerprint".into());
            }
            let fingerprint = item
                .get("fingerprint")
                .and_then(J::as_str)
                .ok_or("approval requires fingerprint")?;
            if !valid_fingerprint(fingerprint) {
                return Err("approval fingerprint must be lowercase SHA256 hex".into());
            }
            fingerprints.insert(fingerprint.to_owned());
        } else {
            if fields.len() != 2 {
                return Err("approval entry requires path and fingerprints".into());
            }
            let values = item
                .get("fingerprints")
                .and_then(J::as_array)
                .ok_or("approval requires a fingerprint array")?;
            if values.is_empty() {
                return Err("approval fingerprint array cannot be empty".into());
            }
            for value in values {
                let fingerprint = value
                    .as_str()
                    .ok_or("approval fingerprint must be lowercase SHA256 hex")?;
                if !valid_fingerprint(fingerprint) {
                    return Err("approval fingerprint must be lowercase SHA256 hex".into());
                }
                if !fingerprints.insert(fingerprint.to_owned()) {
                    return Err("duplicate approval fingerprint".into());
                }
            }
        }
        if result.insert(path.into(), fingerprints).is_some() {
            return Err("duplicate approval instance".into());
        }
    }
    Ok(result)
}
pub(crate) fn evaluate(
    snapshot: &Snapshot,
    path: Option<&Path>,
    enforce: bool,
) -> Result<J, String> {
    let approved = path.map(approvals).transpose()?;
    if approved.is_some() && snapshot.format != SnapshotFormat::Npm {
        return Err("bound approvals are qualified only for npm v3".into());
    }
    let mut issues = Vec::new();
    if enforce && snapshot.evidence.is_none() {
        issues.push(string(
            "explicit execution evidence is required for enforcement",
        ))
    }
    if enforce && approved.is_none() {
        issues.push(string(
            "an explicit bound-approval file is required for enforcement",
        ))
    }
    let mut violations = Vec::new();
    if let Some(evidence) = &snapshot.evidence {
        for (path, e) in evidence {
            if !e.qualified() {
                issues.push(object([("path", string(path)), ("evidence", e.json(path))]));
            }
            if e.candidate()
                && e.fingerprint().is_some_and(|fp| {
                    approved
                        .as_ref()
                        .and_then(|a| a.get(path))
                        .is_none_or(|fingerprints| !fingerprints.contains(fp))
                })
            {
                violations.push(object([
                    ("path", string(path)),
                    (
                        "fingerprint",
                        e.fingerprint().map(string).unwrap_or(J::Null),
                    ),
                ]));
            }
        }
    }
    let outcome = if !snapshot.is_complete() || !issues.is_empty() {
        "incomplete"
    } else if !enforce {
        "advisory"
    } else if !violations.is_empty() {
        "blocked"
    } else {
        "allowed"
    };
    Ok(object([
        ("outcome",string(outcome)),("enforcement_requested",J::Bool(enforce)),
        ("approval_scope",string("exact npm instance, source/integrity, original archive, manifest bytes, lifecycle bodies and native facts; supplied source snapshots retain caller trust")),
        ("issues",J::Array(issues)),("unapproved_execution_candidates",J::Array(violations)),
    ]))
}
