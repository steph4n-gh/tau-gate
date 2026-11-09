//! Explicit, bounded source context. These bytes never qualify execution evidence.
use crate::{
    digest::sha256,
    graph::ProjectInputs,
    parser::{JsonNode as J, MiniParser},
};
use std::{collections::BTreeMap, path::Path};

pub(crate) struct Loaded {
    pub files: ProjectInputs,
    pub hashes: BTreeMap<String, J>,
    pub index_hash: String,
}
fn keys(value: &J, expected: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.len() == expected.len() && expected.iter().all(|k| m.contains_key(*k)))
}
pub(crate) fn load(index: &Path) -> Result<Loaded, String> {
    let bytes = crate::evidence::read_regular(index, 4 * 1024 * 1024)?;
    let root = MiniParser::parse_json(
        std::str::from_utf8(&bytes).map_err(|_| "project input index must be UTF-8")?,
    )
    .map_err(|e| e.to_string())?;
    if !keys(&root, &["schema_version", "files"])
        || root.get("schema_version") != Some(&J::Number(1.0))
    {
        return Err("invalid project input index schema".into());
    }
    let entries = root
        .get("files")
        .and_then(J::as_array)
        .ok_or("project input files must be an array")?;
    if entries.len() > 10_000 {
        return Err("too many project input files".into());
    }
    let parent = index
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut loaded = Loaded {
        files: BTreeMap::new(),
        hashes: BTreeMap::new(),
        index_hash: sha256(&bytes),
    };
    let mut total = 0;
    for entry in entries {
        if !keys(entry, &["path", "file"]) {
            return Err("invalid project input entry".into());
        }
        let logical = entry
            .get("path")
            .and_then(J::as_str)
            .ok_or("project input path must be a string")?;
        crate::evidence::safe_relative(logical, false)?;
        if loaded.files.contains_key(logical) {
            return Err(format!("duplicate project input path {logical}"));
        }
        let locator = entry
            .get("file")
            .and_then(J::as_str)
            .ok_or("project input locator must be a string")?;
        let path = crate::evidence::confined(parent, locator)?;
        let data = crate::evidence::read_regular(&path, 1024 * 1024)?;
        total += data.len();
        if total > 64 * 1024 * 1024 {
            return Err("project input source budget exceeded".into());
        }
        loaded
            .hashes
            .insert(logical.into(), J::String(sha256(&data)));
        loaded.files.insert(logical.into(), data);
    }
    Ok(loaded)
}
