//! Retired registry adapter: metadata is not a reproducible installation snapshot.
use crate::error::{GateError, Result};
pub fn fetch_npm_metadata(_package_name: &str) -> Result<String> {
    Err(GateError::Graph(
        "INCOMPLETE: registry fetching is unsupported; supply a frozen npm v3 lockfile".into(),
    ))
}
