use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Configuration for the Tau-Gate security engine.
/// Defines mathematical thresholds and topological bindings.
#[derive(Debug, Deserialize, Serialize)]
pub struct SentinelConfig {
    /// List of glob patterns for trusted packages that are allowed to bridge to isolation.
    pub whitelist: Vec<String>,
    /// The structural median anomaly threshold percentage (Default 15.0).
    pub threshold_percentage: f64,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            whitelist: vec![],
            threshold_percentage: 15.0,
        }
    }
}

impl SentinelConfig {
    /// Loads configuration from a TOML file. Falls back to default if file is missing.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config: SentinelConfig =
            toml::from_str(&content).context("Failed to parse config file")?;
        Ok(config)
    }
}
