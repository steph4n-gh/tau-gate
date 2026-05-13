use crate::error::{GateContext, GateError, Result};
use crate::parser::{ConfigValue, MiniParser};
use std::fs;
use std::path::Path;

/// Security Enforcement Mode
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EnforcementMode {
    /// Kill the build if an anomaly is detected.
    Enforcement,
    /// Warn but allow the build to proceed.
    Advisory,
}

/// Configuration for the Tau-Gate security engine.
pub struct SentinelConfig {
    /// List of glob patterns for trusted packages.
    pub whitelist: Vec<String>,
    /// The structural median anomaly threshold percentage.
    pub threshold_percentage: f64,
    /// Operating mode (Advisory or Enforcement).
    pub mode: EnforcementMode,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            whitelist: vec![],
            threshold_percentage: 15.0,
            mode: EnforcementMode::Enforcement,
        }
    }
}

impl SentinelConfig {
    /// Loads configuration using the bespoke MiniParser.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        
        let content = fs::read_to_string(path).map_err(|e| GateError::Config(format!("Failed to read config file: {}", e)))?;
        let map = MiniParser::parse_config(&content).map_err(|e| GateError::Config(format!("Failed to parse config file: {}", e)))?;
        
        let mut config = Self::default();
        
        if let Some(ConfigValue::Float(val)) = map.get("threshold_percentage") {
            config.threshold_percentage = *val;
        }
        
        if let Some(ConfigValue::Array(val)) = map.get("whitelist") {
            config.whitelist = val.clone();
        }

        if let Some(ConfigValue::String(val)) = map.get("mode") {
            if val == "advisory" {
                config.mode = EnforcementMode::Advisory;
            }
        }
        
        Ok(config)
    }
}
