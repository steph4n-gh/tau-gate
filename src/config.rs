use crate::error::{GateError, Result};
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
    /// Exact name@version approvals; these do not pin artifact digests.
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

        let content = fs::read_to_string(path)
            .map_err(|e| GateError::Config(format!("Failed to read config file: {}", e)))?;
        let map = MiniParser::parse_config(&content)
            .map_err(|e| GateError::Config(format!("Failed to parse config file: {}", e)))?;

        for (key, value) in &map {
            let valid = match key.as_str() {
                "whitelist" => matches!(value, ConfigValue::Array(_)),
                "mode" => matches!(value, ConfigValue::String(_)),
                "threshold_percentage" => matches!(value, ConfigValue::Float(_)),
                _ => false,
            };
            if !valid {
                return Err(GateError::Config(format!("Invalid type for {key}")));
            }
        }
        let mut config = Self::default();

        if let Some(ConfigValue::Float(val)) = map.get("threshold_percentage") {
            if !val.is_finite() || !(0.0..=100.0).contains(val) {
                return Err(GateError::Config(
                    "threshold_percentage must be finite and in 0..=100".into(),
                ));
            }
            config.threshold_percentage = *val;
        }

        if let Some(ConfigValue::Array(val)) = map.get("whitelist") {
            config.whitelist = val.clone();
        }

        if let Some(ConfigValue::String(val)) = map.get("mode") {
            if val.eq_ignore_ascii_case("advisory") {
                config.mode = EnforcementMode::Advisory;
            } else if !val.eq_ignore_ascii_case("enforcement") {
                return Err(GateError::Config(
                    "mode must be advisory or enforcement".into(),
                ));
            }
        }

        Ok(config)
    }
}
