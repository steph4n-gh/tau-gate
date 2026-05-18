use crate::error::{GateError, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Structured log for recorded supply chain anomalies.
pub struct AnomalyLog {
    /// Unix timestamp of the event.
    pub timestamp: String,
    /// The mathematical bisection point used.
    pub tau: f64,
    /// Number of nodes in the anomaly partition.
    pub anomaly_size: usize,
    /// Total nodes in the analyzed graph.
    pub total_nodes: usize,
    /// Names of the nodes quarantined during the audit.
    pub isolated_nodes: Vec<String>,
    /// Summary of the security violation.
    pub message: String,
}

/// Dispatches structured JSON telemetry to the local SIEM log directory.
pub fn log_anomaly(log: &AnomalyLog) -> Result<()> {
    let local_dir = Path::new("logs");

    if !local_dir.exists() {
        fs::create_dir_all(local_dir)
            .map_err(|e| GateError::Telemetry(format!("Failed to create logs directory: {}", e)))?;
    }

    let log_path = local_dir.join("tau-gate_anomalies.json");

    // Manual JSON serialization to move toward zero-dependency
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!(
        "  \"timestamp\": \"{}\",\n",
        escape_json_string(&log.timestamp)
    ));
    json.push_str(&format!("  \"tau\": {},\n", log.tau));
    json.push_str(&format!("  \"anomaly_size\": {},\n", log.anomaly_size));
    json.push_str(&format!("  \"total_nodes\": {},\n", log.total_nodes));
    json.push_str("  \"isolated_nodes\": [\n");
    for (i, node) in log.isolated_nodes.iter().enumerate() {
        json.push_str(&format!("    \"{}\"", escape_json_string(node)));
        if i < log.isolated_nodes.len() - 1 {
            json.push_str(",\n");
        } else {
            json.push('\n');
        }
    }
    json.push_str("  ],\n");
    json.push_str(&format!(
        "  \"message\": \"{}\"\n",
        escape_json_string(&log.message)
    ));
    json.push('}');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| GateError::Telemetry(format!("Failed to open telemetry log file: {}", e)))?;

    writeln!(file, "{}", json).map_err(|e| {
        GateError::Telemetry(format!("Failed to write to telemetry log file: {}", e))
    })?;

    Ok(())
}

fn escape_json_string(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '\"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(c),
        }
    }
    escaped
}
