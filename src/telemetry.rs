use anyhow::{Context, Result};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Structured log for recorded supply chain anomalies.
#[derive(Serialize)]
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
        fs::create_dir_all(local_dir).context("Failed to create logs directory")?;
    }

    let log_path = local_dir.join("tau-gate_anomalies.json");
    let json = serde_json::to_string(log).context("Failed to serialize telemetry log")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .context("Failed to open telemetry log file")?;

    writeln!(file, "{}", json).context("Failed to write to telemetry log file")?;

    Ok(())
}
