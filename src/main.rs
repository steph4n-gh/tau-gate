mod config;
mod daemon;
mod error;
mod graph;
mod graph_impl;
mod math;
mod network;
mod parser;
mod semver;
mod telemetry;

use crate::error::Result;
use config::{EnforcementMode, SentinelConfig};
use graph::{DepGraph, EngineType};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::process::{exit, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// V3.0.7 Build Metadata
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_HASH: &str = env!("GIT_HASH");

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "daemon" {
        return daemon::run();
    }

    let dry_run = args.iter().any(|arg| arg == "--dry-run" || arg == "-d");
    let show_verify = args.iter().any(|arg| arg == "--verify" || arg == "-v");
    let use_network = args.iter().any(|arg| arg == "--network" || arg == "-n");

    if show_verify {
        println!("[\u{03C4}-Gate] \u{1F512}  Integrity Verification");
        println!("Version: {}", VERSION);
        println!("Build Hash: {}", BUILD_HASH);
        return Ok(());
    }

    println!("\n[\u{03C4}-Gate] \u{1F6E1}\u{FE0F}  Zero-Trust Supply Chain Security v3.0.7");
    if dry_run {
        println!("[\u{03C4}-Gate] \u{1F50D}  MODE: DRY-RUN (Passive Audit)");
    }
    println!("--------------------------------------------------");

    // 1. Initialize Configuration
    let config = SentinelConfig::load("tau-gate.toml").unwrap_or_default();

    println!("[\u{03C4}-Gate] \u{23F3}  Mapping topology and verifying connectivity...");

    let start_time = SystemTime::now();

    // 2. The Extraction Phase
    let (dep_graph, engine) = match DepGraph::build(use_network) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[\u{03C4}-Gate] \u{274C} Lockfile Extraction Failed: {}", e);
            exit(1);
        }
    };

    let node_count = dep_graph.graph.node_count();

    if node_count < 3 {
        println!("[\u{03C4}-Gate] \u{2139}\u{FE0F} Graph too small for audit. Proceeding...");
        if dry_run {
            return Ok(());
        }
        execute_actual_install(engine);
    }

    // 3. The Math & Tripwire Phase (Recursive Bisection)
    let mut current_graph = dep_graph.graph.clone();
    let mut total_quarantined_execution = BTreeSet::new();
    let mut total_quarantined_entropy = BTreeSet::new();
    let mut iteration = 0;
    let mut first_connectivity_score = 0.0;
    let mut first_tau = 0.0;
    let mut first_anomaly_size = 0;

    println!("[\u{03C4}-Gate] \u{1F50D}  Performing Recursive Spectral Bisection...");

    loop {
        let node_count = current_graph.node_count();
        if node_count < 3 { break; }

        let partition_result = match math::analyze_graph(&current_graph) {
            Ok(r) => r,
            Err(_) => break,
        };

        if iteration == 0 {
            first_connectivity_score = partition_result.connectivity_score;
            first_tau = partition_result.tau;
            first_anomaly_size = partition_result.partition_b.len();
        }

        let total_nodes = node_count as f64;
        let global_scan_threshold = 0.5 / total_nodes;
        
        println!(
            "[\u{03C4}-Gate] \u{1F517} Iteration {}: \u{03BB}\u{2082} = {:.6} (Threshold: {:.2e})",
            iteration + 1,
            partition_result.connectivity_score,
            global_scan_threshold
        );

        // Scan the isolated island for threats
        for node in &partition_result.partition_b {
            let is_exec = check_threat_match(node, &dep_graph.execution_packages);
            let is_entropy = check_threat_match(node, &dep_graph.suspicious_packages);

            if is_exec || is_entropy {
                let mut is_whitelisted = false;
                for pattern_str in &config.whitelist {
                    if glob_match(pattern_str, node) {
                        is_whitelisted = true;
                        if !pattern_str.contains('@') {
                            println!("[\u{03C4}-Gate] \u{26A0}\u{FE0F}  WHITELIST ROT WARNING: '{}' is unpinned.", pattern_str);
                        }
                        break;
                    }
                }
                if !is_whitelisted {
                    if is_exec { total_quarantined_execution.insert(node.clone()); }
                    if is_entropy { total_quarantined_entropy.insert(node.clone()); }
                }
            }
        }

        // v3.0.7 Paradox Resolution: Recurse on partition_a if it remains isolated.
        if partition_result.connectivity_score < global_scan_threshold && iteration < 10 {
            current_graph = dep_graph.graph.subgraph(&partition_result.partition_a);
            iteration += 1;
        } else {
            break;
        }
    }

    let elapsed = start_time
        .elapsed()
        .unwrap_or(Duration::from_secs(0))
        .as_millis();

    println!(
        "[\u{03C4}-Gate] \u{2705} Recursive Audit Complete ({} iterations) in {} ms",
        iteration + 1, elapsed
    );

    let execution_threats: Vec<String> = total_quarantined_execution.into_iter().collect();
    let entropy_threats: Vec<String> = total_quarantined_entropy.into_iter().collect();

    // 5. The Gate Phase (Enforcement)
    if !execution_threats.is_empty() || !entropy_threats.is_empty() {
        eprintln!("\n[\u{03C4}-Gate] \u{26A0}\u{FE0F}  CRITICAL TOPOLOGICAL ANOMALY!");

        if !execution_threats.is_empty() {
            eprintln!("Quarantined execution-privileged nodes:");
            for node in &execution_threats {
                eprintln!("  \u{2192} {}", node);
            }
        }

        if !entropy_threats.is_empty() {
            eprintln!("Quarantined high-entropy (obfuscated) nodes:");
            for node in &entropy_threats {
                eprintln!("  \u{26A0} {}", node);
            }
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".to_string());
        
        let log = telemetry::AnomalyLog {
            timestamp,
            tau: first_tau,
            anomaly_size: first_anomaly_size,
            total_nodes: node_count,
            isolated_nodes: execution_threats.clone(),
            message: format!(
                "Recursive Isolation Detection. Base Score: {:.6}, Total Quarantined: {}",
                first_connectivity_score, execution_threats.len() + entropy_threats.len()
            ),
        };
        let _ = telemetry::log_anomaly(&log);

        if let EngineType::Npm = engine {
            let _ = fs::remove_file("package-lock.json");
        }

        if config.mode == EnforcementMode::Enforcement {
            eprintln!("\n[\u{03C4}-Gate] \u{1F6AB} INSTALLATION ABORTED. Environment secured.\n");
            exit(1);
        } else {
            println!("\n[\u{03C4}-Gate] \u{26A0}\u{FE0F}  ADVISORY MODE: Anomaly detected but proceeding as per policy.");
        }
    }

    println!("[\u{03C4}-Gate] \u{1F6A7} Topology nominal. Gate opened.");
    if !dry_run {
        execute_actual_install(engine);
    }
    Ok(())
}

fn check_threat_match(node: &str, threats: &BTreeSet<String>) -> bool {
    if threats.contains(node) {
        return true;
    }
    for threat in threats {
        if node.contains(threat) || threat.contains(node) {
            return true;
        }
    }
    false
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("*") {
        return text.starts_with(prefix);
    }
    pattern == text
}

fn execute_actual_install(engine: EngineType) {
    let cmd = match engine {
        EngineType::Npm => "npm",
        EngineType::Pnpm => "pnpm",
        EngineType::Bun => "bun",
        EngineType::Yarn => "yarn",
        EngineType::Cargo => "cargo",
        EngineType::Go => "go",
        EngineType::Network => {
            println!("[\u{03C4}-Gate] \u{1F6A7} Network audit completed. Bypassing installation due to lack of lockfile context.");
            exit(0);
        }
    };
    let args = match engine {
        EngineType::Cargo => vec!["build"],
        EngineType::Go => vec!["mod", "download"],
        _ => vec!["install"],
    };

    let home = std::env::var("HOME").unwrap_or_default();
    let safe_path = format!(
        "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/home/linuxbrew/.linuxbrew/bin:{}/.cargo/bin",
        home
    );

    let status = Command::new(cmd)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", safe_path)
        .args(&args)
        .status()
        .expect("Native install failed");
    exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("@astrojs/*", "@astrojs/compiler"));
        assert!(!glob_match("@astrojs/*", "lodash"));
    }

    #[test]
    fn test_threat_match() {
        let mut threats = BTreeSet::new();
        threats.insert("malicious".to_string());
        assert!(check_threat_match("node_modules/malicious@1.0.0", &threats));
    }
}
