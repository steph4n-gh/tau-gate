mod config;
mod error;
mod graph;
mod graph_impl;
mod math;
mod parser;
mod telemetry;
mod network;
mod semver;
mod daemon;

use crate::error::Result;
use config::{EnforcementMode, SentinelConfig};
use graph::{DepGraph, EngineType};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::process::{Command, exit};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// V3.0.0 Build Metadata
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

    println!("\n[\u{03C4}-Gate] \u{1F6E1}\u{FE0F}  Zero-Trust Supply Chain Security v3.0.0");
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
        if dry_run { return Ok(()); }
        execute_actual_install(engine);
    }

    // 3. The Math Phase
    let partition_result = match math::analyze_graph(&dep_graph.graph) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[\u{03C4}-Gate] \u{274C} Math Engine Error: {}", e);
            exit(1);
        }
    };

    let elapsed = start_time.elapsed().unwrap_or(Duration::from_secs(0)).as_millis();

    pb_finish_and_clear(); // Custom replacement for pb

    println!("[\u{03C4}-Gate] \u{2705} Analyzed {} nodes in {} ms", node_count, elapsed);
    println!("[\u{03C4}-Gate] \u{1F517} Connectivity Score (\u{03BB}\u{2082}): {:.6}", partition_result.connectivity_score);

    let total_nodes = node_count as f64;
    let anomaly_size = partition_result.partition_b.len() as f64;
    let percentage = (anomaly_size / total_nodes) * 100.0;

    println!("[\u{03C4}-Gate] \u{1F4CA} Smallest Partition: {} nodes ({:.2}%)", partition_result.partition_b.len(), percentage);

    // 4. The Tripwire Phase
    let mut execution_threats = Vec::new();
    let mut entropy_threats = Vec::new();

    for node in &partition_result.partition_b {
        let is_exec = check_threat_match(node, &dep_graph.execution_packages);
        let is_entropy = check_threat_match(node, &dep_graph.suspicious_packages);

        if is_exec || is_entropy {
            let mut is_whitelisted = false;
            for pattern_str in &config.whitelist {
                if glob_match(pattern_str, node) {
                    is_whitelisted = true;
                    
                    let is_scoped = pattern_str.starts_with('@');
                    let has_version_pin = if is_scoped {
                        pattern_str[1..].contains('@')
                    } else {
                        pattern_str.contains('@')
                    };
                    
                    if !has_version_pin {
                        println!("[\u{03C4}-Gate] \u{26A0}\u{FE0F}  WHITELIST ROT WARNING: '{}' is unpinned. Any future compromised version will automatically bypass security. Please pin to a specific version.", pattern_str);
                    }
                    break;
                }
            }
            if !is_whitelisted { 
                if is_exec { execution_threats.push(node.clone()); }
                if is_entropy { entropy_threats.push(node.clone()); }
            }
        }
    }

    // 5. The Gate Phase (Enforcement)
    let extreme_isolation = partition_result.connectivity_score < 1e-4 && (!execution_threats.is_empty() || !entropy_threats.is_empty());

    if (!execution_threats.is_empty() || !entropy_threats.is_empty()) && (percentage < config.threshold_percentage || extreme_isolation) {
        eprintln!("\n[\u{03C4}-Gate] \u{26A0}\u{FE0F}  CRITICAL TOPOLOGICAL ANOMALY!");
        
        if !execution_threats.is_empty() {
            eprintln!("Quarantined execution-privileged nodes:");
            for node in &execution_threats { eprintln!("  \u{2192} {}", node); }
        }

        if !entropy_threats.is_empty() {
            eprintln!("Quarantined high-entropy (obfuscated) nodes:");
            for node in &entropy_threats { eprintln!("  \u{26A0} {}", node); }
        }

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
        let log = telemetry::AnomalyLog {
            timestamp,
            tau: partition_result.tau,
            anomaly_size: partition_result.partition_b.len(),
            total_nodes: total_nodes as usize,
            isolated_nodes: execution_threats.clone(),
            message: format!("Isolation Detection. Score: {:.6}, Partition: {:.2}%", partition_result.connectivity_score, percentage),
        };
        let _ = telemetry::log_anomaly(&log);

        if let EngineType::Npm = engine { let _ = fs::remove_file("package-lock.json"); }

        if config.mode == EnforcementMode::Enforcement {
            eprintln!("\n[\u{03C4}-Gate] \u{1F6AB} INSTALLATION ABORTED. Environment secured.\n");
            exit(1);
        } else {
            println!("\n[\u{03C4}-Gate] \u{26A0}\u{FE0F}  ADVISORY MODE: Anomaly detected but proceeding as per policy.");
        }
    }

    println!("[\u{03C4}-Gate] \u{1F6A7} Topology nominal. Gate opened.");
    if !dry_run { execute_actual_install(engine); }
    Ok(())
}

fn pb_finish_and_clear() {
    // No-op for now as we removed indicatif
}

fn check_threat_match(node: &str, threats: &BTreeSet<String>) -> bool {
    if threats.contains(node) { return true; }
    for threat in threats {
        if node.contains(threat) || threat.contains(node) { return true; }
    }
    false
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" { return true; }
    if let Some(prefix) = pattern.strip_suffix("*") { return text.starts_with(prefix); }
    pattern == text
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

fn execute_actual_install(engine: EngineType) {
    let cmd = match engine { EngineType::Npm => "npm", EngineType::Pnpm => "pnpm", EngineType::Bun => "bun", EngineType::Yarn => "yarn", EngineType::Cargo => "cargo", EngineType::Go => "go", EngineType::Network => {
        println!("[\u{03C4}-Gate] \u{1F6A7} Network audit completed. Bypassing installation due to lack of lockfile context.");
        exit(0);
    }};
    let args = match engine { EngineType::Cargo => vec!["build"], EngineType::Go => vec!["mod", "download"], _ => vec!["install"] };
    
    let home = std::env::var("HOME").unwrap_or_default();
    let safe_path = format!("/usr/bin:/bin:/usr/local/bin:{}/.cargo/bin", home);
    
    let status = Command::new(cmd).env_clear().env("HOME", &home).env("PATH", safe_path).args(&args).status().expect("Native install failed");
    exit(status.code().unwrap_or(1));
}
