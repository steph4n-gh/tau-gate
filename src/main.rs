mod config;
mod graph;
mod math;
mod telemetry;

use anyhow::Result;
use config::SentinelConfig;
use glob::Pattern;
use graph::{DepGraph, EngineType};
use indicatif::{ProgressBar, ProgressStyle};
use std::env;
use std::fs;
use std::process::{Command, exit};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// V1.1.0 Build Metadata
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_HASH: &str = env!("GIT_HASH"); 

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let dry_run = args.iter().any(|arg| arg == "--dry-run" || arg == "-d");
    let show_verify = args.iter().any(|arg| arg == "--verify" || arg == "-v");

    if show_verify {
        println!("[\u{03C4}-Gate] \u{1F512}  Integrity Verification");
        println!("Version: {}", VERSION);
        println!("Build Hash: {}", BUILD_HASH);
        return Ok(());
    }

    println!("\n[\u{03C4}-Gate] \u{1F6E1}\u{FE0F}  Zero-Trust Supply Chain Security v1.1.0");
    if dry_run {
        println!("[\u{03C4}-Gate] \u{1F50D}  MODE: DRY-RUN (Passive Audit)");
    }
    println!("--------------------------------------------------");

    let config = SentinelConfig::load("tau-gate.toml").unwrap_or_default();
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().tick_chars("\u{25DC}\u{25DD}\u{25DE}\u{25DF}").template("{spinner:.blue} {msg}")?);
    pb.set_message("Mapping topology and verifying connectivity...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let start_time = SystemTime::now();
    let (dep_graph, engine) = match DepGraph::build() {
        Ok(res) => res,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("[\u{03C4}-Gate] \u{274C} Lockfile Extraction Failed: {}", e);
            exit(1);
        }
    };

    let node_count = dep_graph.graph.node_count();

    if node_count < 3 {
        pb.finish_and_clear();
        println!("[\u{03C4}-Gate] \u{2139}\u{FE0F} Graph too small for audit. Proceeding...");
        if dry_run { return Ok(()); }
        execute_actual_install(engine);
    }

    let partition_result = match math::analyze_graph(&dep_graph.graph) {
        Ok(r) => r,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("[\u{03C4}-Gate] \u{274C} Math Engine Error: {}", e);
            exit(1);
        }
    };

    let elapsed = start_time.elapsed().unwrap().as_millis();
    pb.finish_and_clear();

    println!("[\u{03C4}-Gate] \u{2705} Analysis Complete ({} ms)", elapsed);
    println!("[\u{03C4}-Gate] \u{1F517} Connectivity Score (\u{03BB}\u{2082}): {:.6}", partition_result.connectivity_score);

    let total_nodes = node_count as f64;
    let anomaly_size = partition_result.partition_b.len() as f64;
    let percentage = (anomaly_size / total_nodes) * 100.0;

    println!("[\u{03C4}-Gate] \u{1F4CA} Smallest Partition: {} nodes ({:.2}%)", partition_result.partition_b.len(), percentage);

    let mut execution_threats = Vec::new();
    for node in &partition_result.partition_b {
        if dep_graph.execution_packages.contains(node) {
            let mut is_whitelisted = false;
            for pattern_str in &config.whitelist {
                if let Ok(pattern) = Pattern::new(pattern_str) {
                    if pattern.matches(node) { is_whitelisted = true; break; }
                }
            }
            if !is_whitelisted { execution_threats.push(node.clone()); }
        }
    }

    let extreme_isolation = partition_result.connectivity_score < 1e-4 && !execution_threats.is_empty();

    if (!execution_threats.is_empty() && percentage < config.threshold_percentage) || extreme_isolation {
        eprintln!("\n[\u{03C4}-Gate] \u{26A0}\u{FE0F}  CRITICAL TOPOLOGICAL ANOMALY!");
        if extreme_isolation && percentage >= config.threshold_percentage {
            eprintln!("WARNING: Detected a 'Bloated Trojan' attack (Extreme isolation in a large partition).");
        }
        eprintln!("Quarantined execution-privileged nodes:");
        for node in &execution_threats { eprintln!("  \u{2192} {}", node); }

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
        eprintln!("\n[\u{03C4}-Gate] \u{1F6AB} INSTALLATION ABORTED. Environment secured.\n");
        exit(1);
    }

    println!("[\u{03C4}-Gate] \u{1F6A7} Topology nominal. Gate opened.");
    if !dry_run { execute_actual_install(engine); }
    Ok(())
}

fn execute_actual_install(engine: EngineType) {
    let cmd = match engine {
        EngineType::Npm => "npm",
        EngineType::Pnpm => "pnpm",
        EngineType::Bun => "bun",
        EngineType::Yarn => "yarn",
        EngineType::Cargo => "cargo",
    };

    let args = match engine {
        EngineType::Cargo => vec!["build"],
        _ => vec!["install"],
    };

    let status = Command::new(cmd)
        .args(&args)
        .status()
        .expect(&format!("Failed to execute native {} installation", cmd));
    exit(status.code().unwrap_or(1));
}
