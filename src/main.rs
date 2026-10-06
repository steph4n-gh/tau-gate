use std::{env, path::Path, process::ExitCode};
use tau_gate::{
    config::SentinelConfig,
    parser::JsonNode as J,
    review::{self, Snapshot},
};
const HELP:&str="tau-gate: read-only dependency review\n\
Usage: tau-gate [audit] [--lock package-lock.json] [--manifest package.json] [--json] [--enforce]\n\
       tau-gate review --base BASE_LOCK --head HEAD_LOCK [--base-manifest FILE] [--head-manifest FILE] [--json]\n\
       tau-gate --verify | --help\n\
Audit never resolves, installs, deletes inputs, or writes logs. Npm v3 is the qualified review format.\n\
Exit: 0 completed advisory report; 1 explicit enforcement finding; 2 incomplete/invalid; 64 usage.\n\
--dry-run/-d is a compatibility alias for read-only audit. Network and legacy daemon are unsupported.";
fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args == ["--verify"] {
        println!(
            "Version: {}\nBuild commit: {} (provenance only)",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_HASH")
        );
        return ExitCode::SUCCESS;
    }
    let json = args.iter().any(|a| a == "--json");
    match run(&args) {
        Ok((report, code)) => {
            if json {
                println!("{}", report.to_json())
            } else {
                println!(
                    "Read-only dependency review: {}",
                    report
                        .get("status")
                        .and_then(J::as_str)
                        .unwrap_or("complete")
                );
                human(&report);
            }
            ExitCode::from(code)
        }
        Err((message, code)) => {
            if json {
                println!(
                    "{}",
                    review::object([
                        ("schema_version", J::Number(1.0)),
                        (
                            "status",
                            review::string(if code == 64 {
                                "usage_error"
                            } else {
                                "incomplete"
                            })
                        ),
                        ("error", review::string(message))
                    ])
                    .to_json()
                )
            } else {
                eprintln!("{message}")
            }
            ExitCode::from(code)
        }
    }
}
fn run(args: &[String]) -> Result<(J, u8), (String, u8)> {
    let mode = args
        .first()
        .filter(|s| !s.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("audit");
    if !matches!(mode, "audit" | "review") {
        return Err((format!("Unsupported command {mode}; use --help"), 64));
    }
    let mut opts = std::collections::BTreeMap::new();
    let mut enforce = false;
    let mut i = usize::from(args.first().is_some_and(|s| !s.starts_with('-')));
    while i < args.len() {
        let key = args[i].as_str();
        match key{"--json"|"--dry-run"|"-d"=>{},"--enforce"=>enforce=true,"--network"|"-n"=>return Err(("INCOMPLETE: network resolver cannot represent an exact installation snapshot; provide an npm v3 lock".into(),2)),"--lock"|"--manifest"|"--base"|"--head"|"--base-manifest"|"--head-manifest"=>{i+=1;let value=args.get(i).filter(|v|!v.starts_with('-')).ok_or_else(||(format!("Missing value for {key}"),64))?;if opts.insert(key,value.as_str()).is_some(){return Err((format!("Duplicate option {key}"),64))}},_=>return Err((format!("Unknown argument {key}; use --help"),64))}
        i += 1;
    }
    let load = |lock: &str, manifest: Option<&str>| {
        Snapshot::load(Path::new(lock), manifest.map(Path::new)).map_err(|e| (e.to_string(), 2))
    };
    if mode == "review" {
        if opts.contains_key("--lock") || opts.contains_key("--manifest") {
            return Err(("lock/manifest options require audit".into(), 64));
        }
        if enforce {
            return Err((
                "Review is advisory; --enforce is available only for audit".into(),
                64,
            ));
        }
        let base = load(
            opts.get("--base")
                .copied()
                .ok_or_else(|| ("review requires --base".into(), 64))?,
            opts.get("--base-manifest").copied(),
        )?;
        let head = load(
            opts.get("--head")
                .copied()
                .ok_or_else(|| ("review requires --head".into(), 64))?,
            opts.get("--head-manifest").copied(),
        )?;
        let report = review::compare(&base, &head);
        let code = if report.get("status").and_then(J::as_str) == Some("incomplete") {
            2
        } else {
            0
        };
        return Ok((report, code));
    }
    if opts
        .keys()
        .any(|k| k.starts_with("--base") || k.starts_with("--head"))
    {
        return Err(("base/head options require review".into(), 64));
    }
    let lock = opts.get("--lock").copied().unwrap_or("package-lock.json");
    let manifest = opts.get("--manifest").copied().or_else(|| {
        if lock == "package-lock.json" && Path::new("package.json").exists() {
            Some("package.json")
        } else {
            None
        }
    });
    let snapshot = load(lock, manifest)?;
    let config = SentinelConfig::load("tau-gate.toml").map_err(|e| (e.to_string(), 2))?;
    let mut report = snapshot.report();
    let violations: Vec<J> = snapshot
        .graph
        .execution_packages
        .iter()
        .filter_map(|n| {
            let p = &snapshot.graph.packages[n];
            let coord = format!("{}@{}", p.name, p.version);
            if config.whitelist.contains(&coord) {
                None
            } else {
                Some(review::object([
                    ("path", review::string(&p.path)),
                    ("coordinate", review::string(coord)),
                ]))
            }
        })
        .collect();
    let outcome = if !snapshot.graph.issues.is_empty() {
        "incomplete"
    } else if !enforce {
        "advisory"
    } else if !violations.is_empty() {
        "blocked"
    } else {
        "allowed"
    };
    let code = match outcome {
        "incomplete" => 2,
        "blocked" => 1,
        _ => 0,
    };
    if let J::Object(ref mut fields) = report {
        fields.insert("policy".into(),review::object([("outcome",review::string(outcome)),("enforcement_requested",J::Bool(enforce)),("approval_scope",review::string("exact name@version; artifact digest is not pinned; missing markers do not prove absence of execution")),("unapproved_execution_candidates",J::Array(violations))]));
    }
    Ok((report, code))
}

fn human(r: &J) {
    if let Some(changes) = r.get("package_changes").and_then(J::as_array) {
        println!("{} package changes", changes.len());
        for c in changes {
            println!(
                "  {} {} ({})",
                c.get("change").and_then(J::as_str).unwrap_or(""),
                c.get("path").and_then(J::as_str).unwrap_or("root"),
                c.get("changed_fields").unwrap().to_json()
            );
        }
        if let Some(base) = r.get("base") {
            println!(
                "Base snapshot: {}",
                base.get("status").and_then(J::as_str).unwrap_or("unknown")
            );
            human_issues(base, "base");
        }
        if let Some(h) = r.get("head") {
            println!(
                "Head snapshot: {}",
                h.get("status").and_then(J::as_str).unwrap_or("unknown")
            );
            human(h)
        }
        return;
    }
    println!(
        "Scope: {}",
        r.get("scope").and_then(J::as_str).unwrap_or("unknown")
    );
    println!(
        "All lockfile records; platform/dev/optional installation selection is not evaluated."
    );
    if let Some(c) = r.get("execution_candidates").and_then(J::as_array) {
        println!(
            "{} execution candidates (markers, not malicious-code findings)",
            c.len()
        );
        for item in c {
            let p = item.get("package").unwrap();
            println!(
                "  {}@{} [{}] via {}",
                p.get("name").and_then(J::as_str).unwrap_or(""),
                p.get("version").and_then(J::as_str).unwrap_or(""),
                p.get("path").and_then(J::as_str).unwrap_or(""),
                item.get("introducer_path").unwrap().to_json()
            );
        }
    }
    human_issues(r, "snapshot");
    if let Some(policy) = r.get("policy") {
        println!(
            "Policy: {}",
            policy
                .get("outcome")
                .and_then(J::as_str)
                .unwrap_or("unknown")
        );
    }
    println!(
        "Use --json for input hashes, artifact identities, typed edges and convergence evidence."
    );
}

fn human_issues(r: &J, label: &str) {
    if let Some(issues) = r.get("issues").and_then(J::as_array) {
        for issue in issues {
            println!(
                "INCOMPLETE {label}: {}",
                issue.as_str().unwrap_or("unknown")
            );
        }
    }
    if let Some(omissions) = r.get("optional_omissions").and_then(J::as_array) {
        for omission in omissions {
            println!(
                "OPTIONAL OMISSION {label}: {}",
                omission.as_str().unwrap_or("unknown")
            );
        }
    }
}
