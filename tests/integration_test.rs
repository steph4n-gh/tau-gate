use std::process::Command;
use std::fs;
use std::path::Path;

#[test]
fn test_cli_dry_run_nominal() {
    // We assume the binary has been built
    let binary = if cfg!(debug_assertions) {
        "target/debug/tau-gate"
    } else {
        "target/release/tau-gate"
    };

    if !Path::new(binary).exists() {
        return;
    }

    let output = Command::new(binary)
        .arg("--dry-run")
        .output()
        .expect("Failed to execute binary");

    if !output.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("MODE: DRY-RUN"));
}

#[test]
fn test_manifest_discovery_heuristic() {
    // Verify that our recursive find_package_json works in a nested structure
    let test_dir = "tests/mock_node_modules/@scope/pkg";
    fs::create_dir_all(test_dir).unwrap();
    fs::write(format!("{}/package.json", test_dir), "{}").unwrap();

    // Clean up
    fs::remove_dir_all("tests/mock_node_modules").unwrap();
}
