use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("tau-project-inputs-{}-{name}", std::process::id()));
        fs::create_dir_all(root.join("files")).unwrap();
        fs::write(
            root.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1"}}}"#,
        )
        .unwrap();
        fs::write(
            root.join("files/root.json"),
            r#"{"name":"root","version":"1"}"#,
        )
        .unwrap();
        fs::write(
            root.join("inputs.json"),
            r#"{"schema_version":1,"files":[{"path":"package.json","file":"files/root.json"}]}"#,
        )
        .unwrap();
        Self(root)
    }
    fn run(&self, extra: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_tau-gate"))
            .current_dir(&self.0)
            .env("PATH", "")
            .args([
                "audit",
                "--lock",
                "package-lock.json",
                "--project-inputs",
                "inputs.json",
                "--json",
            ])
            .args(extra)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn explicit_project_inputs_bind_the_consumed_source_bytes() {
    let f = Fixture::new("hashes");
    let before = fs::read(f.0.join("files/root.json")).unwrap();
    let output = f.run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("project_input_hashes"));
    assert!(text.contains(&tau_gate::digest::sha256(&before)));
    assert_eq!(before, fs::read(f.0.join("files/root.json")).unwrap());
}

#[test]
fn project_inputs_cannot_replace_required_execution_evidence() {
    let f = Fixture::new("enforcement");
    let output = f.run(&["--enforce"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("explicit execution evidence"));
}

#[test]
fn project_input_parent_traversal_is_rejected() {
    let f = Fixture::new("traversal");
    fs::write(
        f.0.join("inputs.json"),
        r#"{"schema_version":1,"files":[{"path":"../package.json","file":"files/root.json"}]}"#,
    )
    .unwrap();
    let output = f.run(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("project input"));
}

#[cfg(unix)]
#[test]
fn project_input_symlink_is_rejected() {
    let f = Fixture::new("symlink");
    std::os::unix::fs::symlink("root.json", f.0.join("files/linked.json")).unwrap();
    fs::write(
        f.0.join("inputs.json"),
        r#"{"schema_version":1,"files":[{"path":"package.json","file":"files/linked.json"}]}"#,
    )
    .unwrap();
    let output = f.run(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("symlink"));
}

#[test]
fn explicit_manifest_cannot_disagree_with_bundled_root() {
    let f = Fixture::new("conflict");
    fs::write(f.0.join("other.json"), r#"{"name":"different"}"#).unwrap();
    let output = f.run(&["--manifest", "other.json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("disagree"));
}

#[test]
fn unused_malformed_fixture_does_not_poison_the_selected_project() {
    let f = Fixture::new("unused");
    fs::write(
        f.0.join("files/invalid.json"),
        "this is an intentionally invalid test fixture",
    )
    .unwrap();
    fs::write(f.0.join("inputs.json"), r#"{"schema_version":1,"files":[{"path":"package.json","file":"files/root.json"},{"path":"fixtures/invalid/package.json","file":"files/invalid.json"}]}"#).unwrap();
    let output = f.run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn legacy_npm_versions_keep_distinct_scope_and_unknown_execution() {
    let f = Fixture::new("legacy");
    for (version, contents) in [
        (1, r#""dependencies":{}"#),
        (2, r#""packages":{"":{"name":"root","version":"1"}}"#),
    ] {
        fs::write(
            f.0.join("package-lock.json"),
            format!("{{\"lockfileVersion\":{version},{contents}}}"),
        )
        .unwrap();
        let output = f.run(&[]);
        assert_eq!(output.status.code(), Some(2));
        let report =
            tau_gate::parser::MiniParser::parse_json(std::str::from_utf8(&output.stdout).unwrap())
                .unwrap();
        assert_eq!(
            report.get("format").unwrap().as_str(),
            Some(format!("npm_v{version}").as_str())
        );
        assert_eq!(
            report.get("topology_status").unwrap().as_str(),
            Some("complete")
        );
        assert_eq!(
            report.get("execution_metadata_status").unwrap().as_str(),
            Some("unknown_transitive_scripts")
        );
        assert_eq!(
            report.get("lock_sha256").unwrap().as_str(),
            Some(
                tau_gate::digest::sha256(&fs::read(f.0.join("package-lock.json")).unwrap())
                    .as_str()
            )
        );
    }
}

#[test]
fn pnpm_version_scope_uses_the_parsed_scalar_and_rejects_unknown_versions() {
    let f = Fixture::new("pnpm-version");
    let lock = "lockfileVersion: '6.0' # generator comment\nimporters:\n  .: {}\npackages: {}\n";
    fs::write(f.0.join("package-lock.json"), lock).unwrap();
    let output = f.run(&[]);
    let report =
        tau_gate::parser::MiniParser::parse_json(std::str::from_utf8(&output.stdout).unwrap())
            .unwrap();
    assert_eq!(report.get("format").unwrap().as_str(), Some("pnpm_v6"));
    fs::write(f.0.join("package-lock.json"), lock.replace("6.0", "8.0")).unwrap();
    let output = f.run(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout).unwrap().contains("error"));
}
