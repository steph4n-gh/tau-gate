use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
use tau_gate::{
    digest::sha256,
    parser::{JsonNode as J, MiniParser},
};
static ID: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "tau-review-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn put(&self, n: &str, s: &str) {
        fs::write(self.0.join(n), s).unwrap()
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tau-gate"))
            .current_dir(&self.0)
            .env("PATH", "")
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn json(o: &Output) -> J {
    MiniParser::parse_json(std::str::from_utf8(&o.stdout).unwrap()).unwrap()
}
const BASE: &str = include_str!("../examples/review/base.json");
const HEAD: &str = include_str!("../examples/review/head.json");
#[test]
fn all_candidates_read_only_policy_and_determinism() {
    let f = Fixture::new();
    f.put("package-lock.json", HEAD);
    f.put("tau-gate.toml","mode = 'Advisory' # comment\nwhitelist = [\n 'test-tool@1.0.0',\n]\nthreshold_percentage = 15\n");
    let before = sha256(&fs::read(f.0.join("package-lock.json")).unwrap());
    let a = f.run(&["--dry-run", "--json"]);
    assert!(a.status.success(), "{:?}", a);
    let r = json(&a);
    assert_eq!(r.get("status").and_then(J::as_str), Some("complete"));
    assert_eq!(
        r.get("execution_candidates")
            .and_then(J::as_array)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(a.stdout, f.run(&["audit", "--json"]).stdout);
    let b = f.run(&["--enforce", "--json"]);
    assert_eq!(b.status.code(), Some(1));
    let r = json(&b);
    assert_eq!(
        r.get("policy").unwrap().get("outcome").and_then(J::as_str),
        Some("blocked")
    );
    assert_eq!(
        r.get("policy")
            .unwrap()
            .get("unapproved_execution_candidates")
            .and_then(J::as_array)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        before,
        sha256(&fs::read(f.0.join("package-lock.json")).unwrap())
    );
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 2);
}
#[test]
fn review_same_version_digest_and_capability_changes() {
    let f = Fixture::new();
    f.put("base.json", BASE);
    f.put("head.json", HEAD);
    let o = f.run(&[
        "review",
        "--base",
        "base.json",
        "--head",
        "head.json",
        "--json",
    ]);
    assert!(o.status.success());
    let r = json(&o);
    let c = r.get("package_changes").and_then(J::as_array).unwrap();
    assert_eq!(c.len(), 2);
    assert!(c
        .iter()
        .any(|v| v.get("changed_fields").unwrap().to_json() == "[\"integrity\"]"));
    let leaf = r
        .get("head")
        .unwrap()
        .get("execution_candidates")
        .and_then(J::as_array)
        .unwrap()
        .iter()
        .find(|v| v.get("package").unwrap().get("name").and_then(J::as_str) == Some("leaf"))
        .unwrap();
    assert_eq!(
        leaf.get("introducer_path").unwrap().to_json(),
        "[\"root\",\"node_modules/bridge\",\"node_modules/leaf\"]"
    );
    assert!(leaf
        .get("introducer_edges")
        .unwrap()
        .to_json()
        .contains("dependencies"));
}
#[test]
fn missing_and_unsupported_never_invoke_manager() {
    let f = Fixture::new();
    f.put("package.json", "{}");
    for args in [
        vec!["--json"],
        vec!["--network", "--json"],
        vec!["--lock", "pnpm-lock.yaml", "--json"],
    ] {
        assert_eq!(f.run(&args).status.code(), Some(2));
    }
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 1);
    f.put(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"missing":"1"}}}}"#,
    );
    let o = f.run(&["--json"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        json(&o).get("status").and_then(J::as_str),
        Some("incomplete")
    );
}
#[test]
fn usage_and_help_no_effects() {
    let f = Fixture::new();
    assert!(f.run(&["--help"]).status.success());
    for args in [
        vec!["--surprise"],
        vec!["review", "--lock", "x"],
        vec!["audit", "--base", "x"],
        vec!["--lock"],
        vec!["daemon"],
    ] {
        assert_eq!(f.run(&args).status.code(), Some(64));
    }
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 0);
}
#[test]
fn config_invalid_cannot_fail_open() {
    let f = Fixture::new();
    f.put("package-lock.json", BASE);
    for v in [
        "threshold_percentage = NaN",
        "threshold_percentage = 'bad'",
        "whitelist = 3",
        "mode = 'maybe'",
        "threshold_percentage = 101",
        "unknown = 1",
    ] {
        f.put("tau-gate.toml", v);
        assert_eq!(
            f.run(&["--enforce", "--json"]).status.code(),
            Some(2),
            "{v}"
        );
    }
}
#[test]
fn root_script_only_change() {
    let f = Fixture::new();
    let lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1"}}}"#;
    f.put("lock.json", lock);
    f.put("a.json", r#"{"scripts":{"postinstall":"echo before"}}"#);
    f.put("b.json", r#"{"scripts":{"postinstall":"echo after"}}"#);
    let o = f.run(&[
        "review",
        "--base",
        "lock.json",
        "--head",
        "lock.json",
        "--base-manifest",
        "a.json",
        "--head-manifest",
        "b.json",
        "--json",
    ]);
    assert!(o.status.success());
    let r = json(&o);
    assert_eq!(
        r.get("package_changes")
            .and_then(J::as_array)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        r.get("head")
            .unwrap()
            .get("execution_candidates")
            .and_then(J::as_array)
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn every_consumed_input_unchanged() {
    let f = Fixture::new();
    f.put("base.json", BASE);
    f.put("head.json", HEAD);
    f.put("package.json", "{}");
    f.put("tau-gate.toml", "whitelist = []");
    let snapshot = |p: &Path| {
        let mut entries = fs::read_dir(p)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), fs::read(e.path()).unwrap())
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    };
    let before = snapshot(&f.0);
    f.run(&[
        "review",
        "--base",
        "base.json",
        "--head",
        "head.json",
        "--json",
    ]);
    f.run(&[
        "--lock",
        "head.json",
        "--manifest",
        "package.json",
        "--json",
    ]);
    assert_eq!(before, snapshot(&f.0));
}

#[test]
fn incomplete_base_human_report_explains_reason() {
    let f = Fixture::new();
    f.put(
        "base.json",
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"missing":"1"}}}}"#,
    );
    f.put("head.json", BASE);
    let o = f.run(&["review", "--base", "base.json", "--head", "head.json"]);
    assert_eq!(o.status.code(), Some(2));
    let text = String::from_utf8(o.stdout).unwrap();
    assert!(text.contains("INCOMPLETE base: unresolved dependencies"));
    assert!(text.contains("Head snapshot: complete"));
}
