use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
use tau_gate::parser::{JsonNode as J, MiniParser};
static ID: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "tau-adapter-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
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
fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/real")
        .join(name)
        .to_str()
        .unwrap()
        .into()
}
#[test]
fn supported_resolution_graphs_never_allow_unknown_execution() {
    let f = Fixture::new();
    for (format, lock, manifest) in [
        ("pnpm_v9", "pnpm-hono-v9.yaml", "pnpm-hono.package.json"),
        (
            "yarn_classic_v1",
            "yarn-classic-v1.lock",
            "yarn-classic.package.json",
        ),
    ] {
        let lock = fixture(lock);
        let manifest = fixture(manifest);
        let o = f.run(&[
            "audit",
            "--lock",
            &lock,
            "--manifest",
            &manifest,
            "--enforce",
            "--json",
        ]);
        assert_eq!(o.status.code(), Some(2));
        let r = json(&o);
        assert_eq!(r.get("format").and_then(J::as_str), Some(format));
        assert_eq!(
            r.get("topology_status").and_then(J::as_str),
            Some("complete")
        );
        assert_eq!(
            r.get("execution_metadata_status").and_then(J::as_str),
            Some("unknown_transitive_scripts")
        );
        assert_eq!(
            r.get("policy").unwrap().get("outcome").and_then(J::as_str),
            Some("incomplete")
        );
        assert!(r.get("packages").and_then(J::as_array).unwrap().len() > 1000);
    }
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 0);
}
#[test]
fn resolution_lock_comparisons_remain_useful_when_capabilities_unknown() {
    let f = Fixture::new();
    for (lock, manifest) in [
        ("pnpm-hono-v9.yaml", "pnpm-hono.package.json"),
        ("yarn-classic-v1.lock", "yarn-classic.package.json"),
    ] {
        let lock = fixture(lock);
        let manifest = fixture(manifest);
        let o = f.run(&[
            "review",
            "--base",
            &lock,
            "--head",
            &lock,
            "--base-manifest",
            &manifest,
            "--head-manifest",
            &manifest,
            "--json",
        ]);
        assert_eq!(o.status.code(), Some(2));
        let r = json(&o);
        for k in ["package_changes", "added_edges", "removed_edges"] {
            assert!(r.get(k).and_then(J::as_array).unwrap().is_empty());
        }
        assert!(
            r.get("head")
                .unwrap()
                .get("packages")
                .and_then(J::as_array)
                .unwrap()
                .len()
                > 1000
        );
    }
}
#[test]
fn yarn_without_manifest_has_no_invented_attribution() {
    let f = Fixture::new();
    let lock = fixture("yarn-classic-v1.lock");
    let o = f.run(&["audit", "--lock", &lock, "--json"]);
    assert_eq!(o.status.code(), Some(2));
    let r = json(&o);
    assert_eq!(
        r.get("topology_status").and_then(J::as_str),
        Some("complete")
    );
    assert_eq!(
        r.get("root_attribution_status").and_then(J::as_str),
        Some("incomplete")
    );
    assert!(!r
        .get("edges")
        .and_then(J::as_array)
        .unwrap()
        .iter()
        .any(|e| e.get("from").and_then(J::as_str) == Some("root")));
}
#[test]
fn default_discovery_is_read_only_and_rejects_ambiguity() {
    let f = Fixture::new();
    let bytes = fs::read(fixture("yarn-classic-v1.lock")).unwrap();
    fs::write(f.0.join("yarn.lock"), &bytes).unwrap();
    let o = f.run(&["--json"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        json(&o).get("format").and_then(J::as_str),
        Some("yarn_classic_v1")
    );
    assert_eq!(fs::read(f.0.join("yarn.lock")).unwrap(), bytes);
    fs::write(f.0.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'").unwrap();
    let o = f.run(&["--json"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(json(&o)
        .get("error")
        .and_then(J::as_str)
        .unwrap()
        .contains("multiple lockfiles"));
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 2);
}
#[test]
fn cross_format_comparison_refuses_incomparable_identity_keys() {
    let f = Fixture::new();
    let a = fixture("pnpm-hono-v9.yaml");
    let b = fixture("yarn-classic-v1.lock");
    let o = f.run(&["review", "--base", &a, "--head", &b, "--json"]);
    assert_eq!(o.status.code(), Some(2));
    let r = json(&o);
    assert!(r
        .get("error")
        .and_then(J::as_str)
        .unwrap()
        .contains("Cross-format"));
    let o = f.run(&["review", "--base", &a, "--head", &b]);
    assert!(String::from_utf8(o.stdout)
        .unwrap()
        .contains("Cross-format"));
}

#[test]
fn pnpm_other_importer_is_an_actual_introducer_root() {
    let f = Fixture::new();
    let yaml="lockfileVersion: '9.0'\nimporters:\n  .: {}\n  apps/web:\n    dependencies:\n      leaf:\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  leaf@1.0.0:\n    requiresBuild: true\nsnapshots:\n  leaf@1.0.0: {}\n";
    fs::write(f.0.join("pnpm-lock.yaml"), yaml).unwrap();
    let o = f.run(&["--json"]);
    assert_eq!(o.status.code(), Some(2));
    let r = json(&o);
    let c = &r.get("execution_candidates").and_then(J::as_array).unwrap()[0];
    assert_eq!(
        c.get("introducer_path").unwrap().to_json(),
        "[\"pnpm:project:importer:apps/web\",\"pnpm:project:snapshot:leaf@1.0.0\"]"
    );
    assert_eq!(
        r.get("introducer_path_scope").and_then(J::as_str),
        Some("all_known_importers")
    );
    assert!(!r
        .get("edges")
        .and_then(J::as_array)
        .unwrap()
        .iter()
        .any(|e| e.get("from").and_then(J::as_str) == Some("root")));
}
