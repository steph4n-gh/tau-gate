use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
use tau_gate::{
    digest::{sha256, sha512},
    parser::{JsonNode as J, MiniParser},
};
static ID: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tau-evidence-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("bundle/projects/local")).unwrap();
        Self(path)
    }
    fn put(&self, path: &str, bytes: impl AsRef<[u8]>) {
        fs::write(self.0.join(path), bytes).unwrap()
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tau-gate"))
            .current_dir(&self.0)
            .env("PATH", "")
            .args(args)
            .output()
            .unwrap()
    }
    fn index(&self, packages: &str) {
        self.put(
            "bundle/index.json",
            format!(
                r#"{{"schema_version":1,"lock_sha256":"{}","packages":{packages}}}"#,
                sha256(&fs::read(self.0.join("lock.json")).unwrap())
            ),
        );
    }
    fn audit(&self, enforce: bool) -> Output {
        let mut args = vec![
            "audit",
            "--lock",
            "lock.json",
            "--evidence",
            "bundle/index.json",
            "--json",
        ];
        if enforce {
            args.extend(["--enforce", "--approvals", "approvals.json"])
        }
        self.run(&args)
    }
    fn approve(&self) {
        let output = self.audit(false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report = json(&output);
        let approvals = report
            .get("execution_evidence")
            .and_then(J::as_array)
            .unwrap()
            .iter()
            .filter(|e| e.get("candidate") == Some(&J::Bool(true)))
            .map(|e| {
                format!(
                    r#"{{"path":{},"fingerprint":{}}}"#,
                    e.get("path").unwrap().to_json(),
                    e.get("approval_fingerprint").unwrap().to_json()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        self.put(
            "approvals.json",
            format!(r#"{{"schema_version":1,"approvals":[{approvals}]}}"#),
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap()
    }
}
fn json(output: &Output) -> J {
    MiniParser::parse_json(std::str::from_utf8(&output.stdout).unwrap()).unwrap()
}
fn outcome(output: &Output, code: i32, expected: &str) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        json(output)
            .get("policy")
            .unwrap()
            .get("outcome")
            .and_then(J::as_str),
        Some(expected)
    );
}
const ROOT: &str = r#"{"name":"app","version":"1","scripts":{"postinstall":"echo before"}}"#;
const LOCATORS: &str = r#"[{"path":"","project_manifest":"projects/package.json"}]"#;
fn root_fixture() -> Fixture {
    let f = Fixture::new();
    f.put(
        "lock.json",
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1"}}}"#,
    );
    f.put("bundle/projects/package.json", ROOT);
    f.index(LOCATORS);
    f
}
fn artifact_fixture(entries: &[(&str, &[u8])], source: &str) -> Fixture {
    let f = Fixture::new();
    let mut tar = Vec::new();
    for (name, body) in entries {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        let checksum: usize = header.iter().map(|b| *b as usize).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(body);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut archive = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 1];
    let length = u16::try_from(tar.len()).unwrap();
    archive.extend_from_slice(&length.to_le_bytes());
    archive.extend_from_slice(&(!length).to_le_bytes());
    archive.extend_from_slice(&tar);
    let mut crc = !0u32;
    for byte in &tar {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    archive.extend_from_slice(&(!crc).to_le_bytes());
    archive.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    let integrity = canonical_integrity(&archive);
    f.put("bundle/pkg.tgz", archive);
    f.put(
        "bundle/projects/package.json",
        r#"{"name":"app","version":"1"}"#,
    );
    f.put("lock.json", format!(r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"app","version":"1"}},"node_modules/pkg":{{"version":"1","resolved":{},"integrity":"{integrity}"}}}}}}"#, J::String(source.into()).to_json()));
    f.index(r#"[{"path":"","project_manifest":"projects/package.json"},{"path":"node_modules/pkg","artifact":"pkg.tgz"}]"#);
    f.put("approvals.json", r#"{"schema_version":1,"approvals":[]}"#);
    f
}
fn canonical_integrity(archive: &[u8]) -> String {
    let hex = sha512(archive);
    let digest: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut integrity = "sha512-".to_owned();
    for chunk in digest.chunks(3) {
        let word = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        for (offset, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            integrity.push(if offset <= chunk.len() {
                alphabet[((word >> shift) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    integrity
}
fn replace_integrity(f: &Fixture, integrity: Option<&str>) {
    let mut lock =
        MiniParser::parse_json(&fs::read_to_string(f.0.join("lock.json")).unwrap()).unwrap();
    let J::Object(root) = &mut lock else { panic!() };
    let J::Object(packages) = root.get_mut("packages").unwrap() else {
        panic!()
    };
    let J::Object(package) = packages.get_mut("node_modules/pkg").unwrap() else {
        panic!()
    };
    if let Some(integrity) = integrity {
        package.insert("integrity".into(), J::String(integrity.into()));
    } else {
        package.remove("integrity");
    }
    f.put("lock.json", lock.to_json());
    f.index(r#"[{"path":"","project_manifest":"projects/package.json"},{"path":"node_modules/pkg","artifact":"pkg.tgz"}]"#);
}
fn package_evidence(report: &J) -> &J {
    report
        .get("execution_evidence")
        .and_then(J::as_array)
        .unwrap()
        .iter()
        .find(|e| e.get("path").and_then(J::as_str) == Some("node_modules/pkg"))
        .unwrap()
}
fn unsupported_artifact(f: &Fixture, expected_reason: &str) {
    let output = f.audit(true);
    outcome(&output, 2, "incomplete");
    let report = json(&output);
    let evidence = package_evidence(&report);
    assert_eq!(
        evidence.get("state").and_then(J::as_str),
        Some("unsupported")
    );
    assert_eq!(
        evidence.get("reason").and_then(J::as_str),
        Some(expected_reason)
    );
    assert_eq!(evidence.get("approval_fingerprint"), Some(&J::Null));
    assert_eq!(evidence.get("facts"), Some(&J::Null));
}
#[test]
fn matching_archive_integrity_does_not_qualify_git_or_directory_sources() {
    let entries = [(
        "package/package.json",
        br#"{"name":"pkg","version":"1","scripts":{"prepare":"node prepare.js"}}"#.as_slice(),
    )];
    for source in [
        "https://registry.npmjs.org/pkg/-/pkg-1.tgz",
        "http://127.0.0.1:12345/pkg.tgz",
        "https://custom.example.org/archives/pkg.tar.gz",
        "https://registry.npmjs.org/@scope/pkg/-/pkg-1.tgz",
    ] {
        outcome(
            &artifact_fixture(&entries, source).audit(true),
            0,
            "allowed",
        );
    }
    for source in [
        "git+https://github.com/example/package.git#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://github.com/example/package.git",
        "https://github.com/example/package.tgz",
        "https://gitlab.com/example/package.tgz",
        "https://gist.github.com/example/package.tgz",
        "https://bitbucket.org/example/package.tgz",
        "https://git.sr.ht/~example/package.tgz",
        "file:../package",
        "file:package.tgz",
        "https://registry.npmjs.org/pkg/-/pkg-1.tgz?token=secret",
        "https://registry.npmjs.org/pkg/-/pkg-1.tgz#commit",
        "https://user@registry.npmjs.org/pkg.tgz",
        "https://registry.npmjs.org/pkg%2ftgz",
    ] {
        unsupported_artifact(
            &artifact_fixture(&entries, source),
            "artifact source requires a supported direct HTTP(S) archive URL",
        );
    }
}
#[test]
fn portable_archive_paths_cannot_hide_native_or_manifest_inputs() {
    let manifest = br#"{"name":"pkg","version":"1"}"#;
    let source = "https://registry.npmjs.org/pkg/-/pkg-1.tgz";
    for path in ["package/Binding.gyp", "package/Package.json"] {
        unsupported_artifact(
            &artifact_fixture(&[("package/package.json", manifest), (path, b"{}")], source),
            "noncanonical lifecycle evidence tar path",
        );
    }
    for (first, second, reason) in [
        (
            "package/A",
            "package/a/b",
            "tar file conflicts with a parent directory",
        ),
        (
            "package/a/b",
            "package/A",
            "tar file conflicts with a parent directory",
        ),
        ("package/a", "package/A", "duplicate case-folded tar path"),
    ] {
        unsupported_artifact(
            &artifact_fixture(
                &[
                    ("package/package.json", manifest),
                    (first, b"a"),
                    (second, b"b"),
                ],
                source,
            ),
            reason,
        );
    }
    for path in [
        "package/binding.gyp.",
        "package/binding.gyp ",
        "package/caf\u{e9}.js",
        "package/NUL.txt",
    ] {
        unsupported_artifact(
            &artifact_fixture(&[("package/package.json", manifest), (path, b"{}")], source),
            "unsupported nonportable tar path",
        );
    }
    let f = artifact_fixture(
        &[
            ("package/package.json", manifest),
            ("package/binding.gyp", b"{}"),
        ],
        source,
    );
    outcome(&f.audit(true), 1, "blocked");
}
#[test]
fn approvals_bind_source_bytes_lifecycle_and_identity() {
    let f = root_fixture();
    f.put("approvals.json", r#"{"schema_version":1,"approvals":[]}"#);
    outcome(&f.audit(true), 1, "blocked");
    f.approve();
    let before = fs::read(f.0.join("approvals.json")).unwrap();
    outcome(&f.audit(true), 0, "allowed");
    let a = f.audit(false);
    assert_eq!(a.stdout, f.audit(false).stdout);
    let report = json(&a);
    assert_eq!(
        report.get("manifest_sha256").and_then(J::as_str),
        Some(sha256(ROOT.as_bytes()).as_str())
    );
    assert_eq!(
        report.get("evidence_index_sha256").and_then(J::as_str),
        Some(sha256(&fs::read(f.0.join("bundle/index.json")).unwrap()).as_str())
    );
    assert_eq!(
        report.get("scope").and_then(J::as_str),
        Some("npm_v3_artifacts_and_source_snapshots")
    );
    f.put(
        "bundle/projects/package.json",
        ROOT.replace("before", "after"),
    );
    outcome(&f.audit(true), 1, "blocked");
    f.put("bundle/projects/package.json", format!("{ROOT}\n"));
    outcome(&f.audit(true), 1, "blocked");
    f.put("bundle/projects/package.json", ROOT);
    for (field, value) in [
        ("resolved", "https://example.test/changed"),
        ("integrity", "changed"),
    ] {
        f.put("lock.json",format!(r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"app","version":"1","{field}":"{value}"}}}}}}"#));
        f.index(LOCATORS);
        outcome(&f.audit(true), 1, "blocked");
    }
    assert_eq!(before, fs::read(f.0.join("approvals.json")).unwrap());
}
#[test]
fn approval_sets_keep_old_and_new_evidence_valid_during_transition() {
    let f = root_fixture();
    f.approve();
    outcome(&f.audit(true), 0, "allowed");
    let fingerprint = |output: &Output| {
        json(output)
            .get("execution_evidence")
            .and_then(J::as_array)
            .unwrap()[0]
            .get("approval_fingerprint")
            .and_then(J::as_str)
            .unwrap()
            .to_owned()
    };
    let old = fingerprint(&f.audit(false));
    let changed = ROOT.replace("before", "after");
    f.put("bundle/projects/package.json", &changed);
    outcome(&f.audit(true), 1, "blocked");
    let new = fingerprint(&f.audit(false));
    assert_ne!(old, new);
    f.put("bundle/projects/package.json", ROOT);
    f.put(
        "approvals.json",
        format!(
            r#"{{"schema_version":2,"approvals":[{{"path":"","fingerprints":["{old}","{new}"]}}]}}"#
        ),
    );
    outcome(&f.audit(true), 0, "allowed");
    f.put("bundle/projects/package.json", &changed);
    outcome(&f.audit(true), 0, "allowed");
    f.put(
        "approvals.json",
        format!(r#"{{"schema_version":2,"approvals":[{{"path":"","fingerprints":["{new}"]}}]}}"#),
    );
    outcome(&f.audit(true), 0, "allowed");
    f.put("bundle/projects/package.json", ROOT);
    outcome(&f.audit(true), 1, "blocked");
}

#[test]
fn malformed_approval_sets_cannot_authorize_execution() {
    let f = root_fixture();
    let report = json(&f.audit(false));
    let fingerprint = report
        .get("execution_evidence")
        .and_then(J::as_array)
        .unwrap()[0]
        .get("approval_fingerprint")
        .and_then(J::as_str)
        .unwrap();
    for input in [
        r#"{"schema_version":2,"approvals":[{"path":"","fingerprints":[]}]}"#.to_owned(),
        format!(
            r#"{{"schema_version":2,"approvals":[{{"path":"","fingerprints":["{fingerprint}","{fingerprint}"]}}]}}"#
        ),
        format!(
            r#"{{"schema_version":2,"approvals":[{{"path":"","fingerprints":["{fingerprint}"]}},{{"path":"","fingerprints":["{fingerprint}"]}}]}}"#
        ),
        format!(
            r#"{{"schema_version":2,"approvals":[{{"path":"","fingerprint":"{fingerprint}"}}]}}"#
        ),
        format!(
            r#"{{"schema_version":2,"approvals":[{{"path":"","fingerprints":["{}"]}}]}}"#,
            fingerprint.to_ascii_uppercase()
        ),
    ] {
        f.put("approvals.json", input);
        assert_eq!(f.audit(true).status.code(), Some(2));
    }
}
#[test]
fn missing_conflicting_and_untrusted_inputs_precede_approvals() {
    let f = root_fixture();
    f.approve();
    f.index("[]");
    outcome(&f.audit(true), 2, "incomplete");
    f.index(LOCATORS);
    f.put("lock.json",r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1","hasInstallScript":false}}}"#);
    f.index(LOCATORS);
    let o = f.audit(true);
    outcome(&o, 2, "incomplete");
    assert_eq!(
        json(&o)
            .get("execution_evidence")
            .and_then(J::as_array)
            .unwrap()[0]
            .get("state")
            .and_then(J::as_str),
        Some("conflict")
    );
    f.put(
        "bundle/projects/package.json",
        r#"{"name":"wrong","version":"1"}"#,
    );
    let o = f.audit(true);
    outcome(&o, 2, "incomplete");
    assert_eq!(
        json(&o)
            .get("execution_evidence")
            .and_then(J::as_array)
            .unwrap()[0]
            .get("state")
            .and_then(J::as_str),
        Some("unsupported")
    );
    f.put("bundle/projects/package.json", ROOT);
    f.put("different.json", ROOT.replace("before", "other"));
    let o = f.run(&[
        "--lock",
        "lock.json",
        "--manifest",
        "different.json",
        "--evidence",
        "bundle/index.json",
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o
        .stdout
        .windows(27)
        .any(|w| w == b"index root manifest differs"));
}
#[test]
fn workspace_links_and_disconnected_instances_keep_separate_approvals() {
    let f = Fixture::new();
    f.put("lock.json",r#"{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1","dependencies":{"local":"file:packages/local"}},"node_modules/local":{"resolved":"packages/local","link":true},"packages/local":{"name":"local","version":"1"},"packages/other":{"name":"other","version":"1"}}}"#);
    f.put(
        "bundle/projects/package.json",
        r#"{"name":"app","version":"1","dependencies":{"local":"file:packages/local"}}"#,
    );
    f.put(
        "bundle/projects/local/package.json",
        r#"{"name":"local","version":"1","scripts":{"prepare":"build"}}"#,
    );
    f.put(
        "bundle/projects/other.json",
        r#"{"name":"other","version":"1","scripts":{"install":"build"}}"#,
    );
    f.index(r#"[{"path":"","project_manifest":"projects/package.json"},{"path":"packages/local","project_manifest":"projects/local/package.json"},{"path":"packages/other","project_manifest":"projects/other.json"}]"#);
    f.approve();
    outcome(&f.audit(true), 0, "allowed");
    let r = json(&f.audit(false));
    let candidates = r.get("execution_candidates").and_then(J::as_array).unwrap();
    assert_eq!(candidates.len(), 2);
    let other = candidates
        .iter()
        .find(|e| {
            e.get("package").unwrap().get("path").and_then(J::as_str) == Some("packages/other")
        })
        .unwrap();
    assert_eq!(other.get("introducer_path"), Some(&J::Null));
    f.put(
        "bundle/projects/local/package.json",
        r#"{"name":"local","version":"1","scripts":{"prepare":"changed"}}"#,
    );
    outcome(&f.audit(true), 1, "blocked");
}
#[test]
fn native_default_and_empty_scripts_are_distinct_from_binary_entrypoints() {
    let f = root_fixture();
    f.put(
        "bundle/projects/package.json",
        r#"{"name":"app","version":"1","bin":"cli.js","scripts":{"install":""}}"#,
    );
    let r = json(&f.audit(false));
    assert!(r
        .get("execution_candidates")
        .and_then(J::as_array)
        .unwrap()
        .is_empty());
    f.put("bundle/projects/binding.gyp", b"{}");
    f.approve();
    outcome(&f.audit(true), 0, "allowed");
    let r = json(&f.audit(false));
    assert_eq!(
        r.get("execution_evidence").and_then(J::as_array).unwrap()[0]
            .get("facts")
            .unwrap()
            .get("implicit_node_gyp"),
        Some(&J::Bool(true))
    );
    f.put("bundle/projects/binding.gyp", b"changed");
    outcome(&f.audit(true), 1, "blocked");
    f.put(
        "bundle/projects/package.json",
        r#"{"name":"app","version":"1","gypfile":false,"bin":"cli.js"}"#,
    );
    outcome(&f.audit(true), 0, "allowed");
}
#[test]
fn strict_index_and_approval_schemas_reject_duplicate_fields_and_symlinks() {
    let f = root_fixture();
    f.approve();
    for input in [
        r#"{"schema_version":1,"schema_version":1,"approvals":[]}"#,
        r#"{"schema_version":1,"approvals":[],"verified":true}"#,
        r#"{"schema_version":1,"approvals":[{"path":"","fingerprint":"bad"}]}"#,
    ] {
        f.put("approvals.json", input);
        assert_eq!(f.audit(true).status.code(), Some(2));
    }
    f.index(r#"[{"path":"","project_manifest":"../outside.json"}]"#);
    assert_eq!(f.audit(false).status.code(), Some(2));
    #[cfg(unix)]
    {
        f.index(LOCATORS);
        fs::rename(
            f.0.join("bundle/projects/package.json"),
            f.0.join("outside.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            f.0.join("outside.json"),
            f.0.join("bundle/projects/package.json"),
        )
        .unwrap();
        assert_eq!(f.audit(false).status.code(), Some(2));
    }
}
#[test]
fn review_reports_evidence_changes_and_requires_both_evidence_inputs() {
    let f = root_fixture();
    f.approve();
    let args = [
        "review",
        "--base",
        "lock.json",
        "--head",
        "lock.json",
        "--base-evidence",
        "bundle/index.json",
        "--head-evidence",
        "bundle/index.json",
        "--approvals",
        "approvals.json",
        "--enforce",
        "--json",
    ];
    outcome(&f.run(&args), 0, "allowed");
    let r = json(&f.run(&args));
    assert!(r
        .get("execution_evidence_changes")
        .and_then(J::as_array)
        .unwrap()
        .is_empty());
    outcome(
        &f.run(&[
            "review",
            "--base",
            "lock.json",
            "--head",
            "lock.json",
            "--head-evidence",
            "bundle/index.json",
            "--approvals",
            "approvals.json",
            "--enforce",
            "--json",
        ]),
        2,
        "incomplete",
    );
    fs::create_dir_all(f.0.join("head/projects")).unwrap();
    f.put(
        "head/projects/package.json",
        ROOT.replace("before", "after"),
    );
    f.put(
        "head/index.json",
        fs::read(f.0.join("bundle/index.json")).unwrap(),
    );
    let r = json(&f.run(&[
        "review",
        "--base",
        "lock.json",
        "--head",
        "lock.json",
        "--base-evidence",
        "bundle/index.json",
        "--head-evidence",
        "head/index.json",
        "--json",
    ]));
    let changes = r
        .get("execution_evidence_changes")
        .and_then(J::as_array)
        .unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(
        changes[0].get("after_introducer_path").unwrap().to_json(),
        "[\"root\"]"
    );
}
#[test]
fn review_reports_changed_verified_bytes_for_unsupported_artifacts() {
    let source = "https://registry.npmjs.org/pkg/-/pkg-1.tgz";
    let base = artifact_fixture(&[("package/package.json", b"\xff")], source);
    let head = artifact_fixture(&[("package/package.json", b"\xfe")], source);
    let output = base.run(&[
        "review",
        "--base",
        "lock.json",
        "--head",
        head.0.join("lock.json").to_str().unwrap(),
        "--base-evidence",
        "bundle/index.json",
        "--head-evidence",
        head.0.join("bundle/index.json").to_str().unwrap(),
        "--approvals",
        "approvals.json",
        "--enforce",
        "--json",
    ]);
    outcome(&output, 2, "incomplete");
    let report = json(&output);
    let changes = report
        .get("execution_evidence_changes")
        .and_then(J::as_array)
        .unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(
        changes[0].get("path").and_then(J::as_str),
        Some("node_modules/pkg")
    );
    for (side, fixture) in [("before", &base), ("after", &head)] {
        let evidence = changes[0].get(side).unwrap();
        assert_eq!(
            evidence.get("state").and_then(J::as_str),
            Some("unsupported")
        );
        assert_eq!(evidence.get("facts"), Some(&J::Null));
        assert_eq!(evidence.get("approval_fingerprint"), Some(&J::Null));
        assert_eq!(
            evidence.get("verified_artifact_sha512").and_then(J::as_str),
            Some(sha512(&fs::read(fixture.0.join("bundle/pkg.tgz")).unwrap()).as_str())
        );
    }
    assert_eq!(
        changes[0].get("before").unwrap().get("reason"),
        changes[0].get("after").unwrap().get("reason")
    );
}
#[test]
fn verified_bytes_survive_content_rejection_and_stale_approvals() {
    let source = "https://registry.npmjs.org/pkg/-/pkg-1.tgz";
    let manifest = br#"{"name":"pkg","version":"1","scripts":{"install":"node install.js"}}"#;
    let original = artifact_fixture(&[("package/package.json", manifest)], source);
    original.approve();
    let approvals = fs::read(original.0.join("approvals.json")).unwrap();
    for entries in [
        vec![("package/package.json", b"\xff".as_slice())],
        vec![(
            "package/package.json",
            br#"{"name":"other","version":"1"}"#.as_slice(),
        )],
        vec![
            ("package/package.json", manifest.as_slice()),
            ("package/Binding.gyp", b"{}".as_slice()),
        ],
    ] {
        let invalid = artifact_fixture(&entries, source);
        invalid.put("approvals.json", &approvals);
        let output = invalid.audit(true);
        outcome(&output, 2, "incomplete");
        let report = json(&output);
        let evidence = package_evidence(&report);
        assert_eq!(
            evidence.get("state").and_then(J::as_str),
            Some("unsupported")
        );
        assert_eq!(evidence.get("facts"), Some(&J::Null));
        assert_eq!(evidence.get("approval_fingerprint"), Some(&J::Null));
        assert_eq!(
            evidence.get("verified_artifact_sha512").and_then(J::as_str),
            Some(sha512(&fs::read(invalid.0.join("bundle/pkg.tgz")).unwrap()).as_str())
        );
    }
    let mut corrupt = fs::read(original.0.join("bundle/pkg.tgz")).unwrap();
    let crc = corrupt.len() - 8;
    corrupt[crc] ^= 1;
    original.put("bundle/pkg.tgz", &corrupt);
    replace_integrity(&original, Some(&canonical_integrity(&corrupt)));
    let output = original.audit(true);
    outcome(&output, 2, "incomplete");
    let report = json(&output);
    let evidence = package_evidence(&report);
    assert_eq!(
        evidence.get("state").and_then(J::as_str),
        Some("unsupported")
    );
    assert_eq!(evidence.get("facts"), Some(&J::Null));
    assert_eq!(evidence.get("approval_fingerprint"), Some(&J::Null));
    assert_eq!(
        evidence.get("verified_artifact_sha512").and_then(J::as_str),
        Some(sha512(&corrupt).as_str())
    );
}
#[test]
fn unbound_or_unreadable_artifacts_have_no_verified_byte_observation() {
    let source = "https://registry.npmjs.org/pkg/-/pkg-1.tgz";
    let entries = [(
        "package/package.json",
        br#"{"name":"pkg","version":"1"}"#.as_slice(),
    )];
    let fixture = artifact_fixture(&entries, source);
    let canonical = canonical_integrity(&fs::read(fixture.0.join("bundle/pkg.tgz")).unwrap());
    for integrity in [
        None,
        Some("sha512-invalid"),
        Some(canonical_integrity(b"different bytes").as_str()),
        Some(canonical.trim_end_matches('=')),
        Some(&format!("{canonical} {canonical}")),
    ] {
        replace_integrity(&fixture, integrity);
        let output = fixture.audit(true);
        outcome(&output, 2, "incomplete");
        let report = json(&output);
        let evidence = package_evidence(&report);
        assert_eq!(evidence.get("verified_artifact_sha512"), Some(&J::Null));
        assert_eq!(evidence.get("facts"), Some(&J::Null));
        assert_eq!(evidence.get("approval_fingerprint"), Some(&J::Null));
    }
    replace_integrity(&fixture, Some(&canonical));
    for locator in ["missing.tgz", "../pkg.tgz", "projects"] {
        fixture.index(&format!(r#"[{{"path":"","project_manifest":"projects/package.json"}},{{"path":"node_modules/pkg","artifact":"{locator}"}}]"#));
        let output = fixture.audit(true);
        outcome(&output, 2, "incomplete");
        assert_eq!(
            package_evidence(&json(&output)).get("verified_artifact_sha512"),
            Some(&J::Null)
        );
    }
    fixture.put("bundle/index.json", b"{");
    let output = fixture.audit(true);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8(output.stdout).unwrap().contains(&sha512(
        &fs::read(fixture.0.join("bundle/pkg.tgz")).unwrap()
    )));
}
#[test]
fn supplied_files_are_unchanged_and_no_files_are_written() {
    let f = root_fixture();
    f.approve();
    fn inventory(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut results = Vec::new();
        for entry in fs::read_dir(root).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                results.extend(inventory(&p))
            } else {
                results.push((p.clone(), fs::read(&p).unwrap()))
            }
        }
        results.sort();
        results
    }
    let before = inventory(&f.0);
    outcome(&f.audit(true), 0, "allowed");
    assert_eq!(before, inventory(&f.0));
}
