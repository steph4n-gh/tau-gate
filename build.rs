use std::{env, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-env-changed=TAU_GATE_SOURCE_COMMIT");
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD^{commit}"])
        .output()
        .expect("Git is required to identify the exact source commit");
    assert!(
        output.status.success(),
        "Git could not resolve the source commit"
    );
    let hash = String::from_utf8(output.stdout).expect("Git commit ID is not UTF-8");
    let hash = hash.trim();
    assert!(
        matches!(hash.len(), 40 | 64) && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Git returned an invalid source commit ID"
    );
    if let Ok(expected) = env::var("TAU_GATE_SOURCE_COMMIT") {
        assert_eq!(
            hash, expected,
            "release source commit does not match Git HEAD"
        );
    }
    println!("cargo:rustc-env=GIT_HASH={hash}");
}
