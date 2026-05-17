use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap_or_else(|_| Command::new("echo").arg("no-git").output().unwrap());

    let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}
