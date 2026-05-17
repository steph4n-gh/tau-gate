use crate::error::{GateError, Result};
use std::process::Command;

/// Fetches JSON metadata from the npm registry using the OS-native curl binary.
/// This fulfills the Absolute Zero dependency mandate by delegating TLS to the host OS.
pub fn fetch_npm_metadata(package_name: &str) -> Result<String> {
    let url = format!("https://registry.npmjs.org/{}", package_name);

    // We use -s for silent mode, -S to show errors if they occur, and -L to follow redirects.
    let output = Command::new("curl")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin")
        .args(["-s", "-S", "-L", &url])
        .output()
        .map_err(|e| GateError::Generic(format!("Failed to execute curl: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GateError::Generic(format!(
            "Network request to {} failed with status {}: {}",
            url,
            output.status.code().unwrap_or(-1),
            stderr
        )));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| GateError::Generic(format!("Invalid UTF-8 from registry: {}", e)))
}
