# Interpreting Topological Anomalies: A Guide to $\tau$-Gate Results

When using $\tau$-Gate, you may encounter a **CRITICAL TOPOLOGICAL ANOMALY** that halts your installation. 

Before panicking, it is crucial to understand *how* $\tau$-Gate thinks. $\tau$-Gate does not use malware signatures or CVE databases. It uses **graph theory (Spectral Bisection)** to look for the *shape* of a supply chain attack.

## The Shape of an Attack (The Fiedler Vector)

When a package manager builds a dependency tree, it forms a massive, highly connected "mainland." 

A classic supply chain attack (like the `event-stream` or `xz` hacks) typically involves an attacker inserting a tiny, obfuscated script deep into a forgotten sub-dependency. 

Mathematically, this creates a **Topological Island**: a small cluster of nodes that is barely connected to the mainland but requests **execution privileges** (like `preinstall` or `postinstall` scripts) to run code on your machine.

When $\tau$-Gate calculates the **Maximum Spectral Gap**, it is explicitly looking for these isolated execution islands. If it finds one, it drops the gate and aborts the install.

## "Good" Failures (False Positives)

If $\tau$-Gate aborts an installation, **it does not necessarily mean you have been hacked.**

To the bisection algorithm, a malicious backdoor and a legitimate native compiler tool look mathematically identical. Both are isolated from the main JavaScript logic, and both require OS-level execution scripts to run.

**Common "Good Failures" include:**
*   **Native File Watchers:** Packages like `fsevents` (Apple) or `@parcel/watcher` (Microsoft).
*   **Native Compilers/Bundlers:** Tools like `esbuild`, `swc`, or `node-gyp`.
*   **Binary Wrappers:** OS-specific binary packages published to avoid local compilation.

If $\tau$-Gate quarantines one of these known tools, **the system is working perfectly.** It proves the mathematical firewall is correctly identifying execution threats on the perimeter of your dependency graph.

## How to Handle an Anomaly

If $\tau$-Gate halts your build, you do **not** need to get rid of the package (assuming you recognize it as a legitimate tool like `esbuild`).

Because $\tau$-Gate is a Zero-Trust firewall, it defaults to blocking *everything* that looks structurally suspicious. To bypass the firewall for trusted tools, you must explicitly declare them in your local policy file.

### The Whitelist Solution

Create or update the `tau-gate.toml` file in the root of your project:

```toml
# tau-gate.toml
threshold_percentage = 5.0 # The max size (%) of an allowed execution island
mode = "Enforcement"       # "Enforcement" blocks, "Advisory" warns

# Explicitly trust known native binaries to bypass the math engine
whitelist = [
    "fsevents",
    "@parcel/watcher-*",
    "esbuild"
]
```

By adding the package to the `whitelist`, you are telling $\tau$-Gate: *"I acknowledge that this package is topologically isolated and has execution privileges, but I trust the vendor."* 

$\tau$-Gate will then ignore that specific node during the bisection math and allow your installation to proceed safely.