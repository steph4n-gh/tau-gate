# Extensibility Guide: Adding New Package Managers

$\tau$-Gate v1.1.0 was designed with an extensible architecture. We want to support every major ecosystem, from Go to Python to Ruby. 

Adding a new language engine is a standardized 4-step process.

---

## 🏗️ The 4-Step Engine Template

### 1. Register the Engine
In `src/graph.rs`, add your new language to the `EngineType` enum:
```rust
pub enum EngineType {
    // ... existing engines
    YourLang, 
}
```

### 2. Implement the Discovery
Update the `DepGraph::build()` function to detect your language's lockfile:
```rust
if Path::new("your-lang.lock").exists() {
    Ok((Self::build_from_your_lang()?, EngineType::YourLang))
}
```

### 3. Implement the Extraction Logic
Create a `build_from_your_lang()` method. This is where you convert your ecosystem's metadata into a directed graph.
*   **Recommendation:** Use your language's native CLI (e.g., `cargo metadata`, `go mod graph`) to get the transitive tree.
*   **Safety:** Always implement a physical manifest fallback (scanning `node_modules` or equivalent) if CLI output is noisy.

### 4. Map the Execution Sink
Identify what "Install-time execution" looks like in your language (e.g., `setup.py`, `build.rs`, `extconf.rb`). Add these packages to the `execution_packages` HashSet during extraction.

---

## 📈 Pro-Tips for High-Integrity Engines
*   **Transitive Closure:** Your engine must return the *entire* dependency tree, not just top-level packages.
*   **Algebraic Stability:** The math layer relies on an accurate map. Ensure all dependency edges are correctly captured.
*   **Recursive Resolution:** If your language supports nested dependency trees (like npm), emulate the native resolution algorithm to avoid "false isolation."

---

## 🤝 Need Help?
Open a [GitHub Issue](https://github.com/steph4n-gh/tau-gate/issues) or submit a Pull Request! We are excited to see $\tau$-Gate protecting new ecosystems.
