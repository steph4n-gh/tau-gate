> **Historical research note.** The claims and commands below do not describe the current product. Use the [README](../README.md) and [review contract](review.md) for supported behavior.
>
> **Supported now:** read-only review of npm v3, pnpm v9, and Yarn Classic v1 lockfiles. Bun, Yarn Berry, Go, and the Cargo CLI are unsupported. Cargo metadata parsing is an incomplete library preview. There is no immunity, formal verification, or safety proof.
>
> **License:** [Apache License 2.0](../LICENSE). Any argument below for the PolyForm Noncommercial License is withdrawn. Versions before 4.0.0 were released under PolyForm Noncommercial 1.0.0.
>
> Current scope: [README](../README.md) and [review contract](review.md).

# Extensibility Guide: Adding New Package Managers (v3.0.0)

$\tau$-Gate v3.0.0 was designed with a modular, **Absolute Zero** architecture. We welcome contributions that add support for new ecosystems while maintaining our 0-dependency standard.

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
Create a `build_from_your_lang()` method. 
*   **Standard Library Only:** You must implement the extraction using only `std`. 
*   **Physical Verification:** Do not rely purely on CLI output; implement a structural fallback to scan for real manifests on disk.
*   **MiniParser Integration:** Use the native `MiniParser` in `src/parser.rs` for extracting metadata.

### 4. Map the Execution Sink
Identify the "Install-time execution" vector (e.g. `setup.py`, `build.rs`). Add these packages to the `execution_packages` HashSet during extraction.

---

## 📈 High-Integrity Standards
*   **Transitive Closure:** Engines must return the *entire* transitive dependency tree.
*   **Algebraic Stability:** Ensure all dependency edges are correctly captured for the spectral solver.
*   **Recursive Resolution:** Emulate native resolution algorithms to avoid false structural isolation.

---

## 🤝 Community Engines
**Withdrawn.** The list below is not current support.

~~$\tau$-Gate currently natively supports:~~
*   ~~🦀 **Rust (Cargo)**~~
*   ~~📦 **npm**~~
*   ~~⚡ **pnpm**~~
*   ~~🥟 **Bun**~~
*   ~~🧶 **Yarn Berry**~~

Current support is npm v3, pnpm v9, and Yarn Classic v1. See the [README](../README.md).

**Join the mission to secure every ecosystem.** Submit a PR on [GitHub](https://github.com/steph4n-gh/tau-gate).
