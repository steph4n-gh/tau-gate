# Governance & Security Policy

This document explains how to configure $\tau$-Gate and translates its mathematical signals into real-world security scenarios.

---

## ⚙️ Configuration (`tau-gate.toml`)

The `tau-gate.toml` file in your project root acts as your **Topological Security Policy**.

```toml
# Threshold: The size limit (%) of a quarantined island. (Default: 15.0)
# If an isolated cluster is smaller than this, the gate triggers.
threshold_percentage = 15.0

# Whitelist: Trust entire scopes using Glob patterns.
# Use this to allow legitimate but isolated packages (e.g. CLI tools).
whitelist = [
  "@astrojs/*",
  "@types/*",
  "vite"
]
```

---

## 🚫 Real-World Attack Scenarios

### 1. The "Typosquatter" (Isolated Island)
*   **What happens:** You install `asttro` instead of `astro`.
*   **Math Signal:** **Small Partition < 15%**.
*   **Verdict:** The `max_gap` algorithm snaps the graph at the single thread connecting your app to the fake package.

### 2. The "Sleeper Cell" (Transitive Bridge)
*   **What happens:** A utility library 10 levels deep is hijacked and adds an install script.
*   **Math Signal:** **Extreme Connectivity Isolation ($\lambda_2 < 10^{-4}$)**.
*   **Verdict:** The Fiedler Vector identifies that the entire project "snaps" at the structural bottleneck created by the deep dependency.

### 3. The "Trojan Horse" (The Bloated Trojan)
*   **What happens:** An attacker adds 500 safe dependencies to their malicious package to look "big."
*   **Math Signal:** **Zero Connectivity Score**.
*   **Verdict:** While the partition size might exceed 15%, the **Algebraic Connectivity** remains near zero, triggering the "Bloated Trojan" alarm.

---

## 🤝 How to Contribute

We welcome contributions for:
*   🦀 **Native extraction engines** for Rust, Python, and Go.
*   📈 **Mathematical optimizations** for the sparse iterative solver.
*   ☁️ **Cloud integrations** (S3 centralized whitelists).

See [GEMINI.md](../GEMINI.md) for the internal developer architecture guide.
