> Historical research/prototype document. Claims and benchmark results below are unverified and do not describe the current qualified CLI. See [current scope and limitations](../README.md) and [review contract](review.md). No formal safety proof, immunity, XZ coverage or TSP workload benefit is established.

# Governance & Security Policy (v2.0.1)

This document explains how to configure $\tau$-Gate and translates its mathematical signals into real-world security scenarios.

---

## ⚙️ Configuration (`tau-gate.toml`)

### Operational Modes
V3.0.0 introduces **Advisory Mode**, allowing teams to baseline projects without blocking development.

```toml
# "enforcement" (Kill build - Default) or "advisory" (Warn only)
mode = "enforcement"

# Threshold: The size limit (%) of a quarantined island. (Default: 15.0)
threshold_percentage = 15.0

# Whitelist: Trust entire scopes using Glob patterns.
whitelist = ["@astrojs/*", "@types/*", "vite"]
```

---

## 🚫 Real-World Attack Scenarios

### 1. The "Typosquatter" (Isolated Island)
*   **What happens:** A developer accidentally installs a tiny, unknown package that immediately tries to run an exfiltration script.
*   **Signal:** **Small Partition < 15%**.

### 2. The "Sleeper Cell" (Deep Transitive Bridge)
*   **What happens:** A utility library 10 levels deep is hijacked to add a `postinstall` or `build.rs` backdoor.
*   **Signal:** **Connectivity Isolation ($\lambda_2 < 10^{-4}$)**.

### 3. The "Trojan Horse" (The Bloated Trojan)
*   **What happens:** An attacker adds 500 safe dependencies to their malicious package to look "big" and bypass the 15% rule.
*   **Signal:** **Zero Connectivity Score**. Despite the size, the math identifies the entire cluster is connected to your project by only one thread.

### 4. Obfuscated Payloads (Entropy Alarm)
*   **What happens:** An attacker hides a large, encrypted payload in their manifest metadata.
*   **Signal:** **Entropy Engine Trigger**. The `MiniParser` identifies high-entropy strings (>128 continuous characters with >16 distinct characters) and bridges them to the quarantine.

---

## 🤝 How to Contribute

$\tau$-Gate v2.0.1 is built on an **Absolute Zero** foundation. We welcome contributions that maintain our zero-dependency standard for:
*   🦀 **Native extraction engines** for Python, Go, and Ruby.
*   📈 **Mathematical optimizations** for the standard-library-only solver.

See [GEMINI.md](../GEMINI.md) for architectural constraints.
