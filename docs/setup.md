# Installation & Operation Guide

This document details how to install, run, and integrate $\tau$-Gate into your local environment and CI/CD pipelines.

---

## 💻 Local Installation

### 1. Requirements
*   **Rust:** `cargo` 1.70+
*   **Package Managers:** Ensure your preferred tool (`npm`, `pnpm`, `bun`, or `yarn`) is installed globally.

### 2. Quick Install (Global Symlink)
The provided `install.sh` script automates the build and links the binary to `/usr/local/bin`.

```bash
./install.sh
```

### 3. Manual Build
```bash
cargo build --release
sudo ln -sf $(pwd)/target/release/tau-gate /usr/local/bin/tau-gate
```

---

## 🛠️ Usage & CLI Flags

Just run `tau-gate` in your project root. It will automatically detect your lockfile and apply the audit.

| Flag | Description |
| :--- | :--- |
| `--dry-run`, `-d` | **Passive Audit:** Runs the math and identifies threats without triggering an install. |
| `--verify`, `-v` | **Integrity Check:** Displays the version and Git build hash of the binary. |
| `--help`, `-h` | Displays the help menu. |

---

## 🚀 CI/CD Integration

### GitHub Actions (`.github/workflows/security.yml`)
Add this step to your pipeline to enforce a zero-trust gate before your build.

```yaml
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1 
      
      - name: Install τ-Gate
        run: |
          git clone https://github.com/steph4n-gh/tau-gate.git
          cd tau-gate && cargo build --release
          sudo ln -sf $(pwd)/target/release/tau-gate /usr/local/bin/tau-gate

      - name: Run Security Gate
        # Replaces 'bun install'
        run: tau-gate
```

---

## 🧹 Telemetry & Logs

When the gate identifies an anomaly and aborts, it writes a structured JSON log to:
`./logs/tau-gate_anomalies.json`

This file is designed for **SIEM ingestion** (Splunk, Datadog, ELK) and contains:
*   Bisection Tau-point
*   Algebraic Connectivity Score ($\lambda_2$)
*   List of Quarantined Nodes
*   Full Transitive Chain
