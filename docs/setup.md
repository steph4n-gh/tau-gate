# Installation & Operation Guide (v2.0.0)

This document details how to install, run, and integrate $\tau$-Gate into your local environment and zero-trust CI/CD pipelines.

---

## 💻 Local Installation

### 1. Requirements
*   **Rust:** `cargo` 1.80+ (Pinned in `rust-toolchain.toml`)
*   **Package Managers:** Native support for `npm`, `pnpm`, `bun`, `yarn`, and `cargo`.

### 2. Reproducible Build
To ensure your local binary matches the official source code, use our reproduction engine:

```bash
./reproduce.sh
```

### 3. Quick Global Link
```bash
./install.sh
```

---

## 🛠️ Usage & CLI Flags

| Flag | Description |
| :--- | :--- |
| `--dry-run`, `-d` | **Passive Audit:** Runs bisection math without triggering a physical install. |
| `--verify`, `-v` | **Integrity Check:** Displays binary version and Git commit build hash. |
| `--help`, `-h` | Displays the help menu. |

---

## 🚀 Zero-Action CI/CD Integration

To maintain the "Absolute Zero" standard, we recommend integrating $\tau$-Gate into GitHub Actions using **only native system tools**. This eliminates the risk of 3rd-party action hijacking.

### Example Workflow (`.github/workflows/security.yml`)

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Native Checkout
        run: |
          git clone https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }} .
          git checkout ${{ github.sha }}

      - name: Run τ-Gate Audit
        run: |
          # Use pre-built release binary or build from source
          cargo build --release
          ./target/release/tau-gate
```

---

## 🧹 Telemetry & Logs

When the gate identifies an anomaly, it writes a structured JSON log to:
`./logs/tau-gate_anomalies.json`

This file is designed for SIEM ingestion and includes:
*   **Connectivity Score ($\lambda_2$):** Direct measure of structural isolation.
*   **Bisection Threshold ($\tau$):** The point where the project was bisected.
*   **Quarantined Nodes:** List of packages identified as structural outliers.
