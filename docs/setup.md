# Installation & Operation Guide (v3.0.0)

This document provides exhaustive instructions for installing $\tau$-Gate across different use cases.

---

## ⚡ Option 1: The "One-Click" Install
Best for users who want to get started immediately without managing source code. This script clones, builds, and installs the binary to `/usr/local/bin`.

```bash
curl -L https://raw.githubusercontent.com/steph4n-gh/tau-gate/main/install.sh | bash
```

---

## 🛠️ Option 2: The "Developer" Install (Manual)
Best for contributors or users who want to audit the source code before building.

### 1. Download the Source
```bash
git clone https://github.com/steph4n-gh/tau-gate.git
cd tau-gate
```

### 2. Build & Link
You can build the binary and create a global link manually:

```bash
# Build the optimized release
cargo build --release

# Link globally (MacOS/Linux)
sudo ln -sf $(pwd)/target/release/tau-gate /usr/local/bin/tau-gate
```

---

## 🛡️ Option 3: High-Integrity Reproduction
Best for security-conscious teams who require byte-for-byte identical binaries that match the public source.

### 1. Requirements
*   **Rustup:** Ensure you have `rustup` installed.
*   **Toolchain:** The reproduction engine will automatically ensure you are using the pinned **Rust 1.85.0** version.

### 2. Run Reproduction
```bash
# This builds the binary using strict deterministic flags
./reproduce.sh
```

---

## 📖 CLI Usage Reference

Just run `tau-gate` in your project root. It will automatically detect your lockfile and apply the audit.

| Flag | Description |
| :--- | :--- |
| `--dry-run`, `-d` | **Passive Audit:** Runs the math and identifies threats without triggering a physical install. |
| `--verify`, `-v` | **Integrity Check:** Displays the version and Git build hash of the binary. |
| `--help`, `-h` | Displays the help menu. |

---

## 🚀 CI/CD Integration

We recommend integrating $\tau$-Gate using native system tools to maintain the zero-dependency security model.

```yaml
# GitHub Actions Example
- name: Native τ-Gate Install
  run: curl -L https://raw.githubusercontent.com/steph4n-gh/tau-gate/main/install.sh | bash

- name: Security Gate
  run: tau-gate
```
