# Install and run Tau-Gate

The published v4.2.1 binary is qualified for Debian 12 x86_64. Build from source for other environments; those builds are not covered by the published Linux release receipt.

## Install the verified Linux release

Download the archive, checksums, and provenance bundle from the [v4.2.1 release](https://github.com/steph4n-gh/tau-gate/releases/tag/v4.2.1). Verify the checksum and workflow attestation before extracting the binary.

```sh
mkdir tau-gate-v4.2.1
cd tau-gate-v4.2.1
gh release download v4.2.1 --repo steph4n-gh/tau-gate \
	--pattern 'tau-gate-v4.2.1-linux-x86_64.tar.gz' \
	--pattern 'tau-gate-v4.2.1-linux-x86_64.cdx.json' \
	--pattern 'SHA256SUMS' \
	--pattern 'provenance.sigstore.json'
sha256sum --check SHA256SUMS
gh attestation verify tau-gate-v4.2.1-linux-x86_64.tar.gz \
	--repo steph4n-gh/tau-gate \
	--signer-workflow steph4n-gh/tau-gate/.github/workflows/release.yml \
	--source-digest 6c333b490747d79e51920a8d266bac22f0dcf777 \
	--bundle provenance.sigstore.json
tar -xzf tau-gate-v4.2.1-linux-x86_64.tar.gz
./tau-gate --verify
```

The checksum file covers both the archive and SBOM, so download both before running `sha256sum --check`. The [release verification guide](release-verification.md) gives the pinned independent rebuild and SBOM-attestation procedure. A matching checksum alone does not authenticate the publisher.

## Build from source

Use Rust 1.85.0 and the checked-in `Cargo.lock`. The core has no third-party Rust dependencies.

```sh
git clone https://github.com/steph4n-gh/tau-gate.git
cd tau-gate
git checkout v4.2.1
cargo build --release --offline
./target/release/tau-gate --verify
```

This local build is useful for development. It is not an independent byte-for-byte verification of the published Linux archive. Use the [release verification guide](release-verification.md) for that comparison.

## Review a lockfile

Run an advisory review with explicit input paths. The CLI reads inputs without installing dependencies, changing the project, or contacting a registry.

```sh
./target/release/tau-gate audit --lock package-lock.json --manifest package.json --json
./target/release/tau-gate review --base base-lock.json --head head-lock.json \
	--base-manifest base-package.json --head-manifest head-package.json --json
```

An npm review needs [original-archive evidence and bound approvals](execution-evidence.md) before `--enforce` can return allowed. For a pull-request gate, follow the [trusted Git-object workflow](pr-review.md). pnpm v9 and Yarn Classic v1 topology reports exit 2 because transitive execution metadata is unknown. See the [review contract](review.md) for supported input scopes and exit codes.
