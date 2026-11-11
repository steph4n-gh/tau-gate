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

## Install the npm PR reviewer beta

The v4.3.0-beta.2 Debian 12 x86_64 archive includes the checker, three standard-library Python helpers, a PR review guide, and two GitHub workflow examples. Download the beta's archive, SBOM, checksums, and provenance bundle from its [release page](https://github.com/steph4n-gh/tau-gate/releases/tag/v4.3.0-beta.2), then verify the expected commit and workflow identity with the [release verification guide](release-verification.md).

```sh
mkdir tau-gate-v4.3.0-beta.2
cd tau-gate-v4.3.0-beta.2
gh release download v4.3.0-beta.2 --repo steph4n-gh/tau-gate \
	--pattern 'tau-gate-v4.3.0-beta.2-linux-x86_64.tar.gz' \
	--pattern 'tau-gate-v4.3.0-beta.2-linux-x86_64.cdx.json' \
	--pattern 'SHA256SUMS' \
	--pattern 'provenance.sigstore.json'
sha256sum --check SHA256SUMS
tar -xzf tau-gate-v4.3.0-beta.2-linux-x86_64.tar.gz
./tau-gate --verify
python3 -B tools/pr_review.py --help
```

The [PR review guide](pr-review.md) shows the exact-base/head command and approval workflow. The beta supports npm v3 PRs whose original package archives can be verified within the documented bounds. Unsupported or missing evidence stays incomplete; approval cannot waive it. The helper never runs package lifecycle scripts.

To see a PR review before configuring approvals, fetch its base and head commits, change into the npm repository, and run the packaged helper:

```sh
python3 /path/to/tau-gate/tools/pr_review.py --preview --base main --head my-pr-branch
```

It prints the path to a Markdown summary. A complete preview is informational; use the [enforced PR workflow](pr-review.md#enforce-an-approval-decision) for an approval decision.

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
