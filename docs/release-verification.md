# Verify a Linux release independently

The declared release platform is Debian 12 x86_64. The build uses Rust 1.85.0
inside the pinned Linux amd64 image
`rust@sha256:16a7f242108de02f10fe4a392991679bafa7694e59f5b40a54d5af1be9b40d03`.
The core has no third-party Rust runtime crates. The archive contains the
executable, license, README, CycloneDX 1.5 SBOM, and its direct ELF library
inventory. The SBOM records the binary SHA256, a commit-derived UUID, and direct
system library names. It does not inventory an entire Debian installation or
assign versions to system libraries that the release does not ship.

The [release-candidate workflow](../.github/workflows/release.yml) runs only by
manual dispatch. It builds the exact commit twice from separate clean clones
in network-disabled containers, compares executable, archive, SBOM, and
checksum bytes, and runs the Rust tests. A different source path is used for
each build; rustc path remapping prevents those paths from entering the
artifact. The previous automatic tag-triggered release and asset clobbering
have been removed. The workflow creates signed Sigstore bundles for SLSA
provenance and the SBOM assertion through GitHub's
[`actions/attest`](https://github.com/actions/attest). It uploads a candidate
workflow artifact and does not publish a GitHub Release.

To rebuild without trusting the published executable, clone the exact commit
and run the [build script](../tools/release/build.sh) in the pinned image. For
example, with the published commit hash substituted for `COMMIT`:

```sh
COMMIT=40_lowercase_hex_commit
work=$(mktemp -d)
git clone https://github.com/steph4n-gh/tau-gate.git "$work/source"
git -C "$work/source" checkout --detach "$COMMIT"
mkdir "$work/output"
docker run --rm --platform linux/amd64 --network none \
  --cpus 2 --memory 2g --pids-limit 256 --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$work/source,dst=/source,readonly" \
  --mount "type=bind,src=$work/output,dst=/output" \
  --workdir /source \
  --env HOME=/tmp \
  --env CARGO_HOME=/tmp/cargo \
  --env "TAU_GATE_SOURCE_COMMIT=$COMMIT" \
  --env CARGO_TARGET_DIR=/output/target \
  --env RELEASE_OUTPUT_DIR=/output/release \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/source \
  rust@sha256:16a7f242108de02f10fe4a392991679bafa7694e59f5b40a54d5af1be9b40d03 \
  sh tools/release/build.sh
```

The build script selects the installed Rust 1.85.0 toolchain explicitly, so
the repository's `rustfmt` component request cannot trigger a network lookup.
The container uses the caller's user and group IDs so it can write the output
mount without extra capabilities, and the caller can read the resulting files.
It rejects a dirty checkout, a wrong explicit commit, a missing Cargo lockfile,
and output inside the source. It tests and builds with Cargo's frozen offline
mode. Compare every file in `$work/output/release/dist` to the
published candidate or release asset with `cmp` or SHA256; matching JSON
reports or a successful compilation alone are insufficient. The downloaded
archive can be checked with `sha256sum --check SHA256SUMS`.

Install the archive in a clean Debian 12 x86_64 runtime to check the declared
platform without relying on the Rust build image:

```sh
archive="$work/output/release/dist/tau-gate-v4.2.0-linux-x86_64.tar.gz"
docker run --rm --platform linux/amd64 --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=64m --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$archive,dst=/input/release.tar.gz,readonly" \
  debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 \
  sh -ceu 'mkdir /tmp/tau-gate; tar -xzf /input/release.tar.gz -C /tmp/tau-gate; /tmp/tau-gate/tau-gate --verify'
```

For published assets, verify both the Sigstore signature and the expected
GitHub workflow identity before use:

```sh
gh attestation verify tau-gate-v4.2.0-linux-x86_64.tar.gz \
  --repo steph4n-gh/tau-gate \
  --signer-workflow steph4n-gh/tau-gate/.github/workflows/release.yml \
  --source-digest "$COMMIT" \
  --bundle provenance.sigstore.json
gh attestation verify tau-gate-v4.2.0-linux-x86_64.tar.gz \
  --repo steph4n-gh/tau-gate \
  --signer-workflow steph4n-gh/tau-gate/.github/workflows/release.yml \
  --source-digest "$COMMIT" \
  --predicate-type https://cyclonedx.org/bom \
  --bundle sbom.sigstore.json
```

Verification must fail if a copy of the archive is altered. The signature
authenticates the attested digest and workflow identity; reproducibility is
the separate byte-for-byte rebuild comparison. GitHub's
[attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
documents the CLI and non-default SBOM predicate. Two containers run by one
operator show local repeatability; a third party following this procedure is
an independent operator check and must be reported separately if performed.
