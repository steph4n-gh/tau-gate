#!/bin/sh
# Run inside the pinned Linux amd64 Rust image from a clean Git checkout.
set -eu
export LC_ALL=C
export TZ=UTC
export CARGO_INCREMENTAL=0
export RUSTUP_TOOLCHAIN=1.85.0-x86_64-unknown-linux-gnu

: "${TAU_GATE_SOURCE_COMMIT:?set the exact source commit}"
: "${CARGO_TARGET_DIR:?set an output directory outside the source tree}"
: "${RELEASE_OUTPUT_DIR:?set an output directory outside the source tree}"
case "$TAU_GATE_SOURCE_COMMIT" in
  *[!0-9a-f]*|'') echo 'invalid source commit' >&2; exit 1 ;;
esac
test "${#TAU_GATE_SOURCE_COMMIT}" -eq 40
test "$(git rev-parse --verify 'HEAD^{commit}')" = "$TAU_GATE_SOURCE_COMMIT"
test -z "$(git status --porcelain --untracked-files=no)"
test ! -e "$RELEASE_OUTPUT_DIR"
case "$CARGO_TARGET_DIR" in /*) ;; *) echo 'target must be absolute' >&2; exit 1 ;; esac
case "$RELEASE_OUTPUT_DIR" in /*) ;; *) echo 'release output must be absolute' >&2; exit 1 ;; esac
case "$CARGO_TARGET_DIR" in "$PWD"/*) echo 'target must be outside source' >&2; exit 1 ;; esac
case "$RELEASE_OUTPUT_DIR" in "$PWD"/*) echo 'release output must be outside source' >&2; exit 1 ;; esac

SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$TAU_GATE_SOURCE_COMMIT")
export SOURCE_DATE_EPOCH
RUSTFLAGS="--remap-path-prefix=$PWD=/source --remap-path-prefix=$CARGO_TARGET_DIR=/build"
export RUSTFLAGS
version=$(sed -n '/^\[package\]/,/^\[/s/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"/\1/p' Cargo.toml | head -1)
test -n "$version"
test "$(rustc --version)" = 'rustc 1.85.0 (4d91de4e4 2025-02-17)'

cargo test --frozen --release --all-targets --target x86_64-unknown-linux-gnu --jobs 2
cargo build --frozen --release --bin tau-gate --target x86_64-unknown-linux-gnu --jobs 2
binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/tau-gate"
"$binary" --verify | grep -F "Build commit: $TAU_GATE_SOURCE_COMMIT"
readelf -h "$binary" | grep -F 'Advanced Micro Devices X86-64'

mkdir -p "$RELEASE_OUTPUT_DIR/stage" "$RELEASE_OUTPUT_DIR/dist"
stage="$RELEASE_OUTPUT_DIR/stage"
dist="$RELEASE_OUTPUT_DIR/dist"
install -m 0755 "$binary" "$stage/tau-gate"
install -m 0644 LICENSE "$stage/LICENSE"
install -m 0644 README.md "$stage/README.md"
readelf -dW "$binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort -u > "$stage/runtime-libraries.txt"
test -s "$stage/runtime-libraries.txt"
if grep -Ev '^[A-Za-z0-9_.-]+$' "$stage/runtime-libraries.txt"; then
  echo 'unsupported runtime library name' >&2
  exit 1
fi

binary_sha=$(sha256sum "$binary" | cut -d ' ' -f 1)
created=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')
serial=$(python3 -c 'import sys, uuid; print("urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/steph4n-gh/tau-gate/commit/" + sys.argv[1])))' "$TAU_GATE_SOURCE_COMMIT")
sbom="$dist/tau-gate-v$version-linux-x86_64.cdx.json"
{
  printf '{"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"%s","version":1,' "$serial"
  printf '"metadata":{"timestamp":"%s","component":{' "$created"
  printf '"type":"application","bom-ref":"tau-gate@%s","name":"tau-gate","version":"%s",' "$version" "$version"
  printf '"hashes":[{"alg":"SHA-256","content":"%s"}],"licenses":[{"license":{"id":"Apache-2.0"}}],' "$binary_sha"
  printf '"externalReferences":[{"type":"vcs","url":"https://github.com/steph4n-gh/tau-gate/commit/%s"}]' "$TAU_GATE_SOURCE_COMMIT"
  printf '}},"components":['
  separator=''
  while IFS= read -r library; do
    printf '%s{"type":"library","bom-ref":"%s","name":"%s","scope":"required"}' "$separator" "$library" "$library"
    separator=','
  done < "$stage/runtime-libraries.txt"
  printf '],"dependencies":[{"ref":"tau-gate@%s","dependsOn":[' "$version"
  separator=''
  while IFS= read -r library; do
    printf '%s"%s"' "$separator" "$library"
    separator=','
  done < "$stage/runtime-libraries.txt"
  printf ']}]}\n'
} > "$sbom"
install -m 0644 "$sbom" "$stage/sbom.cdx.json"

archive="tau-gate-v$version-linux-x86_64.tar.gz"
tar --format=ustar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - . | gzip -n -9 > "$dist/$archive"
(cd "$dist" && sha256sum "$archive" "$(basename "$sbom")" > SHA256SUMS)
sha256sum "$binary" "$dist/$archive" "$sbom"
