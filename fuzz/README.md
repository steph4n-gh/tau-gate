# Input robustness harness

This is a separate development crate. Its oracle and fuzzing libraries are
absent from the Tau-Gate core, whose `Cargo.toml` remains dependency-free.
The archive target includes the production `src/artifact.rs` verbatim so that
private gzip, DEFLATE, tar, and artifact functions are exercised without a
new production API.

The eight targets cover JSON and digests, gzip, raw DEFLATE, tar, full artifact
integrity, npm/pnpm/Yarn/config parsing, bounded valid FFI callers, and
evidence/approval review. Accepted JSON values are checked against serde_json;
accepted decompression and tar facts are checked against flate2, tar, and
SHA-2. Rejection by the production parser is allowed when it is stricter than
the reference library. Valid gzip and DEFLATE streams are regenerated from
every input. A leading byte of `1` in the tar and artifact targets tells the
harness to repair ustar checksums; the artifact target also repacks gzip and
recomputes SRI. Other inputs exercise the raw byte surface. The FFI target
uses only live owned pointers, including documented null cases.

Generate seeds with `python3 fuzz/seeds.py`. The script uses Python's json,
gzip, zlib, and tarfile, not Tau-Gate's implementation. Run
`cargo test --manifest-path fuzz/Cargo.toml --lib --locked` to verify that the
valid tar, artifact, and enforcement seeds reach successful inspection paths.
The generated tar seeds include an ordinary root, a named root, and an
identical non-lifecycle dot-alias pair observed in registry archives.
The generated corpus and crash artifacts are deliberately outside Git; the
seed recipe and dependency lockfile are versioned.

The fuzz crate uses Rust 1.88 or newer for its separately versioned oracle
dependencies, including SHA-2 0.11. CI runs its seed checks with Rust 1.88
while building and testing the dependency-free Tau-Gate core with Rust 1.85.
Review Dependabot fuzz updates against the fuzz toolchain without raising the
core or release toolchain. A green seed check exercises the reference harness;
it does not qualify a release or replace a finite fuzz campaign.

For a local build, use a Rust nightly with `rust-src` and a current
`cargo-fuzz`:

```
RUSTUP_TOOLCHAIN=nightly cargo fuzz build
RUSTUP_TOOLCHAIN=nightly cargo fuzz run json fuzz/corpus/json -- -max_len=65536 -timeout=2 -rss_limit_mb=512 -max_total_time=300
```

Run each target separately and retain its toolchain, source commit, command,
seed hashes, exit status, execution count, coverage summary, and any minimized
crash input. Long campaigns belong after the M2 candidate is frozen. A finite
clean campaign is evidence about exercised inputs, not a proof of parser or
archive correctness. The fixed snapshot work limits also have exact boundary,
repeated-work, and failed-inspection tests in the production suite; ordinary
mutation capped at 64 KiB cannot reach the multi-GiB limits.
