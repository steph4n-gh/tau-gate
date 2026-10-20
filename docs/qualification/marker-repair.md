# Stale positive npm install marker repair

The first two owned-repository pilot lockfiles exposed the same false conflict in
v4.2.0. Their `fsevents@2.3.3` records set `hasInstallScript: true`, but the
SHA512-SRI-matched registry archive contains neither an install lifecycle body
nor a regular `binding.gyp`. An isolated `npm ci --ignore-scripts` installation
gave the same unpacked manifest. npm 11.19.1 treats the positive marker as a
reason to inspect the unpacked manifest before scheduling a build. The old
gate treated the marker as an assertion that the archive must contain an
install event, so a no-change review returned incomplete.

The repair makes the complete, integrity-verified archive authoritative for
execution candidacy. It keeps the original lock marker visible. A false marker
paired with an observed install hook or implicit native build still conflicts.
Missing, invalid, or unsupported evidence remains incomplete, and a verified
install hook still needs an exact-instance approval. No approval fingerprint or
report schema changes. The independent Python reference uses the same rule.

The regression was red against v4.2.0 and green against the repaired binary.
The 307 black-box npm evidence controls, Rust tests, Python qualification
tests, and offline Clippy passed. With the original archives cached by SRI,
earthquake-lab-publication's no-change review changed from incomplete to
allowed: all 45 locked instances qualified and zero execution candidates
remained. REA's no-change review changed from incomplete to complete and
blocked: all 561 instances qualified, with its root `prepare` and nested
`esbuild@0.25.12` `postinstall` correctly requiring approvals. Those two
approval fingerprints equal their pre-repair values. This is a coverage repair,
not evidence that package scripts are safe or that a dependency update should
be approved automatically.

Local receipts and full reports are under
`/Volumes/Storage/taugate-qualification/marker-repair/`. The repaired
earthquake report SHA256 is
`2eca553cba08cba249d755757a9d95e95c479e718617b0163cb958201532780d`;
the repaired REA report SHA256 is
`79ef1a03cc836d09349097367a9381b8eb84b6b49e4013c7065c5ac3c325328b`.
The frozen public corpus, its original v4.1 baseline, and the v4.2.0 M2
candidate remain unchanged. A separate post-pilot replay receipt is required
before claiming any corpus change.
