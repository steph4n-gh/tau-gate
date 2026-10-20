# v4.1 execution evidence

Baseline is v4.0.0 at e052ac03517286f2f56dfac46aa19770358ccbe8.

## Chosen shape

Two independent designs compared direct archive verification with supplied-manifest or external-attestation input. Both rejected using self-asserted verification for authorization. The independent judge chose candidate A, 28/30 against 27/30, for its smaller locator schema. Candidate B contributed an additive Snapshot::load_with_evidence API, typed native-build facts, source dependency-map checks and trusted-base PR controls.

The index has schema_version, lock_sha256 and packages. Each package entry has its exact npm lock key in path and either an artifact path or a project_manifest path. All referenced files are bounded relative paths within the bundle. Root uses the empty path. Workspace link records derive their target evidence from the lock and do not duplicate source manifests. No supplied verified flags exist.

The private artifact reader checks original compressed bytes against SHA512 SRI, decodes one bounded gzip member, checks CRC32 and size, and inspects the complete bounded tar. Stored, fixed and dynamic DEFLATE blocks are required. Unsupported archive extensions, ambiguous paths, duplicates, corruption and resource-limit breaches stay incomplete. It never extracts files or invokes another program.

Snapshot owns per-record typed execution evidence. It reuses the current graph, candidate paths and package comparisons. Verified locked archives and caller-supplied root/workspace manifests remain distinct evidence kinds. The latter scope proves consumed source bytes, not registry authenticity. Observe sibling binding.gyp bytes in each supplied source snapshot. Inventory install-relevant lifecycle bodies using an operation-specific table grounded in the pinned npm source. Binary entrypoints remain separate. Scripts-disabled reference installs prove artifact and installation agreement, not which scripts execute.

Fingerprint each qualified execution candidate with canonical structured JSON and SHA256. Include format, exact instance identity, coordinate, source, lock integrity, evidence kind, original artifact identity, manifest bytes, relevant lifecycle body hashes and implicit build evidence. Missing or conflicting evidence cannot produce a fingerprint. Legacy coordinate approvals cannot authorize stronger evidence policy. Strong enforcement requires evidence for every lock record, including host-omitted optional packages. It does not recreate npm installation selection.

The separate Python tools own explicit acquisition, independent npm reference installs and Git revision capture. The Rust auditor stays read-only, offline, standard-library-only, and compatible with the current C ABI.

## Milestone gates

1. Run actual npm ci with scripts disabled against controlled local archives. Independently verify artifact-to-installed-manifest agreement, aliases, nested versions, workspace links, optional/platform omissions and negative binding controls. Preserve original artifacts, locators and an independent oracle. No Rust enforcement change before this passes.
2. Pass cryptographic fixed vectors, cross-language gzip/tar differential checks and malformed-input controls. Then prove qualified approval, source/integrity/lifecycle invalidation, unknown/conflict precedence, read-only operation, unchanged pnpm/Yarn incompleteness and native ABI checks. No PR workflow before this passes.
3. Capture exact base/head Git objects, source snapshots and trusted-base approvals. Demonstrate correct hashes despite a dirty working tree. A head-side approval edit must not bypass base policy. Emit deterministic JSON and concise review output with allowed/blocked/incomplete distinctions. Run the full suite and independent final review.

## Scope limits

Archive integrity binds bytes to the supplied lock. It does not authenticate a publisher or prove arbitrary code safe. Source snapshots retain the caller trust boundary. All-lock evidence does not predict host-specific execution. A common strict gzip/ustar profile is the first qualification target. Unsupported features fail visibly. No resolver, daemon, hosted service, extra package ecosystem or graph-math rewrite belongs to this phase.

## Enforcement decision

The independent judge identified implicit legacy fallback as avoidable risk. v4.1 --enforce requires the evidence index and an explicit bound-approval file. Coordinate whitelists remain advisory compatibility metadata and cannot produce an allowed enforcement result. This is a deliberate tightening of the old weak policy. Missing evidence or approvals returns incomplete. Review can enforce the head against the explicit supplied policy, with incomplete base/head input taking precedence. The PR helper always supplies the policy captured from the base revision.
