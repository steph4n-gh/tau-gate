# Execution evidence and bound approvals

`Snapshot::load_with_evidence` adds an offline locator bundle to the existing snapshot API. `Snapshot::load` remains an advisory lock and root-manifest reader. The Rust core uses only the standard library. Neither API installs, extracts files, invokes programs, accesses the network, or writes reports to disk.

## Locator schema

An index has exactly these fields.

```json
{
	"schema_version": 1,
	"lock_sha256": "SHA256 of the exact lock bytes",
	"packages": [
		{"path": "", "project_manifest": "projects/package.json"},
		{"path": "node_modules/example", "artifact": "artifacts/original.tgz"},
		{"path": "packages/local", "project_manifest": "projects/packages/local/package.json"}
	]
}
```

`path` is the exact raw npm v3 `packages` key. The root key is empty. Each non-link record has one locator. Link records have no locator and derive evidence from their exact source target. Duplicate or unknown fields, duplicate or extra instances, and a wrong lock hash reject the index. A missing instance remains explicitly incomplete.

Locator files are relative to the index directory. Empty components, parent traversal, dot components, absolute paths, backslashes, control characters, symlinks, and nonregular files fail. The locator identifies original compressed archive bytes, never an extracted manifest that claims to be verified.

Installed dependency instances require artifact locators and a supported direct archive source. Root and workspace records require source manifest locators. Source name, version, and dependency maps must agree with the corresponding lock record. An explicit `--manifest` must contain the same root bytes as the indexed root. A source manifest's sibling `binding.gyp` is read and hashed when present. Its absence is an explicit observation within that supplied directory. Source files retain caller trust and never become registry-artifact proof.

## Artifact profile

Artifact verification checks one canonical SHA512 SRI token against the original gzip bytes. Stored, fixed, and dynamic DEFLATE blocks are supported. Gzip header bounds, optional header CRC, payload CRC32, and ISIZE are checked. Multiple members and trailing bytes fail.

The locked `resolved` source must use lowercase `http://` or `https://` and end in `.tgz` or `.tar.gz`. Its authority must be an ASCII DNS or IPv4 host with an optional decimal port from 1 through 65535. Credentials, queries, fragments, escapes, IPv6 literals, and ambiguous path components are unsupported. URL path components contain only ASCII letters, digits, `.`, `_`, `-`, `@`, and `+`. Git, directory, and other source kinds remain incomplete even if a supplied archive matches a caller-added integrity token. The hosted Git domains `github.com`, `gist.github.com`, `gitlab.com`, `bitbucket.org`, and `git.sr.ht`, including their subdomains, remain unsupported. This conservative profile avoids applying registry archive lifecycle rules to npm Git preparation.

The complete tar must use POSIX ustar headers with octal numeric fields and regular files or directories under one exact top-level directory. That directory may have an ordinary npm package name instead of `package`. Exactly one regular root-relative `package.json` is required. A regular root-relative `binding.gyp` contributes its content hash. Path components use printable ASCII except Windows-invalid punctuation; empty and dot components, trailing dots or spaces, and Windows device names are unsupported. Non-ASCII archive names remain incomplete because the core does not normalize filesystem Unicode names. Manifest content remains UTF-8. Case aliases of the root-relative lifecycle files, case-folded duplicate paths, mixed top-level directories, and case-folded file and parent directory conflicts fail. A measured legacy header layout is accepted only when its otherwise empty prefix contains exactly two octal timestamp fields with null terminators and the full header checksum is valid. These restrictions prevent evidence from changing when npm extracts to a case-insensitive filesystem. Links, special records, PAX or GNU extensions, malformed checksums, nonzero file padding, missing end markers, and truncation fail. Unsupported data remains incomplete.

Files, compressed archives, and expanded tar each have a 64 MiB limit. A manifest has a 1 MiB limit. Tar archives have at most 10,000 entries. JSON nesting is limited to 128. Artifact integrity binds bytes to the supplied lock. It does not authenticate a publisher or prove code safe.

## Execution facts

Reports identify the consumed index bytes in `evidence_index_sha256`. The root `manifest_sha256` also identifies the indexed root when `--manifest` is omitted. The explicit evidence scope is `npm_v3_artifacts_and_source_snapshots`.

`execution_evidence` contains one record per locked instance. Each has `path`, `state`, `candidate`, `locked_install_marker`, `facts`, `reason`, and `approval_fingerprint`. States are `qualified`, `missing`, `unsupported`, or `conflict`. Only qualified evidence has a fingerprint. Facts distinguish `artifact`, `source_project`, and derived `workspace_link` evidence.

Lifecycle body hashes follow the qualified npm 11.19.1 `ci` rules.

- Root events are `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, and `postprepare`.
- Archived dependency events are `preinstall`, `install`, and `postinstall`.
- Workspace source targets also include `prepare`.

Empty bodies retain their hashes but do not create execution candidates. A regular `binding.gyp` supplies implicit `node-gyp rebuild` when `gypfile` is not false and both `preinstall` and `install` are absent or empty. Binary entrypoints remain separate from automatic installation execution.

An absent `hasInstallScript` makes no assertion. An explicit marker that contradicts the inspected install events or implicit native build produces a conflict. Unknown and conflicting evidence cannot authorize execution. Workspace scripts require approval once at the source target, not again at each structural link. Link evidence and provenance remain visible.

Every locked record remains in scope, including disconnected and platform-omitted optional packages. This inventory does not predict host installation selection or observe script execution. The independent scripts-disabled reference check proves artifact and installed-manifest correspondence within its fixture scope.

## Approval schema and outcomes

An approval file has exactly these fields.

```json
{
	"schema_version": 1,
	"approvals": [
		{"path": "node_modules/example", "fingerprint": "64 lowercase SHA256 hex characters"}
	]
}
```

A fingerprint is SHA256 of canonical compact JSON. The tuple includes its domain and schema, npm format, exact raw instance key, locked name and version, source, integrity, and derived facts. Facts include the evidence kind, manifest name and version, original archive SHA512, manifest byte hash, lifecycle body hashes, native metadata, and binary metadata. JSON object keys use lexical order. Changing relevant evidence invalidates approval. A manifest formatting change also invalidates approval because manifest bytes are pinned. Lock formatting changes require a new index lock hash but preserve unchanged per-instance fingerprints.

Advisory evidence reports emit candidate fingerprints without approving anything. `--enforce` always requires explicit evidence and an explicit approval file. Legacy `tau-gate.toml` coordinate whitelists cannot authorize execution.

- Missing, unsupported, conflicting, or invalid input returns `incomplete` and exit 2.
- Complete evidence with an unapproved candidate returns `blocked` and exit 1.
- Complete evidence with every candidate approved returns `allowed` and exit 0.
- Completed reports without `--enforce` return `advisory` and exit 0.

For audit, the explicit inputs are `--evidence INDEX --approvals FILE`. For review, they are `--base-evidence INDEX --head-evidence INDEX --approvals FILE`. Review checks the head against that supplied approval file. Incomplete base or head evidence takes precedence over policy. pnpm and Yarn remain incomplete under enforcement because transitive execution evidence is unqualified.

`execution_evidence_changes` contains before and after evidence with introducer paths. Existing package changes and typed edge changes remain available. A changed script, archive, or source snapshot can therefore appear even when the lock version does not change.
