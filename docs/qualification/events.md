# Independent qualification event labels

`tools/qualification_oracle.py` labels npm lockfile-v3 snapshots and historical changes. It uses Python's standard `json`, `gzip`, `hashlib`, and `tarfile` implementations. It imports neither the production evidence collector nor Tau-Gate reports. It executes no package scripts and extracts no archive members to disk.

These are static manifest facts. The event rules follow the npm 11.19.1 source qualification documented in [the npm reference check](../npm-reference.md). They do not observe execution or establish script safety.

## Snapshot API

`snapshot_facts(lock_path, index_path, manifest=None)` accepts filesystem paths. The optional `manifest` supplies the original root manifest. Its bytes must match the root locator's bytes.

The returned dictionary has `status`, `packages`, and `issues`. Status is `unavailable` when the lock cannot establish the package inventory. Status is `partial` when any package's execution facts are unknown. Status is `complete` when all package facts are known. Completeness concerns these static facts. It does not mean that the core supports every archive profile.

`packages` maps exact lock paths to records. Every record preserves lock-derived `name`, `version`, `source`, and `integrity`, including when execution facts are unknown. An unknown record has `reason` and omits `scripts`, `implicit_native`, and `install_candidate`. Unknown scripts never become an empty script map.

A known record additionally has these fields.

| Field | Meaning |
| --- | --- |
| `scope` | `root`, `workspace`, `archive`, or `link`. |
| `scripts` | Qualified event names and their exact script bodies. |
| `implicit_native` | Whether the qualified npm default native-build rule applies. |
| `install_candidate` | A nonempty qualified lifecycle body or an implicit native build exists. |
| `manifest_sha256` | SHA256 of original manifest bytes. Links omit this field. |
| `binding_sha256` | SHA256 of original `binding.gyp` bytes, or null when absent. Links omit this field. |
| `artifact_sha256`, `artifact_sha512` | Original compressed artifact digests when bytes are available. |
| `archive_root` | Actual single top-level archive component. Archive records expose it after successful archive inspection. |
| `binary_entrypoints` | The manifest's `bin` value. It does not imply automatic lifecycle execution. |
| `profile_conditions` | Observed metadata differences from the core's strict profile. This list is diagnostic, not an exhaustive core-compatibility verdict. |

Archive digests remain visible when supplied bytes fail integrity validation. They describe those bytes and do not authenticate them. A source manifest's provenance remains the caller's snapshot and locator receipt. The oracle does not upgrade copied files into signed source attestations.

The index uses schema 1 with `lock_sha256` and `packages`. Each entry has an exact `path` plus either `artifact` or `project_manifest`. The index must bind the exact original lock bytes. Duplicate, unknown, and link locators invalidate the index. Missing locators make individual packages unknown. Locators cannot traverse parents or symlinks.

## Qualified lifecycle rules

The root has `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, and `postprepare`. Archive dependencies have `preinstall`, `install`, and `postinstall`. Workspace source targets also have `prepare`.

A regular `binding.gyp` enables the implicit native build when `gypfile` is not false and both `preinstall` and `install` are absent or empty. A nonempty `preinstall` suppresses this default even if `install` is absent.

A workspace link points to its source target and has no independent install candidate. The target retains execution facts, so one workspace does not require duplicate approval. A broken or chained link remains unknown.

Git sources and local file sources remain unknown. A caller-supplied matching archive cannot prove their npm preparation semantics. The oracle inspects HTTP and HTTPS archive evidence without adopting the core's narrower portable URL profile. It does not fetch that evidence.

## Archive and parser boundaries

Files and compressed archives have a 64 MiB limit. Expanded gzip data has a separate 64 MiB limit. Archives have at most 10,000 yielded members. Manifests have a 1 MiB limit. JSON has at most 128 nested containers and rejects duplicate keys and nonfinite constants. Large hidden tar extension data still counts against the expanded limit.

The oracle accepts valid PAX and GNU metadata and ordinary names with spaces or Unicode. It follows npm's first-component stripping for archives with one consistent top-level component. The component may be `package`, a legacy package name such as `json5`, or another safe relative name. A non-`package` component receives `legacy_archive_root` in `profile_conditions`. The actual component remains visible as `archive_root`. This is an oracle compatibility rule, not a change to the core's supported archive profile.

Only exact regular root-relative `package.json` and `binding.gyp` members supply lifecycle facts. A top-level entry without a second component must be a directory. Multiple roots, roots that differ only in case, duplicate paths, case-fold collisions, lifecycle case aliases, and file-ancestor conflicts make the artifact's execution facts unknown. The oracle never chooses the last duplicate manifest as truth. Manifest name and version still must match the lock identity. A root named `json5` does not establish the package identity.

Python's mature tar parser interprets legacy ustar fields, including nonzero padding after an early NUL in the prefix field. Such padding does not change the root-relative manifest lookup. SRI still binds all original compressed bytes. The oracle does not relabel a valid legacy archive as an integrity failure merely because the core rejects its narrower archive profile.

The oracle verifies SRI against original compressed bytes. It accepts SHA1, SHA256, SHA384, and SHA512 tokens and verifies the strongest algorithm present. At least one strongest digest must match. A verified form outside the core's single canonical SHA512 token receives `noncanonical_integrity`. An incorrect digest remains unknown with an integrity error.

## Change API

`events(base_facts, head_facts)` returns deterministic, JSON-serializable event dictionaries. Every event has `path`, `kind`, `before`, `after`, `obligation`, and `approval_relevant`.

| Kind | Obligation | Compared values |
| --- | --- | --- |
| `added`, `removed` | `package_change` | Package record presence. |
| `name_changed`, `version_changed` | `package_change` | Available lock identity and verified manifest identity. |
| `source_changed`, `integrity_changed` | `package_change` | Original lock metadata for every package. |
| `manifest_changed`, `artifact_changed`, `binding_changed` | `package_change` | Original byte digests available on both sides. |
| `lifecycle_added`, `lifecycle_removed`, `lifecycle_changed` | `execution_change` | Exact event names and script bodies. |
| `implicit_native_changed` | `execution_change` | Qualified native-build rule. |

`approval_relevant` is true when either side is a known install candidate. This distinguishes all-package reporting obligations from execution-candidate approval obligations. It does not assert what an unknown side might execute.

Execution-change comparisons require known facts on both sides. Missing evidence does not invent a lifecycle removal. Available source and integrity changes remain visible when execution metadata is unknown. Byte changes from JSON formatting or gzip recompression remain visible even when lifecycle bodies are unchanged.

`artifact_changed` carries the independently computed `artifact_sha512` values. Manifest and binding events carry SHA256 values. The comparator requires the exact before and after digest for each event. A transition between missing facts and a known digest does not establish both sides of a known byte change. See [the scoring contract](scoring.md).

These labels define narrow change events. They do not label all runtime payload changes as malware or claim general malware detection. Lock install markers are metadata and do not override independently observed manifest facts. Comparison of marker conflicts belongs to the core result and qualification report.

## Verification

Run the independent controls from the repository root.

```sh
python3 -m unittest discover -s tests -p test_qualification_oracle.py -v
```

The tests generate independent ustar, PAX, and GNU inputs. They cover legacy roots and ustar padding, hook changes, source changes, native defaults, workspace scope, binary separation, duplicate and ambiguous inputs, missing evidence, integrity failures, recompression, resource bounds, and root byte binding.

The legacy-root correction was also checked with npm 11.19.1 and Node v26.9.0. Offline installs of an independently generated `legacy-root` archive and the development corpus's original `@types/json5` 0.0.29 archive produced byte-identical installed manifests. The controlled archive's native-build input also matched, and its lifecycle canary remained absent under `--ignore-scripts`. The original `@types/cacheable-request` 6.0.3 archive was inspected independently without installing its external dependencies. These checks establish byte correspondence for those examples. They do not observe lifecycle execution or establish universal npm archive support.
