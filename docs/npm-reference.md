# Run the independent npm reference check

Run the reference check with an installed Node and npm. Use exact executable paths when the machine has several installations.

```sh
python3 tools/npm_reference.py \
	--node /path/to/node \
	--npm /path/to/npm/bin/npm-cli.js \
	--output /tmp/tau-gate-npm-reference
```

The output directory must be empty. A successful run prints `"status": "pass"` and writes `receipt.json`. Omit `--output` for a disposable run. Add `--tau-gate /path/to/tau-gate` to compare the existing CLI's package identities with the independent fixture inventory.

Inspect `receipt.json` for command arguments, exit codes, npm and Node versions, executable hashes, input hashes, selected instances, exclusions, and negative-control results. The `commands` directory preserves stdout and stderr. `oracle.json` records expected artifact and source-project facts. `evidence/index.json` locates original archives and copied project manifests. `archive-cache` contains the same original archives under their SHA512 digest names.

The check creates deterministic gzip and ustar artifacts from `tests/fixtures/npm-reference/matrix.json`. Its registry listens on `127.0.0.1` and serves only those artifacts and their metadata. Both lock creation and `npm ci` use `--ignore-scripts --no-audit --no-fund`. The npm configuration, HOME, prefix, cache, and project directories are private temporary directories. Lifecycle canaries must remain absent.

The fixture covers alias identities, nested versions, a workspace target and link, selected and platform-excluded optional packages, an absent optional peer, native build defaults, an explicit install override, `gypfile: false`, a script-free package, and all seven root lifecycle keys. The check compares each installed registry manifest's raw bytes with the original SRI-verified archive manifest. It records excluded packages without removing them from locked audit scope. It checks the workspace symlink target and source manifest separately.

Scripts-disabled installation proves manifest correspondence for this controlled matrix. It does not observe lifecycle scheduling. The receipt separately records the hashes and relevant line numbers of the exact npm implementation's `ci.js`, Arborist `rebuild.js`, and `run-script-pkg.js`. Those source rules qualify the root's seven events, registry dependencies' three events, workspace links' additional `prepare` event, and native-build suppression rules. The source files are copied under `npm-source` for inspection.

Negative controls must reject corrupted archives, same-name/version substitutions, wrong-version archives even with matching SRI, duplicate instances, wrong lock hashes, missing evidence, registry manifests supplied without artifacts, wrong workspace identity, unsafe locators, and invented verification flags. A lifecycle body paired with an explicit false install marker must produce a conflict. These are independent Python outcomes. Rust enforcement requires its separate milestone gate.

An absent install marker makes no assertion about execution. The controlled native package's lock has no install marker, although its archive contains `binding.gyp` and qualifies for npm's implicit build rule. Archive facts refine missing marker metadata. An explicit false marker contradicts positive install evidence. An explicit true marker contradicts the absence of both install scripts and an implicit build.

## Collect a locator bundle without installing

Run the explicit acquisition helper against a trusted source snapshot.

```sh
python3 tools/npm_evidence.py collect \
	--lock /snapshot/package-lock.json \
	--project /snapshot \
	--output /tmp/npm-evidence
```

The helper invokes no package manager and runs no package scripts. Network acquisition accepts only `https://registry.npmjs.org` on the default port or port 443. Credentials, fragments, and redirects fail. For another registry or a fully offline run, supply original archives through `--archive-cache`. Name each cache file `<hex-sha512-of-compressed-bytes>.tgz`. The archive must match the exact locked SHA512 SRI.

The helper copies each root or workspace manifest and its adjacent `binding.gyp` when present. These files are caller-supplied source inputs. They are not registry-artifact attestations or signed proof of a Git revision. Links receive no separate artifact entry. Their source targets retain exact lock keys.

Validate a bundle offline.

```sh
python3 tools/npm_evidence.py validate \
	--lock /snapshot/package-lock.json \
	--manifest /snapshot/package.json \
	--index /tmp/npm-evidence/index.json
```

Validation exits 0 for a complete supported bundle and 2 for invalid or missing evidence. Marker conflicts appear in derived facts and cannot establish a clean approval. The locator schema contains only `schema_version`, `lock_sha256`, and `packages`. Each package entry contains its exact lock `path` plus either `artifact` or `project_manifest`. Relative paths cannot traverse parents or symlinks. Files, compressed archives, and decompressed tar data have bounded sizes. The supported archive profile uses one gzip member and regular ustar files or directories. Extension records, special entries, duplicate paths, malformed data, and extra gzip members fail.

The Rust audit remains the read-only verifier. The Python helper's facts do not authorize themselves. The core derives artifact facts from the original archive bytes and source facts from the copied source inputs.
