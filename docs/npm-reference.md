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

An absent install marker makes no assertion about execution. The controlled native package's lock has no install marker, although its archive contains `binding.gyp` and qualifies for npm's implicit build rule. Archive facts refine missing marker metadata. An explicit false marker contradicts positive install evidence. A true marker only prompts npm to inspect the unpacked manifest. If the integrity-verified archive has no install script or implicit native build, its inspected facts resolve the hint without an execution candidate; the raw marker remains in the report.

## Collect a locator bundle without installing

Run the explicit acquisition helper against a trusted source snapshot.

```sh
python3 tools/npm_evidence.py collect \
	--lock /snapshot/package-lock.json \
	--project /snapshot \
	--output /tmp/npm-evidence
```

The helper invokes no package manager and runs no package scripts. Network acquisition accepts only `https://registry.npmjs.org` on the default port or port 443. Credentials, fragments, and redirects fail. For another registry or a fully offline run, supply original archives through `--archive-cache`. Name each cache file `<hex-sha512-of-compressed-bytes>.tgz`. The archive must match the exact locked SHA512 SRI.

Both cached and downloaded archives require a supported direct HTTP or HTTPS `resolved` URL ending in `.tgz` or `.tar.gz`. Git and directory sources remain incomplete, even when a supplied archive matches a caller-added SRI. The domains `github.com`, `gist.github.com`, `gitlab.com`, `bitbucket.org`, `git.sr.ht`, and their subdomains are outside this profile. URLs with credentials, query strings, fragments, percent escapes, non-ASCII characters, or ambiguous path components are unsupported. This restriction preserves npm's distinction between an original remote archive and a source that npm prepares before installation.

The helper copies each root or workspace manifest and its adjacent `binding.gyp` when present. These files are caller-supplied source inputs. They are not registry-artifact attestations or signed proof of a Git revision. Links receive no separate artifact entry. Their source targets retain exact lock keys.

Validate a bundle offline.

```sh
python3 tools/npm_evidence.py validate \
	--lock /snapshot/package-lock.json \
	--manifest /snapshot/package.json \
	--index /tmp/npm-evidence/index.json
```

Validation exits 0 for a complete supported bundle and 2 for invalid or missing evidence. Marker conflicts appear in derived facts and cannot establish a clean approval. The locator schema contains only `schema_version`, `lock_sha256`, and `packages`. Each package entry contains its exact lock `path` plus either `artifact` or `project_manifest`. Relative paths cannot traverse parents or symlinks. Files, compressed archives, and decompressed tar data have bounded sizes. The supported archive profile uses one gzip member and regular ustar files or directories. Extension records, special entries, duplicate paths, malformed data, and extra gzip members fail.

Archive path components use printable ASCII except Windows-invalid punctuation. Empty or dot components, trailing dots or spaces, and Windows device names are unsupported. All entries must have one consistent top-level directory, which need not be named `package`. The lifecycle inputs must have the exact root-relative names `package.json` and `binding.gyp`. Case aliases such as `root/Binding.gyp` fail rather than hiding a native build on a case-insensitive filesystem. Paths cannot collide after ASCII case folding or conflict with a file used as an ancestor directory. A non-lifecycle regular file may use `root/./rest` only when `root/rest` appears with identical bytes and header fields apart from its name and checksum. Unicode names remain unsupported.

The Rust audit remains the read-only verifier. The Python helper's facts do not authorize themselves. The core derives artifact facts from the original archive bytes and source facts from the copied source inputs.

## Replay the independent core controls

After the reference check passes, run the black-box corpus against the built binary.

```sh
python3 tools/verify_npm_evidence.py \
	--binary target/release/tau-gate \
	--reference-bundle /tmp/tau-gate-npm-reference \
	--output /tmp/tau-gate-core-controls
```

The output directory must be empty. The corpus checks stored, fixed, and dynamic DEFLATE blocks, overlapping copies, malformed archives, locator binding, resource limits, approval invalidation, the npm oracle, and input preservation. It also checks case aliases of native inputs, manifest overwrites, case-folded file and parent conflicts, nonportable filenames, and unsupported Git or directory sources with matching archive SRI. These cases enforce an empty approval file and must report the intended incomplete diagnosis. A canonical native package provides the corresponding blocked-policy control. Python's standard library generates and independently inspects the inputs. It invokes the auditor directly and runs no package manager, scripts, or network operation. A crash, timeout, unexpected outcome, changed binary, or changed input fails the run.

Inspect `receipt.json` and the captured command output. The receipt records the seed, binary and verifier hashes, exact commands, and per-case checks. This finite corpus does not prove exhaustive decoder correctness or artifact safety.
