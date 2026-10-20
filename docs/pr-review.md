# Review an npm pull request from Git objects

Use the caller-trusted v4.1 Python helpers and checker binary to review two commits. The helper captures the root manifest, every locked workspace manifest, sibling `binding.gyp` files, and the npm v3 lock directly from Git objects. A dirty working tree does not change those inputs. No package manager, checkout, package script, or head-side helper runs.

1. Put an explicit [bound approval file](execution-evidence.md#approval-schema-and-outcomes) in the trusted base commit. Review candidate fingerprints from an advisory evidence report before you approve them. An empty approval list is valid policy. A missing file is incomplete input.
2. Fetch the exact base and head commits before the review. Use Git with support for `--no-lazy-fetch`. Object reads disable replacement objects and lazy fetching. Unavailable objects return incomplete instead of accessing the network.
3. Run the helper from a trusted checkout outside the target repository. Use an absolute path to the trusted checker binary.

```sh
python3 /trusted/tau-gate/tools/pr_review.py \
	--repo /repositories/application \
	--base "$BASE_COMMIT" \
	--head "$HEAD_COMMIT" \
	--project apps/web \
	--approvals apps/web/tau-gate.approvals.json \
	--tau-gate /trusted/bin/tau-gate \
	--archive-cache /evidence/archive-cache \
	--output /evidence/pr-review
```

4. Read `summary.md` and `report.json` in the output directory. Preserve the exit code when you run the helper in CI. Exit 0 means allowed, 1 means blocked, and 2 means incomplete.

Omit `--project` for a repository-root npm project. `--approvals` is repository-relative and defaults to `tau-gate.approvals.json`. The helper reads this file from the base commit only. Head-side edits cannot authorize new execution. The trusted base revision is a caller choice and must come from the repository's PR metadata or equivalent trusted policy.

The archive cache uses `<original-archive-sha512-hex>.tgz` filenames. With `--archive-cache`, acquisition is offline and a missing archive returns incomplete. Without that option, the separate [evidence collector](npm-reference.md) can download original archives from HTTPS `registry.npmjs.org` on port 443. It rejects redirects, credentials, proxy use, and custom registry downloads. The Rust core stays offline and read-only.

The output directory must be new or empty and separate from the target repository and archive cache. A symlink output directory is rejected. Parent paths are resolved before the separation check. The helper writes captured inputs, evidence bundles, the base approval file, a deterministic JSON report, and a Markdown summary. It never writes the target checkout or archive cache.

`report.json` records full commit IDs, each captured Git blob ID, original mode, size, and SHA256. It records observed `binding.gyp` absences and the base policy's path, commit, blob ID, and SHA256. Trusted helper and binary byte hashes identify the implementation used. `core` contains the complete review and policy report. `errors` identifies the stage and reason for invalid inputs. Generated metadata has no timestamps or absolute repository and output paths. Filesystem diagnostics replace local path prefixes. Locked package values remain verbatim, including source URLs. The same commits, tool bytes, policy, and artifacts produce identical report and summary bytes in different output directories.

Only npm v3 `package-lock.json` is supported. Root and workspace source paths use the [portable ASCII profile](execution-evidence.md#artifact-profile). Source directories with non-ASCII entry names remain incomplete. Case aliases and trailing-dot aliases of captured paths fail. This prevents a case-insensitive checkout from observing a native input that an exact Git lookup treated as absent. Regular Git blob modes `100644` and `100755` are preserved in the report. Symlinks, gitlinks, missing manifests, unavailable revisions, non-commit objects, unsupported locks, and invalid policy remain incomplete. Revisions accept ordinary refs and full object IDs, without revision operators. Raw Git trees have a 16 MiB bound. Files and rendered Git output have a 64 MiB bound, and source manifests have a 1 MiB bound.

The summary lists package coordinates, changed source and integrity values, changed execution facts, introducer paths, unapproved fingerprints, and incomplete reasons. Package and evidence change lists show at most 30 entries each. The JSON report retains every entry. Artifact integrity proves agreement with the supplied lock bytes. Source snapshots retain caller trust. Neither result establishes publisher authenticity, script safety, or host-specific installation selection.

## Add a read-only CI check

Adapt [the GitHub Actions example](examples/npm-pr-review.yml) in the npm application's repository. It uses `pull_request` and read-only contents permission. It fetches both commits, checks out only the trusted base, runs the Python helpers from that base, and verifies an externally supplied checker binary against an administrator-configured SHA256. Head source is read only through Git objects.

Before you enable the example, put the v4.1 `tools/pr_review.py` and `tools/npm_evidence.py` in the trusted base. Publish or otherwise supply a qualified v4.1 Linux checker binary. Set repository variables `TAU_GATE_BINARY_URL` and `TAU_GATE_BINARY_SHA256` to its HTTPS URL and lowercase SHA256. The example deliberately has no default download URL or digest. Keep those variables and the workflow under trusted repository administration. Use branch protection or the repository's required-workflow policy to require the check. The example does not post comments, upload source, modify approvals, or use `pull_request_target`.

A `pull_request` workflow can itself be changed by the PR. Review or protect workflow changes. The base-tool guarantee assumes a trusted, unchanged workflow and runtime. This example alone cannot enforce that assumption when a PR replaces the workflow.

The example preserves only `report.json` and `summary.md` as a seven-day workflow artifact, including blocked and incomplete results. It never uploads the captured source or archive bundle. The upload step pins [GitHub's upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) to its exact commit.

This repository is a Rust project, so the npm example is documentation rather than an active npm audit job. The active CI runs the helper's temporary-Git behavioral tests against its freshly built checker.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_pr_review.py' -v
```

Replay the separate black-box Git qualification against the same trusted tools.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_pr_review.py \
	--wrapper tools/pr_review.py \
	--binary target/release/tau-gate \
	--output /tmp/tau-gate-pr-controls
```

This verifier constructs its own original archives and commits. Expected hashes, modes, sizes, and object IDs come from those Git objects. It checks policy resistance to head edits, dirty-tree exclusion, changed execution evidence, deterministic reports, intended incomplete diagnoses, and unchanged repository, `.git`, and archive-cache contents. It imports no wrapper implementation and runs no npm command or network operation. Inspect its `receipt.json` for commands, input hashes, tool hashes, and each outcome. This finite matrix does not qualify arbitrary Git servers or online acquisition.
