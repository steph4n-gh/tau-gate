# Review an npm pull request from Git objects

Use the caller-trusted Python helpers and checker binary to review two commits. The helper captures the root manifest, every locked workspace manifest, sibling `binding.gyp` files, and the npm v3 lock directly from Git objects. A dirty working tree does not change those inputs. No package manager, package script, or head-side helper runs.

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

Adapt [the GitHub Actions example](examples/npm-pr-review.yml) in the npm application's repository. It uses `pull_request_target` for PRs targeting `main` and grants only `contents: read`. The workflow comes from the trusted base, fetches both exact commits, checks out only the base, runs helpers from that base, and verifies the release archive against an administrator-configured SHA256 before extracting the checker. Head source is read only through Git objects. Never add a step that executes the fetched head or its dependency scripts. [GitHub documents this trust boundary](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

Put `tools/pr_review.py`, `tools/npm_evidence.py`, and an explicit approval file on the trusted base branch first. Set repository variables `TAU_GATE_ARCHIVE_URL` and `TAU_GATE_ARCHIVE_SHA256` to the published Linux archive's HTTPS URL and lowercase SHA256. The example verifies the archive before extracting the checker. It has no default download URL or digest. Keep those variables and the workflow under trusted repository administration. Confirm the repository's Actions event policy permits `pull_request_target`; GitHub's [public-repository policy](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target) can block it. Change the branch filter if the protected base is not `main`.

Open a test PR that changes execution evidence and confirm the `tau-gate` job blocks it, then require that check from GitHub Actions in branch protection or a ruleset. Require up-to-date checks if base policy changes while PRs are open. A missing, skipped, or policy-blocked run must prevent merge; a green report alone does not establish that branch protection is active. If the repository uses a merge queue, add and separately verify a `merge_group` check before making this job required; [GitHub treats that event separately](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

Upgrade trusted helpers and checker before adopting approval schema 2. The checker continues to read schema 1. For a dependency update, first review its advisory fingerprint and merge a policy-only PR whose schema 2 entry holds both the current and proposed fingerprints. The old evidence must remain allowed after that merge. Next merge the dependency PR; the wrapper uses the staged base policy and blocks any unreviewed fingerprint. Finally merge a policy-only cleanup PR that removes the old fingerprint. Verify main after each merge. Head-side changes to the policy, helpers, workflow, or a purported checker binary do not alter the trusted base tools for that PR.

The example preserves only `report.json` and `summary.md` as a seven-day workflow artifact, including blocked and incomplete results. It never uploads the captured source or archive bundle. The upload step pins [GitHub's upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) to its exact commit.

This repository is a Rust project, so the npm example is documentation rather than an active npm audit job. The active CI runs the helper's temporary-Git behavioral tests against its freshly built checker. Pilot repositories must verify the workflow and required-check setting on GitHub itself.

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
