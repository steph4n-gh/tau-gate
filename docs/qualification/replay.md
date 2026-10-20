# Replay the frozen npm corpus

Use this procedure to acquire original inputs and compare a specified Tau-Gate binary with independently derived package events. The Rust core remains offline and read-only. The acquisition command writes the cache and uses the network. No command installs dependencies or runs public package scripts.

## Acquire original inputs

Run from the repository root. Keep large inputs outside Git.

```sh
python3 tools/qualification.py acquire \
	--corpus docs/qualification/corpus.json \
	--sources /Volumes/Storage/taugate-qualification/sources \
	--archive-cache /Volumes/Storage/taugate-qualification/archives \
	--discovery-cache /tmp/taugate-corpus-discovery/objects \
	--workers 4 \
	--max-bytes 17179869184
```

`--discovery-cache` is optional. Its layout is `OWNER/REPOSITORY/COMMIT/PATH`. Frozen source hashes and lengths are verified before use. Cache filenames alone establish no trust.

The command captures root and workspace manifests, `binding.gyp`, and exact-path HTTP 404 absence receipts. Source receipts bind URLs, full commits, hashes, lengths, and missing inputs. This is caller-trusted raw GitHub capture. It does not prove Git tree modes, case aliases, signatures, or publisher trust. It does not substitute for the production Git-object wrapper.

Archives use canonical SHA512 SRI identities. The constrained production downloader permits HTTPS `registry.npmjs.org` without redirects. Custom registry archives require a supplied cache. The cache filename is `SHA512-HEX.tgz`. Every cache read checks the original bytes against SRI. Acquisition preserves original bytes before strict archive validation, so valid archives outside the supported profile remain measurable.

At most four workers fetch inputs. Each source or archive is limited to 64 MiB. The declared aggregate budget accounts for unique archive identities and source inputs, including verified cache hits. No additional cache file is written after that budget is exhausted. Concurrent responses can transfer up to four additional 64 MiB responses before rejection. Acquisition failures remain per-instance receipts. A run can complete with unavailable inputs.

The source directory contains `acquisition-run.json` and one `OWNER__REPOSITORY/COMMIT` directory per revision. Each revision contains `project`, `evidence/index.json`, `source.json`, and `acquisition.json`. Artifact files are hard-linked to the content-addressed cache where possible. Replay hashes them again.

Re-running acquisition reuses verified bytes. A corrupt cached input is reported. It is not silently replaced. Source absence receipts describe the exact requested path. They do not establish filesystem alias absence.

## Replay the preserved baseline

Use a fresh output directory. The committed corpus binds the preserved macOS arm64 baseline binary to its SHA256. That binary is a measurement baseline, not the supported Linux release payload.

```sh
python3 tools/qualification.py replay \
	--corpus docs/qualification/corpus.json \
	--sources /Volumes/Storage/taugate-qualification/sources \
	--binary /Volumes/Storage/taugate-qualification/baseline/tau-gate-4.1.0 \
	--output /Volumes/Storage/taugate-qualification/baseline-replay \
	--jobs 2 \
	--timeout 120
```

Replay verifies source, locator, and archive hashes before inspection. It invokes the core's advisory `review` command without generated approvals. It does not require public projects to adopt a policy file. Missing locators remain missing. A script-free artifact change remains a reporting obligation without becoming an install-script approval obligation.

At most two cases run concurrently. Each core or collector validation process has a wall timeout of at least 120 seconds. Standard output and standard error each have a 64 MiB limit. Timeout and excess output terminate the process and remain explicit outcomes. Per-process peak RSS uses `/usr/bin/time` where available. Darwin reports bytes. GNU time reports KiB, which the runner converts to bytes. Metrics have a separate raw file and digest. Unsupported platforms and interrupted processes without a usable metric record `null`.

The production collector's `validate` command independently attempts its strict input profile on the diagnostic locator bundle. This measures profile validation, not a second network acquisition or Git capture. The separate oracle uses original archive bytes and source manifests. It reads no core report. The comparison checks reported fields, lifecycle body hashes, native-build facts, and independently known byte facts.

Each case records capture, acquisition, collector, oracle, core, and comparison statuses separately. Raw core and collector output, exact argument vectors, exit codes, termination reasons, output hashes, elapsed time, and source input hashes remain in its directory. `implementation.json` binds the binary, Python helpers, corpus, interpreter, and resource settings. `implementation-after.json` rehashes the binary and helpers after the run. Changed implementation bytes invalidate the run.

A `complete` core report does not establish zero misses. Read the comparison status, known misses, and fact mismatches separately. Unknown oracle truth is not a pass. Partial oracle inspection can still establish some identity-change obligations. No scripts-disabled npm install is performed on these public projects. Static lifecycle qualification relies on the separately pinned npm reference controls.

## Compare a candidate

Give the candidate's independently recorded SHA256 explicitly. Keep baseline receipts unchanged.

```sh
python3 tools/qualification.py replay \
	--corpus docs/qualification/corpus.json \
	--sources /Volumes/Storage/taugate-qualification/sources \
	--binary target/release/tau-gate \
	--expected-binary-sha256 ACTUAL_CANDIDATE_SHA256 \
	--split development \
	--output /Volumes/Storage/taugate-qualification/candidate-development
```

`--split` accepts `all`, `development`, or `holdout`. The default is `all`. Use `--case CASE_ID` for a first single-pair check. Repeat the option to select more cases. The summary retains every unrun frozen pair. Reserve holdout inputs until development repairs stop. Development-only runs still summarize all frozen pairs, with unrun pairs visible.

## Account for every selected pair

```sh
python3 tools/qualification.py summarize \
	--corpus docs/qualification/corpus.json \
	--receipts /Volumes/Storage/taugate-qualification/baseline-replay \
	--output /Volumes/Storage/taugate-qualification/baseline-summary.json
```

The denominator includes every frozen pair, including missing receipts, unsupported archives, invalid captures, timeouts, and incomplete oracle facts. Package counts describe pair-side records. A revision reused by multiple pairs appears more than once. `core_complete_pairs` counts valid core reports with exit code zero. `complete_pairs` additionally requires complete capture, acquisition, collector validation, and oracle stages. Comparison misses remain separate. Core evidence states and oracle known-package counts remain separate. If oracle package records are unavailable, `package_denominator_complete` is false.

Review-decision counts are mechanical proxies. They are not human review minutes. The simple-diff baseline counts independently known changed instances and events. It does not simulate a maintainer or claim equivalent security outcomes. Historical cohort results do not establish malware detection, sustained adoption, or representative random-sample coverage.

## Verify the replay tool

```sh
python3 -m unittest discover -s tests -p test_qualification.py -v
python3 -m py_compile tools/qualification.py tools/qualification_oracle.py
```

The tests cover hash substitution, unavailable artifacts, source hash failures, known misses under incomplete reports, unknown truth, script-free source changes, missing receipts, and subprocess timeouts.
